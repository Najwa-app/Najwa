//! HTTP-based mailbox client implementation.
//!
//! Communicates with mailbox servers over Tor using JSON request/response
//! format defined in S16 §3. Includes retry logic with exponential backoff
//! and automatic PoW solving on 429 responses.

use std::sync::Arc;

use async_trait::async_trait;
use najwa_transport::circuit::CircuitIsolation;
use rand::Rng;

use super::client::{MailboxClient, Transport};
use super::error::{MailboxError, Result, RetryConfig};
use super::pow::solve_pow;
use super::types::*;

/// Mailbox client that communicates over Tor via HTTP/JSON.
#[derive(Clone)]
pub struct HttpMailboxClient {
    transport: Arc<dyn Transport>,
    retry: RetryConfig,
}

impl HttpMailboxClient {
    /// Deactivation during local profile erasure (S13 §10.1). One attempt, no
    /// PoW, the endpoint's `ByMailbox` circuit (S04 §4.1.1), the S16 §3.9 base64
    /// body, and zeroizing request bytes containing the capability.
    pub async fn deactivate_emergency(&self, onion: &str, fetch: &[u8; 32]) -> Result<()> {
        use base64::Engine;
        if onion.len() != 56
            || !onion
                .bytes()
                .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
        {
            return Err(MailboxError::ServerError(400));
        }
        #[derive(serde::Serialize)]
        struct Request<'a> {
            fetch_capability: &'a str,
        }
        let circuit = self
            .transport
            .get_circuit(CircuitIsolation::ByMailbox(onion.into()))
            .await?;
        let encoded =
            zeroize::Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(fetch));
        let body = zeroize::Zeroizing::new(serde_json::to_vec(&Request {
            fetch_capability: &encoded,
        })?);
        let response = self
            .transport
            .post(
                &circuit,
                &format!("http://{onion}.onion/v1/capability/deactivate"),
                &body,
                "application/json",
            )
            .await?;
        if (200..300).contains(&response.status) || response.status == 404 {
            Ok(())
        } else {
            Err(MailboxError::ServerError(response.status))
        }
    }

    /// Create a new `HttpMailboxClient`.
    pub fn new(transport: Arc<dyn Transport>) -> Self {
        Self {
            transport,
            retry: RetryConfig::default(),
        }
    }

    /// Create with custom retry configuration.
    pub fn with_retry(transport: Arc<dyn Transport>, retry: RetryConfig) -> Self {
        Self { transport, retry }
    }

    /// Build the full URL for a mailbox endpoint.
    ///
    /// For `.onion` addresses: `http://<hash>.onion<path>`
    /// For direct addresses (testing): `http://<host:port><path>`
    fn url(mailbox: &MailboxConfig, path: &str) -> String {
        if mailbox.onion_address.contains(':')
            || mailbox.onion_address.contains('.') && !mailbox.onion_address.ends_with("onion")
        {
            // Direct address (e.g. "10.0.2.2:8080") — no .onion suffix
            format!("http://{}{}", mailbox.onion_address, path)
        } else {
            format!("http://{}.onion{}", mailbox.onion_address, path)
        }
    }

    /// POST a JSON body over a circuit with the caller-chosen isolation (§4.1.1).
    async fn post_json_isolated<T: serde::Serialize>(
        &self,
        mailbox: &MailboxConfig,
        path: &str,
        body: &T,
        isolation: CircuitIsolation,
    ) -> Result<najwa_transport::http::HttpResponse> {
        let circuit = self.transport.get_circuit(isolation).await?;

        let url = Self::url(mailbox, path);
        let body_bytes = serde_json::to_vec(body)?;

        let response = self
            .transport
            .post(&circuit, &url, &body_bytes, "application/json")
            .await?;

        Ok(response)
    }

    async fn post_json_once<T: serde::Serialize>(
        &self,
        mailbox: &MailboxConfig,
        path: &str,
        body: &T,
        isolation: CircuitIsolation,
    ) -> Result<najwa_transport::http::HttpResponse> {
        let resp = self
            .post_json_isolated(mailbox, path, body, isolation)
            .await?;
        match resp.status {
            200..=299 => Ok(resp),
            429 => Err(MailboxError::RateLimited),
            404 => Err(MailboxError::CapabilityNotFound),
            413 => Err(MailboxError::MessageTooLarge),
            507 => Err(MailboxError::QuotaExceeded),
            status => Err(MailboxError::ServerError(status)),
        }
    }

    pub async fn prepare_registration_pow(&self, mailbox: &MailboxConfig) -> Result<PowSolution> {
        self.solve_challenge(mailbox).await
    }

    /// Called after a tier-6 grant; each registration has its own circuit.
    pub async fn register_cover_once(
        &self,
        mailbox: &MailboxConfig,
        settings: &CapabilitySettings,
        pow: PowSolution,
    ) -> Result<()> {
        let request = RegisterCapabilityRequest {
            capability_type: Some(2),
            expires_at: None,
            fetch_capability: mailbox.fetch_capability,
            deposit_capability: mailbox.deposit_capability,
            pow_solution: Some(pow),
            settings: settings.clone(),
        };
        self.post_json_once(
            mailbox,
            "/v1/capability/register",
            &request,
            CircuitIsolation::OneShot,
        )
        .await?;
        Ok(())
    }

    /// Register a S16 type-1 invitation after a control slot. Retries are owned
    /// by the caller and preserve the exact pair and absolute expiry.
    pub async fn register_ephemeral_once(
        &self,
        mailbox: &MailboxConfig,
        settings: &CapabilitySettings,
        pow: PowSolution,
        expires_at: u64,
    ) -> Result<()> {
        let request = RegisterCapabilityRequest {
            capability_type: Some(1),
            expires_at: Some(expires_at),
            fetch_capability: mailbox.fetch_capability,
            deposit_capability: mailbox.deposit_capability,
            pow_solution: Some(pow),
            settings: settings.clone(),
        };
        self.post_json_once(
            mailbox,
            "/v1/capability/register",
            &request,
            CircuitIsolation::OneShot,
        )
        .await?;
        Ok(())
    }

    /// POST with retry logic on transport errors.
    ///
    /// Retries on transport failures with exponential backoff.
    /// Returns the raw HTTP response for 2xx; maps 4xx/5xx to errors.
    /// Does NOT auto-solve PoW — callers that need PoW must handle it
    /// explicitly (see `register_capability`).
    async fn post_json_with_retry<T: serde::Serialize>(
        &self,
        mailbox: &MailboxConfig,
        path: &str,
        body: &T,
    ) -> Result<najwa_transport::http::HttpResponse> {
        let isolation = CircuitIsolation::ByMailbox(mailbox.onion_address.clone());
        self.post_json_with_retry_isolated(mailbox, path, body, isolation)
            .await
    }

    /// `post_json_with_retry` with a caller-chosen circuit isolation (§4.1.1).
    async fn post_json_with_retry_isolated<T: serde::Serialize>(
        &self,
        mailbox: &MailboxConfig,
        path: &str,
        body: &T,
        isolation: CircuitIsolation,
    ) -> Result<najwa_transport::http::HttpResponse> {
        let mut attempts = 0;

        loop {
            let response = self
                .post_json_isolated(mailbox, path, body, isolation.clone())
                .await;

            match response {
                Ok(resp) => match resp.status {
                    200..=299 => return Ok(resp),
                    429 => return Err(MailboxError::RateLimited),
                    404 => return Err(MailboxError::CapabilityNotFound),
                    413 => return Err(MailboxError::MessageTooLarge),
                    507 => return Err(MailboxError::QuotaExceeded),
                    _ => return Err(MailboxError::ServerError(resp.status)),
                },
                Err(e) => {
                    attempts += 1;
                    if attempts > self.retry.max_retries {
                        return Err(e);
                    }

                    // S04 §9.1.1: CSPRNG full-jitter backoff — sleep a uniform
                    // random delay in `[0, min(60s, base * 2^(n-1))]`. Deterministic
                    // exponential backoff is an explicitly-forbidden correlation
                    // vector; the ceiling is 60s (not `max_delay_ms`).
                    let ceiling = self
                        .retry
                        .base_delay_ms
                        .saturating_mul(1u64 << (attempts - 1).min(20))
                        .min(60_000);
                    let delay_ms = rand::thread_rng().gen_range(0..=ceiling.max(1));

                    tracing::warn!(
                        attempt = attempts,
                        max = self.retry.max_retries,
                        delay_ms,
                        error = %e,
                        "retrying mailbox request (full-jitter)"
                    );

                    tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
                }
            }
        }
    }

    /// Acquire a PoW challenge from `/v1/challenge` and solve it, bound to the
    /// given per-endpoint capability binding (+ blob hash for deposits) per §7.1.
    ///
    /// S04 §4.1.1: the challenge rides `isolation`, the isolation of the request
    /// it gates — never the user's `ByMailbox` circuit, which would let the
    /// mailbox link the gated request to the user's real fetches.
    async fn solve_challenge_bound(
        &self,
        mailbox: &MailboxConfig,
        cap_binding: Vec<u8>,
        blob_hash: [u8; 32],
        isolation: CircuitIsolation,
    ) -> Result<PowSolution> {
        // capability_hint = SHA256(deposit_capability)[0:8]
        let cap_hint: [u8; 8] = {
            use sha2::{Digest, Sha256};
            let hash = Sha256::digest(mailbox.deposit_capability);
            let mut hint = [0u8; 8];
            hint.copy_from_slice(&hash[..8]);
            hint
        };

        let challenge = self.challenge_on(mailbox, &cap_hint, isolation).await?;
        tracing::info!(difficulty = challenge.difficulty, "solving PoW challenge");

        let solution = tokio::task::spawn_blocking({
            let c = challenge.clone();
            move || solve_pow(&c, &cap_binding, &blob_hash)
        })
        .await
        .map_err(|e| MailboxError::DeserializationError(format!("join error: {e}")))??;

        tracing::info!(nonce = solution.nonce, "PoW solved");
        Ok(solution)
    }

    /// Solve a registration PoW. Binding = `fetch_cap || deposit_cap`, no blob.
    /// Registrations ride `OneShot` (S04 §4.1.1), so the challenge does too.
    async fn solve_challenge(&self, mailbox: &MailboxConfig) -> Result<PowSolution> {
        let mut cap_binding = Vec::with_capacity(64);
        cap_binding.extend_from_slice(&mailbox.fetch_capability);
        cap_binding.extend_from_slice(&mailbox.deposit_capability);
        self.solve_challenge_bound(mailbox, cap_binding, [0u8; 32], CircuitIsolation::OneShot)
            .await
    }

    /// `POST /v1/challenge` over the caller-chosen isolation (S04 §4.1.1).
    async fn challenge_on(
        &self,
        mailbox: &MailboxConfig,
        capability_hint: &[u8; 8],
        isolation: CircuitIsolation,
    ) -> Result<PowChallenge> {
        let request = ChallengeRequest {
            capability_hint: capability_hint.to_vec(),
        };
        let response = self
            .post_json_with_retry_isolated(mailbox, "/v1/challenge", &request, isolation)
            .await?;
        Self::parse_response(&response)
    }

    /// Parse a JSON response body.
    fn parse_response<T: serde::de::DeserializeOwned>(
        response: &najwa_transport::http::HttpResponse,
    ) -> Result<T> {
        serde_json::from_slice(&response.body).map_err(|e| {
            MailboxError::DeserializationError(format!("failed to parse response: {e}"))
        })
    }
}

#[async_trait]
impl MailboxClient for HttpMailboxClient {
    async fn register_capability(
        &self,
        mailbox: &MailboxConfig,
        settings: &CapabilitySettings,
        pow: Option<&PowSolution>,
    ) -> Result<()> {
        // Registration always requires PoW (S16 §7.2).
        // If caller didn't provide a pre-solved PoW, acquire and solve one.
        let solved_pow = match pow {
            Some(p) => p.clone(),
            None => self.solve_challenge(mailbox).await?,
        };

        let request = RegisterCapabilityRequest {
            capability_type: Some(2),
            expires_at: None,
            fetch_capability: mailbox.fetch_capability,
            deposit_capability: mailbox.deposit_capability,
            pow_solution: Some(solved_pow),
            settings: settings.clone(),
        };

        self.post_json_with_retry(mailbox, "/v1/capability/register", &request)
            .await?;
        Ok(())
    }

    /// A bare challenge gates nothing known here, so it takes an unlinkable
    /// `OneShot` circuit. Internal PoW paths use the gated request's isolation.
    async fn get_challenge(
        &self,
        mailbox: &MailboxConfig,
        capability_hint: &[u8; 8],
    ) -> Result<PowChallenge> {
        self.challenge_on(mailbox, capability_hint, CircuitIsolation::OneShot)
            .await
    }

    async fn deposit(
        &self,
        mailbox: &MailboxConfig,
        deposit_cap: &[u8; 32],
        blob: &[u8],
        pow: Option<&PowSolution>,
    ) -> Result<DepositResult> {
        // On a PoW-required 429 (adaptive threshold, or a type-1 cap's always-on
        // floor), solve a deposit-bound challenge (§7.1: deposit_cap + SHA256(blob))
        // and retry ONCE. A `RateLimited` that is actually a hard rate ceiling
        // (60/min) simply resurfaces after the single retry rather than looping.
        let mut solution = pow.cloned();
        let mut attempted_pow = false;
        loop {
            let request = DepositRequest {
                deposit_capability: *deposit_cap,
                blob: blob.to_vec(),
                pow_solution: solution.clone(),
            };
            match self
                .post_json_with_retry_isolated(
                    mailbox,
                    "/v1/deposit",
                    &request,
                    CircuitIsolation::OneShot,
                )
                .await
            {
                Ok(response) => return Self::parse_response(&response),
                // Only auto-solve when the caller opted in (default). With
                // `retry_on_pow = false` a 429 resurfaces as RateLimited unchanged.
                Err(MailboxError::RateLimited) if !attempted_pow && self.retry.retry_on_pow => {
                    use sha2::{Digest, Sha256};
                    let blob_hash: [u8; 32] = Sha256::digest(blob).into();
                    solution = Some(
                        self.solve_challenge_bound(
                            mailbox,
                            deposit_cap.to_vec(),
                            blob_hash,
                            CircuitIsolation::OneShot,
                        )
                        .await?,
                    );
                    attempted_pow = true;
                }
                Err(e) => return Err(e),
            }
        }
    }

    async fn deposit_once(
        &self,
        mailbox: &MailboxConfig,
        deposit_cap: &[u8; 32],
        blob: &[u8],
        pow: Option<&PowSolution>,
    ) -> Result<DepositResult> {
        let request = DepositRequest {
            deposit_capability: *deposit_cap,
            blob: blob.to_vec(),
            pow_solution: pow.cloned(),
        };
        let response = self
            .post_json_once(mailbox, "/v1/deposit", &request, CircuitIsolation::OneShot)
            .await?;
        Self::parse_response(&response)
    }

    async fn deposit_file_once(
        &self,
        mailbox: &MailboxConfig,
        deposit_cap: &[u8; 32],
        blob: &[u8],
        pow: Option<&PowSolution>,
        isolation: [u8; 32],
    ) -> Result<DepositResult> {
        let request = DepositRequest {
            deposit_capability: *deposit_cap,
            blob: blob.to_vec(),
            pow_solution: pow.cloned(),
        };
        let response = self
            .post_json_once(mailbox, "/v1/deposit", &request, CircuitIsolation::FileTransfer(isolation))
            .await?;
        Self::parse_response(&response)
    }

    async fn prepare_deposit_pow(
        &self,
        mailbox: &MailboxConfig,
        deposit_cap: &[u8; 32],
        blob: &[u8],
    ) -> Result<PowSolution> {
        if !self.retry.retry_on_pow {
            return Err(MailboxError::RateLimited);
        }
        use sha2::{Digest, Sha256};
        // The gated retry is a `OneShot` deposit (or a Responsive file part,
        // whose `FileTransfer` circuit a fresh `OneShot` cannot link to more).
        self.solve_challenge_bound(
            mailbox,
            deposit_cap.to_vec(),
            Sha256::digest(blob).into(),
            CircuitIsolation::OneShot,
        )
        .await
    }

    async fn acknowledge_cover(
        &self,
        mailbox: &MailboxConfig,
        fetch_cap: &[u8; 32],
        ids: &[String],
    ) -> Result<()> {
        let request = AcknowledgeRequest {
            fetch_capability: *fetch_cap,
            message_ids: ids.to_vec(),
        };
        self.post_json_once(
            mailbox,
            "/v1/acknowledge",
            &request,
            CircuitIsolation::CoverTraffic(mailbox.onion_address.clone()),
        )
        .await?;
        Ok(())
    }

    async fn fetch(
        &self,
        mailbox: &MailboxConfig,
        fetch_cap: &[u8; 32],
        since_id: Option<&str>,
        limit: u32,
    ) -> Result<Vec<MailboxMessage>> {
        let request = FetchRequest {
            fetch_capability: *fetch_cap,
            since_id: since_id.map(String::from),
            limit,
        };

        let response = self
            .post_json_with_retry(mailbox, "/v1/fetch", &request)
            .await?;
        let fetch_resp: FetchResponse = Self::parse_response(&response)?;
        Ok(fetch_resp.messages)
    }

    async fn deposit_cover(
        &self,
        mailbox: &MailboxConfig,
        deposit_cap: &[u8; 32],
        blob: &[u8],
    ) -> Result<DepositResult> {
        // S10 §4.3: a fresh OneShot circuit per cover deposit, exactly like a
        // real deposit. A reused cover circuit would let the user's guard tell
        // a real deposit (new circuit) from cover (existing one). No PoW
        // auto-solve: a rate-limited cover deposit is just dropped noise.
        let isolation = CircuitIsolation::OneShot;
        let request = DepositRequest {
            deposit_capability: *deposit_cap,
            blob: blob.to_vec(),
            pow_solution: None,
        };
        let response = self
            .post_json_once(mailbox, "/v1/deposit", &request, isolation)
            .await?;
        Self::parse_response(&response)
    }

    async fn fetch_cover(
        &self,
        mailbox: &MailboxConfig,
        fetch_cap: &[u8; 32],
        limit: u32,
    ) -> Result<Vec<MailboxMessage>> {
        // S10 §4.2: per-mailbox CoverTraffic circuit for cover polls.
        let isolation = CircuitIsolation::CoverTraffic(mailbox.onion_address.clone());
        let request = FetchRequest {
            fetch_capability: *fetch_cap,
            since_id: None,
            limit,
        };
        let response = self
            .post_json_once(mailbox, "/v1/fetch", &request, isolation)
            .await?;
        let fetch_resp: FetchResponse = Self::parse_response(&response)?;
        Ok(fetch_resp.messages)
    }

    async fn upload_prekey_bundle(
        &self,
        mailbox: &MailboxConfig,
        deposit_cap: &[u8; 32],
        bundle: &PrekeyBundle,
    ) -> Result<()> {
        let request = UploadPrekeyRequest {
            deposit_capability: *deposit_cap,
            fetch_capability: mailbox.fetch_capability,
            replace_opks: false,
            bundle: bundle.clone(),
        };

        self.post_json_with_retry(mailbox, "/v1/prekey/upload", &request)
            .await?;
        Ok(())
    }

    async fn publish_prekeys_once(
        &self,
        mailbox: &MailboxConfig,
        bundle: &PrekeyBundle,
        replace: bool,
    ) -> Result<()> {
        let request = UploadPrekeyRequest {
            deposit_capability: mailbox.deposit_capability,
            fetch_capability: mailbox.fetch_capability,
            replace_opks: replace,
            bundle: bundle.clone(),
        };
        self.post_json_once(
            mailbox,
            "/v1/prekey/upload",
            &request,
            CircuitIsolation::ByMailbox(mailbox.onion_address.clone()),
        )
        .await?;
        Ok(())
    }

    async fn fetch_prekey_bundle(
        &self,
        mailbox: &MailboxConfig,
        deposit_cap: &[u8; 32],
        contact_pseudonym: &[u8; 32],
    ) -> Result<PrekeyBundle> {
        // S16 §3.7: POST /v1/prekey/fetch. On a PoW-required 429 (adaptive
        // prekey-fetch floor, §7.2), solve a `deposit_cap`-bound challenge
        // (§7.1: blob_hash = zeros) and retry ONCE. A hard rate ceiling
        // resurfaces after the single retry rather than looping.
        //
        // S04 §4.1.1: the fetch rides a `ByContact(pseudonym)` circuit — one per
        // prospective contact — so a mailbox cannot correlate a user's prekey
        // fetches for several new contacts on one circuit.
        let isolation = CircuitIsolation::ByContact(*contact_pseudonym);
        let mut solution: Option<PowSolution> = None;
        let mut attempted_pow = false;
        loop {
            let request = FetchPrekeyRequest {
                deposit_capability: *deposit_cap,
                pow_solution: solution.clone(),
            };
            match self
                .post_json_with_retry_isolated(
                    mailbox,
                    "/v1/prekey/fetch",
                    &request,
                    isolation.clone(),
                )
                .await
            {
                Ok(response) => return Self::parse_response(&response),
                Err(MailboxError::RateLimited) if !attempted_pow && self.retry.retry_on_pow => {
                    solution = Some(
                        self.solve_challenge_bound(
                            mailbox,
                            deposit_cap.to_vec(),
                            [0u8; 32],
                            isolation.clone(),
                        )
                        .await?,
                    );
                    attempted_pow = true;
                }
                Err(e) => return Err(e),
            }
        }
    }

    async fn get_status(
        &self,
        mailbox: &MailboxConfig,
        fetch_cap: &[u8; 32],
    ) -> Result<CapabilityStatus> {
        let request = StatusRequest {
            fetch_capability: *fetch_cap,
        };

        let response = self
            .post_json_with_retry(mailbox, "/v1/status", &request)
            .await?;
        Self::parse_response(&response)
    }

    async fn get_status_once(&self, mailbox: &MailboxConfig) -> Result<CapabilityStatus> {
        let request = StatusRequest {
            fetch_capability: mailbox.fetch_capability,
        };
        let response = self
            .post_json_once(
                mailbox,
                "/v1/status",
                &request,
                CircuitIsolation::ByMailbox(mailbox.onion_address.clone()),
            )
            .await?;
        Self::parse_response(&response)
    }

    async fn deactivate_capability(
        &self,
        mailbox: &MailboxConfig,
        fetch_cap: &[u8; 32],
    ) -> Result<()> {
        let request = DeactivateRequest {
            fetch_capability: *fetch_cap,
        };

        self.post_json_with_retry(mailbox, "/v1/capability/deactivate", &request)
            .await?;
        Ok(())
    }

    async fn deactivate_once(&self, mailbox: &MailboxConfig) -> Result<()> {
        let request = DeactivateRequest {
            fetch_capability: mailbox.fetch_capability,
        };
        self.post_json_once(
            mailbox,
            "/v1/capability/deactivate",
            &request,
            CircuitIsolation::ByMailbox(mailbox.onion_address.clone()),
        )
        .await?;
        Ok(())
    }

    async fn acknowledge(
        &self,
        mailbox: &MailboxConfig,
        fetch_cap: &[u8; 32],
        message_ids: &[String],
    ) -> Result<()> {
        let request = AcknowledgeRequest {
            fetch_capability: *fetch_cap,
            message_ids: message_ids.to_vec(),
        };

        self.post_json_with_retry(mailbox, "/v1/acknowledge", &request)
            .await?;
        Ok(())
    }
}

/// Production `Transport`: the arti-backed `TorTransport`. v1 carried this
/// impl as a CLI-local adapter (`TorAdapter`); the delegation is 1:1, so the
/// impl lives with the trait and every consumer (FFI, CLI) gets it for free.
#[async_trait::async_trait]
impl Transport for najwa_transport::tor::TorTransport {
    async fn get_circuit(
        &self,
        isolation: CircuitIsolation,
    ) -> std::result::Result<
        najwa_transport::circuit::CircuitHandle,
        najwa_transport::error::TransportError,
    > {
        najwa_transport::tor::TorTransport::get_circuit(self, isolation).await
    }

    async fn post(
        &self,
        circuit: &najwa_transport::circuit::CircuitHandle,
        url: &str,
        body: &[u8],
        content_type: &str,
    ) -> std::result::Result<
        najwa_transport::http::HttpResponse,
        najwa_transport::error::TransportError,
    > {
        najwa_transport::tor::TorTransport::post(self, circuit, url, body, content_type).await
    }

    async fn get(
        &self,
        circuit: &najwa_transport::circuit::CircuitHandle,
        url: &str,
    ) -> std::result::Result<
        najwa_transport::http::HttpResponse,
        najwa_transport::error::TransportError,
    > {
        najwa_transport::tor::TorTransport::get(self, circuit, url).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU32, Ordering};
    use tokio::sync::Mutex;

    #[tokio::test]
    async fn ephemeral_registration_transmits_type_expiry_and_never_retries_inside_a_slot() {
        struct RegistrationTransport {
            status: u16,
            calls: AtomicU32,
        }
        #[async_trait]
        impl Transport for RegistrationTransport {
            async fn get_circuit(
                &self,
                isolation: CircuitIsolation,
            ) -> std::result::Result<
                najwa_transport::circuit::CircuitHandle,
                najwa_transport::error::TransportError,
            > {
                assert!(matches!(isolation, CircuitIsolation::OneShot));
                Ok(najwa_transport::circuit::CircuitHandle::new(isolation))
            }
            async fn post(
                &self,
                _: &najwa_transport::circuit::CircuitHandle,
                url: &str,
                body: &[u8],
                _: &str,
            ) -> std::result::Result<
                najwa_transport::http::HttpResponse,
                najwa_transport::error::TransportError,
            > {
                use base64::Engine;
                assert!(url.ends_with("/v1/capability/register"));
                let request: serde_json::Value = serde_json::from_slice(body).unwrap();
                assert_eq!(request["capability_type"], 1);
                assert_eq!(request["expires_at"], 1_700_000_900u64);
                assert_eq!(
                    request["fetch_capability"],
                    base64::engine::general_purpose::STANDARD.encode([0xAA; 32])
                );
                assert_eq!(
                    request["deposit_capability"],
                    base64::engine::general_purpose::STANDARD.encode([0xBB; 32])
                );
                assert_eq!(request["pow_solution"]["nonce"], 42);
                self.calls.fetch_add(1, Ordering::Relaxed);
                Ok(najwa_transport::http::HttpResponse {
                    status: self.status,
                    headers: HashMap::new(),
                    body: b"{}".to_vec(),
                })
            }
            async fn get(
                &self,
                _: &najwa_transport::circuit::CircuitHandle,
                _: &str,
            ) -> std::result::Result<
                najwa_transport::http::HttpResponse,
                najwa_transport::error::TransportError,
            > {
                panic!("a registration slot must use its prepared PoW and make one POST");
            }
        }
        for status in [200, 429, 503] {
            let transport = Arc::new(RegistrationTransport {
                status,
                calls: AtomicU32::new(0),
            });
            let client = HttpMailboxClient::new(transport.clone());
            let result = client
                .register_ephemeral_once(
                    &test_mailbox(),
                    &CapabilitySettings::default(),
                    PowSolution {
                        challenge: vec![0; 32],
                        nonce: 42,
                        hash: [0; 32],
                        timestamp: 1_700_000_000,
                    },
                    1_700_000_900,
                )
                .await;
            assert_eq!(result.is_ok(), status == 200);
            assert_eq!(transport.calls.load(Ordering::Relaxed), 1);
        }
    }

    // -----------------------------------------------------------------------
    // Mock transport for unit testing
    // -----------------------------------------------------------------------

    struct MockTransport {
        /// Canned responses: path → (status, body)
        responses: Mutex<HashMap<String, (u16, Vec<u8>)>>,
        /// Count of POST requests made (for retry verification)
        post_count: AtomicU32,
    }

    #[tokio::test]
    async fn control_slot_operations_never_retry_inside_one_attempt() {
        use base64::Engine;
        let mock = Arc::new(MockTransport::new());
        for path in [
            "/v1/status",
            "/v1/capability/deactivate",
            "/v1/prekey/upload",
        ] {
            mock.set_response(path, 503, serde_json::json!({})).await;
        }
        let client = HttpMailboxClient::new(mock.clone());
        let mailbox = test_mailbox();
        let bundle: PrekeyBundle = serde_json::from_value(serde_json::json!({
            "mailbox_ik_pub": base64::engine::general_purpose::STANDARD.encode([1;32]),
            "signed_prekey": base64::engine::general_purpose::STANDARD.encode([2;32]),
            "signed_prekey_id":1,
            "signed_prekey_signature":base64::engine::general_purpose::STANDARD.encode([3;64]),
            "signed_prekey_timestamp":1, "one_time_prekeys":[]
        }))
        .unwrap();
        assert!(client.get_status_once(&mailbox).await.is_err());
        assert!(client.deactivate_once(&mailbox).await.is_err());
        assert!(client
            .publish_prekeys_once(&mailbox, &bundle, false)
            .await
            .is_err());
        assert_eq!(mock.post_count.load(Ordering::Relaxed), 3);
    }

    struct EmergencyTransport(MockTransport);
    #[async_trait]
    impl Transport for EmergencyTransport {
        async fn get_circuit(
            &self,
            isolation: CircuitIsolation,
        ) -> std::result::Result<
            najwa_transport::circuit::CircuitHandle,
            najwa_transport::error::TransportError,
        > {
            assert!(matches!(isolation, CircuitIsolation::ByMailbox(ref onion) if *onion == "a".repeat(56)));
            self.0.get_circuit(isolation).await
        }
        async fn post(
            &self,
            circuit: &najwa_transport::circuit::CircuitHandle,
            url: &str,
            body: &[u8],
            content_type: &str,
        ) -> std::result::Result<
            najwa_transport::http::HttpResponse,
            najwa_transport::error::TransportError,
        > {
            assert!(url.ends_with(".onion/v1/capability/deactivate"));
            // The S16 §3.9 body the server accepts: the capability as base64.
            assert_eq!(
                serde_json::from_slice::<DeactivateRequest>(body).unwrap().fetch_capability,
                [7u8; 32]
            );
            self.0.post(circuit, url, body, content_type).await
        }
        async fn get(
            &self,
            _: &najwa_transport::circuit::CircuitHandle,
            _: &str,
        ) -> std::result::Result<
            najwa_transport::http::HttpResponse,
            najwa_transport::error::TransportError,
        > {
            panic!("emergency cleanup cannot fetch content")
        }
    }

    #[tokio::test]
    async fn emergency_deactivation_uses_the_mailbox_circuit_and_never_retries_or_solves_pow() {
        let transport = Arc::new(EmergencyTransport(MockTransport::new()));
        transport
            .0
            .set_response(
                "/v1/capability/deactivate",
                429,
                serde_json::json!({"difficulty": 24}),
            )
            .await;
        let client = HttpMailboxClient::new(transport.clone());
        assert!(client
            .deactivate_emergency(&"a".repeat(56), &[7; 32])
            .await
            .is_err());
        assert_eq!(transport.0.post_count.load(Ordering::Relaxed), 1);
        assert!(client
            .deactivate_emergency("127.0.0.1:8080", &[7; 32])
            .await
            .is_err());
        assert_eq!(transport.0.post_count.load(Ordering::Relaxed), 1);
    }

    impl MockTransport {
        fn new() -> Self {
            Self {
                responses: Mutex::new(HashMap::new()),
                post_count: AtomicU32::new(0),
            }
        }

        async fn set_response(&self, path: &str, status: u16, body: impl serde::Serialize) {
            let body_bytes = serde_json::to_vec(&body).unwrap();
            self.responses
                .lock()
                .await
                .insert(path.to_string(), (status, body_bytes));
        }
    }

    #[async_trait]
    impl Transport for MockTransport {
        async fn get_circuit(
            &self,
            _isolation: CircuitIsolation,
        ) -> std::result::Result<
            najwa_transport::circuit::CircuitHandle,
            najwa_transport::error::TransportError,
        > {
            Ok(najwa_transport::circuit::CircuitHandle::new(
                CircuitIsolation::OneShot,
            ))
        }

        async fn post(
            &self,
            _circuit: &najwa_transport::circuit::CircuitHandle,
            url: &str,
            _body: &[u8],
            _content_type: &str,
        ) -> std::result::Result<
            najwa_transport::http::HttpResponse,
            najwa_transport::error::TransportError,
        > {
            self.post_count.fetch_add(1, Ordering::Relaxed);

            // Extract path from URL
            let path = url
                .find(".onion")
                .map(|i| &url[i + ".onion".len()..])
                .unwrap_or("/");

            let responses = self.responses.lock().await;
            if let Some((status, body)) = responses.get(path) {
                Ok(najwa_transport::http::HttpResponse {
                    status: *status,
                    headers: HashMap::new(),
                    body: body.clone(),
                })
            } else {
                Ok(najwa_transport::http::HttpResponse {
                    status: 404,
                    headers: HashMap::new(),
                    body: Vec::new(),
                })
            }
        }

        async fn get(
            &self,
            _circuit: &najwa_transport::circuit::CircuitHandle,
            url: &str,
        ) -> std::result::Result<
            najwa_transport::http::HttpResponse,
            najwa_transport::error::TransportError,
        > {
            let path = url
                .find(".onion")
                .map(|i| &url[i + ".onion".len()..])
                .unwrap_or("/");

            let responses = self.responses.lock().await;
            if let Some((status, body)) = responses.get(path) {
                Ok(najwa_transport::http::HttpResponse {
                    status: *status,
                    headers: HashMap::new(),
                    body: body.clone(),
                })
            } else {
                Ok(najwa_transport::http::HttpResponse {
                    status: 404,
                    headers: HashMap::new(),
                    body: Vec::new(),
                })
            }
        }
    }

    fn test_mailbox() -> MailboxConfig {
        MailboxConfig::new("testmailbox123456".to_string(), [0xAA; 32], [0xBB; 32])
    }

    #[tokio::test]
    async fn register_capability_success() {
        let mock = Arc::new(MockTransport::new());
        // Registration now does: GET /v1/challenge → solve PoW → POST /v1/capability/register
        let challenge = PowChallenge {
            challenge: vec![0u8; 32],
            difficulty: 0, // trivial for tests
            algorithm: "sha256-leading-zeros".to_string(),
            expires_at: u64::MAX,
        };
        mock.set_response("/v1/challenge", 200, &challenge).await;
        mock.set_response("/v1/capability/register", 200, serde_json::json!({}))
            .await;

        let client = HttpMailboxClient::new(mock);
        let result = client
            .register_capability(&test_mailbox(), &CapabilitySettings::default(), None)
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn register_capability_with_presolved_pow_skips_challenge() {
        let mock = Arc::new(MockTransport::new());
        // Only mock register — challenge should NOT be called
        mock.set_response("/v1/capability/register", 200, serde_json::json!({}))
            .await;

        let pre_solved = PowSolution {
            challenge: vec![0u8; 32],
            nonce: 42,
            hash: [0u8; 32],
            timestamp: 1_700_000_000,
        };
        let client = HttpMailboxClient::new(mock.clone());
        let result = client
            .register_capability(
                &test_mailbox(),
                &CapabilitySettings::default(),
                Some(&pre_solved),
            )
            .await;
        assert!(result.is_ok());
        // Should be exactly 1 POST (register only, no challenge)
        assert_eq!(mock.post_count.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn register_capability_solves_pow_then_registers() {
        let mock = Arc::new(MockTransport::new());
        let challenge = PowChallenge {
            challenge: vec![0u8; 32],
            difficulty: 0,
            algorithm: "sha256-leading-zeros".to_string(),
            expires_at: u64::MAX,
        };
        mock.set_response("/v1/challenge", 200, &challenge).await;
        mock.set_response("/v1/capability/register", 200, serde_json::json!({}))
            .await;

        let client = HttpMailboxClient::new(mock.clone());
        let result = client
            .register_capability(&test_mailbox(), &CapabilitySettings::default(), None)
            .await;
        assert!(result.is_ok());
        // 2 POSTs: one for /v1/challenge, one for /v1/capability/register
        assert_eq!(mock.post_count.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn deposit_success() {
        let mock = Arc::new(MockTransport::new());
        let deposit_result = DepositResult {
            accepted: true,
            message_id: Some("msg-001".to_string()),
        };
        mock.set_response("/v1/deposit", 200, &deposit_result).await;

        let client = HttpMailboxClient::new(mock);
        let mailbox = test_mailbox();
        let result = client
            .deposit(
                &mailbox,
                &mailbox.deposit_capability,
                b"encrypted-blob",
                None,
            )
            .await
            .unwrap();
        assert!(result.accepted);
        assert_eq!(result.message_id.as_deref(), Some("msg-001"));
    }

    #[tokio::test]
    async fn fetch_messages() {
        let mock = Arc::new(MockTransport::new());
        let fetch_resp = FetchResponse {
            messages: vec![
                MailboxMessage {
                    id: "msg-001".to_string(),
                    blob: vec![1, 2, 3],
                    deposited_at: 1700000000,
                    size: 3,
                    cap_hint: None,
                },
                MailboxMessage {
                    id: "msg-002".to_string(),
                    blob: vec![4, 5, 6],
                    deposited_at: 1700000001,
                    size: 3,
                    cap_hint: None,
                },
            ],
            has_more: false,
        };
        mock.set_response("/v1/fetch", 200, &fetch_resp).await;

        let client = HttpMailboxClient::new(mock);
        let mailbox = test_mailbox();
        let messages = client
            .fetch(&mailbox, &mailbox.fetch_capability, None, 50)
            .await
            .unwrap();
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].id, "msg-001");
        assert_eq!(messages[1].id, "msg-002");
    }

    #[tokio::test]
    async fn fetch_with_pagination() {
        let mock = Arc::new(MockTransport::new());
        let fetch_resp = FetchResponse {
            messages: vec![MailboxMessage {
                id: "msg-003".to_string(),
                blob: vec![7, 8, 9],
                deposited_at: 1700000002,
                size: 3,
                cap_hint: None,
            }],
            has_more: true,
        };
        mock.set_response("/v1/fetch", 200, &fetch_resp).await;

        let client = HttpMailboxClient::new(mock);
        let mailbox = test_mailbox();
        let messages = client
            .fetch(&mailbox, &mailbox.fetch_capability, Some("msg-002"), 10)
            .await
            .unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].id, "msg-003");
    }

    #[tokio::test]
    async fn upload_prekey_bundle_success() {
        let mock = Arc::new(MockTransport::new());
        mock.set_response("/v1/prekey/upload", 200, serde_json::json!({}))
            .await;

        let client = HttpMailboxClient::new(mock);
        let mailbox = test_mailbox();
        let bundle = PrekeyBundle {
            identity_key: [1; 32],
            signed_prekey: [2; 32],
            signed_prekey_id: 1,
            signed_prekey_signature: vec![3; 64],
            signed_prekey_timestamp: 0,
            one_time_prekeys: vec![],
            manifest: None,
        };
        let result = client
            .upload_prekey_bundle(&mailbox, &mailbox.deposit_capability, &bundle)
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn fetch_prekey_bundle_success() {
        let mock = Arc::new(MockTransport::new());
        let bundle = PrekeyBundle {
            identity_key: [10; 32],
            signed_prekey: [20; 32],
            signed_prekey_id: 2,
            signed_prekey_signature: vec![30; 64],
            signed_prekey_timestamp: 0,
            one_time_prekeys: vec![OneTimePrekey {
                id: 1,
                key: [40; 32],
            }],
            manifest: None,
        };
        mock.set_response("/v1/prekey/fetch", 200, &bundle).await;

        let client = HttpMailboxClient::new(mock);
        let result = client
            .fetch_prekey_bundle(&test_mailbox(), &[0xBB; 32], &[0u8; 32])
            .await
            .unwrap();
        assert_eq!(result.identity_key, [10; 32]);
        assert_eq!(result.one_time_prekeys.len(), 1);
    }

    #[tokio::test]
    async fn get_status_success() {
        let mock = Arc::new(MockTransport::new());
        let status = CapabilityStatus {
            messages_stored: 5,
            quota_remaining: 1000,
            oldest_message_age: 3600,
            prekey_count: 10,
            prekey_ids: (0..10).collect(),
        };
        mock.set_response("/v1/status", 200, &status).await;

        let client = HttpMailboxClient::new(mock);
        let mailbox = test_mailbox();
        let result = client
            .get_status(&mailbox, &mailbox.fetch_capability)
            .await
            .unwrap();
        assert_eq!(result.messages_stored, 5);
        assert_eq!(result.prekey_count, 10);
    }

    #[tokio::test]
    async fn deactivate_capability_success() {
        let mock = Arc::new(MockTransport::new());
        mock.set_response("/v1/capability/deactivate", 200, serde_json::json!({}))
            .await;

        let client = HttpMailboxClient::new(mock);
        let mailbox = test_mailbox();
        let result = client
            .deactivate_capability(&mailbox, &mailbox.fetch_capability)
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn capability_not_found() {
        let mock = Arc::new(MockTransport::new());
        // No response registered → 404

        let client = HttpMailboxClient::new(mock);
        let mailbox = test_mailbox();
        let result = client.get_status(&mailbox, &mailbox.fetch_capability).await;
        assert!(matches!(result, Err(MailboxError::CapabilityNotFound)));
    }

    #[tokio::test]
    async fn rate_limited_response() {
        let mock = Arc::new(MockTransport::new());
        mock.set_response("/v1/deposit", 429, serde_json::json!({}))
            .await;

        let retry = RetryConfig {
            retry_on_pow: false,
            ..Default::default()
        };
        let client = HttpMailboxClient::with_retry(mock, retry);
        let mailbox = test_mailbox();
        let result = client
            .deposit(&mailbox, &mailbox.deposit_capability, b"blob", None)
            .await;
        assert!(matches!(result, Err(MailboxError::RateLimited)));
    }

    #[tokio::test]
    async fn message_too_large() {
        let mock = Arc::new(MockTransport::new());
        mock.set_response("/v1/deposit", 413, serde_json::json!({}))
            .await;

        let client = HttpMailboxClient::new(mock);
        let mailbox = test_mailbox();
        let result = client
            .deposit(&mailbox, &mailbox.deposit_capability, b"blob", None)
            .await;
        assert!(matches!(result, Err(MailboxError::MessageTooLarge)));
    }

    #[tokio::test]
    async fn quota_exceeded() {
        let mock = Arc::new(MockTransport::new());
        mock.set_response("/v1/deposit", 507, serde_json::json!({}))
            .await;

        let client = HttpMailboxClient::new(mock);
        let mailbox = test_mailbox();
        let result = client
            .deposit(&mailbox, &mailbox.deposit_capability, b"blob", None)
            .await;
        assert!(matches!(result, Err(MailboxError::QuotaExceeded)));
    }

    #[tokio::test]
    async fn server_error_passthrough() {
        let mock = Arc::new(MockTransport::new());
        mock.set_response("/v1/deposit", 500, serde_json::json!({}))
            .await;

        let client = HttpMailboxClient::new(mock);
        let mailbox = test_mailbox();
        let result = client
            .deposit(&mailbox, &mailbox.deposit_capability, b"blob", None)
            .await;
        assert!(matches!(result, Err(MailboxError::ServerError(500))));
    }

    #[tokio::test]
    async fn get_challenge_success() {
        let mock = Arc::new(MockTransport::new());
        let challenge = PowChallenge {
            challenge: vec![1, 2, 3, 4],
            difficulty: 16,
            algorithm: "sha256-leading-zeros".to_string(),
            expires_at: 1700000000,
        };
        mock.set_response("/v1/challenge", 200, &challenge).await;

        let client = HttpMailboxClient::new(mock);
        let mailbox = test_mailbox();
        let result = client.get_challenge(&mailbox, &[0xAA; 8]).await.unwrap();
        assert_eq!(result.difficulty, 16);
        assert_eq!(result.algorithm, "sha256-leading-zeros");
    }

    /// Records the path and circuit isolation of every POST.
    struct IsolationLog {
        inner: MockTransport,
        log: std::sync::Mutex<Vec<(String, CircuitIsolation)>>,
    }

    #[async_trait]
    impl Transport for IsolationLog {
        async fn get_circuit(
            &self,
            isolation: CircuitIsolation,
        ) -> std::result::Result<
            najwa_transport::circuit::CircuitHandle,
            najwa_transport::error::TransportError,
        > {
            Ok(najwa_transport::circuit::CircuitHandle::new(isolation))
        }
        async fn post(
            &self,
            circuit: &najwa_transport::circuit::CircuitHandle,
            url: &str,
            body: &[u8],
            content_type: &str,
        ) -> std::result::Result<
            najwa_transport::http::HttpResponse,
            najwa_transport::error::TransportError,
        > {
            let path = url[url.find(".onion").unwrap() + ".onion".len()..].to_string();
            self.log
                .lock()
                .unwrap()
                .push((path, circuit.isolation.clone()));
            self.inner.post(circuit, url, body, content_type).await
        }
        async fn get(
            &self,
            _: &najwa_transport::circuit::CircuitHandle,
            _: &str,
        ) -> std::result::Result<
            najwa_transport::http::HttpResponse,
            najwa_transport::error::TransportError,
        > {
            unreachable!()
        }
    }

    // S04 §4.1.1: a PoW challenge rides the isolation of the request it gates,
    // never the user's `ByMailbox` circuit, or the mailbox could link the
    // gated deposit, registration or prekey fetch to the user's real fetches.
    #[tokio::test]
    async fn pow_challenge_rides_the_gated_requests_isolation() {
        let transport = Arc::new(IsolationLog {
            inner: MockTransport::new(),
            log: Default::default(),
        });
        let challenge = PowChallenge {
            challenge: vec![0u8; 32],
            difficulty: 0,
            algorithm: "sha256-leading-zeros".to_string(),
            expires_at: u64::MAX,
        };
        transport.inner.set_response("/v1/challenge", 200, &challenge).await;
        transport
            .inner
            .set_response("/v1/deposit", 429, serde_json::json!({}))
            .await;
        transport
            .inner
            .set_response("/v1/prekey/fetch", 429, serde_json::json!({}))
            .await;
        let client = HttpMailboxClient::new(transport.clone());
        let mailbox = test_mailbox();

        client
            .prepare_deposit_pow(&mailbox, &[0xBB; 32], b"blob")
            .await
            .unwrap();
        let _ = client.deposit(&mailbox, &[0xBB; 32], b"blob", None).await;
        client.prepare_registration_pow(&mailbox).await.unwrap();
        let _ = client
            .fetch_prekey_bundle(&mailbox, &[0xBB; 32], &[5; 32])
            .await;

        let log = transport.log.lock().unwrap();
        let challenges: Vec<_> = log
            .iter()
            .filter(|(path, _)| path == "/v1/challenge")
            .map(|(_, isolation)| isolation.clone())
            .collect();
        assert_eq!(
            challenges,
            vec![
                CircuitIsolation::OneShot,          // prepared deposit PoW
                CircuitIsolation::OneShot,          // auto-solved deposit PoW
                CircuitIsolation::OneShot,          // registration PoW
                CircuitIsolation::ByContact([5; 32]), // prekey-fetch PoW
            ]
        );
    }

    // S04 §4.1.1, S10 §4.3: every cover deposit builds a fresh `OneShot`
    // circuit, as real deposits do, so the guard cannot tell them apart.
    #[tokio::test]
    async fn cover_deposits_use_a_fresh_one_shot_circuit_each() {
        let transport = Arc::new(IsolationLog {
            inner: MockTransport::new(),
            log: Default::default(),
        });
        let accepted = DepositResult {
            accepted: true,
            message_id: None,
        };
        transport.inner.set_response("/v1/deposit", 200, &accepted).await;
        let client = HttpMailboxClient::new(transport.clone());
        let mailbox = test_mailbox();
        for _ in 0..3 {
            client
                .deposit_cover(&mailbox, &[0xBB; 32], &[9; 256])
                .await
                .unwrap();
        }
        // `OneShot` is never reused by the registry (najwa-transport
        // `one_shot_handle_is_consumed_once_and_tokens_are_distinct`).
        let log = transport.log.lock().unwrap();
        assert_eq!(log.len(), 3);
        assert!(log
            .iter()
            .all(|(_, isolation)| *isolation == CircuitIsolation::OneShot));
    }

    #[tokio::test]
    async fn retry_on_transport_error() {
        // Transport that always fails
        struct FailTransport {
            attempts: AtomicU32,
        }

        #[async_trait]
        impl Transport for FailTransport {
            async fn get_circuit(
                &self,
                _: CircuitIsolation,
            ) -> std::result::Result<
                najwa_transport::circuit::CircuitHandle,
                najwa_transport::error::TransportError,
            > {
                Ok(najwa_transport::circuit::CircuitHandle::new(
                    CircuitIsolation::OneShot,
                ))
            }
            async fn post(
                &self,
                _: &najwa_transport::circuit::CircuitHandle,
                _: &str,
                _: &[u8],
                _: &str,
            ) -> std::result::Result<
                najwa_transport::http::HttpResponse,
                najwa_transport::error::TransportError,
            > {
                self.attempts.fetch_add(1, Ordering::Relaxed);
                Err(najwa_transport::error::TransportError::Timeout)
            }
            async fn get(
                &self,
                _: &najwa_transport::circuit::CircuitHandle,
                _: &str,
            ) -> std::result::Result<
                najwa_transport::http::HttpResponse,
                najwa_transport::error::TransportError,
            > {
                Err(najwa_transport::error::TransportError::Timeout)
            }
        }

        let fail = Arc::new(FailTransport {
            attempts: AtomicU32::new(0),
        });

        let retry = RetryConfig {
            max_retries: 2,
            base_delay_ms: 1, // fast for testing
            max_delay_ms: 10,
            retry_on_pow: false,
        };
        let client = HttpMailboxClient::with_retry(fail.clone(), retry);
        let mailbox = test_mailbox();

        let result = client
            .register_capability(&mailbox, &CapabilitySettings::default(), None)
            .await;
        assert!(result.is_err());
        // 1 initial + 2 retries = 3 attempts
        assert_eq!(fail.attempts.load(Ordering::Relaxed), 3);
    }
}
