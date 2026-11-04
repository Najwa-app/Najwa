//! Mailbox client trait (S16 §3) and transport abstraction.

use async_trait::async_trait;
use najwa_transport::circuit::{CircuitHandle, CircuitIsolation};
use najwa_transport::error::TransportError;
use najwa_transport::http::HttpResponse;

use super::error::Result;
use super::types::{
    CapabilitySettings, CapabilityStatus, DepositResult, MailboxConfig, MailboxMessage,
    PowChallenge, PowSolution, PrekeyBundle,
};

// ---------------------------------------------------------------------------
// Transport abstraction (for testability / mocking)
// ---------------------------------------------------------------------------

/// Minimal transport interface consumed by the mailbox client.
///
/// `TorTransport` satisfies this contract. The trait exists so that
/// unit tests can inject a mock without needing a live Tor network.
#[async_trait]
pub trait Transport: Send + Sync {
    /// Obtain an isolated circuit handle.
    async fn get_circuit(
        &self,
        isolation: CircuitIsolation,
    ) -> std::result::Result<CircuitHandle, TransportError>;

    /// HTTP POST over Tor.
    async fn post(
        &self,
        circuit: &CircuitHandle,
        url: &str,
        body: &[u8],
        content_type: &str,
    ) -> std::result::Result<HttpResponse, TransportError>;

    /// HTTP GET over Tor.
    async fn get(
        &self,
        circuit: &CircuitHandle,
        url: &str,
    ) -> std::result::Result<HttpResponse, TransportError>;
}

// ---------------------------------------------------------------------------
// Mailbox client trait (S16 §3)
// ---------------------------------------------------------------------------

/// Client-side mailbox protocol operations.
///
/// All methods communicate with a store-and-forward mailbox server
/// via Tor onion services.
#[async_trait]
pub trait MailboxClient: Send + Sync {
    /// Register a new capability pair with the mailbox (S16 §3.1).
    async fn register_capability(
        &self,
        mailbox: &MailboxConfig,
        settings: &CapabilitySettings,
        pow: Option<&PowSolution>,
    ) -> Result<()>;

    /// Get a PoW challenge from the server.
    async fn get_challenge(
        &self,
        mailbox: &MailboxConfig,
        capability_hint: &[u8; 8],
    ) -> Result<PowChallenge>;

    /// Deposit an encrypted blob to a mailbox (S16 §3.3).
    async fn deposit(
        &self,
        mailbox: &MailboxConfig,
        deposit_cap: &[u8; 32],
        blob: &[u8],
        pow: Option<&PowSolution>,
    ) -> Result<DepositResult>;

    /// One network deposit attempt. Slot owners handle all retries themselves.
    /// Implementations with internal retries MUST override this method.
    async fn deposit_once(
        &self,
        mailbox: &MailboxConfig,
        deposit_cap: &[u8; 32],
        blob: &[u8],
        pow: Option<&PowSolution>,
    ) -> Result<DepositResult> {
        self.deposit(mailbox, deposit_cap, blob, pow).await
    }

    /// Single attempt on a circuit isolated to an attachment. Only Responsive
    /// mode opts in; clients without circuit support retain ordinary deposits.
    async fn deposit_file_once(
        &self,
        mailbox: &MailboxConfig,
        deposit_cap: &[u8; 32],
        blob: &[u8],
        pow: Option<&PowSolution>,
        _isolation: [u8; 32],
    ) -> Result<DepositResult> {
        self.deposit_once(mailbox, deposit_cap, blob, pow).await
    }

    /// Prepare a bound PoW after a rate-limited deposit, before acquiring the
    /// next slot. Clients without PoW support leave the frame in the outbox.
    async fn prepare_deposit_pow(
        &self,
        _mailbox: &MailboxConfig,
        _deposit_cap: &[u8; 32],
        _blob: &[u8],
    ) -> Result<PowSolution> {
        Err(super::error::MailboxError::RateLimited)
    }

    /// Delete fetched cover blobs using cover-only circuit isolation.
    async fn acknowledge_cover(
        &self,
        mailbox: &MailboxConfig,
        fetch_cap: &[u8; 32],
        message_ids: &[String],
    ) -> Result<()> {
        self.acknowledge(mailbox, fetch_cap, message_ids).await
    }

    /// Fetch messages from a mailbox (S16 §3.4).
    async fn fetch(
        &self,
        mailbox: &MailboxConfig,
        fetch_cap: &[u8; 32],
        since_id: Option<&str>,
        limit: u32,
    ) -> Result<Vec<MailboxMessage>>;

    /// Deposit a cover blob over a fresh `OneShot` circuit, as real deposits
    /// use (S10 §4.3), so circuit construction cannot tell cover from real.
    /// Default delegates to `deposit` so mock/test impls need no
    /// cover-specific behavior.
    async fn deposit_cover(
        &self,
        mailbox: &MailboxConfig,
        deposit_cap: &[u8; 32],
        blob: &[u8],
    ) -> Result<DepositResult> {
        self.deposit(mailbox, deposit_cap, blob, None).await
    }

    /// Cover poll over a dedicated `CoverTraffic(mailbox_onion)` circuit
    /// (S10 §4.2). Default delegates to `fetch`.
    async fn fetch_cover(
        &self,
        mailbox: &MailboxConfig,
        fetch_cap: &[u8; 32],
        limit: u32,
    ) -> Result<Vec<MailboxMessage>> {
        self.fetch(mailbox, fetch_cap, None, limit).await
    }

    /// Upload a prekey bundle to the mailbox server.
    async fn upload_prekey_bundle(
        &self,
        mailbox: &MailboxConfig,
        deposit_cap: &[u8; 32],
        bundle: &PrekeyBundle,
    ) -> Result<()>;

    /// One paced attempt. Recovery replacement requires owner authentication;
    /// implementations that do not support it must fail closed.
    async fn publish_prekeys_once(
        &self,
        mailbox: &MailboxConfig,
        bundle: &PrekeyBundle,
        replace: bool,
    ) -> Result<()> {
        if replace {
            return Err(super::error::MailboxError::ServerError(501));
        }
        self.upload_prekey_bundle(mailbox, &mailbox.deposit_capability, bundle)
            .await
    }

    /// Fetch a contact's prekey bundle via their deposit capability (S16 §3.7).
    ///
    /// Sends `POST /v1/prekey/fetch` with `deposit_capability` to identify
    /// which bundle to return. The server serves at most one OPK and never
    /// the last available one.
    ///
    /// `contact_pseudonym` is the pairwise pseudonym of the prospective contact;
    /// the request MUST ride a `ByContact(contact_pseudonym)` circuit (S04
    /// §4.1.1) so one circuit is used per prospective contact.
    async fn fetch_prekey_bundle(
        &self,
        mailbox: &MailboxConfig,
        deposit_cap: &[u8; 32],
        contact_pseudonym: &[u8; 32],
    ) -> Result<PrekeyBundle>;

    /// Check capability status on the server.
    async fn get_status(
        &self,
        mailbox: &MailboxConfig,
        fetch_cap: &[u8; 32],
    ) -> Result<CapabilityStatus>;

    /// One control-slot attempt; implementations with retries must override it.
    async fn get_status_once(&self, mailbox: &MailboxConfig) -> Result<CapabilityStatus> {
        self.get_status(mailbox, &mailbox.fetch_capability).await
    }

    /// Deactivate a capability at the mailbox.
    async fn deactivate_capability(
        &self,
        mailbox: &MailboxConfig,
        fetch_cap: &[u8; 32],
    ) -> Result<()>;

    /// One control-slot attempt; implementations with retries must override it.
    async fn deactivate_once(&self, mailbox: &MailboxConfig) -> Result<()> {
        self.deactivate_capability(mailbox, &mailbox.fetch_capability)
            .await
    }

    /// Acknowledge receipt of messages (S16 §3.5).
    ///
    /// Tells the server to delete the acknowledged messages. Called after
    /// successful processing of fetched messages.
    async fn acknowledge(
        &self,
        mailbox: &MailboxConfig,
        fetch_cap: &[u8; 32],
        message_ids: &[String],
    ) -> Result<()>;

    /// Request a PoW challenge from the server (S16 §3.2).
    ///
    /// Alias for `get_challenge` — matches S16 §3 endpoint naming.
    async fn request_challenge(
        &self,
        mailbox: &MailboxConfig,
        capability_hint: &[u8; 8],
    ) -> Result<PowChallenge> {
        self.get_challenge(mailbox, capability_hint).await
    }
}
