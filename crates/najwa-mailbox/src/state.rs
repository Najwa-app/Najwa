//! Shared application state injected into all axum handlers.

use std::sync::atomic::{AtomicI64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};

use crate::api::health::ServerStatus;
use crate::config::Config;
use crate::db::Database;
use crate::pow::ChallengeStore;
use crate::quota::{QuotaChecker, RateLimiter};

/// Signed batching-parameter attestation published in `/v1/status` (S16 §6).
#[derive(Debug, Clone, serde::Serialize)]
pub struct BatchingAttestation {
    /// Ed25519 signature over
    /// `SHA256("najwa-batching-attestation-v1" || min_be(4) || max_be(4) ||
    /// jitter_be(4) || signed_at_be(8))`.
    pub signature: String,
    pub min_hold_secs: u32,
    pub max_hold_secs: u32,
    pub jitter_secs: u32,
    /// Unix seconds the signature was computed at (re-signed at most every 24 h).
    pub signed_at: i64,
}

/// Application state shared across all request handlers via `axum::extract::State`.
#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Database>,
    pub config: Arc<Config>,

    // Server retirement (S16 §13)
    server_status: Arc<AtomicU8>,
    retire_at: Arc<AtomicI64>,

    // Rate limiters (keyed by capability, 60-second windows — §8: per-circuit
    // limits are unimplementable behind an onion service)
    pub register_limiter: Arc<RateLimiter>,
    pub deposit_limiter: Arc<RateLimiter>,
    pub fetch_limiter: Arc<RateLimiter>,
    pub prekey_fetch_limiter: Arc<RateLimiter>,

    /// Outstanding PoW challenges, in memory and capacity-bounded (S16 §3.2).
    pub challenges: Arc<ChallengeStore>,

    /// Operator Ed25519 signing key, resolved once at startup from
    /// `[attestation]` (key file wins over inline seed). `None` = unsigned.
    operator_key: Option<SigningKey>,
    /// 24 h cache for the batching-parameter attestation signature.
    batching_sig_cache: Arc<Mutex<Option<BatchingAttestation>>>,
    /// Recent response deadline overruns contribute to adaptive PoW (S16 §14).
    deadline_overruns: Arc<Mutex<(std::time::Instant, u8)>>,
    /// Silent-drop log aggregation (S16 §12): when the last line was written
    /// and how many drops it has not reported yet.
    silent_drops: Arc<Mutex<(Option<std::time::Instant>, u64)>>,
    /// Per-process key for discard ids (S16 §3.3). Memory only.
    // ponytail: regenerated at restart; live dedup lasts only its window, so
    // only a repeat straddling a restart inside that window can tell.
    discard_key: [u8; 32],
}

impl AppState {
    /// Build the app state. Errors on a config the server MUST NOT start with
    /// (S16 §5: `opk.refuse_last_opk` is a MUST-true knob).
    pub fn new(db: Arc<Database>, config: Arc<Config>) -> anyhow::Result<Self> {
        if !config.opk.refuse_last_opk {
            anyhow::bail!(
                "config.opk.refuse_last_opk = false violates S16 §5 \
                 (\"MUST be true; do not serve final OPK\") — refusing to start"
            );
        }
        let operator_key = resolve_operator_key(&config)?;
        // S16 §13: the operator retires a server by setting
        // `[server].retire_at` and restarting; the server then starts Retiring.
        let retire_at = config.server.retire_at.unwrap_or(0);
        if config.server.retire_at.is_some() && retire_at <= 0 {
            anyhow::bail!("server.retire_at must be a positive Unix time in seconds");
        }
        Ok(Self {
            db,
            config: config.clone(),
            server_status: Arc::new(AtomicU8::new(u8::from(retire_at > 0))), // 0=Active, 1=Retiring
            retire_at: Arc::new(AtomicI64::new(retire_at)),
            register_limiter: Arc::new(RateLimiter::new(60)),
            deposit_limiter: Arc::new(RateLimiter::new(60)),
            fetch_limiter: Arc::new(RateLimiter::new(60)),
            prekey_fetch_limiter: Arc::new(RateLimiter::new(60)),
            challenges: Arc::new(ChallengeStore::default()),
            operator_key,
            batching_sig_cache: Arc::new(Mutex::new(None)),
            deadline_overruns: Arc::new(Mutex::new((std::time::Instant::now(), 0))),
            silent_drops: Arc::new(Mutex::new((None, 0))),
            discard_key: najwa_crypto::random::random_bytes(),
        })
    }

    /// Count a silently dropped deposit (S16 §3.3) and write the warning at
    /// most once a minute, carrying the number of drops since the last line.
    /// Anyone can cause drops with random capabilities and no PoW, so one
    /// line per drop would let them flood the log.
    pub fn note_silent_drop(&self) {
        let mut drops = self.silent_drops.lock().unwrap();
        drops.1 += 1;
        if drops
            .0
            .is_none_or(|t| t.elapsed() >= std::time::Duration::from_secs(60))
        {
            tracing::warn!(
                dropped = drops.1,
                "deposit: unknown/deactivated capability — silent drop (S16 §3.3)"
            );
            *drops = (Some(std::time::Instant::now()), 0);
        }
    }

    /// `message_id` for a discarded deposit (S16 §3.3): the first 16 bytes of
    /// `HMAC-SHA256(discard_key, deposit_cap ‖ SHA256(blob))` laid out as a
    /// UUIDv4. A repeated identical deposit gets the same id, as live dedup
    /// would give, and nothing is stored.
    pub fn discard_message_id(&self, deposit_cap: &[u8; 32], blob_hash: &[u8; 32]) -> String {
        let mut data = [0u8; 64];
        data[..32].copy_from_slice(deposit_cap);
        data[32..].copy_from_slice(blob_hash);
        let mac = najwa_crypto::hash::hmac_sha256(&self.discard_key, &data);
        let bytes: [u8; 16] = mac[..16].try_into().expect("32-byte MAC");
        format!("msg-{}", uuid::Builder::from_random_bytes(bytes).into_uuid())
    }

    /// The resolved operator signing key, if any (attestation endpoint).
    pub fn operator_signing_key(&self) -> Option<&SigningKey> {
        self.operator_key.as_ref()
    }

    /// Signed `(min_hold, max_hold, jitter)` batching attestation for
    /// `/v1/status` (S16 §6): `None` unless `publish_batching_attestation` is
    /// on AND an operator key is configured; re-signed at most every 24 h.
    pub fn batching_attestation(&self) -> Option<BatchingAttestation> {
        if !self.config.attestation.publish_batching_attestation {
            return None;
        }
        let key = self.operator_key.as_ref()?;
        let b = &self.config.batching;
        let now = chrono::Utc::now().timestamp();

        let mut cache = self.batching_sig_cache.lock().unwrap();
        if let Some(att) = cache.as_ref() {
            if now - att.signed_at < 24 * 3600 {
                return Some(att.clone());
            }
        }
        let mut hasher = Sha256::new();
        hasher.update(b"najwa-batching-attestation-v1");
        hasher.update(b.min_hold_secs.to_be_bytes());
        hasher.update(b.max_hold_secs.to_be_bytes());
        hasher.update(b.jitter_secs.to_be_bytes());
        hasher.update(now.to_be_bytes());
        let sig = key.sign(&hasher.finalize());
        let att = BatchingAttestation {
            signature: B64.encode(sig.to_bytes()),
            min_hold_secs: b.min_hold_secs,
            max_hold_secs: b.max_hold_secs,
            jitter_secs: b.jitter_secs,
            signed_at: now,
        };
        *cache = Some(att.clone());
        Some(att)
    }

    /// Get the current server status (S16 §13).
    pub fn server_status(&self) -> ServerStatus {
        match self.server_status.load(Ordering::Relaxed) {
            1 => ServerStatus::Retiring,
            2 => ServerStatus::ReadOnly,
            _ => ServerStatus::Active,
        }
    }

    /// Get the retire_at timestamp (0 = not retiring).
    pub fn retire_at(&self) -> Option<i64> {
        let val = self.retire_at.load(Ordering::Relaxed);
        if val > 0 {
            Some(val)
        } else {
            None
        }
    }

    /// Check if the server is accepting new registrations.
    pub fn is_accepting_registrations(&self) -> bool {
        self.server_status.load(Ordering::Relaxed) == 0
    }

    /// Build a quota checker from the current config.
    pub fn quota_checker(&self) -> QuotaChecker {
        QuotaChecker {
            max_messages: self.config.quotas.max_messages_per_capability,
            max_blob_size: self.config.quotas.max_blob_size_bytes,
            max_storage_bytes: self.config.quotas.max_storage_per_capability_mb * 1024 * 1024,
            max_opks: self.config.quotas.max_opks_per_capability,
        }
    }

    /// Get the current server "load" as a percentage (0–100).
    /// This is a rough heuristic based on active capabilities vs a soft ceiling.
    pub fn estimated_load_percent(&self) -> u8 {
        // Simple heuristic: treat 10K active capabilities as 100% load.
        // A real production server would use CPU/memory/IO metrics.
        const SOFT_CEILING: u64 = 10_000;
        let count = self.db.active_capability_count().unwrap_or(0);
        let capability_load = ((count * 100).min(SOFT_CEILING * 100) / SOFT_CEILING) as u8;
        let overruns = self.deadline_overruns.lock().unwrap();
        let latency_load = if overruns.0.elapsed() < std::time::Duration::from_secs(60) {
            overruns.1
        } else {
            0
        };
        capability_load.max(latency_load)
    }

    pub fn record_deadline_overrun(&self) {
        let mut overruns = self.deadline_overruns.lock().unwrap();
        if overruns.0.elapsed() >= std::time::Duration::from_secs(60) {
            *overruns = (std::time::Instant::now(), 0);
        }
        overruns.1 = overruns.1.saturating_add(10).min(100);
    }
}

/// Resolve the operator signing key at startup: `[attestation].operator_key_path`
/// (a file with 64 hex chars) wins over the inline seed; both absent = unsigned
/// attestations. A configured-but-unparseable key is a startup error, not a
/// silent downgrade to unsigned.
fn resolve_operator_key(config: &Config) -> anyhow::Result<Option<SigningKey>> {
    let hex_seed: Option<String> = match &config.attestation.operator_key_path {
        Some(path) => {
            let contents = std::fs::read_to_string(path).map_err(|e| {
                anyhow::anyhow!(
                    "attestation.operator_key_path {:?} is configured but unreadable: {e}",
                    path
                )
            })?;
            Some(contents.trim().to_string())
        }
        None => {
            let seed = &config.attestation.operator_key_seed_hex;
            (!seed.is_empty()).then(|| seed.clone())
        }
    };
    let Some(hex_seed) = hex_seed else {
        return Ok(None);
    };
    let bytes = hex_decode_32(&hex_seed)
        .ok_or_else(|| anyhow::anyhow!("attestation operator key must be 64 hex chars"))?;
    Ok(Some(SigningKey::from_bytes(&bytes)))
}

fn hex_decode_32(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
    }
    Some(out)
}
