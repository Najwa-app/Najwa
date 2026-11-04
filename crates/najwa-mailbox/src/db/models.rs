//! Database row types used across queries.

use serde::{Deserialize, Serialize};

/// Capability registration row.
#[derive(Debug, Clone)]
pub struct CapabilityRow {
    pub fetch_cap: [u8; 32],
    pub settings_json: String,
    pub created_at: i64,
    pub deactivated: bool,
}

/// Deposit capability mapping row.
#[derive(Debug, Clone)]
pub struct DepositCapRow {
    pub deposit_cap: [u8; 32],
    pub fetch_cap: [u8; 32],
    pub created_at: i64,
}

/// Stored message row.
#[derive(Debug, Clone)]
pub struct MessageRow {
    pub id: String,
    pub fetch_cap: [u8; 32],
    pub blob: Vec<u8>,
    pub deposited_at: i64,
    pub size: i64,
    /// `SHA256(deposit_cap)[0:8]` — allows client to identify which deposit cap
    /// was used for envelope decryption (S16 §3.4, S07 §3.2).
    pub cap_hint: Option<[u8; 8]>,
}

/// Prekey bundle row.
#[derive(Debug, Clone)]
pub struct PrekeyBundleRow {
    pub fetch_cap: [u8; 32],
    pub bundle_json: String,
    pub updated_at: i64,
}

/// One-time prekey row.
#[derive(Debug, Clone)]
pub struct OneTimePrekey {
    pub id: i64,
    pub fetch_cap: [u8; 32],
    pub prekey_id: u32,
    pub key_bytes: [u8; 32],
    pub created_at: i64,
}

/// PoW challenge row.
#[derive(Debug, Clone)]
pub struct PowChallengeRow {
    pub challenge: [u8; 32],
    pub difficulty: u8,
    pub expires_at: i64,
    pub used: bool,
}

// The server stores no push-relay registrations.

// ---------------------------------------------------------------------------
// Capability settings (stored as JSON in capabilities.settings_json)
// ---------------------------------------------------------------------------

/// Per-capability settings provided at registration time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilitySettings {
    #[serde(default = "default_retention_days")]
    pub retention_days: u32,
    #[serde(default = "default_max_message_size")]
    pub max_message_size: usize,
}

fn default_retention_days() -> u32 {
    14
}
fn default_max_message_size() -> usize {
    262_144 // 256 KB
}

impl Default for CapabilitySettings {
    fn default() -> Self {
        Self {
            retention_days: default_retention_days(),
            max_message_size: default_max_message_size(),
        }
    }
}
