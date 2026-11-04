//! Server configuration — parsed from TOML (S16 §5).
//!
//! Every table denies unknown keys, so a misspelled or retired key stops
//! startup with an error naming it instead of silently falling back to a
//! default.

use anyhow::Context;
use serde::Deserialize;
use std::path::{Path, PathBuf};

/// Top-level configuration for the mailbox server.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub server: ServerConfig,
    pub quotas: QuotaConfig,
    pub pow: PowConfig,
    pub rate_limits: RateLimitConfig,
    /// S16 §3.1: server clamp for type-1 `expires_at` (`[capability_expiry]`).
    #[serde(default)]
    pub capability_expiry: CapabilityExpiryConfig,
    /// S16 §3.7: OPK pool policy (`[opk]`).
    #[serde(default)]
    pub opk: OpkConfig,
    /// S16 §3.10: operator attestation (`[attestation]`).
    #[serde(default)]
    pub attestation: AttestationConfig,
    #[serde(default)]
    pub batching: BatchingConfig,
    pub cleanup: CleanupConfig,
    pub logging: LoggingConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,
    #[serde(default = "default_listen_port")]
    pub listen_port: u16,
    #[serde(default = "default_health_port")]
    pub health_port: u16,
    pub database_path: PathBuf,
    /// The server's .onion address (used in attestation response).
    #[serde(default)]
    pub onion_address: String,
    /// S16 §13 operator trigger: when set (Unix seconds), the server starts
    /// `Retiring` — new registrations get `503` — and reports this time in
    /// `/v1/status` and `/v1/health`. Unset = `Active`.
    #[serde(default)]
    pub retire_at: Option<i64>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuotaConfig {
    #[serde(default = "default_max_messages")]
    pub max_messages_per_capability: u64,
    #[serde(default = "default_max_blob_size")]
    pub max_blob_size_bytes: usize,
    #[serde(default = "default_max_storage_mb")]
    pub max_storage_per_capability_mb: u64,
    #[serde(default = "default_max_opks")]
    pub max_opks_per_capability: u32,
    #[serde(default = "default_retention_days")]
    pub default_retention_days: u32,
    /// S16 §9: reduced quota for type-1 (ephemeral handshake) capabilities.
    #[serde(default = "default_ephemeral_max_messages")]
    pub ephemeral_max_messages: u64,
    #[serde(default = "default_ephemeral_max_storage_mb")]
    pub ephemeral_max_storage_mb: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PowConfig {
    #[serde(default = "default_min_difficulty")]
    pub min_difficulty: u8,
    #[serde(default = "default_max_difficulty")]
    pub max_difficulty: u8,
    #[serde(default = "default_challenge_expiry")]
    pub challenge_expiry_secs: u64,
    #[serde(default = "default_true")]
    pub registration_always_requires_pow: bool,
    #[serde(default = "default_deposit_pow_threshold")]
    pub deposit_pow_threshold_per_min: u32,
    /// S16 §7.2/§8: prekey fetch triggers adaptive PoW above this per-cap rate.
    #[serde(default = "default_prekey_fetch_pow_threshold")]
    pub prekey_fetch_pow_threshold_per_min: u32,
    /// S16 §7.2: always-on PoW floor for deposits to `capability_type = 1`
    /// (ephemeral handshake) caps — the cheapest flooding target, so unlike
    /// type-2 they are priced from the first deposit rather than above a rate
    /// threshold. The spec lists this as operator config, not a constant; it was
    /// hardcoded at the call site, which left an operator able to lower
    /// `max_difficulty` below a floor they could not see or raise. Set to 0 to
    /// disable (test servers only — every QR handshake hands out a type-1 cap).
    #[serde(default = "default_ephemeral_deposit_min_difficulty")]
    pub ephemeral_deposit_min_difficulty: u8,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimitConfig {
    /// S16 §8: registrations per minute per fetch capability.
    #[serde(default = "default_register_rate")]
    pub register_per_min: u32,
    #[serde(default = "default_deposit_rate")]
    pub deposit_per_min_per_cap: u32,
    #[serde(default = "default_fetch_rate")]
    pub fetch_per_min_per_cap: u32,
    #[serde(default = "default_prekey_fetch_rate")]
    pub prekey_fetch_per_min: u32,
}

/// Capability expiry (S16 §3.1, `[capability_expiry]`).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityExpiryConfig {
    /// Server clamp for type-1 (ephemeral handshake) `expires_at`:
    /// the effective expiry is `min(requested, created_at + this)`, and it is
    /// default-assigned at that value when omitted — closing the
    /// photographed-QR window.
    #[serde(default = "default_ephemeral_max_lifetime_hours")]
    pub ephemeral_max_lifetime_hours: u64,
}

/// OPK pool policy (S16 §3.7, `[opk]`).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpkConfig {
    /// `/v1/status` reports `opk_low` when the pool is below this.
    #[serde(default = "default_low_alert_threshold")]
    pub low_alert_threshold: u32,
    /// MUST be true (S16 §5): never serve the final OPK. The database layer
    /// enforces the rule unconditionally; startup refuses a config that tries
    /// to disable it.
    #[serde(default = "default_true")]
    pub refuse_last_opk: bool,
}

impl Default for CapabilityExpiryConfig {
    fn default() -> Self {
        Self {
            ephemeral_max_lifetime_hours: default_ephemeral_max_lifetime_hours(),
        }
    }
}

impl Default for OpkConfig {
    fn default() -> Self {
        Self {
            low_alert_threshold: default_low_alert_threshold(),
            refuse_last_opk: true,
        }
    }
}

/// Operator attestation (S16 §3.10, `[attestation]`).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationConfig {
    /// Operator jurisdiction (ISO 3166-1 alpha-2, e.g. "CH").
    #[serde(default)]
    pub jurisdiction: String,
    /// Infrastructure provider name.
    #[serde(default)]
    pub infrastructure_provider: String,
    /// Operator Ed25519 private key seed (64 hex chars) for attestation
    /// signing. Spec §5 names `operator_key_path`; a seed given inline over a
    /// mounted file is operationally equivalent behind a 0600 config — if the
    /// path is set it wins. Empty path + empty seed = unsigned attestations.
    #[serde(default)]
    pub operator_key_seed_hex: String,
    /// Optional path to a file holding the 64-hex-char seed (wins over the
    /// inline seed).
    #[serde(default)]
    pub operator_key_path: Option<std::path::PathBuf>,
    /// S16 §6: publish the signed `(min_hold, max_hold, jitter)` batching
    /// attestation in `/v1/status` (re-signed at most every 24 h).
    #[serde(default)]
    pub publish_batching_attestation: bool,
}

/// Release timing policy. Responsive delivery is the product default; operators
/// can explicitly opt into the S16 timing-privacy hold and jitter profile.
/// Set all three values to zero for immediate eligibility.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BatchingConfig {
    #[serde(default = "default_min_hold")]
    pub min_hold_secs: u32,
    #[serde(default = "default_max_hold")]
    pub max_hold_secs: u32,
    #[serde(default = "default_jitter")]
    pub jitter_secs: u32,
}

impl Default for BatchingConfig {
    fn default() -> Self {
        Self {
            min_hold_secs: default_min_hold(),
            max_hold_secs: default_max_hold(),
            jitter_secs: default_jitter(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CleanupConfig {
    #[serde(default = "default_cleanup_interval")]
    pub interval_secs: u64,
    #[serde(default = "default_vacuum_threshold")]
    pub vacuum_threshold_percent: u32,
}

/// Logs always go to standard output (journald or the container log).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default = "default_log_format")]
    pub format: String,
}

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

fn default_listen_addr() -> String {
    "127.0.0.1".into()
}
fn default_listen_port() -> u16 {
    8080
}
fn default_health_port() -> u16 {
    9090
}
fn default_max_messages() -> u64 {
    4_096
}
fn default_max_blob_size() -> usize {
    262_144 // 256 KB
}
fn default_max_storage_mb() -> u64 {
    512
}
fn default_max_opks() -> u32 {
    200
}
fn default_retention_days() -> u32 {
    14
}
fn default_ephemeral_max_messages() -> u64 {
    100
}
fn default_ephemeral_max_storage_mb() -> u64 {
    8
}
fn default_min_difficulty() -> u8 {
    20 // S16 §7.2: registration ALWAYS requires ≥20-bit difficulty
}
fn default_max_difficulty() -> u8 {
    24
}
fn default_challenge_expiry() -> u64 {
    300
}
fn default_true() -> bool {
    true
}
fn default_deposit_pow_threshold() -> u32 {
    10
}
fn default_prekey_fetch_pow_threshold() -> u32 {
    5
}
fn default_ephemeral_deposit_min_difficulty() -> u8 {
    16
}
fn default_ephemeral_max_lifetime_hours() -> u64 {
    48
}
fn default_low_alert_threshold() -> u32 {
    50 // matches OPK_LOW_ALERT_THRESHOLD (S16 §5 [opk])
}
fn default_register_rate() -> u32 {
    10
}
fn default_deposit_rate() -> u32 {
    60
}
fn default_fetch_rate() -> u32 {
    120
}
fn default_prekey_fetch_rate() -> u32 {
    10 // S16 §8: 10/min hard ceiling per deposit_cap (adaptive PoW above 5/min)
}
fn default_min_hold() -> u32 {
    0
}
fn default_max_hold() -> u32 {
    0
}
fn default_jitter() -> u32 {
    0
}
fn default_cleanup_interval() -> u64 {
    600
}
fn default_vacuum_threshold() -> u32 {
    10
}
fn default_log_level() -> String {
    "info".into()
}
fn default_log_format() -> String {
    "json".into()
}

impl Config {
    /// Load configuration from a TOML file. A missing file is an error: the
    /// server never starts on built-in defaults (S16 §5).
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let contents = std::fs::read_to_string(path).with_context(|| {
            format!(
                "cannot read config file {} (pass the path of mailbox.toml as the only argument)",
                path.display()
            )
        })?;
        toml::from_str(&contents).with_context(|| format!("invalid config file {}", path.display()))
    }

    /// Built-in configuration for tests. The binary never uses it.
    pub fn default_dev() -> Self {
        Self {
            server: ServerConfig {
                listen_addr: default_listen_addr(),
                listen_port: default_listen_port(),
                health_port: default_health_port(),
                database_path: PathBuf::from("mailbox.db"),
                onion_address: String::new(),
                retire_at: None,
            },
            quotas: QuotaConfig {
                max_messages_per_capability: default_max_messages(),
                max_blob_size_bytes: default_max_blob_size(),
                max_storage_per_capability_mb: default_max_storage_mb(),
                max_opks_per_capability: default_max_opks(),
                default_retention_days: default_retention_days(),
                ephemeral_max_messages: default_ephemeral_max_messages(),
                ephemeral_max_storage_mb: default_ephemeral_max_storage_mb(),
            },
            pow: PowConfig {
                min_difficulty: default_min_difficulty(),
                max_difficulty: default_max_difficulty(),
                challenge_expiry_secs: default_challenge_expiry(),
                registration_always_requires_pow: true,
                deposit_pow_threshold_per_min: default_deposit_pow_threshold(),
                prekey_fetch_pow_threshold_per_min: default_prekey_fetch_pow_threshold(),
                ephemeral_deposit_min_difficulty: default_ephemeral_deposit_min_difficulty(),
            },
            rate_limits: RateLimitConfig {
                register_per_min: default_register_rate(),
                deposit_per_min_per_cap: default_deposit_rate(),
                fetch_per_min_per_cap: default_fetch_rate(),
                prekey_fetch_per_min: default_prekey_fetch_rate(),
            },
            capability_expiry: CapabilityExpiryConfig {
                ephemeral_max_lifetime_hours: default_ephemeral_max_lifetime_hours(),
            },
            opk: OpkConfig {
                low_alert_threshold: default_low_alert_threshold(),
                refuse_last_opk: true,
            },
            attestation: AttestationConfig {
                jurisdiction: String::new(),
                infrastructure_provider: String::new(),
                operator_key_seed_hex: String::new(),
                operator_key_path: None,
                publish_batching_attestation: false,
            },
            batching: BatchingConfig::default(),
            cleanup: CleanupConfig {
                interval_secs: default_cleanup_interval(),
                vacuum_threshold_percent: default_vacuum_threshold(),
            },
            logging: LoggingConfig {
                level: default_log_level(),
                format: default_log_format(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every supplied config parses, and an unknown key in any table — here a
    /// retired one, a typo and an unknown table — stops parsing with an error
    /// naming the key instead of silently falling back to a default.
    #[test]
    fn supplied_configs_parse_and_unknown_keys_are_rejected_by_name() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/deployment");
        for file in [
            "config/mailbox.toml",
            "config/mailbox-test.toml",
            "onion-dev/mailbox.toml",
        ] {
            let text = std::fs::read_to_string(root.join(file)).unwrap();
            toml::from_str::<Config>(&text).unwrap_or_else(|e| panic!("{file}: {e}"));
            for (extra, key) in [
                ("[logging]\nrotate_days = 7", "rotate_days"),
                ("[pow]\nmin_dificulty = 20", "min_dificulty"),
                ("[loging]\nlevel = \"info\"", "loging"),
            ] {
                // Append the key to its existing table (TOML forbids a
                // second `[logging]` header).
                let (table, line) = extra.split_once('\n').unwrap();
                let bad = if text.contains(table) {
                    text.replacen(table, extra, 1)
                } else {
                    format!("{text}\n{table}\n{line}\n")
                };
                let err = toml::from_str::<Config>(&bad).unwrap_err().to_string();
                assert!(err.contains(key), "{file}: {err}");
            }
        }
    }
}
