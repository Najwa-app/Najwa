//! Mailbox protocol data types.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

// ---------------------------------------------------------------------------
// Serde helpers for [u8; 32] ↔ base64
// ---------------------------------------------------------------------------

fn serialize_bytes32<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&BASE64.encode(bytes))
}

fn deserialize_bytes32<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
    let encoded = String::deserialize(d)?;
    let decoded = BASE64.decode(&encoded).map_err(serde::de::Error::custom)?;
    <[u8; 32]>::try_from(decoded.as_slice())
        .map_err(|_| serde::de::Error::custom(format!("expected 32 bytes, got {}", decoded.len())))
}

fn serialize_bytes<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&BASE64.encode(bytes))
}

fn deserialize_bytes<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    let encoded = String::deserialize(d)?;
    BASE64.decode(&encoded).map_err(serde::de::Error::custom)
}

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

/// Configuration for a single mailbox server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailboxConfig {
    /// Onion address without `.onion` suffix, e.g. "abc123...xyz".
    pub onion_address: String,
    /// 32-byte fetch capability token.
    #[serde(
        serialize_with = "serialize_bytes32",
        deserialize_with = "deserialize_bytes32"
    )]
    pub fetch_capability: [u8; 32],
    /// 32-byte deposit capability token.
    #[serde(
        serialize_with = "serialize_bytes32",
        deserialize_with = "deserialize_bytes32"
    )]
    pub deposit_capability: [u8; 32],
    /// D3: 32-byte secret that keys the deposit envelope for this capability.
    /// Minted alongside the deposit cap, shared with contacts via the handshake
    /// MailboxEntry, and NEVER sent to the server (which only sees the deposit
    /// cap). Defaults to zero for configs deserialized before D3.
    #[serde(
        default,
        serialize_with = "serialize_bytes32",
        deserialize_with = "deserialize_bytes32"
    )]
    pub envelope_secret: [u8; 32],
    /// Dedicated cover traffic deposit capability (S10 §5).
    /// If `None`, falls back to `deposit_capability`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cover_deposit_capability: Option<[u8; 32]>,
    /// Dedicated cover traffic fetch capability (S10 §5).
    /// If `None`, falls back to `fetch_capability`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cover_fetch_capability: Option<[u8; 32]>,
    /// S10 §5: self-generated envelope secret keying COVER deposits (§2.3).
    /// Distinct from `envelope_secret` (shared with contacts via the handshake):
    /// this one is never shared with anyone and never sent to the server.
    /// `None` ⇒ cover deposits to this mailbox are skipped (never sent raw or
    /// under the real envelope secret).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cover_envelope_secret: Option<[u8; 32]>,
}

impl MailboxConfig {
    /// Create a new MailboxConfig with only required fields (cover caps default
    /// to None). Mints a fresh random `envelope_secret` (D3).
    pub fn new(
        onion_address: String,
        fetch_capability: [u8; 32],
        deposit_capability: [u8; 32],
    ) -> Self {
        Self {
            onion_address,
            fetch_capability,
            deposit_capability,
            envelope_secret: najwa_crypto::random::random_bytes(),
            cover_deposit_capability: None,
            cover_fetch_capability: None,
            cover_envelope_secret: None,
        }
    }
}

/// Settings for a registered capability pair.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilitySettings {
    /// How many days the server should retain messages. Default: 14.
    pub retention_days: u32,
    /// Maximum message size in bytes. Default: 262144 (256 KB).
    pub max_message_size: u32,
}

impl Default for CapabilitySettings {
    fn default() -> Self {
        Self {
            retention_days: 14,
            max_message_size: 262_144,
        }
    }
}

/// A Proof-of-Work challenge issued by the mailbox server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PowChallenge {
    /// Opaque challenge bytes.
    #[serde(
        serialize_with = "serialize_bytes",
        deserialize_with = "deserialize_bytes"
    )]
    pub challenge: Vec<u8>,
    /// Required difficulty (number of leading zero bits).
    pub difficulty: u32,
    /// Algorithm identifier (e.g. "sha256-leading-zeros").
    pub algorithm: String,
    /// Unix timestamp after which the challenge expires.
    pub expires_at: u64,
}

/// A solved Proof-of-Work.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PowSolution {
    /// The original challenge bytes.
    #[serde(
        serialize_with = "serialize_bytes",
        deserialize_with = "deserialize_bytes"
    )]
    pub challenge: Vec<u8>,
    /// The nonce that yields a valid hash.
    pub nonce: u64,
    /// The resulting hash.
    #[serde(
        serialize_with = "serialize_bytes32",
        deserialize_with = "deserialize_bytes32"
    )]
    pub hash: [u8; 32],
    /// Solve-time Unix seconds — part of the S16 §7.1 preimage; MUST fall within
    /// the challenge's validity window (verified server-side).
    #[serde(default)]
    pub timestamp: u64,
}

/// Result of depositing a message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepositResult {
    /// Whether the server accepted the deposit.
    pub accepted: bool,
    /// Server-assigned message ID (if accepted).
    pub message_id: Option<String>,
}

/// A single message fetched from a mailbox.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailboxMessage {
    /// Server-assigned message ID.
    pub id: String,
    /// Encrypted message blob.
    #[serde(
        serialize_with = "serialize_bytes",
        deserialize_with = "deserialize_bytes"
    )]
    pub blob: Vec<u8>,
    /// Unix timestamp when the message was deposited.
    pub deposited_at: u64,
    /// Size of the blob in bytes.
    pub size: u32,
    /// Capability hint: `SHA256(deposit_capability)[0:8]` (S07 §3.2, S16 §3.4).
    ///
    /// Enables O(1) lookup of which deposit capability encrypted the envelope,
    /// avoiding trial decryption across all known capabilities.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cap_hint: Option<String>,
}

/// Status of a capability on the mailbox server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityStatus {
    /// Number of messages currently stored.
    pub messages_stored: u32,
    /// Remaining quota (bytes or messages, server-defined).
    pub quota_remaining: u32,
    /// Age of the oldest stored message in seconds.
    pub oldest_message_age: u64,
    /// Number of prekeys stored for this capability.
    pub prekey_count: u32,
    /// Available OPK IDs from the same server snapshot as `prekey_count`.
    #[serde(default)]
    pub prekey_ids: Vec<u32>,
}

/// Signed prekey-bundle manifest carried on the wire (S06 §2.2 step 1a).
///
/// `spk_id` is taken from the bundle's `signed_prekey_id`, so only the OPK-set
/// commitment, count, timestamp, and signature travel here. An absent manifest
/// remains parseable for an explicit validation error, but initiators reject it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireManifest {
    /// SHA-256 of the sorted u32-BE OPK id set at upload.
    #[serde(
        serialize_with = "serialize_bytes32",
        deserialize_with = "deserialize_bytes32"
    )]
    pub opk_id_set_hash: [u8; 32],
    /// OPK count committed at upload (0 = signed 3-DH-only, authorizes fallback).
    pub opk_count: u32,
    /// Sorted unique IDs witnessing the signed set commitment (at most 200).
    #[serde(default)]
    pub opk_ids: Vec<u32>,
    /// Manifest creation time (Unix seconds).
    pub timestamp: u64,
    /// Ed25519 signature by `mailbox_ik_priv` (64 bytes).
    #[serde(
        serialize_with = "serialize_bytes",
        deserialize_with = "deserialize_bytes"
    )]
    pub signature: Vec<u8>,
}

/// Prekey bundle for X3DH key exchange.
///
/// Contains the identity key, signed prekey (with ID and signature), and an
/// optional one-time prekey needed by the initiator to perform X3DH.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrekeyBundle {
    /// Per-mailbox signing key (Ed25519, 32 bytes), never the real identity key.
    #[serde(
        rename = "mailbox_ik_pub",
        alias = "identity_key",
        serialize_with = "serialize_bytes32",
        deserialize_with = "deserialize_bytes32"
    )]
    pub identity_key: [u8; 32],
    /// Signed prekey (X25519, 32 bytes).
    #[serde(
        serialize_with = "serialize_bytes32",
        deserialize_with = "deserialize_bytes32"
    )]
    pub signed_prekey: [u8; 32],
    /// Signed prekey identifier (4 bytes).
    pub signed_prekey_id: u32,
    /// Signature over the signed prekey (Ed25519, 64 bytes).
    #[serde(
        serialize_with = "serialize_bytes",
        deserialize_with = "deserialize_bytes"
    )]
    pub signed_prekey_signature: Vec<u8>,
    /// SPK creation time (Unix seconds). REQUIRED per S16 §3.6 — part of the SPK
    /// signature input (S06 §4.2), so fetched bundles verify byte-exactly.
    #[serde(default)]
    pub signed_prekey_timestamp: u64,
    /// Optional one-time prekeys (X25519, 32 bytes each). The server omits the
    /// field when it serves none (S06 §4.1); that bundle is the 3-DH case.
    #[serde(default)]
    pub one_time_prekeys: Vec<OneTimePrekey>,
    /// Signed bundle manifest (S06 §2.2 step 1a) — OPK-withholding detector.
    /// Initiators reject `None` before performing X3DH.
    #[serde(default)]
    pub manifest: Option<WireManifest>,
}

/// A single one-time prekey.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OneTimePrekey {
    /// Server-assigned prekey ID.
    pub id: u32,
    /// X25519 public key (32 bytes).
    #[serde(
        serialize_with = "serialize_bytes32",
        deserialize_with = "deserialize_bytes32"
    )]
    pub key: [u8; 32],
}

/// Verification result for onion address pinning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinVerification {
    /// First time seeing this address — pin was created.
    FirstUse,
    /// Pin matches — address is trusted.
    Verified,
    /// Pin has changed — possible MITM or server migration.
    Changed {
        /// Unix timestamp when the address was first pinned.
        first_seen: u64,
    },
}

// ---------------------------------------------------------------------------
// Request / Response serialization types (S16 §3)
// ---------------------------------------------------------------------------

/// POST /v1/capability/register (S16 §3.1)
#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterCapabilityRequest {
    /// S16 §3.1: 1 = expiring single-use handshake, 2 = long-term.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_type: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    #[serde(
        serialize_with = "serialize_bytes32",
        deserialize_with = "deserialize_bytes32"
    )]
    pub fetch_capability: [u8; 32],
    #[serde(
        serialize_with = "serialize_bytes32",
        deserialize_with = "deserialize_bytes32"
    )]
    pub deposit_capability: [u8; 32],
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pow_solution: Option<PowSolution>,
    pub settings: CapabilitySettings,
}

// The mailbox has no capability-link endpoint (S16 §1 lists the endpoints)
// and no channel-feed types.

/// POST /v1/challenge
#[derive(Debug, Serialize, Deserialize)]
pub struct ChallengeRequest {
    #[serde(
        serialize_with = "serialize_bytes",
        deserialize_with = "deserialize_bytes"
    )]
    pub capability_hint: Vec<u8>,
}

/// POST /v1/deposit (S16 §3.3)
#[derive(Debug, Serialize, Deserialize)]
pub struct DepositRequest {
    #[serde(
        serialize_with = "serialize_bytes32",
        deserialize_with = "deserialize_bytes32"
    )]
    pub deposit_capability: [u8; 32],
    #[serde(
        serialize_with = "serialize_bytes",
        deserialize_with = "deserialize_bytes"
    )]
    pub blob: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pow_solution: Option<PowSolution>,
}

/// POST /v1/fetch (S16 §3.4)
#[derive(Debug, Serialize, Deserialize)]
pub struct FetchRequest {
    #[serde(
        serialize_with = "serialize_bytes32",
        deserialize_with = "deserialize_bytes32"
    )]
    pub fetch_capability: [u8; 32],
    #[serde(skip_serializing_if = "Option::is_none")]
    pub since_id: Option<String>,
    pub limit: u32,
}

/// Response for POST /v1/fetch (S16 §3.4)
#[derive(Debug, Serialize, Deserialize)]
pub struct FetchResponse {
    pub messages: Vec<MailboxMessage>,
    pub has_more: bool,
}

/// POST /v1/prekey/upload (S16 §3.6)
#[derive(Debug, Serialize, Deserialize)]
pub struct UploadPrekeyRequest {
    #[serde(
        serialize_with = "serialize_bytes32",
        deserialize_with = "deserialize_bytes32"
    )]
    pub deposit_capability: [u8; 32],
    /// Owner proof, sent on every upload: the queue's fetch capability.
    #[serde(
        serialize_with = "serialize_bytes32",
        deserialize_with = "deserialize_bytes32"
    )]
    pub fetch_capability: [u8; 32],
    /// Owner recovery replacement. Never set during ordinary replenishment.
    #[serde(default)]
    pub replace_opks: bool,
    pub bundle: PrekeyBundle,
}

/// POST /v1/prekey/fetch (S16 §3.7)
#[derive(Debug, Serialize, Deserialize)]
pub struct FetchPrekeyRequest {
    #[serde(
        serialize_with = "serialize_bytes32",
        deserialize_with = "deserialize_bytes32"
    )]
    pub deposit_capability: [u8; 32],
    /// PoW solution when the fetch was previously rate-limited (S16 §7.1/§7.2:
    /// prekey-fetch binding = `deposit_cap`, `blob_hash = zeros`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pow_solution: Option<PowSolution>,
}

/// POST /v1/status
#[derive(Debug, Serialize, Deserialize)]
pub struct StatusRequest {
    #[serde(
        serialize_with = "serialize_bytes32",
        deserialize_with = "deserialize_bytes32"
    )]
    pub fetch_capability: [u8; 32],
}

/// POST /v1/acknowledge (S16 §3.5)
#[derive(Debug, Serialize, Deserialize)]
pub struct AcknowledgeRequest {
    #[serde(
        serialize_with = "serialize_bytes32",
        deserialize_with = "deserialize_bytes32"
    )]
    pub fetch_capability: [u8; 32],
    pub message_ids: Vec<String>,
}

/// POST /v1/capability/deactivate
#[derive(Debug, Serialize, Deserialize)]
pub struct DeactivateRequest {
    #[serde(
        serialize_with = "serialize_bytes32",
        deserialize_with = "deserialize_bytes32"
    )]
    pub fetch_capability: [u8; 32],
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_settings_default() {
        let settings = CapabilitySettings::default();
        assert_eq!(settings.retention_days, 14);
        assert_eq!(settings.max_message_size, 262_144);
    }

    #[test]
    fn mailbox_config_roundtrip() {
        let config = MailboxConfig::new("abc123def456".to_string(), [0xAA; 32], [0xBB; 32]);
        let json = serde_json::to_string(&config).unwrap();
        let parsed: MailboxConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.onion_address, config.onion_address);
        assert_eq!(parsed.fetch_capability, config.fetch_capability);
        assert_eq!(parsed.deposit_capability, config.deposit_capability);
    }

    #[test]
    fn pow_challenge_roundtrip() {
        let challenge = PowChallenge {
            challenge: vec![1, 2, 3, 4],
            difficulty: 16,
            algorithm: "sha256-leading-zeros".to_string(),
            expires_at: 1700000000,
        };
        let json = serde_json::to_string(&challenge).unwrap();
        let parsed: PowChallenge = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.challenge, challenge.challenge);
        assert_eq!(parsed.difficulty, challenge.difficulty);
    }

    #[test]
    fn deposit_request_roundtrip() {
        let req = DepositRequest {
            deposit_capability: [0xCC; 32],
            blob: vec![10, 20, 30],
            pow_solution: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: DepositRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.deposit_capability, req.deposit_capability);
        assert_eq!(parsed.blob, req.blob);
        assert!(parsed.pow_solution.is_none());
    }

    #[test]
    fn fetch_response_roundtrip() {
        let resp = FetchResponse {
            messages: vec![MailboxMessage {
                id: "msg-001".to_string(),
                blob: vec![0xFF; 16],
                deposited_at: 1700000000,
                size: 16,
                cap_hint: None,
            }],
            has_more: false,
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: FetchResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.messages.len(), 1);
        assert_eq!(parsed.messages[0].id, "msg-001");
        assert!(!parsed.has_more);
    }

    #[test]
    fn prekey_bundle_roundtrip() {
        let bundle = PrekeyBundle {
            identity_key: [1; 32],
            signed_prekey: [2; 32],
            signed_prekey_id: 1,
            signed_prekey_signature: vec![3; 64],
            signed_prekey_timestamp: 0,
            one_time_prekeys: vec![OneTimePrekey {
                id: 1,
                key: [4; 32],
            }],
            manifest: None,
        };
        let json = serde_json::to_string(&bundle).unwrap();
        let parsed: PrekeyBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.identity_key, bundle.identity_key);
        assert_eq!(parsed.one_time_prekeys.len(), 1);
    }

    #[test]
    fn prekey_bundle_parses_server_fetch_that_serves_no_opk() {
        // Exact S16 §3.7 fetch shape when no OPK is served: the server omits
        // `one_time_prekeys` entirely (najwa-mailbox FetchPrekeyResponse).
        use base64::Engine;
        let b64 = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);
        let parsed: PrekeyBundle = serde_json::from_value(serde_json::json!({
            "mailbox_ik_pub": b64(&[1; 32]),
            "signed_prekey": b64(&[2; 32]),
            "signed_prekey_id": 7,
            "signed_prekey_signature": b64(&[3; 64]),
            "signed_prekey_timestamp": 1000,
            "manifest": {
                "opk_id_set_hash": b64(&[4; 32]),
                "opk_count": 0,
                "opk_ids": [],
                "timestamp": 1000,
                "signature": b64(&[5; 64]),
            },
        }))
        .unwrap();
        assert!(parsed.one_time_prekeys.is_empty());
        assert_eq!(parsed.manifest.unwrap().opk_count, 0);
    }

    #[test]
    fn register_request_with_pow() {
        let req = RegisterCapabilityRequest {
            capability_type: Some(2),
            expires_at: None,
            fetch_capability: [0xAA; 32],
            deposit_capability: [0xBB; 32],
            pow_solution: Some(PowSolution {
                challenge: vec![1, 2, 3],
                nonce: 12345,
                hash: [0; 32],
                timestamp: 1_700_000_000,
            }),
            settings: CapabilitySettings::default(),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("pow_solution"));
    }

    #[test]
    fn register_request_without_pow() {
        let req = RegisterCapabilityRequest {
            capability_type: Some(2),
            expires_at: None,
            fetch_capability: [0xAA; 32],
            deposit_capability: [0xBB; 32],
            pow_solution: None,
            settings: CapabilitySettings::default(),
        };
        let json = serde_json::to_string(&req).unwrap();
        // pow_solution should be omitted when None
        assert!(!json.contains("pow_solution"));
    }
}
