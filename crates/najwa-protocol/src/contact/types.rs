//! Contact establishment types (S05 §2).

use serde::{Deserialize, Serialize};

use super::mailbox_key::MailboxEntry;

/// Helper module for serde of [u8; 64] arrays.
mod serde_byte_array_64 {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let v: Vec<u8> = Vec::deserialize(deserializer)?;
        v.try_into()
            .map_err(|_| serde::de::Error::custom("expected 64 bytes"))
    }
}

/// Current handshake payload version (S05 §2.1).
pub const HANDSHAKE_VERSION: u8 = 0x02;

/// Domain-separation prefix for the outer `HandshakePayload` signature
/// (S05 §4.1, registry `najwa/v1/handshake/`, 19 bytes).
pub const HANDSHAKE_SIG_PREFIX: &[u8] = b"najwa/v1/handshake/";

/// Maximum handshake payload size in bytes (S05 §2.1).
pub const MAX_HANDSHAKE_SIZE: usize = 2048;

/// Maximum number of mailbox entries (S05 §2.1).
pub const MAX_MAILBOX_COUNT: u8 = 8;

/// Maximum display name length in bytes (S05 §2.1).
pub const MAX_DISPLAY_NAME_LEN: usize = 128;

/// QR code handshake payload TTL: 15 minutes (AUD-02, S05 §5).
/// QR payloads use single-use ephemeral capabilities that expire quickly.
pub const QR_TTL_MINUTES: u64 = 15;

/// Information about a single mailbox endpoint (legacy v0x01 compat).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MailboxInfo {
    /// Onion address (without `.onion` suffix).
    pub onion_address: String,
    /// Per-contact deposit capability token (32 bytes).
    pub deposit_capability: [u8; 32],
}

/// Handshake payload for out-of-band contact exchange (S05 §2, v0x02).
///
/// Contains everything a peer needs to:
/// 1. Verify the sender's identity (outer Ed25519 signature)
/// 2. Verify per-mailbox signing keys (MailboxCertificate signatures)
/// 3. Deposit messages (mailbox addresses + ephemeral deposit capabilities)
///
/// **Wire format (v0x02):**
/// ```text
/// version(1) || ik_pub(32) || mailbox_count(1) || mailboxes[185 each] ||
/// display_name_len(2,BE) || display_name(var) || created_at(8,BE) ||
/// expires_at(8,BE) || signature(64)
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakePayload {
    /// Protocol version (0x02).
    pub version: u8,
    /// Real identity public key (Ed25519, 32 bytes).
    pub ik_pub: [u8; 32],
    /// Per-mailbox entries with derived signing keys and certificates (S05 §2.2).
    pub mailbox_entries: Vec<MailboxEntry>,
    /// Legacy v0x01 mailbox info (kept for backward compat in tests/QR/URI encoding).
    /// In v0x02, this is derived from `mailbox_entries` during `create()`.
    #[serde(default)]
    pub mailboxes: Vec<MailboxInfo>,
    /// Display name (UTF-8, max 128 bytes).
    pub display_name: String,
    /// Creation timestamp (Unix seconds).
    pub created_at: u64,
    /// Expiration timestamp (Unix seconds).
    pub expires_at: u64,
    /// Ed25519 signature over all preceding fields (64 bytes).
    #[serde(with = "serde_byte_array_64")]
    pub signature: [u8; 64],
}

/// Per-contact mailbox capability mapping (§10.3, S05 §8).
///
/// Links a contact to a specific mailbox with per-contact deposit AND fetch
/// capabilities, enabling per-contact isolation (HIGH-09).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactMailboxCap {
    /// Contact identifier.
    pub contact_id: u64,
    /// Mailbox identifier.
    pub mailbox_id: u64,
    /// Our deposit capability for this contact on this mailbox.
    pub deposit_capability: [u8; 32],
    /// Per-contact fetch capability for incoming messages from this contact (S05 §8).
    pub fetch_capability: Option<[u8; 32]>,
    /// Their deposit capability for reaching them on their mailbox.
    pub their_deposit_capability: Option<[u8; 32]>,
    /// D3: their envelope secret (paired with `their_deposit_capability`), used
    /// to key the deposit envelope when sending to them.
    pub their_envelope_secret: Option<[u8; 32]>,
}
