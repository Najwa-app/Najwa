//! Prekey types (S06 §4, §5).

use najwa_crypto::keys::ed25519::{Ed25519Public, Ed25519Signature};
use najwa_crypto::keys::x25519::{X25519KeyPair, X25519Public};
use najwa_crypto::types::PrekeyId;

/// A signed prekey (SPK) with its Ed25519 signature (S06 §4.2).
///
/// The queue's per-mailbox derived key (S05 §3) signs
/// `"najwa/v1/spk/" || spk_pub || spk_id || created_at`.
pub struct SignedPrekey {
    /// 4-byte random identifier.
    pub id: PrekeyId,
    /// X25519 key pair (private + public).
    pub keypair: X25519KeyPair,
    /// Ed25519 signature by the per-mailbox key over the S06 §4.2 SPK message.
    pub signature: Ed25519Signature,
    /// Unix timestamp when this SPK was created.
    pub created_at: u64,
    /// Set when this SPK is rotated out. After `expires_at` + grace period
    /// the key material can be deleted. `None` means this is the current SPK.
    pub expires_at: Option<u64>,
}

/// A one-time prekey (OPK) for forward secrecy (S06 §2.5).
///
/// Each OPK is used at most once in an X3DH handshake.
pub struct OneTimePrekey {
    /// 4-byte random identifier.
    pub id: PrekeyId,
    /// X25519 key pair (private + public).
    pub keypair: X25519KeyPair,
    /// Unix timestamp when this OPK was generated.
    pub created_at: u64,
    /// Whether this OPK has been consumed by a session.
    pub used: bool,
    /// Which mailbox this OPK was uploaded to (`None` if not yet uploaded).
    pub mailbox_id: Option<i64>,
}

/// Bundle for uploading to a mailbox server. `to_mailbox_bundle` converts it
/// to the JSON bundle object of S06 §4.1.
///
/// Contains public-key material only (no private keys).
///
/// This is distinct from `X3DHPrekeyBundle` (S06 §2.6), which holds the
/// single-OPK bundle an initiator receives for one X3DH run.
#[derive(Debug, Clone)]
pub struct PrekeyUploadBundle {
    /// Per-mailbox derived signing public key (S05 §3).
    /// SPK is signed by this key, not the real identity key.
    pub mailbox_ik_pub: Ed25519Public,
    /// Real Ed25519 identity public key (for DH conversion).
    pub identity_key: Ed25519Public,
    /// Current signed prekey (X25519 public).
    pub signed_prekey: X25519Public,
    /// Signed prekey identifier.
    pub signed_prekey_id: PrekeyId,
    /// Ed25519 signature over the SPK, signed by `mailbox_ik_pub`.
    pub signed_prekey_signature: Ed25519Signature,
    /// SPK creation timestamp (Unix seconds, big-endian in wire format).
    pub spk_timestamp: u64,
    /// One-time prekeys (public key + ID pairs).
    pub one_time_prekeys: Vec<(X25519Public, PrekeyId)>,
    /// Signed bundle manifest (S06 §2.2 1a) committing to this OPK id set.
    pub manifest: Option<crate::mailbox::types::WireManifest>,
}

impl PrekeyUploadBundle {
    /// Convert to the mailbox wire-format `PrekeyBundle` for upload (S06 §4.1).
    pub fn to_mailbox_bundle(&self) -> crate::mailbox::types::PrekeyBundle {
        crate::mailbox::types::PrekeyBundle {
            // Serde emits this as `mailbox_ik_pub`: the per-mailbox SPK signer.
            // The Rust field retains its compatibility name.
            identity_key: self.mailbox_ik_pub.to_bytes(),
            signed_prekey: self.signed_prekey.to_bytes(),
            signed_prekey_id: u32::from_be_bytes(self.signed_prekey_id),
            signed_prekey_signature: self.signed_prekey_signature.to_bytes().to_vec(),
            signed_prekey_timestamp: self.spk_timestamp,
            one_time_prekeys: self
                .one_time_prekeys
                .iter()
                .map(|(pub_key, id)| crate::mailbox::types::OneTimePrekey {
                    id: u32::from_be_bytes(*id),
                    key: pub_key.to_bytes(),
                })
                .collect(),
            manifest: self.manifest.clone(),
        }
    }
}

/// Default number of OPKs to generate in an initial bundle.
pub const DEFAULT_OPK_BATCH_SIZE: u32 = 200;

/// Default OPK replenishment threshold.
pub const DEFAULT_OPK_THRESHOLD: u32 = 50;

/// Alert threshold — warn user when OPK count falls below this.
pub const OPK_ALERT_THRESHOLD: u32 = 50;

/// SPK rotation interval in days (S06 §5.1).
pub const DEFAULT_SPK_ROTATION_DAYS: u64 = 7;

/// Grace period for old SPKs after rotation (S06 §5.1: 14 days in seconds).
pub const SPK_GRACE_PERIOD_SECS: u64 = 14 * 24 * 3600;
