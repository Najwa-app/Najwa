//! Double Ratchet state (S06 §3.1).

use std::collections::HashMap;

use najwa_crypto::keys::x25519::{X25519KeyPair, X25519Public};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

/// Maximum number of message keys that can be skipped in a single ratchet
/// step / chain (S06 §3.1). Bounds the work for one out-of-order frame.
///
/// Memory-amplification across many epochs is bounded separately by
/// [`MAX_SKIPPED_KEYS_PER_SESSION`] (a global oldest-evicted cap), so this
/// per-chain limit can stay at the spec value of 1000 without unbounded
/// growth.
pub const MAX_SKIP: u32 = 1000;

/// Global cap on the total number of skipped message keys retained per
/// session, across all epochs (S06 §3.1 / D6). When an insertion would exceed
/// this, the oldest keys (by `created_at`) are evicted first. This is the real
/// memory-DoS bound: a peer that repeatedly forces near-`MAX_SKIP` skips and
/// frequent DH ratchets cannot grow the store without limit.
pub const MAX_SKIPPED_KEYS_PER_SESSION: usize = 4000;

/// Skipped keys expire after 90 days (in seconds), aligned with the mailbox
/// `MAX_RETENTION_DAYS` so that a late-released out-of-order blob is never
/// stranded by a shorter skip-key lifetime (S06 §3.1 / D6).
pub const SKIP_KEY_EXPIRY_SECS: u64 = 90 * 24 * 3600;

/// Double Ratchet session state (S06 §3.1).
///
/// Contains the DH ratchet key pair, root key, chain keys, message counters,
/// and a cache of skipped message keys for out-of-order delivery.
///
/// # Serialization
///
/// The `skipped` HashMap is NOT serialized with bincode (`#[serde(skip)]`).
/// Skipped keys live in the `skipped_keys` SQL table (S03 §5.5): each ratchet
/// commit writes this map's current set there, and a load reads them back
/// from SQL into this map.
#[derive(Serialize, Deserialize)]
pub struct RatchetState {
    /// Our current DH ratchet key pair.
    #[serde(serialize_with = "ser_keypair", deserialize_with = "de_keypair")]
    pub dhs: X25519KeyPair,
    /// Their current DH ratchet public key.
    pub dhr: Option<X25519Public>,
    /// Root key (32 bytes).
    pub rk: [u8; 32],
    /// Sending chain key.
    pub cks: Option<[u8; 32]>,
    /// Receiving chain key.
    pub ckr: Option<[u8; 32]>,
    /// Send message number.
    pub ns: u32,
    /// Receive message number.
    pub nr: u32,
    /// Previous sending chain length.
    pub pn: u32,
    /// Previous sending-epoch DH public key (S06 §3.9).
    ///
    /// Captured in `dh_ratchet` before rotating to a new sending key pair,
    /// and written into the `epoch_link` field of every outgoing header in
    /// the new sending epoch so the receiver can detect missed epoch
    /// boundaries. `None` until the first sender-side DH ratchet step; on
    /// that first post-X3DH epoch the header still ships zeros, which is
    /// indistinguishable from a legacy peer and therefore accepted.
    pub prev_dhs_pub: Option<[u8; 32]>,
    /// Skipped message keys: (ratchet_pub_bytes, msg_num) -> SkippedKey.
    ///
    /// Runtime cache only — not serialized with bincode.
    #[serde(skip)]
    pub skipped: HashMap<([u8; 32], u32), SkippedKey>,
}

/// A skipped message key with its creation timestamp (S06 §3.1).
pub struct SkippedKey {
    /// The derived message key (32 bytes).
    pub message_key: [u8; 32],
    /// Unix timestamp when this key was stored.
    pub created_at: u64,
}

impl Drop for SkippedKey {
    fn drop(&mut self) {
        self.message_key.zeroize();
    }
}

impl Drop for RatchetState {
    fn drop(&mut self) {
        self.rk.zeroize();
        if let Some(ref mut cks) = self.cks {
            cks.zeroize();
        }
        if let Some(ref mut ckr) = self.ckr {
            ckr.zeroize();
        }
        // skipped keys are zeroized via SkippedKey::drop
    }
}

impl std::fmt::Debug for RatchetState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RatchetState")
            .field("dhr", &self.dhr.as_ref().map(|_| "[present]"))
            .field("rk", &"[REDACTED]")
            .field("cks", &self.cks.as_ref().map(|_| "[REDACTED]"))
            .field("ckr", &self.ckr.as_ref().map(|_| "[REDACTED]"))
            .field("ns", &self.ns)
            .field("nr", &self.nr)
            .field("pn", &self.pn)
            .field("skipped_count", &self.skipped.len())
            .finish()
    }
}

// -- Serde helpers for X25519KeyPair (not natively serializable) -------------

fn ser_keypair<S: serde::Serializer>(
    kp: &X25519KeyPair,
    s: S,
) -> std::result::Result<S::Ok, S::Error> {
    // Serialize as private key bytes (32) — public is derived
    s.serialize_bytes(&*Zeroizing::new(kp.private().to_bytes()))
}

fn de_keypair<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<X25519KeyPair, D::Error> {
    let bytes = Zeroizing::new(Vec::<u8>::deserialize(d)?);
    if bytes.len() != 32 {
        return Err(serde::de::Error::custom("expected 32-byte key"));
    }
    let mut seed = Zeroizing::new([0u8; 32]);
    seed.copy_from_slice(&bytes);
    Ok(X25519KeyPair::from_seed(*seed))
}
