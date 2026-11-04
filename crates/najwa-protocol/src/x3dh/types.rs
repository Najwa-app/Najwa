//! X3DH data structures (S06 §2.6).

use najwa_crypto::keys::ed25519::{Ed25519KeyPair, Ed25519Public, Ed25519Signature};
use najwa_crypto::keys::x25519::X25519Public;
use najwa_crypto::types::PrekeyId;
use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

/// The SPK signature message per S06 §4.2:
/// `"najwa/v1/spk/" || spk_pub(32) || spk_id(4) || spk_timestamp(8 BE)`.
/// Signed with the per-mailbox derived signing key (`mailbox_ik_priv`). Binding
/// the id + timestamp lets fetched bundles be verified byte-exactly and prevents
/// an SPK signature being replayed for a different id/time. Used identically at
/// every sign site and by [`X3DHPrekeyBundle::verify_spk_signature`].
pub fn spk_signature_message(spk_pub: &[u8; 32], spk_id: &PrekeyId, spk_timestamp: u64) -> Vec<u8> {
    let mut m = Vec::with_capacity(13 + 32 + 4 + 8);
    m.extend_from_slice(b"najwa/v1/spk/");
    m.extend_from_slice(spk_pub);
    m.extend_from_slice(spk_id);
    m.extend_from_slice(&spk_timestamp.to_be_bytes());
    m
}

/// SHA-256 over the responder's OPK ids, each serialized u32 big-endian and
/// **sorted ascending** (S06 §2.2 step 1a). An order-independent commitment to
/// the served OPK set — part of the signed manifest below.
pub fn opk_id_set_hash(opk_ids: &[u32]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut ids = opk_ids.to_vec();
    ids.sort_unstable();
    let mut h = Sha256::new();
    for id in ids {
        h.update(id.to_be_bytes());
    }
    h.finalize().into()
}

/// The manifest signing message per S06 §4.3:
/// `spk_id(4) || opk_id_set_hash(32) || opk_count(4 BE) || timestamp(8 BE)`.
/// Signed with the per-mailbox derived key so an initiator can detect a mailbox
/// silently withholding OPKs to force a weaker 3-DH handshake (S06 §2.2 step 1b).
pub fn manifest_signing_message(
    spk_id: &PrekeyId,
    opk_id_set_hash: &[u8; 32],
    opk_count: u32,
    timestamp: u64,
) -> Vec<u8> {
    let mut m = Vec::with_capacity(4 + 32 + 4 + 8);
    m.extend_from_slice(spk_id);
    m.extend_from_slice(opk_id_set_hash);
    m.extend_from_slice(&opk_count.to_be_bytes());
    m.extend_from_slice(&timestamp.to_be_bytes());
    m
}

/// Signed prekey-bundle manifest (S06 §2.2 step 1a). Commits the responder's
/// per-mailbox signing key to the SPK id + OPK id-set + count at upload time, so
/// an initiator can reject a mailbox that withholds OPKs to force 3-DH (S06 §2.2 step 1b).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrekeyManifest {
    /// SPK id this manifest is bound to (must equal the served SPK id).
    pub spk_id: PrekeyId,
    /// SHA-256 of the sorted OPK id set at upload (see [`opk_id_set_hash`]).
    pub opk_id_set_hash: [u8; 32],
    /// Number of OPKs the responder uploaded. 0 = signed 3-DH-only.
    pub opk_count: u32,
    /// Manifest creation time (Unix seconds).
    pub timestamp: u64,
    /// Ed25519 signature by `mailbox_ik_priv` over [`manifest_signing_message`].
    pub signature: Ed25519Signature,
}

impl PrekeyManifest {
    /// Verify the manifest signature against the responder's per-mailbox key.
    pub fn verify(&self, mailbox_ik_pub: &Ed25519Public) -> najwa_crypto::error::Result<()> {
        let msg = manifest_signing_message(
            &self.spk_id,
            &self.opk_id_set_hash,
            self.opk_count,
            self.timestamp,
        );
        mailbox_ik_pub.verify(&msg, &self.signature)
    }
}

/// Build + sign a wire manifest (S06 §4.3) for the OPK id set the
/// responder is uploading, using its per-mailbox signing key. Producers call
/// this when assembling a bundle so an initiator can detect OPK withholding.
pub fn build_wire_manifest(
    mailbox_kp: &Ed25519KeyPair,
    spk_id: &PrekeyId,
    opk_ids: &[u32],
    timestamp: u64,
) -> crate::mailbox::types::WireManifest {
    let mut opk_ids = opk_ids.to_vec();
    opk_ids.sort_unstable();
    opk_ids.dedup();
    let opk_id_set_hash = opk_id_set_hash(&opk_ids);
    let opk_count = opk_ids.len() as u32;
    let signature = mailbox_kp
        .sign(&manifest_signing_message(
            spk_id,
            &opk_id_set_hash,
            opk_count,
            timestamp,
        ))
        .to_bytes()
        .to_vec();
    crate::mailbox::types::WireManifest {
        opk_id_set_hash,
        opk_count,
        opk_ids,
        timestamp,
        signature,
    }
}

/// Prekey bundle fetched from a contact's mailbox (S06 §2.6; wire form §4.1).
///
/// Contains the responder's identity key (real + per-mailbox derived),
/// signed prekey, and optionally a one-time prekey.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X3DHPrekeyBundle {
    /// Responder's REAL Ed25519 identity public key (IK_B).
    /// Used for DH operations (converted to X25519).
    pub identity_key: Ed25519Public,
    /// Responder's per-mailbox derived signing key (S05 §3).
    /// SPK signature is verified against THIS key, not the real IK.
    /// If `None`, falls back to verifying against `identity_key` (legacy).
    pub mailbox_ik_pub: Option<Ed25519Public>,
    /// Responder's signed prekey (SPK_B, X25519).
    pub signed_prekey: X25519Public,
    /// Identifier for the signed prekey.
    pub signed_prekey_id: PrekeyId,
    /// Ed25519 signature over the encoded signed prekey.
    /// Signed by `mailbox_ik_pub` (per-mailbox derived key), NOT the real IK.
    pub signed_prekey_signature: Ed25519Signature,
    /// SPK creation time (Unix seconds). Part of the SPK signature input (S06
    /// §4.2), so it must be carried alongside the signature to verify byte-exactly.
    #[serde(default)]
    pub signed_prekey_timestamp: u64,
    /// Optional one-time prekey (OPK_B, X25519). May be `None` if exhausted.
    pub one_time_prekey: Option<X25519Public>,
    /// Identifier for the one-time prekey (if present).
    pub one_time_prekey_id: Option<PrekeyId>,
}

impl X3DHPrekeyBundle {
    /// Verify that the signed prekey signature is valid (S06 §2.2 / §4.2).
    ///
    /// Verifies against `mailbox_ik_pub` (per-mailbox derived key) if available,
    /// otherwise falls back to `identity_key` for backward compatibility.
    /// DH operations still use the real `identity_key` converted to X25519.
    pub fn verify_spk_signature(&self) -> najwa_crypto::error::Result<()> {
        let verifying_key = self.mailbox_ik_pub.as_ref().unwrap_or(&self.identity_key);
        // S06 §4.2: signature over "najwa/v1/spk/" || spk_pub || spk_id || spk_ts.
        let msg = spk_signature_message(
            &self.signed_prekey.to_bytes(),
            &self.signed_prekey_id,
            self.signed_prekey_timestamp,
        );
        verifying_key.verify(&msg, &self.signed_prekey_signature)
    }
}

/// X3DH header sent with the initial message (S06 §2.4).
///
/// Included in the first message so the responder can compute the
/// same shared secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X3DHHeader {
    /// Initiator's Ed25519 identity public key (IK_A).
    pub identity_key: Ed25519Public,
    /// Initiator's ephemeral X25519 public key (EK_A).
    pub ephemeral_key: X25519Public,
    /// Initiator's device signing public key (DK_n_pub, S06 §2.4, §7). Equals
    /// `identity_key` for a single-device sender. Receivers key contact/session
    /// lookup on `(ik_pub, device_pub)` per [S03 §5.2].
    pub device_key: Ed25519Public,
    /// Which one-time prekey was used (if any).
    pub used_one_time_prekey_id: Option<PrekeyId>,
    /// Which signed prekey was used.
    pub signed_prekey_id: PrekeyId,
}

/// Result of an X3DH computation (S06 §2.6).
///
/// Contains everything needed to initialize a Double Ratchet session.
#[derive(ZeroizeOnDrop)]
pub struct X3DHResult {
    /// 32-byte shared secret (SK) for Double Ratchet initialization.
    #[zeroize]
    pub shared_secret: [u8; 32],
    /// The initiator's X3DH ephemeral private key (EK_A). S06 §3.2: this becomes
    /// the FIRST Double Ratchet sending DH key (via `init_alice`), binding the
    /// ratchet to the authenticated handshake instead of a fresh unrelated key.
    /// Secret — zeroized on drop.
    #[zeroize]
    pub ephemeral_seed: [u8; 32],
    /// The X3DH header (not secret — sent with the initial message).
    #[zeroize(skip)]
    pub header: X3DHHeader,
    /// Associated data: AD = Encode(IK_A) || Encode(IK_B).
    #[zeroize(skip)]
    pub associated_data: Vec<u8>,
}

impl std::fmt::Debug for X3DHResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X3DHResult")
            .field("shared_secret", &"[REDACTED]")
            .field("header", &self.header)
            .field("associated_data_len", &self.associated_data.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use najwa_crypto::keys::ed25519::Ed25519KeyPair;

    #[test]
    fn manifest_sign_verify_roundtrip_and_tamper() {
        let kp = Ed25519KeyPair::from_seed(&[7u8; 32]);
        let spk_id: PrekeyId = [0, 0, 0, 5];
        // Set hash is order-independent.
        let hash = opk_id_set_hash(&[3, 1, 2]);
        assert_eq!(hash, opk_id_set_hash(&[1, 2, 3]));

        let sig = kp.sign(&manifest_signing_message(&spk_id, &hash, 3, 1000));
        let m = PrekeyManifest {
            spk_id,
            opk_id_set_hash: hash,
            opk_count: 3,
            timestamp: 1000,
            signature: sig,
        };
        assert!(m.verify(kp.public()).is_ok());

        // Tampering with any signed field breaks verification (downgrade attempt).
        let mut zeroed = m.clone();
        zeroed.opk_count = 0;
        assert!(zeroed.verify(kp.public()).is_err());

        // Wrong signing key fails.
        let other = Ed25519KeyPair::from_seed(&[8u8; 32]);
        assert!(m.verify(other.public()).is_err());
    }
}
