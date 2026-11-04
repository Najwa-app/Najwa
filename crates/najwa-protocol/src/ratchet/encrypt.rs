//! Double Ratchet encryption (S06 §3.4).

use najwa_crypto::aead;
use zeroize::Zeroizing;

use crate::message::{build_wire_prefix, WirePrefixMeta};

use super::error::{RatchetError, Result};
use super::header::RatchetHeader;
use super::kdf::{derive_message_keys, generate_nonce_from_iv, kdf_ck};
use super::state::RatchetState;

/// AEAD nonce size prepended to the ciphertext on the wire (S07 §2).
const NONCE_LEN: usize = 24;
/// Poly1305 tag size appended by the AEAD (S07 §2).
const TAG_LEN: usize = 16;

/// Encrypt a plaintext message using the Double Ratchet (S06 §3.4).
///
/// # Arguments
///
/// * `state` – Mutable ratchet state (sending chain key is advanced).
/// * `plaintext` – The (already padded) message to encrypt.
/// * `session_ad` – The 64-byte X3DH associated data for this session.
/// * `meta` – Wire-format context (version, message type, optional X3DH header)
///   needed to build the canonical AAD for the frame being emitted.
///
/// # Returns
///
/// `(header, encrypted_payload)` where `encrypted_payload = nonce(24) || ct || tag(16)`
/// (S07 §2). The AEAD associated data is `session_ad(64) || wire_prefix`, the
/// exact byte string the receiver reconstructs (S06 §3.4 / S07 §2.3).
pub fn ratchet_encrypt(
    state: &mut RatchetState,
    plaintext: &[u8],
    session_ad: &[u8],
    meta: &WirePrefixMeta,
) -> Result<(RatchetHeader, Vec<u8>)> {
    let next_ns = state.ns.checked_add(1).ok_or(RatchetError::CorruptedState)?;
    let payload_length = plaintext.len().checked_add(NONCE_LEN + TAG_LEN)
        .and_then(|len| u32::try_from(len).ok()).ok_or(RatchetError::EncryptionFailed)?;
    let cks = state.cks.as_ref().ok_or(RatchetError::NoSendingChain)?;
    // Derive on a working copy; commit only after the complete frame exists.
    let (new_ck, mk) = kdf_ck(cks);
    let new_ck = Zeroizing::new(new_ck);
    let mk = Zeroizing::new(mk);

    // Build header. S06 §3.9 — advertise our previous sending
    // epoch's DH pubkey so the receiver can detect a missed epoch boundary.
    // Zeros means "first post-X3DH sending epoch / legacy peer".
    let epoch_link = state.prev_dhs_pub.unwrap_or([0u8; 32]);
    let header =
        RatchetHeader::with_epoch_link(state.dhs.public().clone(), state.pn, state.ns, epoch_link);

    let keys = derive_message_keys(&mk)?;
    let nonce = generate_nonce_from_iv(&keys.iv);

    // Canonical AAD = session_ad(64) || wire_prefix (S06 §3.4). payload_length is
    // the length of the encrypted_payload we are about to emit: nonce + ct + tag.
    let wire_prefix = build_wire_prefix(
        meta.version,
        meta.message_type,
        meta.x3dh_header,
        &header.to_bytes(),
        payload_length,
    );
    let mut aad = Vec::with_capacity(session_ad.len() + wire_prefix.len());
    aad.extend_from_slice(session_ad);
    aad.extend_from_slice(&wire_prefix);

    let ciphertext = aead::encrypt(&keys.encryption_key, &nonce, plaintext, &aad)
        .map_err(|_| RatchetError::EncryptionFailed)?;

    // encrypted_payload = nonce(24) || ciphertext(ct || tag) (S07 §2).
    let mut encrypted_payload = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    encrypted_payload.extend_from_slice(&nonce);
    encrypted_payload.extend_from_slice(&ciphertext);

    state.cks = Some(*new_ck);
    state.ns = next_ns;
    Ok((header, encrypted_payload))
}
