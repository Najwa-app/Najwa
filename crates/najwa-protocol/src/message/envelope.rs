//! Deposit envelope encryption and decryption (S07 §3).
//!
//! Before depositing ANY blob to a mailbox server, the entire WireMessage
//! is wrapped in an outer encryption layer. This makes all deposited blobs
//! — real messages and cover traffic — byte-for-byte indistinguishable
//! to the mailbox server.

use najwa_crypto::aead;
use najwa_crypto::kdf::hkdf_sha256;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::error::{MessageError, Result};

/// Salt used for envelope key derivation.
const ENVELOPE_SALT: &[u8] = b"najwa/v1/deposit-envelope";

/// Info string used for envelope key derivation.
const ENVELOPE_INFO: &[u8] = b"outer-key";

/// Size of the capability hint (truncated SHA-256).
pub const CAP_HINT_SIZE: usize = 8;

/// Overhead added by envelope encryption: 24-byte nonce + 16-byte tag.
pub const ENVELOPE_OVERHEAD: usize = aead::NONCE_SIZE + aead::TAG_SIZE;

/// Compute the capability hint for a deposit capability.
///
/// `cap_hint = SHA256(deposit_capability)[0:8]`
///
/// The server includes this in fetch responses so the client can
/// efficiently look up which deposit capability encrypted the envelope.
pub fn cap_hint(deposit_cap: &[u8; 32]) -> [u8; CAP_HINT_SIZE] {
    let hash = Sha256::digest(deposit_cap);
    let mut hint = [0u8; CAP_HINT_SIZE];
    hint.copy_from_slice(&hash[..CAP_HINT_SIZE]);
    hint
}

/// Derive the outer encryption key from the per-capability **envelope secret** (S07 §3.1).
///
/// `outer_key = HKDF(IKM=envelope_secret, salt="najwa/v1/deposit-envelope", info="outer-key", 32)`
///
/// The IKM is the `envelope_secret`, a 32-byte random secret minted by the
/// capability owner and shared only with parties it hands the deposit capability
/// to — NEVER sent to the server. The server stores the `deposit_capability` (it
/// routes by it), so keying the envelope from the deposit cap would let the
/// server decrypt every blob; keying from a server-unknown secret prevents that.
///
/// The key is wiped when the caller drops it (S01 §6.1).
fn derive_outer_key(envelope_secret: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
    let okm = hkdf_sha256(envelope_secret, ENVELOPE_SALT, ENVELOPE_INFO, 32)
        .map_err(|e| MessageError::InvalidHeader(format!("envelope key derivation: {e}")))?;
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&okm);
    Ok(key)
}

/// Encrypt a blob (WireMessage bytes or cover traffic) into a deposit envelope.
///
/// Returns `nonce(24) || ciphertext || tag(16)`.
///
/// - `envelope_secret` keys the encryption (S07 §3.1; the server never has it).
/// - `deposit_cap` supplies the routing `cap_hint` (carried in AAD); the server
///   knows it and routes by it, but cannot derive the key.
/// - For real messages: `inner_blob` = serialized WireMessage bytes.
/// - For cover traffic: `inner_blob` = `CSPRNG(bucket − ENVELOPE_OVERHEAD)`, so
///   the result is exactly one padding bucket (S07 §3.1).
pub fn envelope_encrypt(
    envelope_secret: &[u8; 32],
    deposit_cap: &[u8; 32],
    inner_blob: &[u8],
) -> Result<Vec<u8>> {
    let outer_key = derive_outer_key(envelope_secret)?;
    let aad = cap_hint(deposit_cap);

    let nonce: [u8; aead::NONCE_SIZE] = najwa_crypto::random::random_bytes();

    let ciphertext = aead::encrypt(&outer_key, &nonce, inner_blob, &aad)
        .map_err(|_| MessageError::InvalidHeader("envelope encryption failed".into()))?;

    let mut out = Vec::with_capacity(aead::NONCE_SIZE + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt a deposit envelope blob.
///
/// Input format: `nonce(24) || ciphertext || tag(16)`. `envelope_secret` keys the
/// decryption; `deposit_cap` recomputes the AAD `cap_hint`.
pub fn envelope_decrypt(
    envelope_secret: &[u8; 32],
    deposit_cap: &[u8; 32],
    blob: &[u8],
) -> Result<Vec<u8>> {
    if blob.len() < ENVELOPE_OVERHEAD {
        return Err(MessageError::TooShort);
    }

    let outer_key = derive_outer_key(envelope_secret)?;
    let aad = cap_hint(deposit_cap);

    let nonce: &[u8; aead::NONCE_SIZE] = blob[..aead::NONCE_SIZE]
        .try_into()
        .map_err(|_| MessageError::TooShort)?;
    let ciphertext = &blob[aead::NONCE_SIZE..];

    aead::decrypt(&outer_key, nonce, ciphertext, &aad)
        .map_err(|_| MessageError::InvalidHeader("envelope decryption failed".into()))
}

/// Try to decrypt an envelope blob by looking up the `(deposit_cap,
/// envelope_secret)` pair from a `cap_hint → (deposit_cap, envelope_secret)` map.
/// Falls back to trial decryption with all known pairs if the hint lookup fails.
/// Returns `(deposit_cap, inner_blob)` on success.
pub fn envelope_decrypt_with_hint(
    hint: &[u8; CAP_HINT_SIZE],
    blob: &[u8],
    cap_map: &std::collections::HashMap<[u8; CAP_HINT_SIZE], ([u8; 32], [u8; 32])>,
) -> Result<([u8; 32], Vec<u8>)> {
    // Fast path: O(1) lookup by cap_hint
    if let Some((dep_cap, env_secret)) = cap_map.get(hint) {
        if let Ok(inner) = envelope_decrypt(env_secret, dep_cap, blob) {
            return Ok((*dep_cap, inner));
        }
    }

    // Slow path: trial decryption with all known pairs
    for (dep_cap, env_secret) in cap_map.values() {
        if let Ok(inner) = envelope_decrypt(env_secret, dep_cap, blob) {
            return Ok((*dep_cap, inner));
        }
    }

    Err(MessageError::InvalidHeader(
        "envelope decryption failed for all known capabilities".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    // S01 §6.1: the derived outer key is wiped on drop. Fails to compile if
    // `derive_outer_key` goes back to returning a plain array.
    #[test]
    fn outer_key_is_zeroizing() {
        let _: Zeroizing<[u8; 32]> = derive_outer_key(&SECRET).unwrap();
    }

    #[test]
    fn cap_hint_deterministic() {
        let cap = [0x42u8; 32];
        let h1 = cap_hint(&cap);
        let h2 = cap_hint(&cap);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), CAP_HINT_SIZE);
    }

    #[test]
    fn cap_hint_different_caps_differ() {
        let cap_a = [0x01u8; 32];
        let cap_b = [0x02u8; 32];
        assert_ne!(cap_hint(&cap_a), cap_hint(&cap_b));
    }

    const SECRET: [u8; 32] = [0x5Eu8; 32];
    const DEP_CAP: [u8; 32] = [0xABu8; 32];

    #[test]
    fn envelope_roundtrip() {
        let inner = b"hello this is a wire message";
        let envelope = envelope_encrypt(&SECRET, &DEP_CAP, inner).unwrap();
        assert_eq!(envelope.len(), inner.len() + ENVELOPE_OVERHEAD);
        let decrypted = envelope_decrypt(&SECRET, &DEP_CAP, &envelope).unwrap();
        assert_eq!(decrypted, inner);
    }

    #[test]
    fn envelope_wrong_secret_fails() {
        let wrong = [0xCDu8; 32];
        let envelope = envelope_encrypt(&SECRET, &DEP_CAP, b"secret message").unwrap();
        assert!(envelope_decrypt(&wrong, &DEP_CAP, &envelope).is_err());
    }

    // S07 §3: a party holding only the deposit cap (the server) cannot decrypt.
    #[test]
    fn deposit_cap_holder_cannot_decrypt() {
        let envelope = envelope_encrypt(&SECRET, &DEP_CAP, b"server must not read").unwrap();
        assert!(envelope_decrypt(&DEP_CAP, &DEP_CAP, &envelope).is_err());
    }

    #[test]
    fn envelope_wrong_cap_hint_fails() {
        let envelope = envelope_encrypt(&SECRET, &DEP_CAP, b"secret message").unwrap();
        let wrong_cap = [0x11u8; 32];
        assert!(envelope_decrypt(&SECRET, &wrong_cap, &envelope).is_err());
    }

    #[test]
    fn envelope_tampered_fails() {
        let mut envelope = envelope_encrypt(&SECRET, &DEP_CAP, b"secret message").unwrap();
        let mid = envelope.len() / 2;
        envelope[mid] ^= 0xFF;
        assert!(envelope_decrypt(&SECRET, &DEP_CAP, &envelope).is_err());
    }

    #[test]
    fn envelope_too_short_fails() {
        assert!(envelope_decrypt(&SECRET, &DEP_CAP, &[0u8; 10]).is_err());
    }

    #[test]
    fn envelope_empty_inner_roundtrip() {
        let envelope = envelope_encrypt(&SECRET, &DEP_CAP, b"").unwrap();
        assert_eq!(envelope.len(), ENVELOPE_OVERHEAD);
        let decrypted = envelope_decrypt(&SECRET, &DEP_CAP, &envelope).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn envelope_decrypt_with_hint_fast_path() {
        let envelope = envelope_encrypt(&SECRET, &DEP_CAP, b"test message").unwrap();
        let hint = cap_hint(&DEP_CAP);
        let mut map = std::collections::HashMap::new();
        map.insert(hint, (DEP_CAP, SECRET));
        let (found_cap, decrypted) = envelope_decrypt_with_hint(&hint, &envelope, &map).unwrap();
        assert_eq!(found_cap, DEP_CAP);
        assert_eq!(decrypted, b"test message");
    }

    #[test]
    fn envelope_decrypt_with_hint_fallback() {
        let envelope = envelope_encrypt(&SECRET, &DEP_CAP, b"test message").unwrap();
        let wrong_hint = [0xFFu8; CAP_HINT_SIZE];
        let mut map = std::collections::HashMap::new();
        map.insert(wrong_hint, (DEP_CAP, SECRET));
        let real_hint = cap_hint(&DEP_CAP);
        let (found_cap, decrypted) =
            envelope_decrypt_with_hint(&real_hint, &envelope, &map).unwrap();
        assert_eq!(found_cap, DEP_CAP);
        assert_eq!(decrypted, b"test message");
    }

    #[test]
    fn envelope_decrypt_with_hint_all_fail() {
        let envelope = envelope_encrypt(&SECRET, &DEP_CAP, b"test message").unwrap();
        let wrong_cap = [0xCDu8; 32];
        let mut map = std::collections::HashMap::new();
        map.insert(cap_hint(&wrong_cap), (wrong_cap, [0xCEu8; 32]));
        let hint = cap_hint(&DEP_CAP);
        assert!(envelope_decrypt_with_hint(&hint, &envelope, &map).is_err());
    }

    #[test]
    fn cover_traffic_indistinguishable() {
        let real_inner = b"real wire message content here padding padding";
        let real_envelope = envelope_encrypt(&SECRET, &DEP_CAP, real_inner).unwrap();
        let cover_inner: Vec<u8> = (0..real_inner.len())
            .map(|i| (i as u8).wrapping_mul(37))
            .collect();
        let cover_envelope = envelope_encrypt(&SECRET, &DEP_CAP, &cover_inner).unwrap();
        assert_eq!(real_envelope.len(), cover_envelope.len());
        assert_ne!(real_envelope, cover_envelope);
    }
}
