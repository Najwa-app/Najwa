//! XChaCha20-Poly1305 AEAD encryption and decryption.
//!
//! Implements the authenticated encryption primitive used throughout
//! the Najwa protocol (S01 §3.4).

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::XChaCha20Poly1305;
use rand_core::CryptoRngCore;

use crate::error::{CryptoError, Result};

/// Key size in bytes (256 bits).
pub const KEY_SIZE: usize = 32;

/// Nonce size in bytes (192 bits — extended nonce).
pub const NONCE_SIZE: usize = 24;

/// Authentication tag size in bytes (128 bits).
pub const TAG_SIZE: usize = 16;

/// Encrypt `plaintext` with XChaCha20-Poly1305.
///
/// Returns `nonce || ciphertext || tag` (24 + plaintext.len() + 16 bytes).
///
/// # Arguments
///
/// * `key` - 32-byte encryption key.
/// * `nonce` - 24-byte nonce (**MUST** be unique per key).
/// * `plaintext` - Data to encrypt.
/// * `aad` - Additional authenticated data (not encrypted, but authenticated).
///
/// # Errors
///
/// Returns [`CryptoError::InvalidKeyLength`] if `key` is not 32 bytes.
pub fn encrypt(
    key: &[u8; KEY_SIZE],
    nonce: &[u8; NONCE_SIZE],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher =
        XChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::InvalidKeyLength {
            expected: KEY_SIZE,
            got: key.len(),
        })?;

    let xnonce = chacha20poly1305::XNonce::from_slice(nonce);
    cipher
        .encrypt(
            xnonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::EncryptionFailed)
}

/// Decrypt `ciphertext` with XChaCha20-Poly1305.
///
/// # Arguments
///
/// * `key` - 32-byte encryption key.
/// * `nonce` - 24-byte nonce used during encryption.
/// * `ciphertext` - Ciphertext **with** appended 16-byte tag.
/// * `aad` - Additional authenticated data used during encryption.
///
/// # Errors
///
/// Returns [`CryptoError::DecryptionFailed`] if authentication fails.
pub fn decrypt(
    key: &[u8; KEY_SIZE],
    nonce: &[u8; NONCE_SIZE],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher =
        XChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::InvalidKeyLength {
            expected: KEY_SIZE,
            got: key.len(),
        })?;

    let xnonce = chacha20poly1305::XNonce::from_slice(nonce);
    cipher
        .decrypt(
            xnonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::DecryptionFailed)
}

/// Generate a random 24-byte nonce suitable for XChaCha20-Poly1305.
pub fn generate_nonce<R: CryptoRngCore>(rng: &mut R) -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    rng.fill_bytes(&mut nonce);
    nonce
}

/// Encrypt and prepend nonce: returns `nonce(24) || ciphertext || tag(16)` (S01 §3.4).
///
/// Convenience wrapper that generates a random nonce and prepends it to the output.
/// This is the canonical wire format for all Najwa AEAD operations.
pub fn encrypt_with_prepended_nonce(
    key: &[u8; KEY_SIZE],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let nonce: [u8; NONCE_SIZE] = crate::random::random_bytes();
    let ct = encrypt(key, &nonce, plaintext, aad)?;
    let mut out = Vec::with_capacity(NONCE_SIZE + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt a blob with prepended nonce: input = `nonce(24) || ciphertext || tag(16)`.
///
/// Inverse of [`encrypt_with_prepended_nonce`].
pub fn decrypt_with_prepended_nonce(
    key: &[u8; KEY_SIZE],
    blob: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    if blob.len() < NONCE_SIZE + TAG_SIZE {
        return Err(CryptoError::DecryptionFailed);
    }
    let nonce: &[u8; NONCE_SIZE] = blob[..NONCE_SIZE]
        .try_into()
        .map_err(|_| CryptoError::DecryptionFailed)?;
    decrypt(key, nonce, &blob[NONCE_SIZE..], aad)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = [0x42u8; KEY_SIZE];
        let nonce = [0x01u8; NONCE_SIZE];
        let plaintext = b"hello najwa protocol";
        let aad = b"header";

        let ct = encrypt(&key, &nonce, plaintext, aad).unwrap();
        let pt = decrypt(&key, &nonce, &ct, aad).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn wrong_key_fails() {
        let key = [0x42u8; KEY_SIZE];
        let nonce = [0x01u8; NONCE_SIZE];
        let ct = encrypt(&key, &nonce, b"secret", b"").unwrap();

        let wrong_key = [0xFFu8; KEY_SIZE];
        assert!(decrypt(&wrong_key, &nonce, &ct, b"").is_err());
    }

    #[test]
    fn wrong_aad_fails() {
        let key = [0x42u8; KEY_SIZE];
        let nonce = [0x01u8; NONCE_SIZE];
        let ct = encrypt(&key, &nonce, b"secret", b"correct-aad").unwrap();
        assert!(decrypt(&key, &nonce, &ct, b"wrong-aad").is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = [0x42u8; KEY_SIZE];
        let nonce = [0x01u8; NONCE_SIZE];
        let mut ct = encrypt(&key, &nonce, b"secret", b"").unwrap();
        ct[0] ^= 0xFF; // flip a byte
        assert!(decrypt(&key, &nonce, &ct, b"").is_err());
    }

    #[test]
    fn empty_plaintext_works() {
        let key = [0x42u8; KEY_SIZE];
        let nonce = [0x01u8; NONCE_SIZE];
        let ct = encrypt(&key, &nonce, b"", b"").unwrap();
        assert_eq!(ct.len(), TAG_SIZE); // only the tag
        let pt = decrypt(&key, &nonce, &ct, b"").unwrap();
        assert!(pt.is_empty());
    }

    #[test]
    fn generate_nonce_unique() {
        let mut rng = rand::thread_rng();
        let n1 = generate_nonce(&mut rng);
        let n2 = generate_nonce(&mut rng);
        assert_ne!(n1, n2);
    }
}
