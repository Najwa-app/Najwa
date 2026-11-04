//! KDF chains for the Double Ratchet (S06 §3.3).

use najwa_crypto::hash::hmac_sha256;
use najwa_crypto::kdf::{hkdf_expand, hkdf_extract, hkdf_sha256, info_strings};
use zeroize::{Zeroize, Zeroizing};

use super::error::{RatchetError, Result};

/// Derived message keys for AEAD encryption (S06 §3.3).
pub struct MessageKeys {
    /// 32-byte encryption key (for XChaCha20-Poly1305).
    pub encryption_key: [u8; 32],
    /// 32-byte authentication key: derived as bytes 32..64 of the expansion
    /// (S01 §8.1) and not used; the message AAD does not include it.
    pub auth_key: [u8; 32],
    /// 16-byte IV (expanded to 24-byte nonce via `generate_nonce_from_iv`).
    pub iv: [u8; 16],
}

impl Drop for MessageKeys {
    fn drop(&mut self) {
        self.encryption_key.zeroize();
        self.auth_key.zeroize();
        self.iv.zeroize();
    }
}

/// Root key ratchet: `(new_rk, ck) = KDF_RK(rk, dh_out)` (S06 §3.3).
///
/// Uses HKDF-Extract(rk, dh_out) then HKDF-Expand(prk, info, 64) to
/// produce a new root key and a chain key.
pub fn kdf_rk(rk: &[u8; 32], dh_out: &[u8; 32]) -> Result<([u8; 32], [u8; 32])> {
    let prk = hkdf_extract(rk, dh_out);
    let output = Zeroizing::new(hkdf_expand(&prk, info_strings::RATCHET_INFO, 64)
        .map_err(|e| RatchetError::KeyDerivationFailed(e.to_string()))?);
    drop(prk);

    let mut new_rk = [0u8; 32];
    let mut ck = [0u8; 32];
    new_rk.copy_from_slice(&output[0..32]);
    ck.copy_from_slice(&output[32..64]);
    Ok((new_rk, ck))
}

/// Chain key ratchet: `(new_ck, mk) = KDF_CK(ck)` (S06 §3.3).
///
/// - Message key: `mk = HMAC-SHA256(ck, 0x01)`
/// - Next chain key: `new_ck = HMAC-SHA256(ck, 0x02)`
pub fn kdf_ck(ck: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mk = hmac_sha256(ck, &[0x01]);
    let new_ck = hmac_sha256(ck, &[0x02]);
    (new_ck, mk)
}

/// Derive encryption key, auth key, and IV from a message key (S06 §3.3).
///
/// Uses HKDF-SHA256 to expand the 32-byte message key to 80 bytes:
/// `encryption_key (32) || auth_key (32) || iv (16)`.
pub fn derive_message_keys(mk: &[u8; 32]) -> Result<MessageKeys> {
    let output = Zeroizing::new(hkdf_sha256(mk, &[0u8; 32], info_strings::MESSAGE_KEY_INFO, 80)
        .map_err(|e| RatchetError::KeyDerivationFailed(e.to_string()))?);

    let mut encryption_key = [0u8; 32];
    let mut auth_key = [0u8; 32];
    let mut iv = [0u8; 16];
    encryption_key.copy_from_slice(&output[0..32]);
    auth_key.copy_from_slice(&output[32..64]);
    iv.copy_from_slice(&output[64..80]);

    Ok(MessageKeys {
        encryption_key,
        auth_key,
        iv,
    })
}

/// Convert 16-byte IV to 24-byte nonce for XChaCha20-Poly1305 (S06 §3.3).
///
/// Pads with 8 zero bytes. This is safe because the IV is already
/// derived from HKDF and is unique per message key.
pub fn generate_nonce_from_iv(iv: &[u8; 16]) -> [u8; 24] {
    let mut nonce = [0u8; 24];
    nonce[..16].copy_from_slice(iv);
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kdf_rk_produces_different_keys() {
        let rk = [0x42u8; 32];
        let dh_out = [0x01u8; 32];
        let (new_rk, ck) = kdf_rk(&rk, &dh_out).unwrap();

        assert_ne!(new_rk, rk);
        assert_ne!(ck, rk);
        assert_ne!(new_rk, ck);
    }

    #[test]
    fn kdf_rk_deterministic() {
        let rk = [0x42u8; 32];
        let dh_out = [0x01u8; 32];
        let (rk1, ck1) = kdf_rk(&rk, &dh_out).unwrap();
        let (rk2, ck2) = kdf_rk(&rk, &dh_out).unwrap();
        assert_eq!(rk1, rk2);
        assert_eq!(ck1, ck2);
    }

    #[test]
    fn kdf_ck_produces_different_keys() {
        let ck = [0x42u8; 32];
        let (new_ck, mk) = kdf_ck(&ck);
        assert_ne!(new_ck, ck);
        assert_ne!(mk, ck);
        assert_ne!(new_ck, mk);
    }

    #[test]
    fn kdf_ck_deterministic() {
        let ck = [0x42u8; 32];
        let (ck1, mk1) = kdf_ck(&ck);
        let (ck2, mk2) = kdf_ck(&ck);
        assert_eq!(ck1, ck2);
        assert_eq!(mk1, mk2);
    }

    #[test]
    fn derive_message_keys_produces_80_bytes() {
        let mk = [0x42u8; 32];
        let keys = derive_message_keys(&mk).unwrap();
        assert_ne!(keys.encryption_key, [0u8; 32]);
        assert_ne!(keys.auth_key, [0u8; 32]);
        assert_ne!(keys.iv, [0u8; 16]);
        assert_ne!(keys.encryption_key, keys.auth_key);
    }

    #[test]
    fn generate_nonce_from_iv_pads_correctly() {
        let iv = [0xABu8; 16];
        let nonce = generate_nonce_from_iv(&iv);
        assert_eq!(nonce.len(), 24);
        assert_eq!(&nonce[..16], &iv);
        assert_eq!(&nonce[16..], &[0u8; 8]);
    }
}
