//! SHA-256, HMAC-SHA256, and constant-time comparison.
//!
//! Implements the hash primitives used throughout the Najwa protocol
//! (S01 §3.6, §3.7, §7).

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Compute SHA-256 over `data`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute HMAC-SHA256 with `key` over `data`.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// Verify HMAC-SHA256 in **constant time**.
///
/// Returns `true` if the computed HMAC matches `expected`.
pub fn hmac_sha256_verify(key: &[u8], data: &[u8], expected: &[u8; 32]) -> bool {
    let computed = hmac_sha256(key, data);
    constant_time_eq(&computed, expected)
}

/// Constant-time byte-slice comparison.
///
/// Returns `true` iff `a` and `b` have the same length and contents.
/// Runs in time proportional to `a.len()`, independent of where the
/// first difference occurs.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_empty() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb924...
        let h = sha256(b"");
        assert_eq!(
            hex::encode(h),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_abc() {
        let h = sha256(b"abc");
        assert_eq!(
            hex::encode(h),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn hmac_sha256_rfc4231_test1() {
        // RFC 4231 Test Case 1
        let key = [0x0bu8; 20];
        let data = b"Hi There";
        let expected =
            hex::decode("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
                .unwrap();
        let mac = hmac_sha256(&key, data);
        assert_eq!(mac.as_slice(), expected.as_slice());
    }

    #[test]
    fn hmac_verify_correct() {
        let key = b"secret-key";
        let data = b"message";
        let mac = hmac_sha256(key, data);
        assert!(hmac_sha256_verify(key, data, &mac));
    }

    #[test]
    fn hmac_verify_wrong() {
        let key = b"secret-key";
        let data = b"message";
        let mut mac = hmac_sha256(key, data);
        mac[0] ^= 0xFF;
        assert!(!hmac_sha256_verify(key, data, &mac));
    }

    #[test]
    fn constant_time_eq_same() {
        assert!(constant_time_eq(b"hello", b"hello"));
    }

    #[test]
    fn constant_time_eq_different() {
        assert!(!constant_time_eq(b"hello", b"world"));
    }

    #[test]
    fn constant_time_eq_different_lengths() {
        assert!(!constant_time_eq(b"hello", b"hi"));
    }
}
