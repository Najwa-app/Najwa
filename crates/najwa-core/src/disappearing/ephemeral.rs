//! Per-message ephemeral-key sealing for disappearing messages (S12 §4.1/§4.2).
//!
//! Each disappearing message's content is encrypted under a unique CSPRNG
//! ephemeral key held ONLY in [`VolatileKeyCache`] (volatile memory). Zeroising
//! that key (on expiry, §5.1) is the PRIMARY deletion defence: even if the
//! best-effort content overwrite fails on flash storage, the ciphertext is
//! irrecoverable once the key is gone.
//!
//! Wire format of a sealed content blob (S12 §4.1 step 3 / §4.2):
//! ```text
//! nonce(24) || XChaCha20Poly1305(ephemeral_key, nonce, plaintext, aad = msg_id)
//! ```
//! The 16-byte transport `msg_id` is the AEAD associated data, binding the
//! ciphertext to its message.
//!
//! These are the crypto primitives the store (send/receive) and read (display)
//! hooks call; the end-to-end flow is specified in S12 §4.

use najwa_crypto::prelude::*;

use super::error::{DisappearError, Result};
use super::volatile_cache::VolatileKeyCache;

/// XChaCha20-Poly1305 nonce length, prefixed to each sealed blob.
const NONCE_LEN: usize = 24;

/// Seal `plaintext` under a fresh per-message ephemeral key (S12 §4.1).
///
/// Generates the ephemeral key in `cache` keyed by `msg_id` (so a later
/// [`open_sealed_content`] / expiry-zeroise can find it), and returns
/// `nonce(24) || ciphertext||tag`. The caller stores the returned blob as the
/// message's at-rest content and, per §3/§4.1, leaves the volatile-key TTL and
/// `disappear_at` UNSET until the disappear trigger fires.
pub fn seal_content(
    cache: &VolatileKeyCache,
    msg_id: &[u8; 16],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let key = zeroize::Zeroizing::new(cache.generate_key(msg_id));
    let nonce: [u8; NONCE_LEN] = random_bytes();
    let ciphertext = aead::encrypt(&key, &nonce, plaintext, msg_id)
        .map_err(|e| DisappearError::CryptoError(e.to_string()))?;

    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Result of attempting to open a sealed disappearing-message blob.
#[derive(Debug)]
pub enum Opened {
    /// The ephemeral key was present and the content decrypted successfully.
    Plaintext(Vec<u8>),
    /// The ephemeral key is gone (message expired) — content is irrecoverable.
    /// The reader MUST surface an "expired" placeholder, never raw bytes.
    Expired,
}

/// Open a sealed content blob using the ephemeral key held in `cache` (S12 §4.2).
///
/// Returns [`Opened::Expired`] if the key is no longer in the cache (the primary
/// defence has fired). A malformed blob or a failed AEAD auth is a hard error —
/// a disappearing message whose key is still live but whose ciphertext does not
/// authenticate indicates corruption/tampering, not expiry.
pub fn open_sealed_content(
    cache: &VolatileKeyCache,
    msg_id: &[u8; 16],
    blob: &[u8],
) -> Result<Opened> {
    let key = match cache.get_key(msg_id) {
        Some(k) => zeroize::Zeroizing::new(k),
        None => return Ok(Opened::Expired),
    };
    if blob.len() < NONCE_LEN {
        return Err(DisappearError::CryptoError(
            "sealed content shorter than the nonce prefix".into(),
        ));
    }
    let (nonce_bytes, ciphertext) = blob.split_at(NONCE_LEN);
    let nonce: [u8; NONCE_LEN] = nonce_bytes
        .try_into()
        .expect("split_at guarantees NONCE_LEN bytes");
    let plaintext = aead::decrypt(&key, &nonce, ciphertext, msg_id)
        .map_err(|e| DisappearError::CryptoError(e.to_string()))?;
    Ok(Opened::Plaintext(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_round_trip() {
        let cache = VolatileKeyCache::new();
        let msg_id = [0x11u8; 16];
        let plaintext = b"disappearing secret";

        let blob = seal_content(&cache, &msg_id, plaintext).unwrap();
        // Blob is nonce(24) || ct||tag — never the plaintext in the clear.
        assert!(blob.len() >= NONCE_LEN + plaintext.len() + 16);
        assert!(!blob.windows(plaintext.len()).any(|w| w == plaintext));

        match open_sealed_content(&cache, &msg_id, &blob).unwrap() {
            Opened::Plaintext(p) => assert_eq!(p, plaintext),
            Opened::Expired => panic!("key is live — must decrypt"),
        }
    }

    #[test]
    fn each_message_gets_a_unique_key_and_nonce() {
        let cache = VolatileKeyCache::new();
        let a = seal_content(&cache, &[0x01; 16], b"x").unwrap();
        let b = seal_content(&cache, &[0x02; 16], b"x").unwrap();
        // Different keys + different nonces → different ciphertext for same text.
        assert_ne!(a, b);
        assert_ne!(cache.get_key(&[0x01; 16]), cache.get_key(&[0x02; 16]));
    }

    #[test]
    fn expired_key_yields_expired_not_plaintext() {
        let cache = VolatileKeyCache::new();
        let msg_id = [0x22u8; 16];
        let blob = seal_content(&cache, &msg_id, b"gone soon").unwrap();

        // Primary defence: zeroise + drop the key (as expiry does, §5.1).
        cache.remove_key(&msg_id);

        match open_sealed_content(&cache, &msg_id, &blob).unwrap() {
            Opened::Expired => {}
            Opened::Plaintext(_) => panic!("key was zeroised — content must be irrecoverable"),
        }
    }

    #[test]
    fn wrong_msg_id_aad_fails_auth() {
        // The msg_id is the AEAD AAD: decrypting a blob under a different key
        // slot (different msg_id) both misses the key and, even if the key were
        // present, would fail the AAD bind. Here the key is absent → Expired;
        // to exercise the AAD bind, reuse the same key under a mismatched id.
        let cache = VolatileKeyCache::new();
        let real_id = [0x33u8; 16];
        let blob = seal_content(&cache, &real_id, b"bound").unwrap();
        // Plant the SAME key under a different msg_id, then open with that id:
        // nonce/key match but the AAD (msg_id) differs → auth failure.
        let other_id = [0x44u8; 16];
        cache.insert_key(&other_id, cache.get_key(&real_id).unwrap());
        let err = open_sealed_content(&cache, &other_id, &blob);
        assert!(matches!(err, Err(DisappearError::CryptoError(_))));
    }

    #[test]
    fn tampered_ciphertext_fails_auth() {
        let cache = VolatileKeyCache::new();
        let msg_id = [0x55u8; 16];
        let mut blob = seal_content(&cache, &msg_id, b"integrity").unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0xFF; // flip a tag byte
        assert!(matches!(
            open_sealed_content(&cache, &msg_id, &blob),
            Err(DisappearError::CryptoError(_))
        ));
    }

    #[test]
    fn too_short_blob_is_rejected() {
        let cache = VolatileKeyCache::new();
        let msg_id = [0x66u8; 16];
        cache.generate_key(&msg_id); // key present so we reach the length check
        assert!(matches!(
            open_sealed_content(&cache, &msg_id, &[0u8; 10]),
            Err(DisappearError::CryptoError(_))
        ));
    }
}
