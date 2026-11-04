//! Relationship key derivation (§9.3).

use najwa_crypto::kdf::hkdf_sha256;
use najwa_crypto::keys::{
    ed25519_priv_to_x25519, ed25519_pub_to_x25519, Ed25519KeyPair, Ed25519Public, X25519KeyPair,
};

use super::derive::canonical_order_ed25519;
use super::error::{PseudonymError, Result};

/// Domain separation prefix for relationship key derivation (§9.3).
const RELATIONSHIP_KEY_INFO: &[u8] = b"NAJWA_RELATIONSHIP_KEY_v1";

/// Derive a shared relationship key for a contact pair (§9.3).
///
/// Used for additional per-relationship cryptographic operations
/// (e.g., group pseudonym derivation, shared secret for rendezvous).
/// Both parties independently derive the same key.
pub fn derive_relationship_key(
    my_ik: &Ed25519KeyPair,
    their_ik_pub: &Ed25519Public,
) -> Result<[u8; 32]> {
    // 1. Convert to X25519
    let my_x = ed25519_priv_to_x25519(my_ik.private());
    let their_x = ed25519_pub_to_x25519(their_ik_pub)
        .map_err(|e| PseudonymError::KeyConversionFailed(e.to_string()))?;

    // 2. ECDH
    let my_x_kp = X25519KeyPair::from_seed(my_x.to_bytes());
    let shared = my_x_kp.diffie_hellman(&their_x)?;

    // 3. Canonical ordering of Ed25519 public keys (deterministic for both parties)
    let my_pub_bytes = my_ik.public().to_bytes();
    let their_pub_bytes = their_ik_pub.to_bytes();
    let (a_pub, b_pub) = canonical_order_ed25519(&my_pub_bytes, &their_pub_bytes);

    // 4. Build deterministic info = prefix || A_pub || B_pub
    let mut info = Vec::with_capacity(RELATIONSHIP_KEY_INFO.len() + 64);
    info.extend_from_slice(RELATIONSHIP_KEY_INFO);
    info.extend_from_slice(&a_pub);
    info.extend_from_slice(&b_pub);

    let derived = hkdf_sha256(shared.as_bytes(), &[0u8; 32], &info, 32)
        .map_err(|e| PseudonymError::KeyDerivationFailed(e.to_string()))?;

    Ok(derived[..].try_into().expect("HKDF returned 32 bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_keypair(seed: u8) -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed(&[seed; 32])
    }

    #[test]
    fn both_parties_derive_same_relationship_key() {
        let alice = make_keypair(0x01);
        let bob = make_keypair(0x02);

        let key_ab = derive_relationship_key(&alice, bob.public()).unwrap();
        let key_ba = derive_relationship_key(&bob, alice.public()).unwrap();
        assert_eq!(key_ab, key_ba);
    }

    #[test]
    fn different_pairs_get_different_keys() {
        let alice = make_keypair(0x01);
        let bob = make_keypair(0x02);
        let carol = make_keypair(0x03);

        let key_ab = derive_relationship_key(&alice, bob.public()).unwrap();
        let key_ac = derive_relationship_key(&alice, carol.public()).unwrap();
        assert_ne!(key_ab, key_ac);
    }

    #[test]
    fn relationship_key_is_deterministic() {
        let alice = make_keypair(0x10);
        let bob = make_keypair(0x20);

        let key1 = derive_relationship_key(&alice, bob.public()).unwrap();
        let key2 = derive_relationship_key(&alice, bob.public()).unwrap();
        assert_eq!(key1, key2);
    }

    #[test]
    fn relationship_key_is_32_bytes() {
        let alice = make_keypair(0x01);
        let bob = make_keypair(0x02);
        let key = derive_relationship_key(&alice, bob.public()).unwrap();
        assert_eq!(key.len(), 32);
    }
}
