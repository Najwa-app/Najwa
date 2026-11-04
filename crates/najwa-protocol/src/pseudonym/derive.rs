//! Pairwise pseudonym derivation (§9.2).

use najwa_crypto::hash::constant_time_eq;
use najwa_crypto::kdf::{hkdf_sha256, info_strings};
use najwa_crypto::keys::{
    ed25519_priv_to_x25519, ed25519_pub_to_x25519, Ed25519KeyPair, Ed25519Public,
};

use super::error::{PseudonymError, Result};
use super::types::Pseudonym;

/// Derive a pairwise pseudonym pair from two identity keys (§9.2).
///
/// Both parties independently derive the SAME pair. The canonical ordering
/// ensures that regardless of who calls this function, the result is identical.
///
/// Returns `(my_pseudonym, their_pseudonym)`.
pub fn derive_pairwise_pseudonyms(
    my_ik: &Ed25519KeyPair,
    their_ik_pub: &Ed25519Public,
) -> Result<(Pseudonym, Pseudonym)> {
    // 1. Convert to X25519 for ECDH
    let my_x = ed25519_priv_to_x25519(my_ik.private());
    let their_x = ed25519_pub_to_x25519(their_ik_pub)
        .map_err(|e| PseudonymError::KeyConversionFailed(e.to_string()))?;

    // 2. ECDH shared secret
    let my_x_kp = najwa_crypto::keys::X25519KeyPair::from_seed(my_x.to_bytes());
    let shared = my_x_kp.diffie_hellman(&their_x)?;

    // 3. Canonical ordering (S01 §8.2, S18 §11): the party whose Ed25519 pubkey
    //    sorts lower (unsigned bytewise) is the "initiator", the other the
    //    "responder". salt = sorted_keys = lower || higher (64 bytes).
    let my_pub_bytes = my_ik.public().to_bytes();
    let their_pub_bytes = their_ik_pub.to_bytes();
    let (lower, higher) = canonical_order_ed25519(&my_pub_bytes, &their_pub_bytes);
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(&lower);
    salt[32..].copy_from_slice(&higher);

    // 4. Derive both role pseudonyms. info = "najwa/v1/pairwise-pseudonym/" ||
    //    role_word; the ordered key material is the salt, NOT the info.
    let derive = |role: &[u8]| -> Result<Pseudonym> {
        let mut info = Vec::with_capacity(info_strings::PSEUDONYM_INFO.len() + role.len());
        info.extend_from_slice(info_strings::PSEUDONYM_INFO);
        info.extend_from_slice(role);
        let bytes = hkdf_sha256(shared.as_bytes(), &salt, &info, 32)
            .map_err(|e| PseudonymError::KeyDerivationFailed(e.to_string()))?;
        Ok(Pseudonym(
            bytes[..].try_into().expect("HKDF returned 32 bytes"),
        ))
    };
    let pseudo_initiator = derive(b"initiator")?;
    let pseudo_responder = derive(b"responder")?;

    // 5. I am the initiator iff my Ed25519 pubkey is the lower one.
    let i_am_initiator = my_pub_bytes < their_pub_bytes;
    let (my_pseudo, their_pseudo) = if i_am_initiator {
        (pseudo_initiator, pseudo_responder)
    } else {
        (pseudo_responder, pseudo_initiator)
    };

    Ok((my_pseudo, their_pseudo))
}

/// Canonical ordering of two Ed25519 public keys (§9.2).
///
/// Returns (lower, higher) by byte comparison.
pub fn canonical_order_ed25519(a: &[u8; 32], b: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    if a < b {
        (*a, *b)
    } else {
        (*b, *a)
    }
}

/// Check if two pseudonyms are equal in constant time.
pub fn pseudonyms_equal(a: &Pseudonym, b: &Pseudonym) -> bool {
    constant_time_eq(&a.0, &b.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_keypair(seed: u8) -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed(&[seed; 32])
    }

    #[test]
    fn both_parties_derive_same_pseudonyms() {
        let alice = make_keypair(0x01);
        let bob = make_keypair(0x02);

        let (alice_my, alice_their) = derive_pairwise_pseudonyms(&alice, bob.public()).unwrap();
        let (bob_my, bob_their) = derive_pairwise_pseudonyms(&bob, alice.public()).unwrap();

        // Alice's "my" == Bob's "their" and vice versa
        assert_eq!(alice_my, bob_their);
        assert_eq!(alice_their, bob_my);
    }

    #[test]
    fn different_contacts_get_different_pseudonyms() {
        let alice = make_keypair(0x01);
        let bob = make_keypair(0x02);
        let carol = make_keypair(0x03);

        let (alice_bob_my, _) = derive_pairwise_pseudonyms(&alice, bob.public()).unwrap();
        let (alice_carol_my, _) = derive_pairwise_pseudonyms(&alice, carol.public()).unwrap();

        assert_ne!(alice_bob_my, alice_carol_my);
    }

    #[test]
    fn pseudonyms_are_32_bytes() {
        let alice = make_keypair(0x01);
        let bob = make_keypair(0x02);

        let (my, their) = derive_pairwise_pseudonyms(&alice, bob.public()).unwrap();
        assert_eq!(my.0.len(), 32);
        assert_eq!(their.0.len(), 32);
    }

    #[test]
    fn canonical_order_is_deterministic() {
        let a = [0x01; 32];
        let b = [0x02; 32];
        assert_eq!(
            canonical_order_ed25519(&a, &b),
            canonical_order_ed25519(&b, &a)
        );
    }

    #[test]
    fn pseudonyms_deterministic_across_calls() {
        let alice = make_keypair(0x10);
        let bob = make_keypair(0x20);

        let (my1, their1) = derive_pairwise_pseudonyms(&alice, bob.public()).unwrap();
        let (my2, their2) = derive_pairwise_pseudonyms(&alice, bob.public()).unwrap();
        assert_eq!(my1, my2);
        assert_eq!(their1, their2);
    }

    #[test]
    fn constant_time_eq_works() {
        let a = Pseudonym([0xAA; 32]);
        let b = Pseudonym([0xAA; 32]);
        let c = Pseudonym([0xBB; 32]);
        assert!(pseudonyms_equal(&a, &b));
        assert!(!pseudonyms_equal(&a, &c));
    }

    // S01 §8.2 / S18 §18: the composite info MUST be exactly the registry string
    // `najwa/v1/pairwise-pseudonym/{initiator,responder}` (37 bytes) — no
    // appended key material, no missing trailing slash, role as an ASCII word.
    #[test]
    fn info_string_matches_registry() {
        let initiator = [info_strings::PSEUDONYM_INFO, b"initiator"].concat();
        let responder = [info_strings::PSEUDONYM_INFO, b"responder"].concat();
        assert_eq!(initiator, b"najwa/v1/pairwise-pseudonym/initiator");
        assert_eq!(responder, b"najwa/v1/pairwise-pseudonym/responder");
        assert_eq!(initiator.len(), 37);
    }

    // S18 §11.2 reference pin for a deterministic seed pair. Locks
    // info/salt/role/ordering: a change to any of them changes these bytes.
    #[test]
    fn pinned_vector() {
        let to_hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let a = Ed25519KeyPair::from_seed(&[0x11; 32]);
        let b = Ed25519KeyPair::from_seed(&[0x22; 32]);
        let (a_my, a_their) = derive_pairwise_pseudonyms(&a, b.public()).unwrap();
        // a_my is the pseudonym under the role matching a's canonical position.
        assert_eq!(to_hex(&a_my.0), PINNED_A_MY);
        assert_eq!(to_hex(&a_their.0), PINNED_A_THEIR);
    }

    // Filled from the corrected implementation (see pinned_vector).
    const PINNED_A_MY: &str = "7d8b8b7344272aa526a854f0449f1aed21d9ef754da695ad11f7063c784d7512";
    const PINNED_A_THEIR: &str = "897ee97c376027909937966837269c17fd261a54f9918fbfda41bee0bc63d061";
}
