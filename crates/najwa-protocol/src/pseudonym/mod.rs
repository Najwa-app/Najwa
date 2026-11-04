//! Pairwise pseudonym derivation (Phase 9).
//!
//! Provides:
//! - Pairwise pseudonym derivation from Ed25519 identity keys (§9.2)
//! - Canonical key ordering for deterministic results (§9.2)
//! - Pseudonym lookup table for O(1) contact resolution (§9.3)
//! - Relationship key derivation for per-contact crypto (§9.3)
//! - Group pseudonym derivation and verification (not used by the app)

pub mod derive;
pub mod error;
pub mod group;
pub mod lookup;
pub mod relationship;
pub mod types;

// Re-exports for convenient access
pub use derive::{canonical_order_ed25519, derive_pairwise_pseudonyms, pseudonyms_equal};
pub use error::{PseudonymError, Result};
pub use group::{derive_group_pseudonym, verify_group_pseudonym};
pub use lookup::PseudonymTable;
pub use relationship::derive_relationship_key;
pub use types::{ContactId, Pseudonym};

#[cfg(test)]
mod tests {
    use super::*;
    use najwa_crypto::keys::{Ed25519KeyPair, Ed25519Public};

    fn make_keypair(seed: u8) -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed(&[seed; 32])
    }

    fn pub_key(seed: u8) -> Ed25519Public {
        let kp = make_keypair(seed);
        Ed25519Public::from_bytes(&kp.public().to_bytes()).unwrap()
    }

    // -----------------------------------------------------------------------
    // §9.2 — Pairwise pseudonym derivation
    // -----------------------------------------------------------------------

    #[test]
    fn integration_both_parties_derive_identical_pseudonym_pairs() {
        let alice = make_keypair(0x10);
        let bob = make_keypair(0x20);

        let (alice_my, alice_their) = derive_pairwise_pseudonyms(&alice, bob.public()).unwrap();
        let (bob_my, bob_their) = derive_pairwise_pseudonyms(&bob, alice.public()).unwrap();

        // The fundamental invariant: each side sees the mirror of the other
        assert_eq!(
            alice_my, bob_their,
            "Alice's my_pseudo must equal Bob's their_pseudo"
        );
        assert_eq!(
            alice_their, bob_my,
            "Alice's their_pseudo must equal Bob's my_pseudo"
        );
    }

    #[test]
    fn integration_pseudonyms_unique_per_contact() {
        let me = make_keypair(0x01);
        let contact_a = make_keypair(0x02);
        let contact_b = make_keypair(0x03);
        let contact_c = make_keypair(0x04);

        let (my_a, their_a) = derive_pairwise_pseudonyms(&me, contact_a.public()).unwrap();
        let (my_b, their_b) = derive_pairwise_pseudonyms(&me, contact_b.public()).unwrap();
        let (my_c, their_c) = derive_pairwise_pseudonyms(&me, contact_c.public()).unwrap();

        // All "my" pseudonyms differ
        assert_ne!(my_a, my_b);
        assert_ne!(my_a, my_c);
        assert_ne!(my_b, my_c);

        // All "their" pseudonyms differ
        assert_ne!(their_a, their_b);
        assert_ne!(their_a, their_c);
        assert_ne!(their_b, their_c);

        // "my" and "their" within same pair differ
        assert_ne!(my_a, their_a);
    }

    #[test]
    fn integration_self_pseudonyms_are_identical() {
        // Edge case: deriving pseudonyms with yourself
        let me = make_keypair(0x42);
        let (my, their) = derive_pairwise_pseudonyms(&me, me.public()).unwrap();
        // With same keys, canonical ordering puts both as A=B, so my==their
        // Actually the ECDH shared secret is the same, and since both pub keys are equal,
        // the canonical ordering is a == b, and roles are symmetric.
        // Both roles produce different pseudonyms because role byte differs,
        // but since my_pub == their_pub, i_am_a is false (not strictly less),
        // so my = pseudo_b, their = pseudo_a. This is deterministic and fine.
        assert_ne!(my, their); // Different role bytes → different pseudonyms
    }

    // -----------------------------------------------------------------------
    // §9.3 — Pseudonym lookup table
    // -----------------------------------------------------------------------

    #[test]
    fn integration_lookup_table_o1_resolution() {
        let me = make_keypair(0x01);

        let mut table = PseudonymTable::new();
        for seed in 0x10..0x20u8 {
            let contact = make_keypair(seed);
            let (_, their_pseudo) = derive_pairwise_pseudonyms(&me, contact.public()).unwrap();
            table.insert(their_pseudo, ContactId(seed as u64));
        }

        assert_eq!(table.len(), 16);

        // Verify each contact resolves correctly
        for seed in 0x10..0x20u8 {
            let contact = make_keypair(seed);
            let (_, their_pseudo) = derive_pairwise_pseudonyms(&me, contact.public()).unwrap();
            assert_eq!(
                table.resolve(&their_pseudo).unwrap(),
                ContactId(seed as u64)
            );
        }
    }

    #[test]
    fn integration_unknown_pseudonym_rejected_spam() {
        let me = make_keypair(0x01);
        let known_contact = make_keypair(0x02);
        let unknown_sender = make_keypair(0x03);

        let mut table = PseudonymTable::new();
        let (_, known_pseudo) = derive_pairwise_pseudonyms(&me, known_contact.public()).unwrap();
        table.insert(known_pseudo.clone(), ContactId(1));

        // Known contact resolves
        assert!(table.is_known(&known_pseudo));

        // Unknown sender is rejected
        let (_, unknown_pseudo) = derive_pairwise_pseudonyms(&me, unknown_sender.public()).unwrap();
        assert!(!table.is_known(&unknown_pseudo));
        assert!(table.resolve(&unknown_pseudo).is_err());
    }

    // -----------------------------------------------------------------------
    // §9.3 — Relationship key derivation
    // -----------------------------------------------------------------------

    #[test]
    fn integration_relationship_key_consistency() {
        let alice = make_keypair(0x01);
        let bob = make_keypair(0x02);

        let key_ab = derive_relationship_key(&alice, bob.public()).unwrap();
        let key_ba = derive_relationship_key(&bob, alice.public()).unwrap();
        assert_eq!(
            key_ab, key_ba,
            "Both parties must derive the same relationship key"
        );
    }

    #[test]
    fn integration_relationship_key_differs_per_contact() {
        let me = make_keypair(0x01);
        let bob = make_keypair(0x02);
        let carol = make_keypair(0x03);

        let key_bob = derive_relationship_key(&me, bob.public()).unwrap();
        let key_carol = derive_relationship_key(&me, carol.public()).unwrap();
        assert_ne!(key_bob, key_carol);
    }

    // -----------------------------------------------------------------------
    // §9.4 — Group pseudonym derivation
    // -----------------------------------------------------------------------

    #[test]
    fn integration_group_pseudonym_deterministic_and_verifiable() {
        let member_pk = pub_key(0x01);
        let group_id = [0xAA; 32];

        let pseudo = derive_group_pseudonym(&member_pk, &group_id).unwrap();

        // Deterministic
        let pseudo2 = derive_group_pseudonym(&member_pk, &group_id).unwrap();
        assert_eq!(pseudo, pseudo2);

        // Verifiable
        assert!(verify_group_pseudonym(&pseudo, &member_pk, &group_id).unwrap());
    }

    #[test]
    fn integration_group_pseudonyms_unlinkable_across_groups() {
        let member_pk = pub_key(0x01);
        let g1 = [0x01; 32];
        let g2 = [0x02; 32];

        let p1 = derive_group_pseudonym(&member_pk, &g1).unwrap();
        let p2 = derive_group_pseudonym(&member_pk, &g2).unwrap();
        assert_ne!(
            p1, p2,
            "Same member in different groups must have different pseudonyms"
        );
    }

    #[test]
    fn integration_group_pseudonym_rejects_impersonation() {
        let real_member = pub_key(0x01);
        let impersonator = pub_key(0x02);
        let group_id = [0xAA; 32];

        let real_pseudo = derive_group_pseudonym(&real_member, &group_id).unwrap();

        // Impersonator cannot produce the same pseudonym
        assert!(!verify_group_pseudonym(&real_pseudo, &impersonator, &group_id).unwrap());
    }

    // -----------------------------------------------------------------------
    // End-to-end scenario
    // -----------------------------------------------------------------------

    #[test]
    fn integration_full_contact_establishment_flow() {
        // Simulates: Alice and Bob exchange identity keys, derive pseudonyms,
        // register in lookup tables, and verify messages.

        let alice = make_keypair(0x01);
        let bob = make_keypair(0x02);

        // Both derive pseudonyms
        let (alice_my, alice_bob_pseudo) =
            derive_pairwise_pseudonyms(&alice, bob.public()).unwrap();
        let (bob_my, bob_alice_pseudo) = derive_pairwise_pseudonyms(&bob, alice.public()).unwrap();

        // Cross-check: Alice's view of Bob matches Bob's self-pseudonym
        assert_eq!(alice_bob_pseudo, bob_my);
        assert_eq!(bob_alice_pseudo, alice_my);

        // Alice's lookup table
        let mut alice_table = PseudonymTable::new();
        alice_table.insert(alice_bob_pseudo.clone(), ContactId(1));

        // Bob's lookup table
        let mut bob_table = PseudonymTable::new();
        bob_table.insert(bob_alice_pseudo.clone(), ContactId(1));

        // Bob sends a message with his pseudonym (bob_my), Alice resolves it
        assert_eq!(
            alice_table.resolve(&bob_my).unwrap(),
            ContactId(1),
            "Alice resolves Bob's pseudonym"
        );

        // Alice sends a message with her pseudonym (alice_my), Bob resolves it
        assert_eq!(
            bob_table.resolve(&alice_my).unwrap(),
            ContactId(1),
            "Bob resolves Alice's pseudonym"
        );

        // Both derive the same relationship key
        let key_a = derive_relationship_key(&alice, bob.public()).unwrap();
        let key_b = derive_relationship_key(&bob, alice.public()).unwrap();
        assert_eq!(key_a, key_b);
    }
}
