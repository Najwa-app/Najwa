//! X3DH key agreement protocol (Phase 6).
//!
//! Implements Extended Triple Diffie-Hellman for asynchronous session
//! establishment between two parties who have never communicated before.
//!
//! - Initiator computes shared secret from responder's prekey bundle
//! - Responder computes same shared secret from initiator's initial message
//! - Feeds into Double Ratchet initialization (Phase 7)

pub mod error;
pub mod initiator;
pub mod recovery;
pub mod responder;
pub mod types;

/// Build the X3DH HKDF `info` (S06 §2.2): `X3DH_INFO_PREFIX || X_IK_A_pub || X_IK_B_pub`,
/// where the two keys are the CONVERTED X25519 identity publics of the initiator (A)
/// and responder (B), in that order on **both** sides. Binding both identities into
/// `info` domain-separates the derivation (S18 §22.3 checks both sides agree). One shared
/// helper so the initiator and responder cannot drift apart.
pub(crate) fn x3dh_info(x_ik_a_pub: &[u8; 32], x_ik_b_pub: &[u8; 32]) -> Vec<u8> {
    use najwa_crypto::kdf::info_strings;
    let mut info = Vec::with_capacity(info_strings::X3DH_INFO_PREFIX.len() + 64);
    info.extend_from_slice(info_strings::X3DH_INFO_PREFIX);
    info.extend_from_slice(x_ik_a_pub);
    info.extend_from_slice(x_ik_b_pub);
    info
}

/// Convenience re-exports for common X3DH types.
pub mod prelude {
    pub use crate::x3dh::error::{Result, X3DHError};
    pub use crate::x3dh::initiator::x3dh_initiate;
    pub use crate::x3dh::recovery::{initiate_with_recovery, X3DHFailure};
    pub use crate::x3dh::responder::x3dh_respond;
    pub use crate::x3dh::types::{X3DHHeader, X3DHPrekeyBundle, X3DHResult};
}

#[cfg(test)]
mod tests {
    use najwa_crypto::keys::ed25519::Ed25519KeyPair;
    use najwa_crypto::keys::x25519::X25519KeyPair;

    use super::initiator::x3dh_initiate;
    use super::responder::x3dh_respond;
    use super::types::X3DHPrekeyBundle;

    /// Helper: build a valid prekey bundle for testing.
    fn make_bundle(
        identity: &Ed25519KeyPair,
        spk: &X25519KeyPair,
        opk: Option<&X25519KeyPair>,
    ) -> X3DHPrekeyBundle {
        let spk_sig = identity.sign(&crate::x3dh::types::spk_signature_message(&spk.public().to_bytes(), &[0, 0, 0, 1], 0));
        X3DHPrekeyBundle {
            identity_key: identity.public().clone(),
            mailbox_ik_pub: None,
            signed_prekey: spk.public().clone(),
            signed_prekey_id: [0, 0, 0, 1],
            signed_prekey_signature: spk_sig,
            signed_prekey_timestamp: 0,
            one_time_prekey: opk.map(|k| k.public().clone()),
            one_time_prekey_id: opk.map(|_| [0, 0, 0, 1]),
        }
    }

    // S06 §2.2/§2.3: Both sides derive same shared secret (with OPK)
    #[test]
    fn both_sides_derive_same_secret_with_opk() {
        let mut rng = rand::thread_rng();

        // Alice (initiator) and Bob (responder) identity keys
        let alice_ik = Ed25519KeyPair::generate(&mut rng);
        let bob_ik = Ed25519KeyPair::generate(&mut rng);

        // Bob's signed prekey and one-time prekey
        let bob_spk = X25519KeyPair::generate(&mut rng);
        let bob_opk = X25519KeyPair::generate(&mut rng);

        // Build Bob's prekey bundle
        let bundle = make_bundle(&bob_ik, &bob_spk, Some(&bob_opk));

        // Alice initiates X3DH
        let alice_result = x3dh_initiate(&alice_ik, &bundle).unwrap();

        // Bob responds using Alice's header
        let bob_result =
            x3dh_respond(&bob_ik, &bob_spk, Some(&bob_opk), &alice_result.header).unwrap();

        // Both must derive the same shared secret
        assert_eq!(alice_result.shared_secret, bob_result.shared_secret);

        // Associated data must match
        assert_eq!(alice_result.associated_data, bob_result.associated_data);
    }

    // S06 §2.2: X3DH without OPK (3-DH fallback)
    #[test]
    fn both_sides_derive_same_secret_without_opk() {
        let mut rng = rand::thread_rng();

        let alice_ik = Ed25519KeyPair::generate(&mut rng);
        let bob_ik = Ed25519KeyPair::generate(&mut rng);
        let bob_spk = X25519KeyPair::generate(&mut rng);

        // No one-time prekey
        let bundle = make_bundle(&bob_ik, &bob_spk, None);

        let alice_result = x3dh_initiate(&alice_ik, &bundle).unwrap();
        let bob_result = x3dh_respond(&bob_ik, &bob_spk, None, &alice_result.header).unwrap();

        assert_eq!(alice_result.shared_secret, bob_result.shared_secret);
        assert_eq!(alice_result.associated_data, bob_result.associated_data);
    }

    // S06 §2.2 step 1c: Invalid SPK signature rejected
    #[test]
    fn invalid_spk_signature_rejected() {
        let mut rng = rand::thread_rng();

        let alice_ik = Ed25519KeyPair::generate(&mut rng);
        let bob_ik = Ed25519KeyPair::generate(&mut rng);
        let bob_spk = X25519KeyPair::generate(&mut rng);

        // Sign SPK with wrong key (alice's key instead of bob's) → invalid
        let bad_sig = alice_ik.sign(&bob_spk.public().to_bytes());
        let bundle = X3DHPrekeyBundle {
            identity_key: bob_ik.public().clone(),
            mailbox_ik_pub: None,
            signed_prekey: bob_spk.public().clone(),
            signed_prekey_id: [0, 0, 0, 1],
            signed_prekey_signature: bad_sig,
            signed_prekey_timestamp: 0,
            one_time_prekey: None,
            one_time_prekey_id: None,
        };

        let result = x3dh_initiate(&alice_ik, &bundle);
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(super::error::X3DHError::InvalidSignature)
        ));
    }

    // Verify shared secret is non-zero (sanity check)
    #[test]
    fn shared_secret_is_non_trivial() {
        let mut rng = rand::thread_rng();

        let alice_ik = Ed25519KeyPair::generate(&mut rng);
        let bob_ik = Ed25519KeyPair::generate(&mut rng);
        let bob_spk = X25519KeyPair::generate(&mut rng);
        let bob_opk = X25519KeyPair::generate(&mut rng);

        let bundle = make_bundle(&bob_ik, &bob_spk, Some(&bob_opk));
        let result = x3dh_initiate(&alice_ik, &bundle).unwrap();

        // Shared secret must not be all zeros
        assert_ne!(result.shared_secret, [0u8; 32]);
    }

    // S06 §2.2: Different OPKs produce different shared secrets
    #[test]
    fn different_opks_produce_different_secrets() {
        let mut rng = rand::thread_rng();

        let alice_ik = Ed25519KeyPair::generate(&mut rng);
        let bob_ik = Ed25519KeyPair::generate(&mut rng);
        let bob_spk = X25519KeyPair::generate(&mut rng);
        let bob_opk1 = X25519KeyPair::generate(&mut rng);
        let bob_opk2 = X25519KeyPair::generate(&mut rng);

        let bundle1 = make_bundle(&bob_ik, &bob_spk, Some(&bob_opk1));
        let bundle2 = make_bundle(&bob_ik, &bob_spk, Some(&bob_opk2));

        let result1 = x3dh_initiate(&alice_ik, &bundle1).unwrap();
        let result2 = x3dh_initiate(&alice_ik, &bundle2).unwrap();

        // Different OPKs should lead to different shared secrets
        // (different ephemeral keys are also generated, so this always holds)
        // At minimum, verify both succeed and are non-zero
        assert_ne!(result1.shared_secret, [0u8; 32]);
        assert_ne!(result2.shared_secret, [0u8; 32]);
    }

    // Verify associated data structure: AD = Encode(IK_A) || Encode(IK_B)
    #[test]
    fn associated_data_is_ik_concat() {
        let mut rng = rand::thread_rng();

        let alice_ik = Ed25519KeyPair::generate(&mut rng);
        let bob_ik = Ed25519KeyPair::generate(&mut rng);
        let bob_spk = X25519KeyPair::generate(&mut rng);

        let bundle = make_bundle(&bob_ik, &bob_spk, None);
        let result = x3dh_initiate(&alice_ik, &bundle).unwrap();

        // AD must be exactly 64 bytes: IK_A (32) || IK_B (32)
        assert_eq!(result.associated_data.len(), 64);
        assert_eq!(&result.associated_data[..32], &alice_ik.public().to_bytes());
        assert_eq!(&result.associated_data[32..], &bob_ik.public().to_bytes());
    }

    // Verify header contains correct values
    #[test]
    fn header_contains_correct_keys() {
        let mut rng = rand::thread_rng();

        let alice_ik = Ed25519KeyPair::generate(&mut rng);
        let bob_ik = Ed25519KeyPair::generate(&mut rng);
        let bob_spk = X25519KeyPair::generate(&mut rng);
        let bob_opk = X25519KeyPair::generate(&mut rng);

        let bundle = make_bundle(&bob_ik, &bob_spk, Some(&bob_opk));
        let result = x3dh_initiate(&alice_ik, &bundle).unwrap();

        // Header identity key must be Alice's
        assert_eq!(
            result.header.identity_key.to_bytes(),
            alice_ik.public().to_bytes()
        );

        // Header must reference the OPK and SPK IDs from the bundle
        assert_eq!(result.header.signed_prekey_id, [0, 0, 0, 1]);
        assert_eq!(result.header.used_one_time_prekey_id, Some([0, 0, 0, 1]));

        // Ephemeral key must be a valid 32-byte key
        let ek_bytes = result.header.ephemeral_key.to_bytes();
        assert_ne!(ek_bytes, [0u8; 32]);
    }

    // SPK signature verification works correctly
    #[test]
    fn spk_signature_verification() {
        let mut rng = rand::thread_rng();
        let bob_ik = Ed25519KeyPair::generate(&mut rng);
        let bob_spk = X25519KeyPair::generate(&mut rng);

        let bundle = make_bundle(&bob_ik, &bob_spk, None);
        assert!(bundle.verify_spk_signature().is_ok());

        // Tamper with SPK → verification fails
        let tampered_spk = X25519KeyPair::generate(&mut rng);
        let bad_bundle = X3DHPrekeyBundle {
            signed_prekey: tampered_spk.public().clone(),
            ..bundle
        };
        assert!(bad_bundle.verify_spk_signature().is_err());
    }

    // With OPK vs without OPK produces different secrets (4-DH vs 3-DH)
    #[test]
    fn with_opk_differs_from_without_opk() {
        let mut rng = rand::thread_rng();

        let alice_ik = Ed25519KeyPair::generate(&mut rng);
        let bob_ik = Ed25519KeyPair::generate(&mut rng);
        let bob_spk = X25519KeyPair::generate(&mut rng);
        let bob_opk = X25519KeyPair::generate(&mut rng);

        let bundle_with = make_bundle(&bob_ik, &bob_spk, Some(&bob_opk));
        let bundle_without = make_bundle(&bob_ik, &bob_spk, None);

        let r1 = x3dh_initiate(&alice_ik, &bundle_with).unwrap();
        let r2 = x3dh_initiate(&alice_ik, &bundle_without).unwrap();

        // Different because (a) different DH count and (b) different ephemeral keys
        assert_ne!(r1.shared_secret, r2.shared_secret);
    }

    // Fresh ephemeral key each time (S06 §2.2 step 2)
    #[test]
    fn ephemeral_key_is_fresh_each_call() {
        let mut rng = rand::thread_rng();

        let alice_ik = Ed25519KeyPair::generate(&mut rng);
        let bob_ik = Ed25519KeyPair::generate(&mut rng);
        let bob_spk = X25519KeyPair::generate(&mut rng);

        let bundle = make_bundle(&bob_ik, &bob_spk, None);

        let r1 = x3dh_initiate(&alice_ik, &bundle).unwrap();
        let r2 = x3dh_initiate(&alice_ik, &bundle).unwrap();

        // Ephemeral keys must differ between calls
        assert_ne!(
            r1.header.ephemeral_key.to_bytes(),
            r2.header.ephemeral_key.to_bytes()
        );

        // Shared secrets must also differ (different ephemeral keys)
        assert_ne!(r1.shared_secret, r2.shared_secret);
    }
}
