//! X3DH error recovery and high-level initiation. Library code; no app path
//! calls it.

use super::error::{Result, X3DHError};
use super::initiator::x3dh_initiate;
use super::types::{X3DHPrekeyBundle, X3DHResult};
use najwa_crypto::keys::ed25519::Ed25519KeyPair;

/// Categorized X3DH failure modes with recovery guidance.
#[derive(Debug)]
pub enum X3DHFailure {
    /// All OPKs consumed — proceed with 3-DH (weaker but valid).
    NoOPKAvailable,
    /// SPK expired on server — trigger prekey refresh and retry.
    StaleBundle {
        /// Age of the signed prekey in seconds.
        spk_age_secs: u64,
    },
    /// Prekey bundle fetch failed (server unreachable).
    FetchFailed(String),
    /// SPK signature verification failed — ABORT, do not proceed.
    InvalidSignature,
}

/// Attempt X3DH initiation with recovery logic.
///
/// # Recovery Rules
///
/// 1. **No OPK:** X3DH with 3 DH values is valid per the protocol.
///    Log a warning. Session still has forward secrecy via the ephemeral key.
/// 2. **Invalid SPK signature:** Hard abort. Do not proceed.
///    Alert user of potential impersonation.
///
/// # Arguments
///
/// * `our_identity` – Our Ed25519 identity key pair.
/// * `their_bundle` – The responder's prekey bundle (already fetched).
///
/// The caller is responsible for fetching the bundle from the mailbox
/// and handling network errors before calling this function.
pub fn initiate_with_recovery(
    our_identity: &Ed25519KeyPair,
    their_bundle: &X3DHPrekeyBundle,
) -> Result<(X3DHResult, Option<X3DHFailure>)> {
    // SPK signature invalid — ABORT. Do not fall back. Alert user.
    if their_bundle.verify_spk_signature().is_err() {
        return Err(X3DHError::InvalidSignature);
    }

    // Check for missing OPK (valid but weaker — log warning)
    let warning = if their_bundle.one_time_prekey.is_none() {
        tracing::warn!("no OPK available for contact; proceeding with 3-DH");
        Some(X3DHFailure::NoOPKAvailable)
    } else {
        None
    };

    let result = x3dh_initiate(our_identity, their_bundle)?;
    Ok((result, warning))
}

#[cfg(test)]
mod tests {
    use super::*;
    use najwa_crypto::keys::ed25519::Ed25519KeyPair;
    use najwa_crypto::keys::x25519::X25519KeyPair;

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

    #[test]
    fn initiate_with_recovery_no_opk_warns() {
        let mut rng = rand::thread_rng();
        let alice_ik = Ed25519KeyPair::generate(&mut rng);
        let bob_ik = Ed25519KeyPair::generate(&mut rng);
        let bob_spk = X25519KeyPair::generate(&mut rng);

        let bundle = make_bundle(&bob_ik, &bob_spk, None);
        let (result, warning) = initiate_with_recovery(&alice_ik, &bundle).unwrap();

        assert!(matches!(warning, Some(X3DHFailure::NoOPKAvailable)));
        assert_ne!(result.shared_secret, [0u8; 32]);
    }

    #[test]
    fn initiate_with_recovery_with_opk_no_warning() {
        let mut rng = rand::thread_rng();
        let alice_ik = Ed25519KeyPair::generate(&mut rng);
        let bob_ik = Ed25519KeyPair::generate(&mut rng);
        let bob_spk = X25519KeyPair::generate(&mut rng);
        let bob_opk = X25519KeyPair::generate(&mut rng);

        let bundle = make_bundle(&bob_ik, &bob_spk, Some(&bob_opk));
        let (result, warning) = initiate_with_recovery(&alice_ik, &bundle).unwrap();

        assert!(warning.is_none());
        assert_ne!(result.shared_secret, [0u8; 32]);
    }

    #[test]
    fn initiate_with_recovery_invalid_sig_aborts() {
        let mut rng = rand::thread_rng();
        let alice_ik = Ed25519KeyPair::generate(&mut rng);
        let bob_ik = Ed25519KeyPair::generate(&mut rng);
        let bob_spk = X25519KeyPair::generate(&mut rng);

        // Sign with wrong key (alice instead of bob) → invalid SPK sig
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

        let result = initiate_with_recovery(&alice_ik, &bundle);
        assert!(matches!(result, Err(X3DHError::InvalidSignature)));
    }
}
