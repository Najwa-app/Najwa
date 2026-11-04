//! Prekey lifecycle management (S06).
//!
//! Provides:
//! - Signed prekey (SPK) generation and rotation with a 14-day grace period (S06 §5.4)
//! - One-time prekey (OPK) generation and replenishment (S06 §5.5)
//! - Upload bundle construction for mailbox servers (S06 §4.1)
//! - Background maintenance: rotation, replenishment, cleanup (S06 §5.6)
//! - OPK consumption tracking (S06 §2.3)

pub mod error;
pub mod manager;
pub mod sqlite;
pub mod types;

// Re-exports
pub use error::{PrekeyError, Result};
pub use manager::{PrekeyManager, PrekeyStorage, StoredOpk, StoredSpk};
pub use types::{
    OneTimePrekey, PrekeyUploadBundle, SignedPrekey, DEFAULT_OPK_BATCH_SIZE, DEFAULT_OPK_THRESHOLD,
    DEFAULT_SPK_ROTATION_DAYS, OPK_ALERT_THRESHOLD, SPK_GRACE_PERIOD_SECS,
};

#[cfg(test)]
mod tests {
    use super::*;
    use najwa_crypto::keys::ed25519::Ed25519KeyPair;

    // -----------------------------------------------------------------------
    // Integration: full lifecycle
    // -----------------------------------------------------------------------

    #[test]
    fn upload_bundle_fields_populated() {
        // Synchronous check: build a bundle and verify fields
        let ik = Ed25519KeyPair::from_seed(&[0x42; 32]);
        let spk = {
            let kp = najwa_crypto::keys::x25519::X25519KeyPair::generate(&mut rand::thread_rng());
            let sig = ik.sign(&kp.public().to_bytes());
            SignedPrekey {
                id: [0x01, 0x02, 0x03, 0x04],
                keypair: kp,
                signature: sig,
                created_at: najwa_crypto::time::now(),
                expires_at: None,
            }
        };

        let opks: Vec<OneTimePrekey> = (0..5)
            .map(|i| OneTimePrekey {
                id: [0, 0, 0, i],
                keypair: najwa_crypto::keys::x25519::X25519KeyPair::generate(
                    &mut rand::thread_rng(),
                ),
                created_at: najwa_crypto::time::now(),
                used: false,
                mailbox_id: None,
            })
            .collect();

        let bundle = PrekeyUploadBundle {
            mailbox_ik_pub: ik.public().clone(),
            identity_key: ik.public().clone(),
            signed_prekey: spk.keypair.public().clone(),
            signed_prekey_id: spk.id,
            signed_prekey_signature: spk.signature.clone(),
            spk_timestamp: spk.created_at,
            one_time_prekeys: opks
                .iter()
                .map(|o| (o.keypair.public().clone(), o.id))
                .collect(),
            manifest: None,
        };

        assert_eq!(bundle.identity_key.to_bytes(), ik.public().to_bytes());
        assert_eq!(bundle.signed_prekey_id, [0x01, 0x02, 0x03, 0x04]);
        assert_eq!(bundle.one_time_prekeys.len(), 5);

        // Verify SPK signature
        assert!(ik
            .public()
            .verify(
                &bundle.signed_prekey.to_bytes(),
                &bundle.signed_prekey_signature
            )
            .is_ok());
    }

    #[test]
    fn upload_bundle_to_mailbox_format_conversion() {
        let ik = Ed25519KeyPair::from_seed(&[0x10; 32]);
        let kp = najwa_crypto::keys::x25519::X25519KeyPair::generate(&mut rand::thread_rng());
        let sig = ik.sign(&kp.public().to_bytes());

        let bundle = PrekeyUploadBundle {
            mailbox_ik_pub: ik.public().clone(),
            identity_key: ik.public().clone(),
            signed_prekey: kp.public().clone(),
            signed_prekey_id: [0xAA, 0xBB, 0xCC, 0xDD],
            signed_prekey_signature: sig,
            spk_timestamp: najwa_crypto::time::now(),
            one_time_prekeys: vec![
                (
                    najwa_crypto::keys::x25519::X25519KeyPair::generate(&mut rand::thread_rng())
                        .public()
                        .clone(),
                    [0, 0, 0, 1],
                ),
                (
                    najwa_crypto::keys::x25519::X25519KeyPair::generate(&mut rand::thread_rng())
                        .public()
                        .clone(),
                    [0, 0, 0, 2],
                ),
            ],
            manifest: None,
        };

        let wire = bundle.to_mailbox_bundle();
        assert_eq!(wire.identity_key, ik.public().to_bytes());
        assert_eq!(wire.signed_prekey, kp.public().to_bytes());
        assert_eq!(wire.signed_prekey_signature.len(), 64);
        assert_eq!(wire.one_time_prekeys.len(), 2);
        assert_eq!(
            wire.one_time_prekeys[0].id,
            u32::from_be_bytes([0, 0, 0, 1])
        );
        assert_eq!(
            wire.one_time_prekeys[1].id,
            u32::from_be_bytes([0, 0, 0, 2])
        );
    }

    #[test]
    fn constants_have_expected_values() {
        assert_eq!(DEFAULT_OPK_BATCH_SIZE, 200);
        assert_eq!(DEFAULT_OPK_THRESHOLD, 50);
        assert_eq!(OPK_ALERT_THRESHOLD, 50);
        assert_eq!(DEFAULT_SPK_ROTATION_DAYS, 7);
        assert_eq!(SPK_GRACE_PERIOD_SECS, 14 * 24 * 3600); // S06 §5.1
    }
}
