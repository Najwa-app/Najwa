//! Hardware mode detection, recovery, and migration.
//!
//! Startup detection of record mode 0x02 and paper-key recovery from a
//! hardware-wrapped record. Not used by the app; S02 §19 covers device-factor
//! loss for the records the app writes.

use crate::creation::create_identity_from_seed;
use crate::error::{IdentityError, Result};
use crate::platform::{detect_hardware_availability, HardwareStatus, StartupAction};
use crate::record::*;

/// Determine the startup action based on the identity record and hardware state.
pub fn startup_identity_check(record_data: Option<&[u8]>) -> StartupAction {
    match record_data {
        Some(data) => {
            // Try to determine mode from the record
            if data.len() >= 10 {
                let mode = data[9]; // S02 §7.1: mode byte is at record offset 9
                if mode == MODE_HARDWARE {
                    match detect_hardware_availability() {
                        HardwareStatus::Available => StartupAction::NormalUnlock,
                        HardwareStatus::KeyLost => StartupAction::OfferRecovery {
                            reason: "Hardware security module was reset".into(),
                        },
                        _ => StartupAction::OfferRecovery {
                            reason: "Hardware security module unavailable".into(),
                        },
                    }
                } else {
                    StartupAction::NormalUnlock
                }
            } else {
                StartupAction::NormalUnlock
            }
        }
        None => StartupAction::CreateIdentity,
    }
}

/// Recover from hardware loss using a paper key (seed).
///
/// Verifies the seed matches the stored public key, then creates
/// a new Standard-mode record protected by the new password.
pub fn recover_from_hardware_loss(
    record: &IdentityRecordHardware,
    seed: &[u8; 32],
    new_password: &str,
) -> Result<IdentityRecordStandard> {
    use najwa_crypto::prelude::Ed25519KeyPair;

    // 1. Derive keypair from seed
    let keypair = Ed25519KeyPair::from_seed(seed);

    // 2. Verify public key matches record
    if keypair.public().to_bytes() != record.ik_pub {
        return Err(IdentityError::PaperKeyMismatch);
    }

    // 3. Re-protect in Standard mode
    let (new_record, _identity) = create_identity_from_seed(seed, new_password, None)?;
    Ok(new_record)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_no_record_creates() {
        assert_eq!(startup_identity_check(None), StartupAction::CreateIdentity);
    }

    #[test]
    fn startup_standard_mode_normal() {
        // Build minimal record with standard mode byte at offset 9 (S02 §7.1)
        let mut data = vec![0u8; 192];
        data[0..8].copy_from_slice(&MAGIC);
        data[8] = VERSION;
        data[9] = MODE_STANDARD;
        assert_eq!(
            startup_identity_check(Some(&data)),
            StartupAction::NormalUnlock
        );
    }

    #[test]
    fn startup_hardware_mode_offers_recovery() {
        // Hardware mode on desktop → NotPresent → OfferRecovery
        let mut data = vec![0u8; 192];
        data[0..8].copy_from_slice(&MAGIC);
        data[8] = VERSION;
        data[9] = MODE_HARDWARE;
        match startup_identity_check(Some(&data)) {
            StartupAction::OfferRecovery { .. } => {} // expected
            other => panic!("expected OfferRecovery, got {:?}", other),
        }
    }

    #[test]
    fn startup_short_record_normal() {
        // Record too short to reach the offset-9 mode byte → NormalUnlock (best effort)
        let data = vec![0u8; 9];
        assert_eq!(
            startup_identity_check(Some(&data)),
            StartupAction::NormalUnlock
        );
    }

    #[test]
    fn hardware_record_roundtrip() {
        // LOW-10: Verify IdentityRecordHardware serialization roundtrip
        let record = IdentityRecordHardware {
            magic: MAGIC,
            version: VERSION,
            mode: MODE_HARDWARE,
            kdf_alg: KDF_ALG_ARGON2ID,
            aead_alg: AEAD_ALG_XCHACHA20,
            argon2_memory: 65536,
            argon2_iterations: 3,
            argon2_parallelism: 2,
            reserved: [0; 3],
            salt_p: [0xAA; 32],
            nonce_inner: [0xBB; 24],
            nonce_ik: [0xCC; 24],
            ik_pub: [0xDD; 32],
            hw_wrapped_blob: vec![0xEE; 64],
            enc_ik: [0xFF; 48],
            checksum: [0x11; 32],
        };
        let bytes = record.to_bytes();
        let restored = IdentityRecordHardware::from_bytes(&bytes).unwrap();
        assert_eq!(restored.mode, MODE_HARDWARE);
        assert_eq!(restored.ik_pub, [0xDD; 32]);
        assert_eq!(restored.hw_wrapped_blob, vec![0xEE; 64]);
        assert_eq!(restored.argon2_memory, 65536);
    }

    #[test]
    fn recover_from_hardware_loss_success() {
        // LOW-10: Full hardware recovery flow with paper key
        use najwa_crypto::keys::ed25519::Ed25519KeyPair;
        let seed = [0x42u8; 32];
        let kp = Ed25519KeyPair::from_seed(&seed);
        let hw_record = IdentityRecordHardware {
            magic: MAGIC,
            version: VERSION,
            mode: MODE_HARDWARE,
            kdf_alg: KDF_ALG_ARGON2ID,
            aead_alg: AEAD_ALG_XCHACHA20,
            argon2_memory: 65536,
            argon2_iterations: 3,
            argon2_parallelism: 2,
            reserved: [0; 3],
            salt_p: [0; 32],
            nonce_inner: [0; 24],
            nonce_ik: [0; 24],
            ik_pub: kp.public().to_bytes(),
            hw_wrapped_blob: vec![0; 48],
            enc_ik: [0; 48],
            checksum: [0; 32],
        };
        let std_record =
            recover_from_hardware_loss(&hw_record, &seed, "new-password-123!").unwrap();
        assert_eq!(std_record.mode, MODE_STANDARD);
        assert_eq!(std_record.ik_pub, kp.public().to_bytes());
    }

    #[test]
    fn recover_wrong_seed_fails() {
        use najwa_crypto::keys::ed25519::Ed25519KeyPair;
        let seed = [0x42u8; 32];
        let kp = Ed25519KeyPair::from_seed(&seed);
        let hw_record = IdentityRecordHardware {
            magic: MAGIC,
            version: VERSION,
            mode: MODE_HARDWARE,
            kdf_alg: KDF_ALG_ARGON2ID,
            aead_alg: AEAD_ALG_XCHACHA20,
            argon2_memory: 65536,
            argon2_iterations: 3,
            argon2_parallelism: 2,
            reserved: [0; 3],
            salt_p: [0; 32],
            nonce_inner: [0; 24],
            nonce_ik: [0; 24],
            ik_pub: kp.public().to_bytes(),
            hw_wrapped_blob: vec![0; 48],
            enc_ik: [0; 48],
            checksum: [0; 32],
        };
        let wrong_seed = [0xFF; 32];
        let result = recover_from_hardware_loss(&hw_record, &wrong_seed, "pass");
        assert!(matches!(result, Err(IdentityError::PaperKeyMismatch)));
    }
}
