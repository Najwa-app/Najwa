//! Hardware migration is unavailable for the current identity record mode.
//!
//! The API is fallible and fails closed: record mode 0x02 is reserved and is
//! never written (S02 §19.3).

use crate::error::{IdentityError, Result};
use crate::record::{IdentityRecordHardware, IdentityRecordStandard};

/// S02 §19.3: never create a mode 0x02 record. No key storage,
/// password derivation or hardware callback is accessed on this path.
pub fn migrate_to_hardware(
    _record: &IdentityRecordStandard,
    _password: &str,
    _hw_wrap: impl FnOnce(&[u8; 32]) -> std::result::Result<Vec<u8>, String>,
) -> Result<IdentityRecordHardware> {
    Err(IdentityError::HardwareError(
        "hardware-mode migration is unavailable in this build".into(),
    ))
}

/// Hardware records cannot be migrated through an unauthenticated unwrap
/// callback. Use the verified paper-key recovery flow for standard-mode recovery.
pub fn migrate_to_standard(
    _hw_record: &IdentityRecordHardware,
    _password: &str,
    _hw_unwrap: impl FnOnce(&[u8]) -> std::result::Result<[u8; 32], String>,
) -> Result<IdentityRecordStandard> {
    Err(IdentityError::HardwareError(
        "hardware-mode migration is unavailable in this build".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::*;

    fn standard_record() -> IdentityRecordStandard {
        IdentityRecordStandard {
            magic: MAGIC,
            version: VERSION,
            mode: MODE_STANDARD,
            kdf_alg: KDF_ALG_ARGON2ID,
            aead_alg: AEAD_ALG_XCHACHA20,
            argon2_memory: 0,
            argon2_iterations: 0,
            argon2_parallelism: 0,
            reserved: [0; 3],
            salt_p: [0; 32],
            nonce: [0; 24],
            ik_pub: [0; 32],
            enc_ik: [0; 48],
            checksum: [0; 32],
        }
    }

    // These formerly ignored roundtrip tests now pin the supported scope:
    // even a malformed record cannot reach key storage or a hardware callback.
    #[test]
    fn migrate_standard_to_hardware_roundtrip() {
        let result = migrate_to_hardware(&standard_record(), "", |_| {
            panic!("unsupported migration invoked hardware")
        });
        assert!(matches!(result, Err(IdentityError::HardwareError(_))));
    }

    #[test]
    fn migrate_hardware_to_standard_roundtrip() {
        let record = IdentityRecordHardware {
            magic: MAGIC,
            version: VERSION,
            mode: MODE_HARDWARE,
            kdf_alg: KDF_ALG_ARGON2ID,
            aead_alg: AEAD_ALG_XCHACHA20,
            argon2_memory: 0,
            argon2_iterations: 0,
            argon2_parallelism: 0,
            reserved: [0; 3],
            salt_p: [0; 32],
            nonce_inner: [0; 24],
            nonce_ik: [0; 24],
            ik_pub: [0; 32],
            hw_wrapped_blob: vec![],
            enc_ik: [0; 48],
            checksum: [0; 32],
        };
        let result = migrate_to_standard(&record, "", |_| {
            panic!("unsupported migration invoked hardware")
        });
        assert!(matches!(result, Err(IdentityError::HardwareError(_))));
    }
}
