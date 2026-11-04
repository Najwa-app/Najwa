//! Hardware tests touch only random test generations, never all-account deletion.
#![cfg(all(target_os = "linux", feature = "linux-tpm"))]

use najwa_identity::{platform, record::*, IdentityManager};
use std::path::PathBuf;

#[test]
fn strict_build_cannot_read_device_factor_from_headless_override() {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().join("synthetic-only");
    // This integration binary has one environment-mutating test. The hardware
    // test does not use the override, and production ignores it in this build.
    std::env::set_var("NAJWA_DKM_FILE", &base);
    let salt = rand::random::<[u8; 32]>();
    let record = IdentityRecordStandard {
        magic: MAGIC,
        version: VERSION,
        mode: MODE_STANDARD,
        kdf_alg: KDF_ALG_ARGON2ID,
        aead_alg: AEAD_ALG_XCHACHA20,
        argon2_memory: 65536,
        argon2_iterations: 1,
        argon2_parallelism: 1,
        reserved: [0; 3],
        salt_p: salt,
        nonce: [0; 24],
        ik_pub: [0; 32],
        enc_ik: [0; 48],
        checksum: [0; 32],
    };
    std::fs::write(&base, "42".repeat(32)).unwrap();
    let scoped = PathBuf::from(format!("{}.key.{}", base.display(), hex::encode(salt)));
    std::fs::write(&scoped, [0x42; 32]).unwrap();
    assert!(platform::retrieve_record_dkm(&record).is_err());
    assert_eq!(std::fs::read(scoped).unwrap(), [0x42; 32]);
    std::env::remove_var("NAJWA_DKM_FILE");
}

#[test]
#[ignore = "creates a synthetic identity using the real Linux TPM and Secret Service"]
fn hardware_identity_create_reopen_password_change_and_key_loss() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("identity.najwa");
    struct Cleanup(PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            if let Ok(bytes) = std::fs::read(&self.0) {
                if let Ok(record) = IdentityRecordStandard::from_bytes(&bytes) {
                    let _ = platform::delete_record_dkm(&record);
                }
            }
        }
    }
    let _cleanup = Cleanup(path.clone());
    let mut manager = IdentityManager::new(path.clone()).unwrap();
    manager.create("synthetic original passphrase").unwrap();
    let public = manager.identity().unwrap().keypair.public().to_bytes();
    let first = IdentityRecordStandard::from_bytes(&std::fs::read(&path).unwrap()).unwrap();
    drop(manager);

    let mut reopened = IdentityManager::new(path.clone()).unwrap();
    assert!(reopened.unlock("incorrect synthetic passphrase").is_err());
    // Failed authentication deliberately starts the persistent backoff after the KDF.
    std::thread::sleep(std::time::Duration::from_millis(1100));
    reopened.unlock("synthetic original passphrase").unwrap();
    assert_eq!(
        reopened.identity().unwrap().keypair.public().to_bytes(),
        public
    );
    reopened
        .change_password(
            "synthetic original passphrase",
            "synthetic replacement passphrase",
        )
        .unwrap();
    assert!(platform::retrieve_record_dkm(&first).is_err());
    drop(reopened);
    assert!(IdentityManager::unlock_once(&path, "synthetic original passphrase").is_err());
    std::thread::sleep(std::time::Duration::from_millis(1100));
    assert_eq!(
        IdentityManager::unlock_once(&path, "synthetic replacement passphrase")
            .unwrap()
            .keypair
            .public()
            .to_bytes(),
        public
    );

    let current = IdentityRecordStandard::from_bytes(&std::fs::read(&path).unwrap()).unwrap();
    platform::delete_record_dkm(&current).unwrap();
    assert!(IdentityManager::unlock_once(&path, "synthetic replacement passphrase").is_err());
}
