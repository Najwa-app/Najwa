//! Exercise the explicit headless backend in its own integration-test process.
#![cfg(not(any(
    all(target_os = "windows", feature = "windows-tpm"),
    all(target_os = "linux", feature = "linux-tpm"),
    all(target_os = "macos", feature = "macos-secure-enclave")
)))]
use najwa_crypto::kdf::Argon2Params;
use najwa_identity::{creation::create_identity_from_seed, platform};

#[test]
fn headless_storage_rejects_bad_utf8_boundaries_and_erases_all_generations() {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().join("synthetic-dkm");
    std::env::set_var("NAJWA_DKM_FILE", &base);
    // Exactly 64 bytes, with multibyte characters crossing the old string-slice
    // boundaries: corrupt key data must return an error, never panic.
    std::fs::write(&base, format!("{}x", "€".repeat(21))).unwrap();
    assert!(platform::retrieve_dkm().is_err());
    let (first, _) =
        create_identity_from_seed(&[1; 32], "synthetic", Some(Argon2Params::ABSOLUTE_MIN)).unwrap();
    let (second, _) =
        create_identity_from_seed(&[2; 32], "synthetic", Some(Argon2Params::ABSOLUTE_MIN)).unwrap();
    assert!(platform::retrieve_record_dkm(&first).is_ok());
    assert!(platform::retrieve_record_dkm(&second).is_ok());
    let unrelated = dir.path().join("synthetic-dkm.key.not-a-key");
    std::fs::write(&unrelated, b"unrelated data").unwrap();
    platform::delete_dkm().unwrap();
    assert!(!base.exists());
    assert!(platform::retrieve_record_dkm(&first).is_err());
    assert!(platform::retrieve_record_dkm(&second).is_err());
    assert_eq!(std::fs::read(&unrelated).unwrap(), b"unrelated data");
    platform::delete_dkm().unwrap();
}
