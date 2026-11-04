//! Platform keychain integration tests (device-factor storage, S02 §17).
//!
//! These tests exercise the platform DKM (Device Key Material) APIs.
//! On Linux (Docker/CI), this uses the keyring crate backed by the
//! Secret Service D-Bus API (GNOME Keyring / KWallet).
//!
//! On headless environments without a secret service, these tests will
//! fail gracefully (the error is the expected behavior — no keychain
//! available).
//!
//! ```sh
//! cargo test -p najwa-identity --test platform_keychain -- --ignored
//! ```

use najwa_identity::platform;

fn require_isolated_keychain() {
    assert_eq!(std::env::var("NAJWA_KEYCHAIN_TEST_SANDBOX").as_deref(), Ok("1"),
        "these destructive tests require an isolated keychain; use scripts/testing/keychain.Dockerfile");
}

/// Store and retrieve a test key from the platform keychain.
///
/// On platforms with a keychain (macOS Keychain, Windows Credential Manager,
/// Linux Secret Service), this verifies the full store → retrieve → delete cycle.
/// On headless Linux (Docker), store_dkm will return an error — we assert the
/// error is graceful (not a panic).
#[test]
#[ignore = "requires platform keychain access"]
fn keychain_store_and_retrieve() {
    require_isolated_keychain();
    let test_key: [u8; 32] = [0x42; 32];

    match platform::store_dkm(&test_key) {
        Ok(()) => {
            // Success promises persistence. An unavailable service must return
            // an error from store, never pretend to have stored the key.
            match platform::retrieve_dkm() {
                Ok(retrieved) => {
                    // Real keychain works — verify full cycle
                    assert_eq!(retrieved, test_key, "retrieved key must match stored key");

                    platform::delete_dkm().expect("delete_dkm should succeed after store");

                    let after_delete = platform::retrieve_dkm();
                    assert!(
                        after_delete.is_err(),
                        "retrieve_dkm should fail after delete"
                    );
                }
                Err(e) => panic!("store_dkm succeeded but retrieve failed: {e}"),
            }
        }
        Err(e) => {
            assert!(
                std::env::var_os("NAJWA_REQUIRE_KEYCHAIN").is_none(),
                "required keychain unavailable: {e}"
            );
            // No keychain available (headless Docker, CI without secret service)
            // This is expected — verify the error is informative
            let msg = e.to_string();
            assert!(
                !msg.is_empty(),
                "DKM error should have a descriptive message"
            );
            eprintln!("keychain not available (expected in headless): {}", msg);
        }
    }
}

/// Verify that storing, deleting, and re-storing works cleanly.
///
/// Tests the idempotency of the delete → store cycle to catch state
/// leakage between identity lifecycle events (account deletion + re-creation).
#[test]
#[ignore = "requires platform keychain access"]
fn keychain_cleanup_on_delete() {
    require_isolated_keychain();
    let key_1: [u8; 32] = [0xAA; 32];
    let key_2: [u8; 32] = [0xBB; 32];

    match platform::store_dkm(&key_1) {
        Ok(()) => {
            match platform::retrieve_dkm() {
                Ok(r1) => {
                    // Real keychain works — test full lifecycle
                    assert_eq!(r1, key_1);

                    platform::delete_dkm().unwrap();

                    platform::store_dkm(&key_2).expect("re-store after delete should succeed");
                    let r2 = platform::retrieve_dkm().unwrap();
                    assert_eq!(
                        r2, key_2,
                        "second key must be retrievable after delete + re-store"
                    );

                    let _ = platform::delete_dkm();
                }
                Err(e) => panic!("store_dkm succeeded but retrieve failed: {e}"),
            }
        }
        Err(e) => {
            assert!(
                std::env::var_os("NAJWA_REQUIRE_KEYCHAIN").is_none(),
                "required keychain unavailable: {e}"
            );
            eprintln!("keychain not available (expected in headless): {}", e);
        }
    }
}

/// Regression for accidental mock-backend selection. Run in a child with a
/// deliberately unavailable D-Bus address so no host credential is touched.
#[cfg(target_os = "linux")]
#[test]
fn missing_secret_service_cannot_report_success() {
    const CHILD: &str = "NAJWA_TEST_NO_SECRET_SERVICE";
    if std::env::var_os(CHILD).is_some() {
        assert!(platform::store_dkm(&[0x42; 32]).is_err());
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "missing_secret_service_cannot_report_success",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .env_remove("NAJWA_DKM_FILE")
        .env(
            "DBUS_SESSION_BUS_ADDRESS",
            format!("unix:path={}", dir.path().join("absent-bus").display()),
        )
        .status()
        .unwrap();
    assert!(status.success());
}

/// Real Secret Service/Credential Manager persistence, with the writer and
/// reader in different processes. Run only in an isolated test keychain.
#[test]
#[ignore = "requires isolated platform keychain access"]
fn record_credentials_survive_process_restart() {
    require_isolated_keychain();
    use najwa_identity::{
        creation::create_identity_from_seed, record::IdentityRecordStandard,
        unlock::unlock_identity,
    };
    const CHILD: &str = "NAJWA_TEST_KEYCHAIN_STEP";
    const RECORD: &str = "NAJWA_TEST_KEYCHAIN_RECORD";
    if let Ok(step) = std::env::var(CHILD) {
        let path = std::path::PathBuf::from(std::env::var_os(RECORD).unwrap());
        if step == "write" {
            let (record, _) = create_identity_from_seed(
                &[0x42; 32],
                "synthetic password",
                Some(najwa_crypto::kdf::Argon2Params::ABSOLUTE_MIN),
            )
            .unwrap();
            std::fs::write(path, record.to_bytes()).unwrap();
        } else {
            let record = IdentityRecordStandard::from_bytes(&std::fs::read(path).unwrap()).unwrap();
            assert!(unlock_identity(&record, "synthetic password").is_ok());
            platform::delete_record_dkm(&record).unwrap();
            assert!(platform::retrieve_record_dkm(&record).is_err());
        }
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    for step in ["write", "read-and-delete"] {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "record_credentials_survive_process_restart",
                "--ignored",
                "--nocapture",
            ])
            .env(CHILD, step)
            .env(RECORD, dir.path().join("record"))
            .env_remove("NAJWA_DKM_FILE")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
#[ignore = "requires isolated platform keychain access"]
fn account_deletion_erases_abandoned_record_credentials() {
    require_isolated_keychain();
    use najwa_identity::creation::create_identity_from_seed;
    let (first, _) = create_identity_from_seed(
        &[1; 32],
        "synthetic",
        Some(najwa_crypto::kdf::Argon2Params::ABSOLUTE_MIN),
    )
    .unwrap();
    let (abandoned, _) = create_identity_from_seed(
        &[2; 32],
        "synthetic",
        Some(najwa_crypto::kdf::Argon2Params::ABSOLUTE_MIN),
    )
    .unwrap();
    assert!(platform::retrieve_record_dkm(&first).is_ok());
    assert!(platform::retrieve_record_dkm(&abandoned).is_ok());
    platform::store_dkm(&[3; 32]).unwrap();
    #[cfg(target_os = "linux")]
    let unrelated = {
        let entry = keyring::Entry::new("com.najwa.identity", "test-unrelated-entry").unwrap();
        entry.set_password("synthetic unrelated data").unwrap();
        entry
    };
    platform::delete_dkm().unwrap();
    assert!(platform::retrieve_record_dkm(&first).is_err());
    assert!(platform::retrieve_record_dkm(&abandoned).is_err());
    assert!(platform::retrieve_dkm().is_err());
    #[cfg(target_os = "linux")]
    {
        assert_eq!(
            unrelated.get_password().unwrap(),
            "synthetic unrelated data"
        );
        unrelated.delete_credential().unwrap();
    }
}

/// Verify that retrieve and delete on an empty keychain return errors, not panics.
///
/// Tests graceful error handling when the keychain has no stored DKM.
/// This is the state after a fresh install or after account deletion.
#[test]
#[ignore = "requires platform keychain access"]
fn keychain_empty_state_error_handling() {
    require_isolated_keychain();
    // Ensure clean state: delete any existing entry (ignore errors)
    let _ = platform::delete_dkm();

    // Retrieve from empty keychain — must return Err, not panic
    let result = platform::retrieve_dkm();
    assert!(
        result.is_err(),
        "retrieve_dkm on empty keychain should return Err, got Ok"
    );

    // Delete from empty keychain — should not panic
    // Some platforms return Ok (idempotent), others return Err — both are acceptable
    let delete_result = platform::delete_dkm();
    // Just verify no panic — either Ok or Err is fine
    drop(delete_result);
}
