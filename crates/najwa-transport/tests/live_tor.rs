//! Live Tor integration tests (S04 §10.1 bootstrap, §5 HTTP over Tor).
//!
//! These tests bootstrap a real Tor connection via embedded Arti.
//! They require internet access and take 30-60 seconds to bootstrap.
//!
//! ```sh
//! cargo test -p najwa-transport --test live_tor -- --ignored --nocapture
//! ```

use std::path::PathBuf;

use najwa_transport::config::TorConfig;
use najwa_transport::tor::TorTransport;

/// Exercise the actual HTTP reader and single-use handle against Tor's onion
/// web mirror. Kept opt-in because public-network availability is external.
#[tokio::test]
#[ignore = "requires live Tor network and the Tor Project onion mirror"]
async fn tor_onion_http_and_single_use_handle() {
    use najwa_transport::{circuit::CircuitIsolation, dns_leak::verify_no_dns_leak_strict};
    use std::time::Duration;
    let mut transport = TorTransport::new(test_config("row4_http"));
    tokio::time::timeout(Duration::from_secs(180), transport.bootstrap())
        .await
        .expect("bootstrap deadline exceeded")
        .expect("bootstrap failed");
    assert!(transport.is_connected());
    verify_no_dns_leak_strict(&transport)
        .await
        .expect("onion HTTP check failed");
    let handle = transport
        .get_circuit(CircuitIsolation::OneShot)
        .await
        .unwrap();
    let response = transport
        .get(
            &handle,
            "http://rzuwtpc4wb3xdzrj3yeajsvm3fkq4vbeubm2tdxaqruzzzgs5dwemlad.onion/",
        )
        .await
        .expect("onion GET failed");
    assert!((200..400).contains(&response.status));
    assert!(!response.body.is_empty());
    assert!(transport
        .get(
            &handle,
            "http://rzuwtpc4wb3xdzrj3yeajsvm3fkq4vbeubm2tdxaqruzzzgs5dwemlad.onion/"
        )
        .await
        .is_err());
    transport.shutdown().await.unwrap();
    assert!(!transport.is_connected());
}

/// Build a TorConfig with a unique writable data directory.
///
/// Each test gets its own temp dir to avoid cache corruption from
/// parallel test execution.
fn test_config(name: &str) -> TorConfig {
    let data_dir = PathBuf::from(format!("/tmp/najwa_test_tor_{}", name));

    // Clean up any stale state from previous runs
    let _ = std::fs::remove_dir_all(&data_dir);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for dir in [&data_dir, &data_dir.join("cache"), &data_dir.join("state")] {
            std::fs::create_dir_all(dir).unwrap();
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(&data_dir).unwrap();
    }

    TorConfig {
        data_dir,
        ..TorConfig::default()
    }
}

/// Bootstrap a real Tor connection and verify it reports connected.
#[tokio::test]
#[ignore = "requires live Tor network access (~30-60s)"]
async fn tor_bootstrap_and_circuit() {
    let mut transport = TorTransport::new(test_config("bootstrap"));
    let result = transport.bootstrap().await;
    assert!(
        result.is_ok(),
        "Tor bootstrap should succeed with network access: {:?}",
        result.err()
    );
    assert!(transport.is_connected());
    assert_eq!(transport.bootstrap_progress(), 100);
}

/// S04 §10.1: a directory cached by an earlier direct session completes Arti's
/// own bootstrap with no network contact. An unreachable bridge must still
/// never report connected.
#[test]
#[ignore = "requires live Tor network access (~30-60s)"]
fn cached_directory_with_unreachable_bridge_is_not_connected() {
    use najwa_transport::config::{BridgeConfig, BridgeType};
    use std::time::Duration;
    let config = test_config("cached_bridge");
    // Dropping the runtime ends Arti's tasks and releases its state lock, as a
    // restarted process does.
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        let mut direct = TorTransport::new(config.clone());
        direct.bootstrap().await.expect("Tor bootstrap failed");
        direct.shutdown().await.unwrap();
    });
    let closed = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let mut bridged = TorTransport::new(TorConfig {
        bridges: vec![BridgeConfig {
            bridge_type: BridgeType::Plain,
            address: format!("{closed} 0123456789ABCDEF0123456789ABCDEF01234567"),
            fingerprint: None,
        }],
        ..config.clone()
    });
    let result = tokio::runtime::Runtime::new().unwrap().block_on(async {
        tokio::time::timeout(Duration::from_secs(30), bridged.bootstrap()).await
    });
    assert!(!matches!(result, Ok(Ok(()))), "bootstrap must not succeed");
    assert!(!bridged.is_connected());
    // The same cache still connects a direct restart.
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        let mut direct = TorTransport::new(config);
        tokio::time::timeout(Duration::from_secs(120), direct.bootstrap())
            .await
            .expect("cached direct bootstrap deadline exceeded")
            .expect("cached direct bootstrap failed");
        assert!(direct.is_connected());
    });
}

/// Bootstrap and verify shutdown cleans up state.
#[tokio::test]
#[ignore = "requires live Tor network access (~30-60s)"]
async fn tor_bootstrap_and_shutdown() {
    let mut transport = TorTransport::new(test_config("shutdown"));
    transport.bootstrap().await.expect("Tor bootstrap failed");
    assert!(transport.is_connected());

    transport.shutdown().await.expect("shutdown failed");
    assert!(!transport.is_connected());
}

/// Verify bootstrap with an unwritable data dir fails gracefully.
#[tokio::test]
#[ignore = "requires live Tor network access"]
async fn tor_bootstrap_bad_data_dir_fails() {
    let config = TorConfig {
        data_dir: PathBuf::from("/proc/tor_state_impossible"),
        ..TorConfig::default()
    };
    let mut transport = TorTransport::new(config);
    let result = transport.bootstrap().await;
    assert!(
        result.is_err(),
        "Tor bootstrap should fail with unwritable data dir"
    );
    assert!(!transport.is_connected());
}
