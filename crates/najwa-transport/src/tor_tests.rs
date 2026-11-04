use super::*;
use crate::config::{BridgeConfig, BridgeType, PluggableTransportConfig};

#[tokio::test]
async fn file_parts_reuse_one_token_and_rotate_without_cross_file_reuse() {
    let transport=connected(TorConfig::default());
    let isolation=CircuitIsolation::FileTransfer([8;32]);
    let first=transport.get_circuit(isolation.clone()).await.unwrap();
    let next=transport.get_circuit(isolation.clone()).await.unwrap();
    let other=transport.get_circuit(CircuitIsolation::FileTransfer([9;32])).await.unwrap();
    assert_eq!(first.id,next.id);
    let (first_token,mut first_use)=transport.begin_request(&first).unwrap();
    let (next_token,mut next_use)=transport.begin_request(&next).unwrap();
    let (other_token,mut other_use)=transport.begin_request(&other).unwrap();
    assert_eq!(first_token,next_token);
    assert_ne!(first_token,other_token);
    first_use.succeeded=true;next_use.succeeded=true;other_use.succeeded=true;
    drop((first_use,next_use,other_use));
    registry_lock(&transport.circuits).get_mut(&first.id).unwrap().created_at=
        Instant::now()-Duration::from_secs(601);
    let fresh=transport.get_circuit(isolation).await.unwrap();
    assert_ne!(first.id,fresh.id);
    let (fresh_token,mut fresh_use)=transport.begin_request(&fresh).unwrap();
    assert_ne!(first_token,fresh_token);fresh_use.succeeded=true;
    assert!(transport.begin_request(&first).is_err());
}

fn connected(config: TorConfig) -> TorTransport {
    let transport = TorTransport::new(config);
    // Exercise token management without pretending to bootstrap a real client.
    transport.state.store(STATE_CONNECTED, Ordering::SeqCst);
    transport
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_reusable_handles_share_exactly_one_token() {
    let transport = std::sync::Arc::new(connected(TorConfig::default()));
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..64 {
        let transport = transport.clone();
        tasks.spawn(async move {
            transport
                .get_circuit(CircuitIsolation::ByMailbox("a".into()))
                .await
                .unwrap()
                .id
        });
    }
    let first = tasks.join_next().await.unwrap().unwrap();
    while let Some(result) = tasks.join_next().await {
        assert_eq!(result.unwrap(), first);
    }
    assert_eq!(registry_lock(&transport.circuits).len(), 1);
}

#[tokio::test]
async fn one_shot_handle_is_consumed_once_and_tokens_are_distinct() {
    let transport = connected(TorConfig::default());
    let a = transport
        .get_circuit(CircuitIsolation::OneShot)
        .await
        .unwrap();
    let b = transport
        .get_circuit(CircuitIsolation::OneShot)
        .await
        .unwrap();
    assert_ne!(a.id, b.id);
    let (ta, _ua) = transport.begin_request(&a).unwrap();
    assert!(transport.begin_request(&a).is_err());
    let (tb, _ub) = transport.begin_request(&b).unwrap();
    assert_ne!(ta, tb);
    assert!(registry_lock(&transport.circuits).is_empty());
}

#[tokio::test]
async fn expiry_and_idle_timeout_retire_old_tokens() {
    let transport = connected(TorConfig {
        circuit_timeout_secs: 5,
        ..TorConfig::default()
    });
    let isolation = CircuitIsolation::ByMailbox("a".into());
    let old = transport.get_circuit(isolation.clone()).await.unwrap();
    registry_lock(&transport.circuits)
        .get_mut(&old.id)
        .unwrap()
        .created_at = Instant::now() - Duration::from_secs(601);
    let fresh = transport.get_circuit(isolation.clone()).await.unwrap();
    assert_ne!(old.id, fresh.id);
    assert!(transport.begin_request(&old).is_err());
    assert_eq!(registry_lock(&transport.circuits).len(), 1);
    registry_lock(&transport.circuits)
        .get_mut(&fresh.id)
        .unwrap()
        .last_used = Instant::now() - Duration::from_secs(6);
    transport.cleanup_idle_circuits().await;
    assert!(registry_lock(&transport.circuits).is_empty());
    assert!(transport.begin_request(&fresh).is_err());
}

#[tokio::test]
async fn registry_bound_does_not_evict_active_streams() {
    let transport = connected(TorConfig {
        max_circuits: 2,
        ..TorConfig::default()
    });
    let a = transport
        .get_circuit(CircuitIsolation::ByMailbox("a".into()))
        .await
        .unwrap();
    let (_, mut a_use) = transport.begin_request(&a).unwrap();
    for _ in 0..100 {
        transport
            .get_circuit(CircuitIsolation::OneShot)
            .await
            .unwrap();
        assert_eq!(registry_lock(&transport.circuits).len(), 2);
        assert!(registry_lock(&transport.circuits).contains_key(&a.id));
    }
    let b = transport
        .get_circuit(CircuitIsolation::ByMailbox("b".into()))
        .await
        .unwrap();
    let (_, _b_use) = transport.begin_request(&b).unwrap();
    assert!(transport
        .get_circuit(CircuitIsolation::OneShot)
        .await
        .is_err());
    a_use.succeeded = true;
    drop(a_use);
    assert!(transport
        .get_circuit(CircuitIsolation::OneShot)
        .await
        .is_ok());
}

#[tokio::test]
async fn invalid_handles_and_failed_requests_cannot_reuse_tokens() {
    let transport = connected(TorConfig::default());
    let mut handle = transport
        .get_circuit(CircuitIsolation::ByMailbox("a".into()))
        .await
        .unwrap();
    handle.isolation = CircuitIsolation::ByContact([1; 32]);
    assert!(transport.begin_request(&handle).is_err());
    handle.isolation = CircuitIsolation::ByMailbox("a".into());
    // No Arti client exists, so the real request fails before network access.
    assert!(transport
        .get(&handle, &format!("http://{}.onion/", "a".repeat(56)))
        .await
        .is_err());
    assert!(registry_lock(&transport.circuits).is_empty());
}

#[tokio::test]
async fn cancellation_while_waiting_for_capacity_retires_token() {
    let transport = connected(TorConfig {
        max_circuits: 1,
        ..TorConfig::default()
    });
    let permit = transport.requests.acquire().await.unwrap();
    let handle = transport
        .get_circuit(CircuitIsolation::ByMailbox("a".into()))
        .await
        .unwrap();
    let result = tokio::time::timeout(
        Duration::from_millis(30),
        transport.send_request(&handle, "unused.onion", 80, b"request"),
    )
    .await;
    assert!(result.is_err());
    assert!(registry_lock(&transport.circuits).is_empty());
    drop(permit);
    assert_eq!(transport.requests.available_permits(), 1);
}

#[tokio::test]
async fn request_deadline_includes_waiting_for_capacity() {
    let transport = connected(TorConfig {
        max_circuits: 1,
        request_timeout_secs: 1,
        ..TorConfig::default()
    });
    let _permit = transport.requests.acquire().await.unwrap();
    let handle = transport
        .get_circuit(CircuitIsolation::OneShot)
        .await
        .unwrap();
    let result = transport
        .send_request(&handle, "unused.onion", 80, b"request")
        .await;
    assert!(matches!(result, Err(TransportError::Timeout)));
    assert!(registry_lock(&transport.circuits).is_empty());
}

#[tokio::test]
async fn invalid_bootstrap_resets_state_and_progress() {
    let mut transport = connected(TorConfig {
        mode: TorMode::SystemSocks {
            addr: "127.0.0.1:9050".parse().unwrap(),
        },
        ..TorConfig::default()
    });
    transport.progress.store(100, Ordering::SeqCst);
    assert!(transport.bootstrap().await.is_err());
    assert!(!transport.is_connected());
    assert_eq!(transport.bootstrap_progress(), 0);
    assert!(transport.client.read().await.is_none());
}

#[test]
fn unsupported_modes_and_empty_bridges_fail_closed() {
    for mode in [
        TorMode::Orbot,
        TorMode::SystemSocks {
            addr: "127.0.0.1:9050".parse().unwrap(),
        },
    ] {
        assert!(TorTransport::new(TorConfig {
            mode,
            ..TorConfig::default()
        })
        .build_arti_config()
        .is_err());
    }
    for kind in [
        BridgeType::Plain,
        BridgeType::Obfs4,
        BridgeType::Meek,
        BridgeType::Snowflake,
    ] {
        let config = TorConfig {
            bridges: vec![BridgeConfig {
                bridge_type: kind,
                address: " ".into(),
                fingerprint: None,
            }],
            ..TorConfig::default()
        };
        assert!(TorTransport::new(config).build_arti_config().is_err());
    }
}

#[test]
fn bridge_transports_require_real_matching_program_configuration() {
    let fp = "0123456789ABCDEF0123456789ABCDEF01234567";
    for kind in [BridgeType::Obfs4, BridgeType::Meek, BridgeType::Snowflake] {
        let config = TorConfig {
            bridges: vec![BridgeConfig {
                bridge_type: kind,
                address: format!("{} 127.0.0.1:1234 {fp}", kind.protocol().unwrap()),
                fingerprint: None,
            }],
            ..TorConfig::default()
        };
        assert!(TorTransport::new(config.clone())
            .build_arti_config()
            .is_err());
        let mut configured = config;
        configured.transports.push(PluggableTransportConfig {
            bridge_type: kind,
            executable: std::env::current_exe().unwrap(),
            arguments: vec!["--test-argument".into()],
        });
        // This builds the actual Arti configuration, not just our input schema.
        assert!(TorTransport::new(configured.clone())
            .build_arti_config()
            .is_ok());
        configured.transports[0].executable = "relative-or-missing".into();
        assert!(TorTransport::new(configured).build_arti_config().is_err());
    }
}

#[test]
fn bridge_fingerprint_is_used_and_conflicts_are_rejected() {
    let fingerprint = "0123456789ABCDEF0123456789ABCDEF01234567";
    let mut config = TorConfig {
        bridges: vec![BridgeConfig {
            bridge_type: BridgeType::Plain,
            address: "127.0.0.1:1234".into(),
            fingerprint: Some(fingerprint.into()),
        }],
        ..TorConfig::default()
    };
    assert!(TorTransport::new(config.clone())
        .build_arti_config()
        .is_ok());
    config.bridges[0].address = format!("127.0.0.1:1234 {}", "A".repeat(40));
    assert!(TorTransport::new(config.clone())
        .build_arti_config()
        .is_err());
    config.bridges[0].fingerprint = Some("invalid".into());
    assert!(TorTransport::new(config).build_arti_config().is_err());
}

#[test]
fn zero_limits_are_rejected() {
    for field in 0..4 {
        let mut config = TorConfig::default();
        match field {
            0 => config.max_circuits = 0,
            1 => config.circuit_timeout_secs = 0,
            2 => config.connect_timeout_secs = 0,
            _ => config.request_timeout_secs = 0,
        }
        assert!(TorTransport::new(config).build_arti_config().is_err());
    }
}
