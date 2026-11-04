//! Adversarial requests and injected SQLite failures from the row-12 review.
use axum_test::TestServer;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use najwa_mailbox::{
    api,
    config::Config,
    db::{CapabilityState, Database},
    state::AppState,
};
use serde_json::{json, Value};
use std::sync::Arc;

fn config(dir: &tempfile::TempDir) -> Config {
    let mut c = Config::default_dev();
    c.server.database_path = dir.path().join("review.db");
    c.pow.registration_always_requires_pow = false;
    c.pow.ephemeral_deposit_min_difficulty = 0;
    c.pow.deposit_pow_threshold_per_min = 1000;
    c.batching.min_hold_secs = 0;
    c.batching.max_hold_secs = 0;
    c.batching.jitter_secs = 0;
    c
}

fn register(
    db: &Database,
    settings: &najwa_mailbox::db::models::CapabilitySettings,
    kind: u8,
    now: i64,
) {
    db.register_capability(&[1; 32], &[2; 32], settings, kind, None, 172800, now)
        .unwrap();
}

fn server(c: Config) -> (TestServer, Arc<Database>) {
    let db = Arc::new(Database::open(&c).unwrap());
    let state = AppState::new(db.clone(), Arc::new(c)).unwrap();
    (TestServer::new(api::router(state)), db)
}

fn trigger(c: &Config, sql: &str) {
    rusqlite::Connection::open(&c.server.database_path)
        .unwrap()
        .execute_batch(sql)
        .unwrap();
}

fn bundle() -> Value {
    json!({"deposit_capability": B64.encode([2;32]), "fetch_capability": B64.encode([1;32]), "bundle": {
        "identity_key": B64.encode([3;32]), "signed_prekey": B64.encode([4;32]),
        "signed_prekey_id": 1, "signed_prekey_signature": B64.encode([5;64]),
        "signed_prekey_timestamp": 123,
        "manifest": {"signature": "opaque"},
        "one_time_prekeys": [{"id":1,"key":B64.encode([6;32])},{"id":2,"key":B64.encode([7;32])}]
    }})
}

#[test]
fn registration_rolls_back_when_mapping_write_fails() {
    let dir = tempfile::tempdir().unwrap();
    let c = config(&dir);
    let db = Database::open(&c).unwrap();
    trigger(&c, "CREATE TRIGGER fail_mapping BEFORE INSERT ON deposit_caps BEGIN SELECT RAISE(ABORT, 'injected'); END;");
    assert!(db
        .register_capability(
            &[1; 32],
            &[2; 32],
            &Default::default(),
            2,
            None,
            172800,
            100
        )
        .is_err());
    assert_eq!(db.active_capability_count().unwrap(), 0);
}

#[test]
fn deposit_rolls_back_when_dedup_write_fails() {
    let dir = tempfile::tempdir().unwrap();
    let c = config(&dir);
    let db = Database::open(&c).unwrap();
    register(&db, &Default::default(), 2, 100);
    trigger(&c, "CREATE TRIGGER fail_dedup BEFORE INSERT ON deposit_dedup BEGIN SELECT RAISE(ABORT, 'injected'); END;");
    assert!(db
        .deposit_message_checked(&[1; 32], &[2; 32], b"mail", 100, &c.batching, 10, 1000)
        .is_err());
    assert_eq!(db.total_message_count().unwrap(), 0);
}

#[test]
fn deactivation_rolls_back_when_erasure_fails() {
    let dir = tempfile::tempdir().unwrap();
    let c = config(&dir);
    let db = Database::open(&c).unwrap();
    register(&db, &Default::default(), 2, 100);
    db.deposit_message(&[1; 32], &[2; 32], b"mail", 100, &c.batching)
        .unwrap();
    trigger(&c, "CREATE TRIGGER fail_erase BEFORE DELETE ON messages BEGIN SELECT RAISE(ABORT, 'injected'); END;");
    assert!(db.deactivate_capability(&[1; 32]).is_err());
    assert_eq!(
        db.capability_state(&[1; 32]).unwrap(),
        CapabilityState::Active
    );
}

#[test]
fn prekey_upload_rolls_back_bundle_on_opk_failure() {
    let dir = tempfile::tempdir().unwrap();
    let c = config(&dir);
    let db = Database::open(&c).unwrap();
    register(&db, &Default::default(), 2, 100);
    db.upload_prekey_bundle(&[1; 32], "old", &[], 10, 100)
        .unwrap();
    trigger(&c, "CREATE TRIGGER fail_opk BEFORE INSERT ON one_time_prekeys BEGIN SELECT RAISE(ABORT, 'injected'); END;");
    assert!(db
        .upload_prekey_bundle(&[1; 32], "new", &[(1, [8; 32])], 10, 100)
        .is_err());
    assert_eq!(
        db.fetch_prekey_bundle(&[1; 32], 2).unwrap().unwrap().0,
        "old"
    );
}

#[test]
fn prekey_fetch_rolls_back_consumption_when_cache_write_fails() {
    let dir = tempfile::tempdir().unwrap();
    let c = config(&dir);
    let db = Database::open(&c).unwrap();
    register(&db, &Default::default(), 1, chrono::Utc::now().timestamp());
    db.upload_prekey_bundle(&[1; 32], "bundle", &[(1, [8; 32]), (2, [9; 32])], 10, 100)
        .unwrap();
    trigger(&c, "CREATE TRIGGER fail_cache BEFORE UPDATE OF prekey_fetch_cache ON capabilities BEGIN SELECT RAISE(ABORT, 'injected'); END;");
    assert!(db.fetch_prekey_bundle(&[1; 32], 1).is_err());
    assert_eq!(db.opk_count(&[1; 32]).unwrap(), 2);
}

#[test]
fn cleanup_honors_registered_retention() {
    let dir = tempfile::tempdir().unwrap();
    let c = config(&dir);
    let db = Database::open(&c).unwrap();
    let now = chrono::Utc::now().timestamp();
    register(
        &db,
        &najwa_mailbox::db::models::CapabilitySettings {
            retention_days: 1,
            ..Default::default()
        },
        2,
        now,
    );
    db.deposit_message(
        &[1; 32],
        &[2; 32],
        b"old fetched mail",
        now - 2 * 86400,
        &c.batching,
    )
    .unwrap();
    db.deposit_message(&[1; 32], &[2; 32], b"unfetched mail", now, &c.batching)
        .unwrap();
    db.fetch_messages(&[1; 32], 1, now).unwrap();
    db.cleanup(now, 14 * 86400, 100).unwrap();
    assert_eq!(db.total_message_count().unwrap(), 1);
}

#[tokio::test]
async fn registration_rejects_lower_difficulty_challenge_from_another_endpoint() {
    let dir = tempfile::tempdir().unwrap();
    let mut c = config(&dir);
    c.pow.registration_always_requires_pow = true;
    c.pow.min_difficulty = 16;
    let db = Arc::new(Database::open(&c).unwrap());
    let state = AppState::new(db.clone(), Arc::new(c)).unwrap();
    let s = TestServer::new(api::router(state.clone()));
    let challenge = [19; 32];
    let ts = chrono::Utc::now().timestamp() as u64;
    state.challenges.issue(challenge, 8, ts as i64 + 300);
    let binding = [[1; 32], [2; 32]].concat();
    let (nonce, hash) = (0..)
        .map(|nonce| {
            (
                nonce,
                najwa_mailbox::pow::pow_hash(&challenge, &binding, ts, &[0; 32], nonce),
            )
        })
        .find(|(_, hash)| hash[0] == 0 && hash[1] != 0)
        .unwrap();
    let res = s.post("/v1/capability/register").json(&json!({
        "fetch_capability":B64.encode([1;32]), "deposit_capability":B64.encode([2;32]),
        "pow_solution":{"challenge":B64.encode(challenge),"timestamp":ts,"nonce":nonce,"hash":B64.encode(hash)}
    })).await;
    assert_eq!(res.status_code(), 400);
    assert_eq!(db.active_capability_count().unwrap(), 0);
}

#[tokio::test]
async fn registered_message_size_is_enforced_and_status_uses_ephemeral_quota() {
    let dir = tempfile::tempdir().unwrap();
    let c = config(&dir);
    let quota = c.quotas.ephemeral_max_messages;
    let (s, db) = server(c);
    register(
        &db,
        &najwa_mailbox::db::models::CapabilitySettings {
            max_message_size: 4,
            retention_days: 3,
        },
        1,
        chrono::Utc::now().timestamp(),
    );
    let res = s
        .post("/v1/deposit")
        .json(&json!({"deposit_capability":B64.encode([2;32]),"blob":B64.encode(b"large")}))
        .await;
    assert_eq!(res.status_code(), 413);
    let res = s
        .post("/v1/status")
        .json(&json!({"fetch_capability":B64.encode([1;32])}))
        .await;
    let body: Value = res.json();
    assert_eq!(body["quota_remaining"], quota);
    assert_eq!(body["current_retention_days"], 3);
}

#[tokio::test]
async fn opk_upload_retries_at_capacity_are_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let mut c = config(&dir);
    c.quotas.max_opks_per_capability = 2;
    let (s, db) = server(c);
    register(&db, &Default::default(), 2, chrono::Utc::now().timestamp());
    for _ in 0..2 {
        assert_eq!(
            s.post("/v1/prekey/upload")
                .json(&bundle())
                .await
                .status_code(),
            200
        );
    }
    assert_eq!(db.opk_count(&[1; 32]).unwrap(), 2);
}

#[tokio::test]
async fn prekey_pow_starts_at_configured_threshold() {
    let dir = tempfile::tempdir().unwrap();
    let c = config(&dir);
    let (s, db) = server(c);
    register(&db, &Default::default(), 2, chrono::Utc::now().timestamp());
    assert_eq!(
        s.post("/v1/prekey/upload")
            .json(&bundle())
            .await
            .status_code(),
        200
    );
    for _ in 0..5 {
        assert_eq!(
            s.post("/v1/prekey/fetch")
                .json(&json!({"deposit_capability":B64.encode([2;32])}))
                .await
                .status_code(),
            200
        );
    }
    assert_eq!(
        s.post("/v1/prekey/fetch")
            .json(&json!({"deposit_capability":B64.encode([2;32])}))
            .await
            .status_code(),
        429
    );
}

#[test]
fn omitted_optional_config_sections_match_empty_sections() {
    let base =
        "[server]\ndatabase_path='test.db'\n[quotas]\n[pow]\n[rate_limits]\n[cleanup]\n[logging]\n";
    let absent: Config = toml::from_str(base).unwrap();
    let empty: Config = toml::from_str(&format!("{base}[opk]\n[capability_expiry]\n")).unwrap();
    assert_eq!(absent.opk.refuse_last_opk, empty.opk.refuse_last_opk);
    assert_eq!(
        absent.opk.low_alert_threshold,
        empty.opk.low_alert_threshold
    );
    assert_eq!(
        absent.capability_expiry.ephemeral_max_lifetime_hours,
        empty.capability_expiry.ephemeral_max_lifetime_hours
    );
}

#[test]
fn independent_database_handles_cannot_overshoot_quota() {
    let dir = tempfile::tempdir().unwrap();
    let c = config(&dir);
    let db = Database::open(&c).unwrap();
    register(&db, &Default::default(), 2, 100);
    let barrier = Arc::new(std::sync::Barrier::new(8));
    let mut tasks = Vec::new();
    for n in 0..8 {
        let peer = Database::open(&c).unwrap();
        let b = barrier.clone();
        let batching = c.batching.clone();
        tasks.push(std::thread::spawn(move || {
            b.wait();
            matches!(
                peer.deposit_message_checked(&[1; 32], &[2; 32], &[n], 100, &batching, 1, 100)
                    .unwrap(),
                najwa_mailbox::db::DepositOutcome::Stored(_)
            )
        }));
    }
    assert_eq!(
        tasks
            .into_iter()
            .filter_map(|t| t.join().ok())
            .filter(|stored| *stored)
            .count(),
        1
    );
    assert_eq!(db.total_message_count().unwrap(), 1);
}

#[test]
fn expired_or_deactivated_capabilities_cannot_be_written() {
    let dir = tempfile::tempdir().unwrap();
    let c = config(&dir);
    let db = Database::open(&c).unwrap();
    register(&db, &Default::default(), 1, 100);
    assert!(matches!(
        db.deposit_message_checked(&[1; 32], &[2; 32], b"expired", 172901, &c.batching, 10, 100)
            .unwrap(),
        najwa_mailbox::db::DepositOutcome::Dropped
    ));
    db.upload_prekey_bundle(&[1; 32], "old", &[(1, [8; 32]), (2, [9; 32])], 10, 101)
        .unwrap();
    db.fetch_prekey_bundle(&[1; 32], 1).unwrap();
    db.deactivate_capability(&[1; 32]).unwrap();
    assert!(db.fetch_prekey_bundle(&[1; 32], 1).unwrap().is_none());
    assert!(db
        .upload_prekey_bundle(&[1; 32], "new", &[], 10, 101)
        .is_err());
    assert_eq!(db.total_message_count().unwrap(), 0);
}

#[tokio::test]
async fn malformed_bundle_and_capability_settings_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let c = config(&dir);
    let (s, db) = server(c);
    for fields in [
        json!({"capability_type":3}),
        json!({"settings":{"retention_days":0}}),
        json!({"settings":{"max_message_size":999999}}),
    ] {
        let mut req =
            json!({"fetch_capability":B64.encode([1;32]),"deposit_capability":B64.encode([2;32])});
        req.as_object_mut()
            .unwrap()
            .extend(fields.as_object().unwrap().clone());
        assert_eq!(
            s.post("/v1/capability/register")
                .json(&req)
                .await
                .status_code(),
            400
        );
    }
    register(&db, &Default::default(), 2, chrono::Utc::now().timestamp());
    let mut bad = bundle();
    bad["bundle"]["signed_prekey_signature"] = json!("not base64");
    assert_eq!(
        s.post("/v1/prekey/upload").json(&bad).await.status_code(),
        400
    );
    assert_eq!(db.opk_count(&[1; 32]).unwrap(), 0);
    assert_eq!(s.post("/v1/attestation").await.status_code(), 200);
}

#[test]
fn wide_json_objects_are_validated_without_quadratic_duplicate_search() {
    let fields: Vec<_> = (0..20_000).map(|i| format!("\"field{i}\":0")).collect();
    let json = format!("{{{}}}", fields.join(","));
    najwa_mailbox::api::hardening::validate_json(json.as_bytes()).unwrap();
    let duplicate = format!("{{{},\"field0\":1}}", fields.join(","));
    assert!(najwa_mailbox::api::hardening::validate_json(duplicate.as_bytes()).is_err());
}

#[tokio::test]
async fn slow_responses_raise_adaptive_pow_load() {
    let dir = tempfile::tempdir().unwrap();
    let c = config(&dir);
    let db = Arc::new(Database::open(&c).unwrap());
    let state = AppState::new(db, Arc::new(c)).unwrap();
    let router = axum::Router::new()
        .route(
            "/slow",
            axum::routing::get(|| async {
                tokio::time::sleep(std::time::Duration::from_millis(110)).await;
                "ok"
            }),
        )
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            api::hardening::fixed_deadline,
        ));
    let server = TestServer::new(router);
    assert_eq!(state.estimated_load_percent(), 0);
    server.get("/slow").await.assert_status_ok();
    assert_eq!(state.estimated_load_percent(), 10);
}
