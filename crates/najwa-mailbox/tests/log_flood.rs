//! Silent-drop log aggregation (S16 §3.3, §12). Its own test binary: a
//! thread-local subscriber can miss events when another test thread registers
//! the same log callsite at the same moment.

use std::sync::{Arc, Mutex};

use axum_test::TestServer;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use najwa_mailbox::{api, config::Config, db::Database, state::AppState};
use serde_json::json;

#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Deposits to random capabilities need no PoW, so one warning per drop would
/// let anyone flood the log. The first drop logs; the rest of the minute only
/// count.
#[tokio::test]
async fn silent_drop_warning_is_aggregated_not_one_line_per_deposit() {
    let captured = Captured::default();
    let writer = captured.clone();
    // `#[tokio::test]` runs on one thread, so a thread-local subscriber sees
    // every event the handlers emit.
    let _guard = tracing::subscriber::set_default(
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::WARN)
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .finish(),
    );

    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config::default_dev();
    cfg.server.database_path = dir.path().join("drops.db");
    let db = Arc::new(Database::open(&cfg).unwrap());
    let server = TestServer::new(api::router(AppState::new(db, Arc::new(cfg)).unwrap()));
    for i in 0..20u8 {
        let res = server
            .post("/v1/deposit")
            .json(&json!({ "deposit_capability": B64.encode([i; 32]), "blob": B64.encode(b"x") }))
            .await;
        assert_eq!(res.status_code(), 200, "{}", res.text());
    }
    let log = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
    assert_eq!(log.matches("silent drop").count(), 1, "{log}");
    assert!(log.contains("dropped=1"), "{log}");
}
