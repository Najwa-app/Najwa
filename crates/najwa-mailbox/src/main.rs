//! Najwa Mailbox Server binary — store-and-forward Tor onion service (S16).
//!
//! Run: `najwa-mailbox [path/to/mailbox.toml]` (defaults to `mailbox.toml`).
//! The file must exist and parse; otherwise the server exits (S16 §5).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use najwa_mailbox::{api, config::Config, db::Database, retention, state::AppState};
use tracing::info;

#[cfg(all(test, target_os = "linux"))]
mod startup_tests {
    #[test]
    fn mailbox_disables_dumps_before_loading_config() {
        const CHILD: &str = "NAJWA_TEST_MAILBOX_STARTUP";
        if std::env::var_os(CHILD).is_some() {
            let dir = tempfile::tempdir().unwrap();
            std::env::set_current_dir(dir.path()).unwrap();
            // main reads argv[1] as its config path. A malformed file lets us
            // exercise real startup and stop before opening a DB or listener.
            let config_arg = std::env::args().nth(1).unwrap();
            std::fs::write(config_arg, "invalid = [").unwrap();
            assert_eq!(unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 1, 0, 0, 0) }, 0);
            assert!(super::main().is_err());
            assert_eq!(unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) }, 0);
            let mut limit = libc::rlimit {
                rlim_cur: 1,
                rlim_max: 1,
            };
            assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut limit) }, 0);
            assert_eq!((limit.rlim_cur, limit.rlim_max), (0, 0));
            return;
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "startup_tests::mailbox_disables_dumps_before_loading_config",
                "--nocapture",
            ])
            .env(CHILD, "1")
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

// S01 §6.1: zero every block on release, covering capability tokens and
// blobs held in dependency buffers.
#[global_allocator]
static ALLOCATOR: najwa_crypto::memory::ZeroizingAllocator =
    najwa_crypto::memory::ZeroizingAllocator(std::alloc::System);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    najwa_crypto::initialize()?;
    // Load config
    let config_path = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("mailbox.toml"));
    // No fallback to built-in defaults: a wrong path must not start a server
    // with a database in the working directory.
    let config = Config::load(&config_path)?;

    // Initialize logging
    init_logging(&config);

    info!(
        listen = %format!("{}:{}", config.server.listen_addr, config.server.listen_port),
        health = %format!("127.0.0.1:{}", config.server.health_port),
        db = %config.server.database_path.display(),
        "starting najwa-mailbox server"
    );

    // Open database
    let db = Arc::new(Database::open(&config)?);
    let config = Arc::new(config);

    // Build app state (refuses a MUST-not-start config, e.g. §5's
    // refuse_last_opk = false, and a broken operator key)
    let state = AppState::new(db.clone(), config.clone())?;
    if let Some(retire_at) = state.retire_at() {
        info!(
            retire_at,
            "server is Retiring; new registrations get 503 (S16 §13)"
        );
    }

    // Record server start time for health endpoint
    api::health::record_start_time();

    // Spawn background retention cleanup task
    retention::spawn_cleanup_task(
        db.clone(),
        config.cleanup.clone(),
        config.quotas.default_retention_days,
    );

    // Spawn periodic rate-limiter eviction to bound memory usage
    {
        let register = state.register_limiter.clone();
        let deposit = state.deposit_limiter.clone();
        let fetch = state.fetch_limiter.clone();
        let prekey = state.prekey_fetch_limiter.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(300));
            ticker.tick().await; // skip immediate first tick
            loop {
                ticker.tick().await;
                register.evict_stale();
                deposit.evict_stale();
                fetch.evict_stale();
                prekey.evict_stale();
            }
        });
    }

    // Build API router (Tor-facing)
    let app = api::router(state.clone());

    // Spawn health endpoint on separate port (S16 §3.11 — NOT exposed via Tor)
    let health_state = state.clone();
    let health_port = config.server.health_port;
    tokio::spawn(async move {
        let health_app = axum::Router::new()
            .route("/v1/health", axum::routing::get(api::health::health))
            .with_state(health_state);
        let health_addr: SocketAddr = format!("127.0.0.1:{}", health_port)
            .parse()
            .expect("invalid health port");
        info!(addr = %health_addr, "health endpoint listening (local only)");
        let listener = tokio::net::TcpListener::bind(health_addr)
            .await
            .expect("failed to bind health port");
        axum::serve(listener, health_app).await.ok();
    });

    // Bind and serve main API
    let addr: SocketAddr = format!(
        "{}:{}",
        config.server.listen_addr, config.server.listen_port
    )
    .parse()?;

    // Install the handlers before announcing the listener, so a signal sent
    // once the log line appears is never the default (kill) action.
    let shutdown = shutdown_signal()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!(addr = %addr, "API server listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await?;

    info!("server shut down gracefully");
    Ok(())
}

/// Graceful shutdown on SIGINT or SIGTERM (`docker stop`, `systemctl stop`)
/// on Unix, Ctrl-C elsewhere: stop accepting, finish in-flight requests
/// (S16 §12). Handlers are installed when this is called, not when awaited.
fn shutdown_signal() -> std::io::Result<impl std::future::Future<Output = ()>> {
    #[cfg(unix)]
    let wait = {
        use tokio::signal::unix::{signal, SignalKind};
        let mut interrupt = signal(SignalKind::interrupt())?;
        let mut terminate = signal(SignalKind::terminate())?;
        async move {
            tokio::select! {
                _ = interrupt.recv() => {}
                _ = terminate.recv() => {}
            }
        }
    };
    #[cfg(not(unix))]
    let wait = {
        let mut ctrl_c = tokio::signal::windows::ctrl_c()?;
        async move {
            ctrl_c.recv().await;
        }
    };
    Ok(async move {
        wait.await;
        info!("shutdown signal received, draining requests...");
    })
}

/// Initialize tracing subscriber based on config.
fn init_logging(config: &Config) {
    use tracing_subscriber::{fmt, EnvFilter};

    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&config.logging.level));

    if config.logging.format == "json" {
        fmt()
            .json()
            .with_env_filter(filter)
            .with_target(true)
            .init();
    } else {
        fmt().with_env_filter(filter).with_target(true).init();
    }
}
