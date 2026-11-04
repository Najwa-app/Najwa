//! Periodic retention cleanup task (S16 §10).

use std::sync::Arc;
use std::time::Duration;

use tracing::{info, warn};

use crate::config::CleanupConfig;
use crate::db::Database;

/// Spawn the background cleanup loop.
pub fn spawn_cleanup_task(db: Arc<Database>, config: CleanupConfig, retention_days: u32) {
    let interval = Duration::from_secs(config.interval_secs);
    let retention_secs = retention_days as i64 * 86_400;
    let vacuum_threshold = config.vacuum_threshold_percent;

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.tick().await; // first tick is immediate — skip it
        loop {
            ticker.tick().await;
            let now = chrono::Utc::now().timestamp();
            match db.cleanup(now, retention_secs, vacuum_threshold) {
                Ok(stats) => {
                    if stats.messages_deleted > 0
                        || stats.challenges_deleted > 0
                        || stats.caps_deleted > 0
                        || stats.vacuumed
                    {
                        info!(
                            messages = stats.messages_deleted,
                            challenges = stats.challenges_deleted,
                            capabilities = stats.caps_deleted,
                            vacuumed = stats.vacuumed,
                            "retention cleanup completed"
                        );
                    }
                }
                Err(e) => {
                    warn!(error = %e, "retention cleanup failed");
                }
            }
        }
    });
}
