//! Background cleanup task for disappearing messages (S12 §6).

use std::sync::Arc;
use std::time::Duration;

use super::delete::delete_expired_messages;
use super::lifecycle::DisappearingMessageManager;
use super::storage::DisappearingStorage;

/// Default cleanup interval: check every 10 seconds.
pub const DEFAULT_CLEANUP_INTERVAL_SECS: u64 = 10;

/// Background task that periodically deletes expired messages
/// and applies 24h fallback timers (S12 §6).
pub struct DisappearingCleanupTask<S: DisappearingStorage + 'static> {
    manager: Arc<DisappearingMessageManager<S>>,
    cache: super::VolatileKeyCache,
    interval: Duration,
}

impl<S: DisappearingStorage + 'static> DisappearingCleanupTask<S> {
    /// Create a new cleanup task.
    pub fn new(manager: Arc<DisappearingMessageManager<S>>, cache: super::VolatileKeyCache, interval: Duration) -> Self {
        Self { manager, cache, interval }
    }

    /// Create with the default 10-second interval.
    pub fn with_default_interval(manager: Arc<DisappearingMessageManager<S>>, cache: super::VolatileKeyCache) -> Self {
        Self::new(manager, cache, Duration::from_secs(DEFAULT_CLEANUP_INTERVAL_SECS))
    }

    /// Run the cleanup loop (blocks until cancelled): [`run_once`] every interval.
    pub async fn run(&self) {
        loop {
            if let Err(error) = self.run_once().await {
                tracing::error!(%error, "disappearing cleanup failed");
            }
            tokio::time::sleep(self.interval).await;
        }
    }

    /// One cleanup pass (S12 §6, §4.3 step 3, §7):
    /// Resolve legacy fallback deadlines, evict expired keys before deleting
    /// their messages, and checkpoint even when only persisted keys were purged.
    pub async fn run_once(&self) -> super::Result<()> {
        // Resolve legacy unset deadlines first, without extending existing ones.
        // Attempt key eviction even if fallback scheduling fails.
        let fallback = self.manager.apply_fallback_timers().await;
        let deletion = delete_expired_messages(self.manager.storage(), &self.cache).await;
        // Also flush removal of persisted keys when there were no message rows.
        let checkpoint = self.manager.storage().wal_checkpoint().await
            .map_err(super::DisappearError::StorageError);
        fallback?;
        deletion?;
        checkpoint
    }

    /// Get the configured interval.
    pub fn interval(&self) -> Duration {
        self.interval
    }
}
