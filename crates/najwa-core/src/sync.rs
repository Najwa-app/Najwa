//! Background sync tasks: polling, retry, prekey replenishment.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use najwa_protocol::mailbox::client::MailboxClient;

use crate::service::MessagingService;
use crate::storage::CoreStorage;
use crate::types::ReceivedMessage;

/// Default polling interval in seconds.
pub const DEFAULT_POLL_INTERVAL_SECS: u64 = 15;

/// Default retry interval for failed sends in seconds.
pub const DEFAULT_RETRY_INTERVAL_SECS: u64 = 60;

/// Handle for the background sync loop.
///
/// Call `stop()` to gracefully shut down the polling loop.
pub struct BackgroundSync {
    running: Arc<AtomicBool>,
    handle: Option<tokio::task::JoinHandle<()>>,
}

impl BackgroundSync {
    /// Start the background sync loop.
    ///
    /// Spawns a Tokio task that periodically:
    /// 1. Polls mailboxes for new messages
    /// 2. Retries failed sends
    ///
    /// Received messages are dispatched via the provided callback.
    pub fn start<S, M, F>(
        service: Arc<MessagingService<S, M>>,
        poll_interval: Duration,
        on_message: F,
    ) -> Self
    where
        S: CoreStorage + 'static,
        M: MailboxClient + 'static,
        F: Fn(ReceivedMessage) + Send + Sync + 'static,
    {
        let running = Arc::new(AtomicBool::new(true));
        let running_clone = running.clone();

        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(poll_interval);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            while running_clone.load(Ordering::Relaxed) {
                interval.tick().await;

                if !running_clone.load(Ordering::Relaxed) {
                    break;
                }

                // Poll for new messages
                match service.poll_messages().await {
                    Ok(messages) => {
                        for msg in messages {
                            on_message(msg);
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "background poll failed");
                    }
                }
            }

            tracing::info!("background sync loop stopped");
        });

        Self {
            running,
            handle: Some(handle),
        }
    }

    /// Signal the background loop to stop.
    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }

    /// Check if the background loop is still running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    /// Wait for the background loop to finish after `stop()`.
    pub async fn join(mut self) {
        self.stop();
        if let Some(handle) = self.handle.take() {
            let _ = handle.await;
        }
    }
}

impl Drop for BackgroundSync {
    fn drop(&mut self) {
        self.stop();
    }
}
