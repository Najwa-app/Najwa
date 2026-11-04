//! Library inactivity auto-lock manager. The local service uses its own idle
//! timer and does not call this module.
//!
//! Provides configurable auto-lock with triggers for:
//! - Inactivity timeout (default 5 minutes)
//! - App minimize/background (mobile default ON, desktop OFF)
//! - OS screen lock (default ON)
//!
//! On lock, all sensitive memory is zeroized:
//! - IK_priv (identity private key)
//! - Ratchet states (chain keys)
//! - db_key (database encryption key)
//! - Message cache (decrypted messages)
//! - Clipboard contents

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

/// Default inactivity timeout in seconds (5 minutes).
pub const DEFAULT_TIMEOUT_SECS: u32 = 300;

/// Minimum inactivity timeout (1 minute). The user cannot disable the
/// inactivity lock entirely, so a `0` or
/// otherwise below-minimum value is clamped up rather than allowed to turn the
/// lock off.
pub const INACTIVITY_TIMEOUT_MIN_SECS: u32 = 60;

/// Maximum inactivity timeout (60 minutes). A huge value must not
/// effectively disable the lock either.
pub const INACTIVITY_TIMEOUT_MAX_SECS: u32 = 3600;

/// Auto-lock settings (serializable for persistence).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoLockSettings {
    /// Inactivity timeout in seconds (default: 300 = 5 minutes).
    pub timeout_secs: u32,
    /// Lock when app is minimized/backgrounded (default: OFF desktop, ON mobile).
    pub lock_on_minimize: bool,
    /// Lock when OS screen locks (default: ON).
    pub lock_on_screen_lock: bool,
}

impl Default for AutoLockSettings {
    fn default() -> Self {
        Self {
            timeout_secs: DEFAULT_TIMEOUT_SECS,
            lock_on_minimize: false, // Desktop default; mobile overrides to true
            lock_on_screen_lock: true,
        }
    }
}

/// Inactivity auto-lock manager.
///
/// Tracks user activity and triggers lock when the inactivity timeout
/// is exceeded, or when the app is minimized/screen locks (if configured).
///
/// On lock, the caller should:
/// 1. Zeroize IK_priv, ratchet states, db_key, message cache
/// 2. Clear clipboard contents
///
/// On lock, the caller MUST **NOT**:
/// - Stop cover traffic. S10 §11: the cover scheduler, its
///   capabilities, envelope secrets, and slot schedule survive the lock **in
///   memory** — they are not message keys and decrypt no user content.
///   Starting and stopping the cover stream in sync with user presence would
///   broadcast the exact activity timeline cover traffic exists to hide.
/// - Close all Tor circuits, for the same reason: cover polls and deposits
///   continue unchanged while locked.
///
/// (Steps 3 and 4 previously listed here instructed both forbidden actions.
/// No caller implemented them — `trigger_lock` only flips a flag — but the
/// contract is what a future caller would follow, so it is corrected here.)
pub struct AutoLockManager {
    /// Inactivity timeout duration.
    timeout: Duration,
    /// Whether to lock on app minimize/background.
    lock_on_minimize: bool,
    /// Whether to lock on OS screen lock.
    lock_on_screen_lock: bool,
    /// Timestamp of last user activity.
    last_activity: RwLock<Instant>,
    /// Whether the app is currently locked.
    locked: AtomicBool,
}

impl AutoLockManager {
    /// Create a new auto-lock manager from settings.
    pub fn new(settings: &AutoLockSettings) -> Self {
        // Clamp to [MIN, MAX]. An out-of-range `timeout_secs`
        // (e.g. 0 or a huge value) MUST NOT silently disable the inactivity
        // lock — `auto_lock_disabled = FALSE`.
        let timeout_secs = settings
            .timeout_secs
            .clamp(INACTIVITY_TIMEOUT_MIN_SECS, INACTIVITY_TIMEOUT_MAX_SECS);
        Self {
            timeout: Duration::from_secs(timeout_secs as u64),
            lock_on_minimize: settings.lock_on_minimize,
            lock_on_screen_lock: settings.lock_on_screen_lock,
            last_activity: RwLock::new(Instant::now()),
            locked: AtomicBool::new(false),
        }
    }

    /// Record user activity (keystroke, tap, mouse move).
    ///
    /// Resets the inactivity timer.
    pub async fn record_activity(&self) {
        *self.last_activity.write().await = Instant::now();
    }

    /// Check if lock should trigger due to inactivity (called on timer).
    ///
    /// Returns `true` if a lock was triggered.
    pub async fn check_timeout(&self) -> bool {
        let activity = self.last_activity.read().await;
        // Keep this snapshot locked until the transition; unlock cannot reset
        // activity and then be overtaken by a stale timeout decision.
        if activity.elapsed() >= self.timeout && !self.locked.swap(true, Ordering::SeqCst) {
            tracing::info!("App locked due to inactivity");
            return true;
        }
        false
    }

    /// Called when app is minimized/backgrounded.
    ///
    /// Triggers lock if `lock_on_minimize` is enabled.
    pub async fn on_app_minimize(&self) {
        if self.lock_on_minimize {
            self.trigger_lock().await;
        }
    }

    /// Called when OS screen locks.
    ///
    /// Triggers lock if `lock_on_screen_lock` is enabled.
    pub async fn on_screen_lock(&self) {
        if self.lock_on_screen_lock {
            self.trigger_lock().await;
        }
    }

    /// Perform lock: mark as locked and log.
    ///
    /// The actual memory zeroization is performed by the caller
    /// via a lock callback, since this module doesn't hold references
    /// to the sensitive data structures directly. The caller's lock
    /// contract, in order:
    /// 1. Volatile disappearing-message keys (S12 §4.3): persist them under
    ///    db_key before zeroizing; a key that is zeroized without being
    ///    persisted is lost, and its message becomes unreadable.
    /// 2. Zeroize IK_priv, message keys, ratchet state, db_key.
    /// 3. Close the database connection.
    /// 4. COVER TRAFFIC CONTINUES (S10 §11). Cover capabilities, envelope
    ///    secrets, and the slot schedule survive the lock in memory — they
    ///    decrypt nothing, and stopping/starting the cover stream in sync
    ///    with user presence would broadcast the very timeline cover exists
    ///    to hide.
    /// 5. Display the unlock screen.
    async fn trigger_lock(&self) {
        self.locked.store(true, Ordering::SeqCst);
        tracing::info!("App locked due to inactivity/minimize/screen lock");
    }

    /// Check if the app is currently locked.
    pub fn is_locked(&self) -> bool {
        self.locked.load(Ordering::SeqCst)
    }

    /// Unlock the app (after successful authentication).
    ///
    /// Resets the activity timer.
    pub async fn unlock(&self) {
        let mut activity = self.last_activity.write().await;
        *activity = Instant::now();
        self.locked.store(false, Ordering::SeqCst);
        tracing::info!("App unlocked");
    }

    /// Get the configured timeout duration.
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Test-only: pretend the last activity was `secs` seconds ago, so
    /// `check_timeout` can be exercised without waiting out the (now clamped,
    /// ≥ 60 s) real timeout.
    #[cfg(test)]
    async fn set_stale_for_test(&self, secs: u64) {
        let past = Instant::now()
            .checked_sub(Duration::from_secs(secs))
            .expect("monotonic clock older than the backdate window");
        *self.last_activity.write().await = past;
    }

    /// Check if lock-on-minimize is enabled.
    pub fn lock_on_minimize_enabled(&self) -> bool {
        self.lock_on_minimize
    }

    /// Check if lock-on-screen-lock is enabled.
    pub fn lock_on_screen_lock_enabled(&self) -> bool {
        self.lock_on_screen_lock
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn default_settings() {
        let settings = AutoLockSettings::default();
        assert_eq!(settings.timeout_secs, 300);
        assert!(!settings.lock_on_minimize);
        assert!(settings.lock_on_screen_lock);
    }

    #[tokio::test]
    async fn new_manager_not_locked() {
        let manager = AutoLockManager::new(&AutoLockSettings::default());
        assert!(!manager.is_locked());
    }

    #[tokio::test]
    async fn timeout_triggers_lock() {
        // 0 is clamped up to the minimum (see `timeout_is_clamped`), so simulate
        // inactivity past the minimum timeout instead of relying on a 0 timeout.
        let settings = AutoLockSettings {
            timeout_secs: INACTIVITY_TIMEOUT_MIN_SECS,
            lock_on_minimize: false,
            lock_on_screen_lock: false,
        };
        let manager = AutoLockManager::new(&settings);
        manager
            .set_stale_for_test(INACTIVITY_TIMEOUT_MIN_SECS as u64 + 1)
            .await;

        let triggered = manager.check_timeout().await;
        assert!(triggered);
        assert!(manager.is_locked());
    }

    #[tokio::test]
    async fn timeout_is_clamped() {
        // 0 (would disable the lock) clamps up to MIN; a huge
        // value clamps down to MAX.
        let too_small = AutoLockManager::new(&AutoLockSettings {
            timeout_secs: 0,
            ..AutoLockSettings::default()
        });
        assert_eq!(
            too_small.timeout().as_secs(),
            INACTIVITY_TIMEOUT_MIN_SECS as u64
        );
        let too_big = AutoLockManager::new(&AutoLockSettings {
            timeout_secs: 999_999,
            ..AutoLockSettings::default()
        });
        assert_eq!(
            too_big.timeout().as_secs(),
            INACTIVITY_TIMEOUT_MAX_SECS as u64
        );
    }

    #[tokio::test]
    async fn activity_resets_timer() {
        let settings = AutoLockSettings {
            timeout_secs: 1,
            lock_on_minimize: false,
            lock_on_screen_lock: false,
        };
        let manager = AutoLockManager::new(&settings);

        // Record activity to reset timer
        manager.record_activity().await;

        // Should not trigger immediately
        let triggered = manager.check_timeout().await;
        assert!(!triggered);
        assert!(!manager.is_locked());
    }

    #[tokio::test]
    async fn minimize_triggers_lock_when_enabled() {
        let settings = AutoLockSettings {
            timeout_secs: 300,
            lock_on_minimize: true,
            lock_on_screen_lock: false,
        };
        let manager = AutoLockManager::new(&settings);

        manager.on_app_minimize().await;
        assert!(manager.is_locked());
    }

    #[tokio::test]
    async fn minimize_does_not_trigger_when_disabled() {
        let settings = AutoLockSettings {
            timeout_secs: 300,
            lock_on_minimize: false,
            lock_on_screen_lock: false,
        };
        let manager = AutoLockManager::new(&settings);

        manager.on_app_minimize().await;
        assert!(!manager.is_locked());
    }

    #[tokio::test]
    async fn screen_lock_triggers_lock_when_enabled() {
        let settings = AutoLockSettings {
            timeout_secs: 300,
            lock_on_minimize: false,
            lock_on_screen_lock: true,
        };
        let manager = AutoLockManager::new(&settings);

        manager.on_screen_lock().await;
        assert!(manager.is_locked());
    }

    #[tokio::test]
    async fn screen_lock_does_not_trigger_when_disabled() {
        let settings = AutoLockSettings {
            timeout_secs: 300,
            lock_on_minimize: false,
            lock_on_screen_lock: false,
        };
        let manager = AutoLockManager::new(&settings);

        manager.on_screen_lock().await;
        assert!(!manager.is_locked());
    }

    #[tokio::test]
    async fn unlock_resets_lock_state() {
        let settings = AutoLockSettings {
            timeout_secs: 300,
            lock_on_minimize: true,
            lock_on_screen_lock: false,
        };
        let manager = AutoLockManager::new(&settings);

        manager.on_app_minimize().await;
        assert!(manager.is_locked());

        manager.unlock().await;
        assert!(!manager.is_locked());
    }

    #[tokio::test]
    async fn timeout_does_not_double_lock() {
        let settings = AutoLockSettings {
            timeout_secs: INACTIVITY_TIMEOUT_MIN_SECS,
            lock_on_minimize: false,
            lock_on_screen_lock: false,
        };
        let manager = AutoLockManager::new(&settings);
        manager
            .set_stale_for_test(INACTIVITY_TIMEOUT_MIN_SECS as u64 + 1)
            .await;

        let first = manager.check_timeout().await;
        assert!(first);

        // Already locked — should not trigger again
        let second = manager.check_timeout().await;
        assert!(!second);
    }

    #[tokio::test]
    async fn getter_methods() {
        let settings = AutoLockSettings {
            timeout_secs: 120,
            lock_on_minimize: true,
            lock_on_screen_lock: false,
        };
        let manager = AutoLockManager::new(&settings);

        assert_eq!(manager.timeout(), Duration::from_secs(120));
        assert!(manager.lock_on_minimize_enabled());
        assert!(!manager.lock_on_screen_lock_enabled());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_timeouts_claim_one_lock_and_unlock_resets_activity() {
        let manager = std::sync::Arc::new(AutoLockManager::new(&AutoLockSettings::default()));
        manager.set_stale_for_test(301).await;
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..32 {
            let manager = manager.clone();
            tasks.spawn(async move { manager.check_timeout().await });
        }
        let mut claimed = 0;
        while let Some(result) = tasks.join_next().await {
            claimed += usize::from(result.unwrap());
        }
        assert_eq!(claimed, 1);
        manager.unlock().await;
        assert!(!manager.check_timeout().await);
        assert!(!manager.is_locked());
    }
}
