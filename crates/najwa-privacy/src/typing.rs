//! Library typing-indicator manager (off by default). The application never
//! sends typing indicators.
//!
//! Typing indicators are disabled by default.
//! When enabled, they are rate-limited to at most one indicator every 5 seconds.

use std::time::{Duration, Instant};

/// Minimum interval between typing indicator messages: 5 seconds.
pub const MIN_TYPING_INTERVAL_SECS: u64 = 5;

/// A sender's `Started` self-expires after this many seconds: if no
/// further keystroke arrives within the window, the receiver presumes the sender
/// stopped, so an explicit `Stopped` is suppressed — eliminating most `Stopped`
/// events (and keeping the remaining ones conditional, closing the side channel).
pub const STARTED_AUTO_EXPIRY_SECS: u64 = 10;

/// A control message for typing indicators.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypingControl {
    /// User started typing.
    Started,
    /// User stopped typing.
    Stopped,
}

/// Manages typing indicator sending with rate limiting.
///
/// Off by default. When enabled, sends at most
/// one indicator every 5 seconds to avoid leaking typing patterns.
pub struct TypingIndicatorManager {
    /// Whether typing indicators are enabled.
    enabled: bool,
    /// When the last indicator was sent.
    last_sent: Option<Instant>,
    /// Minimum interval between indicator messages.
    min_interval: Duration,
    /// Whether a `Started` has been emitted since the last `Stopped`.
    /// A `Stopped` is emitted ONLY after a `Started` — a lone `Stopped` is a
    /// closed side channel.
    started_sent: bool,
    /// When the emitted `Started` auto-expires on the receiver. Set on
    /// keystroke; once elapsed, `on_stop_typing` suppresses the `Stopped` because
    /// the receiver already presumes the sender stopped.
    started_expiry: Option<Instant>,
}

impl TypingIndicatorManager {
    /// Create a new manager. `enabled` defaults to `false` per privacy policy.
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            last_sent: None,
            min_interval: Duration::from_secs(MIN_TYPING_INTERVAL_SECS),
            started_sent: false,
            started_expiry: None,
        }
    }

    /// Check if typing indicators are enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Enable or disable typing indicators.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
        if !enabled {
            self.started_sent = false;
            self.started_expiry = None;
        }
    }

    /// Called on each keystroke in compose field.
    ///
    /// Returns `Some(TypingControl::Started)` if an indicator should be sent,
    /// or `None` if disabled or rate-limited.
    pub fn on_keystroke(&mut self) -> Option<TypingControl> {
        if !self.enabled {
            return None;
        }

        // Rate limit: at least 5 seconds between indicators
        if let Some(last) = self.last_sent {
            if last.elapsed() < self.min_interval {
                return None;
            }
        }

        self.last_sent = Some(Instant::now());
        self.started_sent = true;
        // The Started auto-expires on the receiver after this window.
        self.started_expiry = Some(Instant::now() + Duration::from_secs(STARTED_AUTO_EXPIRY_SECS));
        Some(TypingControl::Started)
    }

    /// Called when user stops typing (debounced) or sends message.
    ///
    /// Returns `Some(TypingControl::Stopped)` if an indicator should be sent,
    /// or `None` if disabled.
    pub fn on_stop_typing(&mut self) -> Option<TypingControl> {
        if !self.enabled {
            return None;
        }
        // Never emit Stopped without a preceding Started — a lone
        // Stopped is a closed side channel.
        if !self.started_sent {
            return None;
        }
        // If the Started has already auto-expired (no keystroke within
        // STARTED_AUTO_EXPIRY_SECS), the receiver already presumes Stopped —
        // suppress the redundant Stopped event.
        let auto_expired = self.started_expiry.is_none_or(|e| Instant::now() >= e);
        self.started_sent = false;
        self.started_expiry = None;
        if auto_expired {
            None
        } else {
            Some(TypingControl::Stopped)
        }
    }

    /// Get the configured minimum interval.
    pub fn min_interval(&self) -> Duration {
        self.min_interval
    }
}

impl Default for TypingIndicatorManager {
    fn default() -> Self {
        Self::new(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_disabled() {
        let mgr = TypingIndicatorManager::default();
        assert!(!mgr.is_enabled());
    }

    #[test]
    fn disabled_returns_none_on_keystroke() {
        let mut mgr = TypingIndicatorManager::new(false);
        assert!(mgr.on_keystroke().is_none());
    }

    #[test]
    fn disabled_returns_none_on_stop() {
        let mut mgr = TypingIndicatorManager::new(false);
        assert!(mgr.on_stop_typing().is_none());
    }

    #[test]
    fn enabled_first_keystroke_sends_indicator() {
        let mut mgr = TypingIndicatorManager::new(true);
        assert_eq!(mgr.on_keystroke(), Some(TypingControl::Started));
    }

    #[test]
    fn rate_limited_within_interval() {
        let mut mgr = TypingIndicatorManager::new(true);

        // First keystroke sends
        assert_eq!(mgr.on_keystroke(), Some(TypingControl::Started));

        // Immediate second keystroke is rate-limited
        assert!(mgr.on_keystroke().is_none());
    }

    #[test]
    fn rate_limit_resets_after_interval() {
        let mut mgr = TypingIndicatorManager::new(true);
        // Use a very short interval for testing
        mgr.min_interval = Duration::from_millis(10);

        assert_eq!(mgr.on_keystroke(), Some(TypingControl::Started));

        // Wait past the interval
        std::thread::sleep(Duration::from_millis(15));

        assert_eq!(mgr.on_keystroke(), Some(TypingControl::Started));
    }

    #[test]
    fn stop_typing_sends_stopped() {
        let mut mgr = TypingIndicatorManager::new(true);
        // A lone Stopped (no preceding Started) is suppressed.
        assert!(mgr.on_stop_typing().is_none());
        // After a Started, one Stopped is emitted.
        assert_eq!(mgr.on_keystroke(), Some(TypingControl::Started));
        assert_eq!(mgr.on_stop_typing(), Some(TypingControl::Stopped));
        // A second Stopped without a new Started is suppressed.
        assert!(mgr.on_stop_typing().is_none());
    }

    // Once the Started has auto-expired (no keystroke within
    // STARTED_AUTO_EXPIRY_SECS), the receiver already presumes Stopped, so the
    // explicit Stopped is suppressed.
    #[test]
    fn stopped_suppressed_after_auto_expiry() {
        let mut mgr = TypingIndicatorManager::new(true);
        assert_eq!(mgr.on_keystroke(), Some(TypingControl::Started));
        // Force the Started to have already auto-expired.
        mgr.started_expiry = Instant::now().checked_sub(Duration::from_secs(1));
        assert!(mgr.on_stop_typing().is_none());
    }

    #[test]
    fn stop_typing_resets_rate_limit() {
        let mut mgr = TypingIndicatorManager::new(true);

        // First keystroke
        assert_eq!(mgr.on_keystroke(), Some(TypingControl::Started));

        // Regression: stopping must not reset the last Started timestamp.
        mgr.on_stop_typing();

        // The next Started is still subject to the five-second floor.
        assert_eq!(mgr.on_keystroke(), None);
    }

    #[test]
    fn toggle_enabled() {
        let mut mgr = TypingIndicatorManager::new(false);
        assert!(!mgr.is_enabled());

        mgr.set_enabled(true);
        assert!(mgr.is_enabled());
        assert_eq!(mgr.on_keystroke(), Some(TypingControl::Started));

        mgr.set_enabled(false);
        assert!(!mgr.is_enabled());
        assert!(mgr.on_keystroke().is_none());
    }

    #[test]
    fn min_interval_is_5_seconds() {
        let mgr = TypingIndicatorManager::new(true);
        assert_eq!(mgr.min_interval(), Duration::from_secs(5));
    }
}
