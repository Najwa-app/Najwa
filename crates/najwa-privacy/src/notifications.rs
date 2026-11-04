//! Notification content control (minimal by default).
//!
//! Library notification-privacy levels; the application does not use this module.
//! Controls what information is exposed in OS notifications.
//! Default level is `Minimal`.

use serde::{Deserialize, Serialize};

/// Notification privacy level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum NotificationLevel {
    /// Show full message content and sender name.
    Full,
    /// Show sender name only ("Message from Alice").
    SenderOnly,
    /// Generic notification ("New message").
    #[default]
    Minimal,
    /// No notification (badge count only).
    Silent,
}

/// Notification configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationConfig {
    /// Privacy level for notification content.
    pub level: NotificationLevel,
    /// Whether to play a sound.
    pub sound: bool,
    /// Whether to vibrate.
    pub vibration: bool,
    /// Whether to show badge count.
    pub badge_count: bool,
}

impl Default for NotificationConfig {
    fn default() -> Self {
        Self {
            level: NotificationLevel::Minimal,
            sound: true,
            vibration: true,
            badge_count: true,
        }
    }
}

/// Platform-agnostic notification payload.
#[derive(Debug, Clone, Default)]
pub struct PlatformNotification {
    /// Notification title.
    pub title: String,
    /// Notification body text.
    pub body: String,
    /// If true, only update badge count — no visible notification.
    pub silent: bool,
    /// If true, only show badge — no banner or alert.
    pub badge_only: bool,
    /// Whether to play sound.
    pub sound: bool,
    /// Whether to vibrate.
    pub vibration: bool,
}

/// Build a platform notification respecting the configured privacy level.
pub fn build_notification(
    config: &NotificationConfig,
    sender_name: &str,
    message_preview: &str,
) -> PlatformNotification {
    let base = PlatformNotification {
        sound: config.sound,
        vibration: config.vibration,
        ..Default::default()
    };

    match config.level {
        NotificationLevel::Full => PlatformNotification {
            // Full → title = "Najwa - {sender_name}", body = preview.
            title: format!("Najwa - {sender_name}"),
            body: message_preview.to_string(),
            ..base
        },
        NotificationLevel::SenderOnly => PlatformNotification {
            title: "Najwa".to_string(),
            body: format!("Message from {}", sender_name),
            ..base
        },
        NotificationLevel::Minimal => PlatformNotification {
            title: "Najwa".to_string(),
            body: "New message".to_string(),
            ..base
        },
        NotificationLevel::Silent => PlatformNotification {
            silent: true,
            badge_only: true,
            sound: false,
            vibration: false,
            ..base
        },
    }
}

/// Platform-specific lock screen visibility.
///
/// On Android: set `Notification.VISIBILITY_SECRET` on notification channel.
/// On iOS: use `UNNotificationServiceExtension` to strip content.
/// On Desktop: respect `NotificationLevel` directly (no lock screen concept).
pub fn configure_lock_screen_visibility(_level: NotificationLevel) {
    // Platform-specific implementation deferred to native bridge.
    // Android: Notification.VISIBILITY_SECRET
    // iOS: UNNotificationServiceExtension modifies before display
    // Desktop: no-op (no lock screen concept)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_notification_level_is_minimal() {
        assert_eq!(NotificationLevel::default(), NotificationLevel::Minimal);
    }

    #[test]
    fn default_config_is_minimal_with_sound() {
        let config = NotificationConfig::default();
        assert_eq!(config.level, NotificationLevel::Minimal);
        assert!(config.sound);
        assert!(config.vibration);
        assert!(config.badge_count);
    }

    #[test]
    fn build_notification_full_level() {
        let config = NotificationConfig {
            level: NotificationLevel::Full,
            ..Default::default()
        };
        let n = build_notification(&config, "Alice", "Hello there!");
        assert_eq!(n.title, "Najwa - Alice");
        assert_eq!(n.body, "Hello there!");
        assert!(!n.silent);
        assert!(!n.badge_only);
        assert!(n.sound);
    }

    #[test]
    fn build_notification_sender_only() {
        let config = NotificationConfig {
            level: NotificationLevel::SenderOnly,
            ..Default::default()
        };
        let n = build_notification(&config, "Bob", "secret stuff");
        assert_eq!(n.title, "Najwa");
        assert_eq!(n.body, "Message from Bob");
        assert!(!n.body.contains("secret"));
    }

    #[test]
    fn build_notification_minimal() {
        let config = NotificationConfig::default();
        let n = build_notification(&config, "Eve", "attack plan");
        assert_eq!(n.title, "Najwa");
        assert_eq!(n.body, "New message");
        assert!(!n.body.contains("Eve"));
        assert!(!n.body.contains("attack"));
    }

    #[test]
    fn build_notification_silent() {
        let config = NotificationConfig {
            level: NotificationLevel::Silent,
            ..Default::default()
        };
        let n = build_notification(&config, "Mallory", "hi");
        assert!(n.silent);
        assert!(n.badge_only);
        assert!(!n.sound);
        assert!(!n.vibration);
    }

    #[test]
    fn notification_respects_sound_setting() {
        let config = NotificationConfig {
            level: NotificationLevel::Full,
            sound: false,
            vibration: false,
            badge_count: true,
        };
        let n = build_notification(&config, "Alice", "test");
        assert!(!n.sound);
        assert!(!n.vibration);
    }
}
