//! Privacy hardening and account lifecycle for Najwa.
//!
//! The application uses local profile erasure (`lifecycle::emergency`,
//! S13 §10) and the file-erasure helpers in `lifecycle::deletion`.
//!
//! Library modules the application does not use:
//! - Notification content control: level-based privacy
//! - Screen protection: screenshot/recording prevention trait
//! - Clipboard security with timed clear
//! - Typing indicators: off by default, rate-limited
//! - Link preview handling: off by default, Tor-routed
//! - DNS leak self-test with structured reporting
//! - Inactivity auto-lock with configurable timeout
//! - A 10-step account deletion procedure (`lifecycle::deletion::delete_account`),
//!   plus mailbox-lifecycle verification (pin wrapping, capability expiry)

pub mod clipboard;
pub mod dns;
pub mod lifecycle;
pub mod links;
pub mod notifications;
pub mod screen;
pub mod typing;

/// Convenience re-exports.
pub mod prelude {
    pub use crate::clipboard::{
        ClipboardBackend, ClipboardError, ClipboardManager, DEFAULT_CLIPBOARD_TIMEOUT_SECS,
    };
    pub use crate::dns::{DnsLeakResult, DnsLeakTest};
    pub use crate::lifecycle::autolock::{AutoLockManager, AutoLockSettings, DEFAULT_TIMEOUT_SECS};
    pub use crate::lifecycle::deletion::{
        delete_dkm, overwrite_and_delete, secure_delete_database, secure_delete_directory,
        DeletionError, DeletionReport,
    };
    pub use crate::lifecycle::verification::{
        ExpirationStatus, MailboxVerifier, OnionPinRecord, PinStatus,
    };
    pub use crate::links::{LinkError, LinkPreview, LinkPreviewConfig, PreviewMode};
    pub use crate::notifications::{
        build_notification, NotificationConfig, NotificationLevel, PlatformNotification,
    };
    pub use crate::screen::{
        AndroidScreenProtection, DesktopScreenProtection, IosScreenProtection, ScreenProtection,
    };
    pub use crate::typing::{TypingControl, TypingIndicatorManager, MIN_TYPING_INTERVAL_SECS};
}
