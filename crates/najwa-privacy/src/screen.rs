//! Library screenshot and screen recording protection; the application does not use this module.
//!
//! Provides a platform-agnostic trait for preventing screenshots,
//! detecting screen capture, and managing app-switcher overlays.
//! Platform-specific implementations delegate to native APIs.

/// Trait for platform-specific screen protection.
pub trait ScreenProtection {
    /// Prevent screenshots and screen recording.
    fn enable_secure_mode(&self);
    /// Allow screenshots (for settings/about screens only).
    fn disable_secure_mode(&self);
    /// Detect active screen capture.
    fn is_screen_captured(&self) -> bool;
    /// Apply blur overlay for app switcher.
    fn apply_switcher_overlay(&self);
    /// Remove blur overlay when app resumes.
    fn remove_switcher_overlay(&self);
}

/// Desktop screen protection.
///
/// On desktop platforms, screenshot prevention is limited.
/// App switcher protection can optionally minimize to tray or show
/// a blank/splash window when losing focus.
pub struct DesktopScreenProtection {
    /// Whether secure mode is currently active.
    secure_mode: std::sync::atomic::AtomicBool,
    /// Whether the switcher overlay is currently applied.
    overlay_active: std::sync::atomic::AtomicBool,
}

impl DesktopScreenProtection {
    /// Create a new desktop screen protection instance.
    pub fn new() -> Self {
        Self {
            secure_mode: std::sync::atomic::AtomicBool::new(false),
            overlay_active: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Check if secure mode is currently enabled.
    pub fn is_secure_mode(&self) -> bool {
        self.secure_mode.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Check if the switcher overlay is currently active.
    pub fn is_overlay_active(&self) -> bool {
        self.overlay_active
            .load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl Default for DesktopScreenProtection {
    fn default() -> Self {
        Self::new()
    }
}

impl ScreenProtection for DesktopScreenProtection {
    fn enable_secure_mode(&self) {
        self.secure_mode
            .store(true, std::sync::atomic::Ordering::Relaxed);
        // Desktop: limited screenshot prevention. This records the state only.
    }

    fn disable_secure_mode(&self) {
        self.secure_mode
            .store(false, std::sync::atomic::Ordering::Relaxed);
    }

    fn is_screen_captured(&self) -> bool {
        // Desktop: no reliable cross-platform detection.
        false
    }

    fn apply_switcher_overlay(&self) {
        self.overlay_active
            .store(true, std::sync::atomic::Ordering::Relaxed);
        // Desktop: minimize to tray or show blank/splash window. This records
        // the state only.
    }

    fn remove_switcher_overlay(&self) {
        self.overlay_active
            .store(false, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Android screen protection stub.
///
/// On Android:
/// - `enable_secure_mode()` sets `FLAG_SECURE` on all activities.
/// - `apply_switcher_overlay()` is handled by `FLAG_SECURE` automatically.
/// - `is_screen_captured()` uses `MediaProjection` detection (Android 14+).
pub struct AndroidScreenProtection;

impl ScreenProtection for AndroidScreenProtection {
    fn enable_secure_mode(&self) {
        // Android: window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        // Implemented via JNI/native bridge
    }

    fn disable_secure_mode(&self) {
        // Android: window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
    }

    fn is_screen_captured(&self) -> bool {
        // Android 14+: Activity.ScreenCaptureCallback
        false
    }

    fn apply_switcher_overlay(&self) {
        // FLAG_SECURE already handles task switcher on Android
    }

    fn remove_switcher_overlay(&self) {
        // No-op on Android (FLAG_SECURE handles this)
    }
}

/// iOS screen protection stub.
///
/// On iOS:
/// - `is_screen_captured()` checks `UIScreen.main.isCaptured`.
/// - `apply_switcher_overlay()` adds `UIVisualEffectView` with `UIBlurEffect`.
/// - `enable_secure_mode()` uses a hidden `UITextField` trick for screenshots.
pub struct IosScreenProtection;

impl ScreenProtection for IosScreenProtection {
    fn enable_secure_mode(&self) {
        // iOS: Add a hidden UITextField with isSecureTextEntry = true
        // over the window to prevent screenshots (known workaround)
    }

    fn disable_secure_mode(&self) {
        // iOS: Remove the hidden secure text field
    }

    fn is_screen_captured(&self) -> bool {
        // iOS: UIScreen.main.isCaptured
        false
    }

    fn apply_switcher_overlay(&self) {
        // In applicationWillResignActive:
        // Add UIVisualEffectView with UIBlurEffect over window
    }

    fn remove_switcher_overlay(&self) {
        // In applicationDidBecomeActive:
        // Remove blur view
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn desktop_secure_mode_toggle() {
        let sp = DesktopScreenProtection::new();
        assert!(!sp.is_secure_mode());

        sp.enable_secure_mode();
        assert!(sp.is_secure_mode());

        sp.disable_secure_mode();
        assert!(!sp.is_secure_mode());
    }

    #[test]
    fn desktop_overlay_toggle() {
        let sp = DesktopScreenProtection::new();
        assert!(!sp.is_overlay_active());

        sp.apply_switcher_overlay();
        assert!(sp.is_overlay_active());

        sp.remove_switcher_overlay();
        assert!(!sp.is_overlay_active());
    }

    #[test]
    fn desktop_screen_capture_always_false() {
        let sp = DesktopScreenProtection::new();
        assert!(!sp.is_screen_captured());
    }

    #[test]
    fn default_desktop_protection() {
        let sp = DesktopScreenProtection::default();
        assert!(!sp.is_secure_mode());
        assert!(!sp.is_overlay_active());
    }
}
