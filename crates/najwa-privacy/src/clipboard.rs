//! Library clipboard policy and timed clearing; the application does not use this module.
//! Hosts supply their platform backend. Without one, copying fails explicitly.

use std::sync::{Arc, Mutex};
use std::time::Duration;
use thiserror::Error;
use zeroize::Zeroizing;

pub const DEFAULT_CLIPBOARD_TIMEOUT_SECS: u64 = 30;

#[derive(Debug, Error)]
pub enum ClipboardError {
    #[error("seed phrase copy denied: manual transcription only")]
    SeedPhraseCopyDenied,
    #[error("clipboard platform error: {0}")]
    PlatformError(String),
}

/// Platform adapter. Comparison and clearing MUST be atomic with respect to
/// other writes; a timeout must never erase text copied by another application.
/// `sensitive` carries the platform's local-only / sensitive-content flags.
pub trait ClipboardBackend: Send + Sync {
    fn set_text(&self, text: &str, sensitive: bool) -> Result<(), ClipboardError>;
    fn clear_if_matches(&self, expected: &str) -> Result<(), ClipboardError>;
    fn clear(&self) -> Result<(), ClipboardError>;
}

struct UnavailableClipboard;
impl ClipboardBackend for UnavailableClipboard {
    fn set_text(&self, _: &str, _: bool) -> Result<(), ClipboardError> {
        Err(unavailable())
    }
    fn clear_if_matches(&self, _: &str) -> Result<(), ClipboardError> {
        Err(unavailable())
    }
    fn clear(&self) -> Result<(), ClipboardError> {
        Err(unavailable())
    }
}
fn unavailable() -> ClipboardError {
    ClipboardError::PlatformError("no platform clipboard backend configured".into())
}

pub struct ClipboardManager {
    clear_timer: Option<tokio::task::JoinHandle<()>>,
    backend: Arc<dyn ClipboardBackend>,
    // This mutex also serializes a waking old timer with a replacement copy.
    owned_text: Arc<Mutex<Option<Zeroizing<String>>>>,
    generation: Arc<std::sync::atomic::AtomicU64>,
}

impl ClipboardManager {
    pub fn new() -> Self {
        Self::with_backend(Arc::new(UnavailableClipboard))
    }

    pub fn with_backend(backend: Arc<dyn ClipboardBackend>) -> Self {
        Self {
            clear_timer: None,
            backend,
            owned_text: Arc::new(Mutex::new(None)),
            generation: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    pub async fn copy_with_timeout(
        &mut self,
        text: &str,
        timeout: Duration,
        is_sensitive: bool,
    ) -> Result<(), ClipboardError> {
        // A failed replacement leaves the previous expiry obligation intact.
        let mut owned = self.owned_text.lock().unwrap();
        self.backend.set_text(text, is_sensitive)?;
        if let Some(task) = self.clear_timer.take() {
            task.abort();
        }
        *owned = Some(Zeroizing::new(text.to_owned()));
        let generation = self.generation.clone();
        let current = generation
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            .wrapping_add(1);
        let owned_text = self.owned_text.clone();
        let backend = self.backend.clone();
        let timeout = if is_sensitive {
            timeout.min(Duration::from_secs(DEFAULT_CLIPBOARD_TIMEOUT_SECS))
        } else {
            timeout
        };
        self.clear_timer = Some(tokio::spawn(async move {
            tokio::time::sleep(timeout).await;
            let mut owned = owned_text.lock().unwrap();
            if generation.load(std::sync::atomic::Ordering::Relaxed) != current {
                return;
            }
            if let Some(expected) = owned.as_ref() {
                match backend.clear_if_matches(expected) {
                    Ok(()) => {
                        *owned = None;
                    }
                    Err(error) => tracing::warn!(%error, "clipboard timed clear failed"),
                }
            }
        }));
        Ok(())
    }

    /// Immediate platform clear on lock/exit. The caller receives failures.
    pub fn clear_now(&mut self) -> Result<(), ClipboardError> {
        let mut owned = self.owned_text.lock().unwrap();
        self.backend.clear()?;
        if let Some(task) = self.clear_timer.take() {
            task.abort();
        }
        *owned = None;
        Ok(())
    }

    pub fn deny_seed_copy() -> ClipboardError {
        ClipboardError::SeedPhraseCopyDenied
    }
    pub fn has_pending_clear(&self) -> bool {
        self.clear_timer
            .as_ref()
            .is_some_and(|task| !task.is_finished())
    }

    #[cfg(test)]
    fn get_content(&self) -> Option<String> {
        self.owned_text
            .lock()
            .unwrap()
            .as_ref()
            .map(|text| text.to_string())
    }
}

impl Default for ClipboardManager {
    fn default() -> Self {
        Self::new()
    }
}
impl Drop for ClipboardManager {
    fn drop(&mut self) {
        if let Some(task) = self.clear_timer.take() {
            task.abort();
        }
        let mut owned = self.owned_text.lock().unwrap();
        if let Some(text) = owned.take() {
            if let Err(error) = self.backend.clear_if_matches(&text) {
                tracing::warn!(%error, "clipboard clear on drop failed");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct MemoryClipboard(Mutex<Option<String>>);
    impl ClipboardBackend for MemoryClipboard {
        fn set_text(&self, text: &str, _: bool) -> Result<(), ClipboardError> {
            *self.0.lock().unwrap() = Some(text.into());
            Ok(())
        }
        fn clear_if_matches(&self, expected: &str) -> Result<(), ClipboardError> {
            let mut value = self.0.lock().unwrap();
            if value.as_deref() == Some(expected) {
                *value = None;
            }
            Ok(())
        }
        fn clear(&self) -> Result<(), ClipboardError> {
            *self.0.lock().unwrap() = None;
            Ok(())
        }
    }
    fn test_manager() -> ClipboardManager {
        ClipboardManager::with_backend(Arc::new(MemoryClipboard::default()))
    }

    #[tokio::test]
    async fn copy_sets_content() {
        let mut mgr = test_manager();
        mgr.copy_with_timeout("hello", Duration::from_secs(30), false)
            .await
            .unwrap();
        assert_eq!(mgr.get_content(), Some("hello".to_string()));
    }

    #[tokio::test]
    async fn clear_now_removes_content() {
        let mut mgr = test_manager();
        mgr.copy_with_timeout("secret", Duration::from_secs(30), false)
            .await
            .unwrap();
        assert!(mgr.get_content().is_some());

        mgr.clear_now().unwrap();
        assert!(mgr.get_content().is_none());
    }

    #[tokio::test]
    async fn timed_clear_removes_content() {
        let mut mgr = test_manager();
        mgr.copy_with_timeout("timed", Duration::from_millis(50), false)
            .await
            .unwrap();
        assert_eq!(mgr.get_content(), Some("timed".to_string()));

        // Wait for the timer to fire
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(mgr.get_content().is_none());
    }

    #[tokio::test]
    async fn copy_replaces_previous_timer() {
        let mut mgr = test_manager();
        // First copy with long timeout
        mgr.copy_with_timeout("first", Duration::from_secs(60), false)
            .await
            .unwrap();
        assert!(mgr.has_pending_clear());

        // Second copy should cancel first timer
        mgr.copy_with_timeout("second", Duration::from_millis(50), false)
            .await
            .unwrap();
        assert_eq!(mgr.get_content(), Some("second".to_string()));

        // Wait for second timer
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(mgr.get_content().is_none());
    }

    #[test]
    fn deny_seed_copy_returns_error() {
        let err = ClipboardManager::deny_seed_copy();
        assert!(matches!(err, ClipboardError::SeedPhraseCopyDenied));
        assert!(err.to_string().contains("seed phrase"));
    }

    #[test]
    fn clear_now_without_prior_copy_is_safe() {
        let mut mgr = test_manager();
        mgr.clear_now().unwrap(); // should not panic
        assert!(mgr.get_content().is_none());
    }

    #[test]
    fn default_clipboard_timeout_constant() {
        assert_eq!(DEFAULT_CLIPBOARD_TIMEOUT_SECS, 30);
    }
}
