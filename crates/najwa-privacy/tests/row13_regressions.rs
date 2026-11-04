use najwa_privacy::{
    clipboard::ClipboardManager,
    lifecycle::deletion::*,
    links::validate_preview_url,
    typing::{TypingControl, TypingIndicatorManager},
};

#[test]
fn url_parser_must_check_the_actual_normalized_host() {
    for url in [
        "http://public.example@127.0.0.1/",
        "http://127.1/",
        "http://2130706433/",
        "http://0x7f000001/",
        "http://0177.0.0.1/",
        "http://localhost./",
        "http://localhost?query",
        "http://[::ffff:127.0.0.1]/",
        "http://[::1]junk/",
    ] {
        assert!(validate_preview_url(url).is_err(), "accepted {url}");
    }
    assert_eq!(
        validate_preview_url("https://example.com?query").unwrap(),
        "example.com"
    );
}

#[test]
fn stopping_does_not_reset_the_started_rate_limit() {
    let mut typing = TypingIndicatorManager::new(true);
    assert_eq!(typing.on_keystroke(), Some(TypingControl::Started));
    assert_eq!(typing.on_stop_typing(), Some(TypingControl::Stopped));
    assert_eq!(typing.on_keystroke(), None);
}

#[tokio::test]
async fn clipboard_without_a_platform_backend_cannot_report_success() {
    let mut clipboard = ClipboardManager::new();
    assert!(clipboard
        .copy_with_timeout("secret", std::time::Duration::from_secs(30), true)
        .await
        .is_err());
}

#[test]
fn database_sidecars_follow_the_exact_database_filename() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("messages.sqlite3");
    for name in [
        "messages.sqlite3",
        "messages.sqlite3-wal",
        "messages.sqlite3-shm",
    ] {
        std::fs::write(dir.path().join(name), "sensitive").unwrap();
    }
    secure_delete_database(&db).unwrap();
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[cfg(unix)]
#[test]
fn directory_deletion_does_not_follow_external_symlinks() {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let secret = outside.path().join("unrelated.txt");
    std::fs::write(&secret, "preserve unrelated data").unwrap();
    std::os::unix::fs::symlink(outside.path(), root.path().join("linked-dir")).unwrap();
    secure_delete_directory(root.path()).unwrap();
    assert_eq!(
        std::fs::read_to_string(secret).unwrap(),
        "preserve unrelated data"
    );
}

#[cfg(unix)]
#[test]
fn file_deletion_does_not_overwrite_symlink_target() {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let secret = outside.path().join("unrelated.txt");
    std::fs::write(&secret, "preserve unrelated data").unwrap();
    let link = root.path().join("linked-file");
    std::os::unix::fs::symlink(&secret, &link).unwrap();
    overwrite_and_delete(&link).unwrap();
    assert_eq!(
        std::fs::read_to_string(secret).unwrap(),
        "preserve unrelated data"
    );
    assert!(std::fs::symlink_metadata(link).is_err());
}

#[derive(Default)]
struct TestClipboard {
    text: std::sync::Mutex<Option<String>>,
    sensitive: std::sync::atomic::AtomicBool,
    fail_clear: std::sync::atomic::AtomicBool,
}
impl najwa_privacy::clipboard::ClipboardBackend for TestClipboard {
    fn set_text(
        &self,
        text: &str,
        sensitive: bool,
    ) -> Result<(), najwa_privacy::clipboard::ClipboardError> {
        *self.text.lock().unwrap() = Some(text.into());
        self.sensitive
            .store(sensitive, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }
    fn clear_if_matches(
        &self,
        expected: &str,
    ) -> Result<(), najwa_privacy::clipboard::ClipboardError> {
        let mut text = self.text.lock().unwrap();
        if text.as_deref() == Some(expected) {
            *text = None;
        }
        Ok(())
    }
    fn clear(&self) -> Result<(), najwa_privacy::clipboard::ClipboardError> {
        if self.fail_clear.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(najwa_privacy::clipboard::ClipboardError::PlatformError(
                "injected".into(),
            ));
        }
        *self.text.lock().unwrap() = None;
        Ok(())
    }
}

#[tokio::test]
async fn clipboard_expiry_preserves_external_copy_and_forwards_sensitive_flag() {
    let platform = std::sync::Arc::new(TestClipboard::default());
    let mut clipboard = ClipboardManager::with_backend(platform.clone());
    clipboard
        .copy_with_timeout("secret", std::time::Duration::from_millis(10), true)
        .await
        .unwrap();
    assert!(platform
        .sensitive
        .load(std::sync::atomic::Ordering::Relaxed));
    *platform.text.lock().unwrap() = Some("another application's text".into());
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(
        platform.text.lock().unwrap().as_deref(),
        Some("another application's text")
    );
    assert!(!clipboard.has_pending_clear());
}

#[tokio::test]
async fn clipboard_drop_clears_owned_text_and_immediate_errors_are_visible() {
    let platform = std::sync::Arc::new(TestClipboard::default());
    let mut clipboard = ClipboardManager::with_backend(platform.clone());
    clipboard
        .copy_with_timeout("secret", std::time::Duration::from_secs(30), true)
        .await
        .unwrap();
    platform
        .fail_clear
        .store(true, std::sync::atomic::Ordering::Relaxed);
    assert!(clipboard.clear_now().is_err());
    drop(clipboard);
    assert!(platform.text.lock().unwrap().is_none());
}

#[cfg(unix)]
#[test]
fn hardlinks_and_special_files_are_refused_without_false_success() {
    let dir = tempfile::tempdir().unwrap();
    let other = tempfile::tempdir().unwrap();
    let original = other.path().join("original");
    std::fs::write(&original, "preserve").unwrap();
    let linked = dir.path().join("copy.tmp");
    std::fs::hard_link(&original, &linked).unwrap();
    assert!(overwrite_and_delete(&linked).is_err());
    assert!(cleanup_temp_files(dir.path()).is_err());
    assert!(secure_delete_directory(dir.path()).is_err());
    assert_eq!(std::fs::read_to_string(original).unwrap(), "preserve");
    let fifo = dir.path().join("fifo");
    let path = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
    assert!(overwrite_and_delete(&fifo).is_err());
}

#[test]
fn deletion_report_requires_all_local_cleanup_steps() {
    let report = DeletionReport {
        database_deleted: true,
        identity_deleted: true,
        dkm_deleted: true,
        ..Default::default()
    };
    assert!(!report.is_complete());
}
