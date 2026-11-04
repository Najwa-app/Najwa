//! File-erasure helpers and a library account-deletion procedure.
//!
//! Provides:
//! - Overwrite-and-delete of files and directories, used by local profile
//!   erasure (`emergency`, S13 §10)
//! - `delete_account` with its `DeletionReport`; the application does not call it
//! - DeletionError for structured error handling
//!
//! Deleting the device key (DKM) makes the identity record undecryptable. The
//! database key derives from the identity seed, so the recovery kit together
//! with any surviving copy of the database still decrypts it (S03 §12). The
//! overwrite-then-delete of each file is best effort on SSDs and copy-on-write
//! file systems.

use std::io::Write;
use std::path::Path;

use najwa_crypto::random::random_bytes_vec;

/// Errors during account deletion.
#[derive(Debug, thiserror::Error)]
pub enum DeletionError {
    /// I/O error during file operations.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Storage error during deletion.
    #[error("storage error: {0}")]
    StorageError(String),

    /// Failed to deactivate a mailbox capability.
    #[error("capability deactivation failed: {0}")]
    CapabilityError(String),

    /// Failed to delete identity record.
    #[error("identity deletion failed: {0}")]
    IdentityError(String),

    /// Failed to delete DKM from platform secure storage.
    #[error("DKM deletion failed: {0}")]
    DkmError(String),
}

/// Report of what `delete_account` deleted.
#[derive(Debug, Clone, Default)]
pub struct DeletionReport {
    /// Number of contacts notified of deletion.
    pub contacts_notified: u32,
    /// Number of mailbox capabilities successfully deactivated.
    pub capabilities_deactivated: u32,
    /// Number of capability deactivations that failed.
    pub capabilities_failed: u32,
    /// Whether the database file was securely deleted.
    pub database_deleted: bool,
    /// Whether the identity record was securely deleted.
    pub identity_deleted: bool,
    /// Whether the DKM was removed from platform secure storage.
    pub dkm_deleted: bool,
    /// Whether temp files were cleaned up.
    pub temp_files_cleaned: bool,
    /// All local data, including recovery material and backups, was removed.
    pub data_directory_deleted: bool,
    /// Failures encountered while attempting all deletion steps.
    pub errors: Vec<String>,
}

impl DeletionReport {
    /// Create a new empty deletion report.
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if all critical steps completed successfully.
    pub fn is_complete(&self) -> bool {
        self.database_deleted
            && self.identity_deleted
            && self.dkm_deleted
            && self.temp_files_cleaned
            && self.data_directory_deleted
            && self.errors.is_empty()
    }
}

fn sync_parent(path: &Path) -> Result<(), DeletionError> {
    // Directory fsync is supported on Unix. Windows has no equivalent portable
    // Rust operation; overwrite buffers are still flushed before unlinking.
    #[cfg(unix)]
    {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        std::fs::File::open(parent)?.sync_all()?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn unlink_symlink(path: &Path, metadata: &std::fs::Metadata) -> Result<(), DeletionError> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x10 != 0 {
            std::fs::remove_dir(path)?;
        } else {
            std::fs::remove_file(path)?;
        }
    }
    #[cfg(not(windows))]
    {
        let _ = metadata;
        std::fs::remove_file(path)?;
    }
    sync_parent(path)
}

/// Securely delete the database and its auxiliary files (used by `delete_account`).
///
/// Overwrites the main database file, WAL, and SHM with random data,
/// fsyncs, then deletes. This is best-effort defence-in-depth;
/// cryptographic erasure (deleting db_key/DKM) is the primary guarantee.
pub fn secure_delete_database(path: &Path) -> Result<(), DeletionError> {
    // SQLite appends suffixes to the complete filename; it does not replace
    // the extension (databases may be named .sqlite3 or have no extension).
    for suffix in ["", "-wal", "-shm", "-journal"] {
        let mut name = path.as_os_str().to_os_string();
        name.push(suffix);
        let candidate = std::path::PathBuf::from(name);
        match std::fs::symlink_metadata(&candidate) {
            Ok(_) => overwrite_and_delete(&candidate)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

/// Overwrite a file with random data, fsync, then delete (S13 §10).
///
/// The random overwrite makes recovery harder on traditional storage.
/// On SSDs/flash, wear-leveling may retain old data — this is why
/// cryptographic erasure is the primary guarantee.
pub fn overwrite_and_delete(path: &Path) -> Result<(), DeletionError> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return unlink_symlink(path, &metadata);
    }
    if !metadata.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "refusing to overwrite a non-regular file",
        )
        .into());
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x00200000); // FILE_FLAG_OPEN_REPARSE_POINT
    }
    let mut file = options.open(path)?;
    let opened = file.metadata()?;
    if !opened.is_file() || opened.file_type().is_symlink() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "file changed during deletion",
        )
        .into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if opened.nlink() != 1 || opened.dev() != metadata.dev() || opened.ino() != metadata.ino() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "refusing changed or multiply-linked file",
            )
            .into());
        }
    }
    let mut remaining = opened.len();
    // Bounded memory even for large databases or sparse files.
    while remaining > 0 {
        let length = remaining.min(64 * 1024) as usize;
        file.write_all(&random_bytes_vec(length))?;
        remaining -= length as u64;
    }
    file.sync_all()?;
    drop(file);
    std::fs::remove_file(path)?;
    sync_parent(path)?;
    Ok(())
}

/// Securely delete a directory and all its contents (best effort).
///
/// Overwrites each file with random data before deletion.
/// Used for cleaning up data directories on account deletion.
pub fn secure_delete_directory(dir: &Path) -> Result<u32, DeletionError> {
    let metadata = match std::fs::symlink_metadata(dir) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e.into()),
    };
    if metadata.file_type().is_symlink() {
        unlink_symlink(dir, &metadata)?;
        return Ok(1);
    }
    let mut count = 0u32;
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        if kind.is_dir() && !kind.is_symlink() {
            count += secure_delete_directory(&entry.path())?;
        } else {
            overwrite_and_delete(&entry.path())?;
            count += 1;
        }
    }
    std::fs::remove_dir(dir)?;
    sync_parent(dir)?;
    Ok(count)
}

/// Delete every Najwa DKM generation through the platform credential backend.
/// Backend failures are reported as incomplete account deletion.
pub fn delete_dkm() -> Result<(), DeletionError> {
    najwa_identity::platform::delete_dkm().map_err(|e| DeletionError::DkmError(e.to_string()))?;
    tracing::info!("DKM deleted from platform secure storage");
    Ok(())
}

/// Clean up temporary files in the data directory (used by `delete_account`).
///
/// Removes any `.tmp`, `.partial`, `.bak`, `.log` files that may contain sensitive data.
pub fn cleanup_temp_files(data_dir: &Path) -> Result<u32, DeletionError> {
    match std::fs::symlink_metadata(data_dir) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e.into()),
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "data directory is a symlink",
            )
            .into());
        }
        Ok(_) => {}
    }
    let mut count = 0;
    for entry in std::fs::read_dir(data_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| matches!(e, "tmp" | "partial" | "bak" | "log"))
        {
            overwrite_and_delete(&path)?;
            count += 1;
        }
    }
    Ok(count)
}

/// Clear in-memory caches (step 8 of `delete_account`).
///
/// This is a no-op at the file level — actual cache clearing is done by
/// the caller (FFI layer / app layer) which holds the runtime state.
/// This function exists to document the step and log it in the report.
pub fn clear_caches_step() {
    tracing::info!("caches cleared (caller responsibility)");
}

/// Library 10-step account deletion procedure. The application does not call
/// it; it uses local profile erasure (`emergency`, S13 §10).
///
/// Steps:
/// 1. Deactivate capabilities (caller provides async closure)
/// 2. Notify contacts (caller provides async closure)
/// 3. Secure-delete DB + WAL + SHM
/// 4. Secure-delete identity record
/// 5. Delete recovery/backup files
/// 6. Delete DKM from platform secure storage
/// 7. Clean up temp files
/// 8. Clear caches (caller responsibility)
/// 9. Remove app data directory contents (files + subdirectories)
/// 10. fsync the PARENT directory so the removal is durable
pub fn delete_account(
    data_dir: &Path,
    db_path: &Path,
    identity_path: &Path,
    caps_deactivated: u32,
    caps_failed: u32,
    contacts_notified: u32,
) -> Result<DeletionReport, DeletionError> {
    let mut report = DeletionReport {
        capabilities_deactivated: caps_deactivated,
        capabilities_failed: caps_failed,
        contacts_notified,
        ..Default::default()
    };
    match secure_delete_database(db_path) {
        Ok(()) => report.database_deleted = true,
        Err(e) => report.errors.push(format!("database: {e}")),
    }
    match overwrite_and_delete(identity_path) {
        Ok(()) => report.identity_deleted = true,
        Err(DeletionError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
            report.identity_deleted = true
        }
        Err(e) => report.errors.push(format!("identity: {e}")),
    }
    match delete_dkm() {
        Ok(()) => report.dkm_deleted = true,
        Err(e) => report.errors.push(format!("DKM: {e}")),
    }
    match cleanup_temp_files(data_dir) {
        Ok(_) => report.temp_files_cleaned = true,
        Err(e) => report.errors.push(format!("temporary files: {e}")),
    }
    // The caller owns and clears runtime caches before calling this file-level
    // routine. Recursion includes every recovery/backup filename, not just two
    // historical spellings. Removal fsyncs each parent before returning.
    match secure_delete_directory(data_dir) {
        Ok(_) => report.data_directory_deleted = true,
        Err(e) => report.errors.push(format!("data directory: {e}")),
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn deletion_report_default_incomplete() {
        let report = DeletionReport::new();
        assert!(!report.is_complete());
        assert_eq!(report.contacts_notified, 0);
        assert_eq!(report.capabilities_deactivated, 0);
    }

    #[test]
    fn deletion_report_complete_when_critical_steps_done() {
        let mut report = DeletionReport::new();
        report.database_deleted = true;
        report.identity_deleted = true;
        report.dkm_deleted = true;
        report.temp_files_cleaned = true;
        report.data_directory_deleted = true;
        assert!(report.is_complete());
    }

    #[test]
    fn deletion_report_incomplete_without_dkm() {
        let mut report = DeletionReport::new();
        report.database_deleted = true;
        report.identity_deleted = true;
        // dkm_deleted = false
        assert!(!report.is_complete());
    }

    #[test]
    fn overwrite_and_delete_removes_file() {
        let dir = std::env::temp_dir().join("najwa_test_delete_file");
        let _ = fs::create_dir_all(&dir);
        let file_path = dir.join("secret.dat");

        // Create a file with sensitive data
        fs::write(&file_path, b"super secret data that must be destroyed").unwrap();
        assert!(file_path.exists());

        // Overwrite and delete
        overwrite_and_delete(&file_path).unwrap();
        assert!(!file_path.exists());

        // Cleanup
        let _ = fs::remove_dir(&dir);
    }

    #[test]
    fn overwrite_and_delete_handles_empty_file() {
        let dir = std::env::temp_dir().join("najwa_test_delete_empty");
        let _ = fs::create_dir_all(&dir);
        let file_path = dir.join("empty.dat");

        // Create an empty file
        fs::write(&file_path, b"").unwrap();
        assert!(file_path.exists());

        overwrite_and_delete(&file_path).unwrap();
        assert!(!file_path.exists());

        let _ = fs::remove_dir(&dir);
    }

    #[test]
    fn secure_delete_database_removes_all_files() {
        let dir = std::env::temp_dir().join("najwa_test_delete_db");
        let _ = fs::create_dir_all(&dir);

        let db_path = dir.join("najwa.db");
        let wal_path = dir.join("najwa.db-wal");
        let shm_path = dir.join("najwa.db-shm");

        // Create DB + auxiliary files
        fs::write(&db_path, b"encrypted database content").unwrap();
        fs::write(&wal_path, b"WAL data").unwrap();
        fs::write(&shm_path, b"SHM data").unwrap();

        secure_delete_database(&db_path).unwrap();

        assert!(!db_path.exists());
        assert!(!wal_path.exists());
        assert!(!shm_path.exists());

        let _ = fs::remove_dir(&dir);
    }

    #[test]
    fn secure_delete_database_handles_missing_auxiliary() {
        let dir = std::env::temp_dir().join("najwa_test_delete_db_no_wal");
        let _ = fs::create_dir_all(&dir);

        let db_path = dir.join("najwa.db");
        fs::write(&db_path, b"database only").unwrap();

        // No WAL or SHM — should still succeed
        secure_delete_database(&db_path).unwrap();
        assert!(!db_path.exists());

        let _ = fs::remove_dir(&dir);
    }

    #[test]
    fn secure_delete_database_nonexistent_is_ok() {
        let path = Path::new("/nonexistent/najwa_test_no_db.db");
        // Should succeed — nothing to delete
        let result = secure_delete_database(path);
        assert!(result.is_ok());
    }

    #[test]
    fn secure_delete_directory_removes_contents() {
        let dir = std::env::temp_dir().join("najwa_test_delete_dir");
        let _ = fs::create_dir_all(&dir);

        fs::write(dir.join("a.txt"), b"file a").unwrap();
        fs::write(dir.join("b.dat"), b"file b").unwrap();

        let count = secure_delete_directory(&dir).unwrap();
        assert_eq!(count, 2);
        assert!(!dir.exists());
    }

    #[test]
    fn secure_delete_directory_nonexistent_returns_zero() {
        let result = secure_delete_directory(Path::new("/nonexistent/dir/najwa_test_no_dir"));
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);
    }

    #[test]
    fn delete_dkm_stub_succeeds() {
        // Route through the file-backed DKM override so the test is hermetic: the
        // real path hits a platform keyring (D-Bus/Secret Service on Linux) that is
        // absent in headless CI/containers. The override just removes the named
        // file (ignoring a missing one) and returns Ok.
        let tmp = std::env::temp_dir().join("najwa_test_dkm_delete_stub");
        let _ = std::fs::write(&tmp, b"x");
        std::env::set_var("NAJWA_DKM_FILE", &tmp);
        let result = delete_dkm();
        std::env::remove_var("NAJWA_DKM_FILE");
        assert!(result.is_ok());
    }
}
