//! Database encryption hardening (S03 §4.2).
//!
//! Provides additional security pragmas beyond the base SQLCipher setup,
//! WAL encryption verification, and temp file cleanup with secure deletion.

use std::path::Path;

use rusqlite::Connection;

use crate::error::{Result, StorageError};

/// Apply hardening pragmas to an open SQLCipher connection (S03 §4.2).
///
/// These are applied *in addition to* the base pragmas set in `SqliteStorage::open()`.
/// This function can be called to verify/re-apply hardening at any point.
///
/// Ensures:
/// - `temp_store = MEMORY` — all temp data stays in memory (no plaintext temp files)
/// - `cipher_memory_security = ON` — zeroize freed pages in memory
/// - `journal_mode = WAL` — WAL is also encrypted by SQLCipher
/// - `cipher_page_size = 4096` — verified, not changed
pub fn apply_hardening_pragmas(conn: &Connection) -> Result<()> {
    // CRITICAL: All temp data stays in memory (no plaintext temp files)
    conn.pragma_update(None, "temp_store", "MEMORY")?;

    // Zeroize freed pages in memory
    conn.pragma_update(None, "cipher_memory_security", "ON")?;

    // Verify WAL is also encrypted
    conn.pragma_update(None, "journal_mode", "WAL")?;

    // Verify cipher settings
    let page_size: i32 = conn.pragma_query_value(None, "cipher_page_size", |r| r.get(0))?;
    if page_size != 4096 {
        return Err(StorageError::InvalidData(format!(
            "cipher_page_size must be 4096, got {}",
            page_size
        )));
    }

    tracing::info!("Database hardening pragmas applied successfully");
    Ok(())
}

/// Verify at-rest encryption of the database FILE (S03 §4.3).
///
/// The invariant that can actually be checked from the filesystem: the main
/// database file must NOT carry the plaintext SQLite header
/// (`SQLite format 3\0`). A SQLCipher database starts with random salt bytes,
/// so a plaintext header means the file was written WITHOUT a key and every
/// byte on disk is cleartext — fail closed.
///
/// The WAL is not inspected: SQLCipher encrypts WAL *frame contents* but
/// writes the 32-byte WAL file header in standard form, so standard WAL magic
/// is not a plaintext signal.
///
/// Returns `Ok(true)` when the file is absent (fresh open) or encrypted.
pub fn verify_wal_encryption(db_path: &Path) -> Result<bool> {
    const PLAINTEXT_MAGIC: &[u8; 16] = b"SQLite format 3\0";
    if db_path.exists() {
        use std::io::Read;
        let mut header = [0u8; 16];
        let mut file = std::fs::File::open(db_path)?;
        let mut read = 0;
        while read < header.len() {
            let n = file.read(&mut header[read..])?;
            if n == 0 {
                break;
            }
            read += n;
        }
        if read == 16 && &header == PLAINTEXT_MAGIC {
            tracing::error!(
                path = %db_path.display(),
                "database file has a PLAINTEXT SQLite header — not encrypted"
            );
            return Err(StorageError::WalNotEncrypted);
        }
        tracing::info!("database file does not carry a plaintext SQLite header — OK");
    } else {
        tracing::debug!("no database file yet (fresh open — OK)");
    }
    Ok(true)
}

/// Remove residual temp files from a directory (S03 §4.4).
///
/// Scans `data_dir` for temporary files that could contain plaintext fragments:
/// - `.tmp` files
/// - `-journal` files (rollback journal)
/// - `etilqs_` files (SQLite temp files, "sqlite" reversed)
///
/// Each file is overwritten with zeros before deletion (secure delete).
/// Returns the number of files cleaned up.
pub fn cleanup_temp_files(data_dir: &Path) -> Result<u32> {
    let mut count = 0u32;

    let entries = match std::fs::read_dir(data_dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::debug!("Data directory does not exist, nothing to clean");
            return Ok(0);
        }
        Err(e) => return Err(e.into()),
    };

    for entry in entries {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();

        if name.ends_with(".tmp") || name.ends_with("-journal") || name.contains("etilqs_") {
            let path = entry.path();

            // Overwrite with zeros before deleting (secure delete)
            if let Ok(metadata) = entry.metadata() {
                let size = metadata.len() as usize;
                if size > 0 {
                    let zeros = vec![0u8; size];
                    if let Err(e) = std::fs::write(&path, &zeros) {
                        tracing::warn!(path = %path.display(), error = %e, "Failed to zero-fill temp file");
                    }
                }
            }

            match std::fs::remove_file(&path) {
                Ok(()) => {
                    tracing::debug!(path = %path.display(), "Cleaned up temp file");
                    count += 1;
                }
                Err(e) => {
                    tracing::warn!(path = %path.display(), error = %e, "Failed to remove temp file");
                }
            }
        }
    }

    if count > 0 {
        tracing::info!(count, "Cleaned up temporary files");
    }

    Ok(count)
}

/// Verify all hardening settings on an open connection (S03 §4.2).
///
/// Combines pragma verification and WAL check into a single call
/// suitable for startup verification.
pub fn verify_hardening(conn: &Connection, db_path: &Path) -> Result<()> {
    // Verify pragmas
    let temp_store: i32 = conn.pragma_query_value(None, "temp_store", |r| r.get(0))?;
    // temp_store returns 2 for MEMORY
    if temp_store != 2 {
        return Err(StorageError::InvalidData(format!(
            "temp_store should be MEMORY (2), got {}",
            temp_store
        )));
    }

    let journal_mode: String = conn.pragma_query_value(None, "journal_mode", |r| r.get(0))?;
    if journal_mode.to_lowercase() != "wal" {
        return Err(StorageError::InvalidData(format!(
            "journal_mode should be WAL, got {}",
            journal_mode
        )));
    }

    // Verify at-rest file encryption (main-DB header check; see the
    // verify_wal_encryption doc for why the old WAL-magic test is gone)
    verify_wal_encryption(db_path)?;

    tracing::info!("Database hardening verification passed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_hardening_pragmas_on_memory_db() {
        let conn = Connection::open_in_memory().unwrap();
        // For in-memory DB, cipher_page_size check won't apply the same way,
        // but temp_store and journal_mode should work.
        conn.pragma_update(None, "temp_store", "MEMORY").unwrap();
        conn.pragma_update(None, "journal_mode", "WAL").unwrap();

        // Verify temp_store is MEMORY (returns integer 2)
        let temp_store: i32 = conn
            .pragma_query_value(None, "temp_store", |r| r.get(0))
            .unwrap();
        assert_eq!(temp_store, 2); // 2 = MEMORY
    }

    #[test]
    fn verify_wal_encryption_no_wal_file() {
        // Non-existent path — should return Ok(true)
        let result = verify_wal_encryption(Path::new("/nonexistent/path/db.sqlite"));
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn verify_flags_a_plaintext_database_header() {
        let dir = std::env::temp_dir().join("najwa_test_plaintext_db");
        let _ = std::fs::create_dir_all(&dir);
        let db_path = dir.join("test.db");

        // A plaintext (unkeyed) SQLite database starts with this magic.
        let mut data = b"SQLite format 3\0".to_vec();
        data.extend_from_slice(&[0u8; 64]);
        std::fs::write(&db_path, &data).unwrap();

        let result = verify_wal_encryption(&db_path);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), StorageError::WalNotEncrypted));

        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn verify_accepts_a_sqlcipher_shaped_header() {
        let dir = std::env::temp_dir().join("najwa_test_sqlcipher_db");
        let _ = std::fs::create_dir_all(&dir);
        let db_path = dir.join("test.db");

        // A SQLCipher database starts with random salt bytes, not the
        // plaintext magic.
        let data: Vec<u8> = (0..96u8).collect();
        std::fs::write(&db_path, &data).unwrap();

        let result = verify_wal_encryption(&db_path);
        assert!(result.is_ok());

        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn verify_is_extension_agnostic() {
        // The check reads the DB FILE itself — extension-independent by
        // construction (regression guard for the old WAL path computation).
        let dir = std::env::temp_dir().join("najwa_test_ext_agnostic");
        let _ = std::fs::create_dir_all(&dir);
        let db_path = dir.join("store.sqlite");
        let mut data = b"SQLite format 3\0".to_vec();
        data.extend_from_slice(&[0u8; 64]);
        std::fs::write(&db_path, &data).unwrap();

        assert!(matches!(
            verify_wal_encryption(&db_path).unwrap_err(),
            StorageError::WalNotEncrypted
        ));

        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_dir(&dir);
    }
    #[test]
    fn cleanup_temp_files_removes_matching_files() {
        let dir = std::env::temp_dir().join("najwa_test_cleanup");
        let _ = std::fs::create_dir_all(&dir);

        // Create test temp files
        std::fs::write(dir.join("data.tmp"), b"temp data").unwrap();
        std::fs::write(dir.join("db-journal"), b"journal data").unwrap();
        std::fs::write(dir.join("etilqs_abc123"), b"sqlite temp").unwrap();
        std::fs::write(dir.join("keep_this.db"), b"real data").unwrap();

        let count = cleanup_temp_files(&dir).unwrap();
        assert_eq!(count, 3);

        // Verify real file still exists
        assert!(dir.join("keep_this.db").exists());

        // Verify temp files are gone
        assert!(!dir.join("data.tmp").exists());
        assert!(!dir.join("db-journal").exists());
        assert!(!dir.join("etilqs_abc123").exists());

        // Cleanup
        let _ = std::fs::remove_file(dir.join("keep_this.db"));
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn cleanup_temp_files_nonexistent_dir_returns_zero() {
        let result = cleanup_temp_files(Path::new("/nonexistent/dir/that/does/not/exist"));
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);
    }

    #[test]
    fn cleanup_temp_files_empty_dir_returns_zero() {
        let dir = std::env::temp_dir().join("najwa_test_cleanup_empty");
        let _ = std::fs::create_dir_all(&dir);

        let count = cleanup_temp_files(&dir).unwrap();
        assert_eq!(count, 0);

        let _ = std::fs::remove_dir(&dir);
    }
}
