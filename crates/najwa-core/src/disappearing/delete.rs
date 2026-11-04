//! Secure deletion of expired disappearing messages (S12 §5).

use std::path::Path;

use najwa_crypto::prelude::now_ms;
use najwa_crypto::random::random_bytes_vec;

use super::error::{DisappearError, Result};
use super::storage::DisappearingStorage;

/// Securely delete all expired disappearing messages (S12 §5.1).
///
/// For each expired message:
/// 1. Zeroize all expired in-memory keys and purge persisted expired keys
/// 2. Overwrite message content with zero bytes in DB
/// 3. If message has associated media file, secure-delete it
/// 4. Delete the database row
/// 5. WAL checkpoint to flush overwrites to disk
///
/// Returns the number of messages deleted.
pub async fn delete_expired_messages<S: DisappearingStorage>(
    storage: &S,
    cache: &super::VolatileKeyCache,
) -> Result<u32> {
    let expired = storage
        .get_expired_disappearing_messages(now_ms() as u64)
        .await
        .map_err(DisappearError::StorageError)?;

    // Evict ALL expired keys before any fallible database or file operation.
    // Even a failed overwrite must leave the old ciphertext irrecoverable.
    for msg in &expired {
        cache.remove_key(&msg.msg_id);
    }
    storage
        .purge_expired_volatile_keys(now_ms().max(0) as u64)
        .await
        .map_err(DisappearError::StorageError)?;

    let mut count = 0u32;

    for msg in &expired {
        // 1. Overwrite message content with zeroblob
        storage
            .overwrite_message_content(msg.id, &[0u8; 0])
            .await
            .map_err(DisappearError::StorageError)?;

        // 2. If message has associated media file, secure-delete it
        if let Some(ref file_path) = msg.file_path {
            let path = Path::new(file_path);
            if path.exists() {
                if let Err(e) = secure_delete_file(path).await {
                    tracing::warn!("Failed to secure-delete file {}: {}", file_path, e);
                    // Continue with DB deletion even if file delete fails
                }
            }
        }

        // 3. Delete the database row
        storage
            .delete_message(msg.id)
            .await
            .map_err(DisappearError::StorageError)?;

        count += 1;
    }

    // 4. WAL checkpoint to ensure overwrites are flushed to disk
    if count > 0 {
        storage
            .wal_checkpoint()
            .await
            .map_err(DisappearError::StorageError)?;
    }

    Ok(count)
}

/// Securely delete a file (S12 §5.2/§10): random overwrite → fsync(file) →
/// remove → fsync(parent dir).
///
/// The parent-directory fsync is the step that makes the *unlink* durable.
/// Without it, a crash after `remove_file` can leave the directory entry — and
/// therefore the file — intact on the next boot, so the overwrite bought
/// nothing: the attacker sees a file whose contents were replaced but which was
/// never actually removed, and on some filesystems the original extents are
/// still reachable.
///
/// **Caveat:** Overwrite-then-delete is best-effort on modern storage
/// (SSDs with wear leveling, CoW filesystems). True secure deletion
/// relies on SQLCipher's encrypted-at-rest property.
pub async fn secure_delete_file(path: &Path) -> Result<()> {
    let owned = path.to_path_buf();
    // The whole sequence is short, local, synchronous file I/O, so it runs on a
    // blocking thread rather than holding a runtime worker across four awaits.
    tokio::task::spawn_blocking(move || secure_delete_file_sync(&owned))
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?
}

/// Blocking twin of [`secure_delete_file`], for callers with no runtime.
///
/// The FFI's media cleanup runs inside a storage closure that already holds the
/// global lock, so it cannot await and must not enter a runtime — but it is the
/// ONLY production media-deletion path, so leaving it on a plain `remove_file`
/// meant the §5.2 sequence existed and was never actually used. Both entry
/// points share this one body so the two cannot drift.
pub fn secure_delete_file_sync(path: &Path) -> Result<()> {
    use std::io::Write;

    let size = std::fs::metadata(path)?.len() as usize;

    // Overwrite with random data
    let random_data = random_bytes_vec(size);
    let mut file = std::fs::OpenOptions::new().write(true).open(path)?;
    file.write_all(&random_data)?;
    file.sync_all()?;
    drop(file);

    // Delete
    std::fs::remove_file(path)?;

    // Persist the unlink itself. Best-effort: a directory that cannot be opened
    // or synced (permissions, or a platform that rejects fsync on a directory
    // handle — notably Windows) must not turn a completed delete into an error.
    if let Some(parent) = path.parent() {
        match std::fs::File::open(parent) {
            Ok(dir) => {
                if let Err(e) = dir.sync_all() {
                    tracing::debug!(dir = %parent.display(), error = %e, "parent-dir fsync unsupported");
                }
            }
            Err(e) => {
                tracing::debug!(dir = %parent.display(), error = %e, "parent-dir open for fsync failed");
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn secure_delete_file_overwrites_and_removes() {
        // Create a temp file with known content
        let mut tmp = NamedTempFile::new().unwrap();
        let original_content = b"secret message content here!";
        tmp.write_all(original_content).unwrap();
        tmp.flush().unwrap();

        // Keep the file by persisting it (prevents auto-cleanup)
        let persisted = tmp.into_temp_path();

        assert!(persisted.exists());

        // Secure delete
        secure_delete_file(&persisted).await.unwrap();

        // File should no longer exist
        assert!(!persisted.exists());
    }

    // S12 §5.2/§10: the parent-dir fsync must be best-effort — a directory that
    // rejects fsync (Windows) or cannot be opened must NOT turn a completed
    // delete into an error, or media deletion would fail on whole platforms.
    #[tokio::test]
    async fn secure_delete_succeeds_even_if_parent_fsync_unsupported() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("media.bin");
        tokio::fs::write(&path, b"payload").await.unwrap();

        secure_delete_file(&path).await.unwrap();
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn secure_delete_nonexistent_file_fails() {
        let path = Path::new("/tmp/najwa_nonexistent_test_file_12345");
        let result = secure_delete_file(path).await;
        assert!(result.is_err());
    }
}
