//! SQLCipher database wrapper and connection management.
//!
//! Implements S03 §4 — SQLCipher initialization with encryption key,
//! security pragmas, and WAL mode.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

use rusqlite::{Connection, OptionalExtension};

use najwa_crypto::prelude::*;

use crate::error::{Result, StorageError};

/// Encode bytes as lowercase hex string.
pub(crate) fn hex_encode(bytes: &[u8]) -> Zeroizing<String> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = Zeroizing::new(String::with_capacity(bytes.len() * 2 + 3));
    s.push_str("x'");
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s.push('\'');
    s
}

/// Derive database encryption key from identity key material.
///
/// `db_key = HKDF-SHA256(ikm=ik_private, salt="najwa-db-key", info=DB_KEY_INFO, len=32)`
///
/// The application does not use this derivation. The SQLCipher key of a
/// profile is `derive_sqlcipher_key` in `najwa-ffi` (S03 §3).
pub fn derive_db_key(ik_private_bytes: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let output = hkdf_sha256(
        ik_private_bytes,
        b"najwa-db-key",
        info_strings::DB_KEY_INFO,
        32,
    )?;
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&output);
    Ok(key)
}

/// Encrypted SQLite storage backed by SQLCipher.
///
/// Thread-safe via internal `Mutex<Connection>`.
pub struct SqliteStorage {
    conn: Mutex<Connection>,
    // S01 §6.2: locked memory, shared with the caller and other handles.
    db_key: Arc<GuardedMemory<[u8; 32]>>,
    // Shared for the connection lifetime; rekey requires sole ownership.
    lease: Option<std::fs::File>,
    db_path: PathBuf,
    data_dir: PathBuf,
}

impl SqliteStorage {
    /// Open (or create) an encrypted database at `path`.
    ///
    /// Applies the encryption key, security pragmas, and initializes the schema.
    pub fn open(path: &Path, db_key: &[u8; 32]) -> Result<Self> {
        Self::open_shared(path, Arc::new(GuardedMemory::new(*db_key)))
    }

    /// [`Self::open`] with a key already in [`GuardedMemory`]. The handle
    /// shares that copy rather than making its own (S01 §6.2).
    pub fn open_shared(path: &Path, db_key: Arc<GuardedMemory<[u8; 32]>>) -> Result<Self> {
        let path = crate::snapshot::absolute_path(path)?;
        let _gate = crate::snapshot::gate(&path)?;
        let lease = crate::snapshot::lease(&path)?;
        let conn = open_connection(&path, &db_key)?;

        init_schema(&conn)?;
        crate::hardening::verify_hardening(&conn, &path)?;
        let data_dir = path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        Ok(Self {
            conn: Mutex::new(conn),
            db_key,
            lease: Some(lease),
            db_path: path,
            data_dir,
        })
    }

    /// Open an in-memory database (for testing).
    pub fn open_in_memory(db_key: &[u8; 32]) -> Result<Self> {
        let conn = open_connection(Path::new(":memory:"), db_key)?;
        init_schema(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
            db_key: Arc::new(GuardedMemory::new(*db_key)),
            lease: None,
            db_path: PathBuf::from(":memory:"),
            data_dir: PathBuf::from("."),
        })
    }

    /// Get a reference to the locked connection; never hold it across await.
    pub(crate) fn conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub(crate) fn db_key(&self) -> &[u8; 32] {
        &self.db_key
    }
    pub fn db_path(&self) -> &Path {
        &self.db_path
    }
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    /// Rotate the outer database key and all keys wrapped by it.
    ///
    /// Requires exclusive ownership of this handle and no other storage handle
    /// on the file. Preparation leaves the original untouched; atomic rename is
    /// the commit point. A post-commit I/O error is explicitly RekeyCommitted.
    pub fn rekey(&mut self, new_key: &[u8; 32]) -> Result<()> {
        if self.lease.is_none() {
            // No at-rest outer cipher exists for :memory:; only reseal fields.
            let conn = self.conn.get_mut().unwrap_or_else(|p| p.into_inner());
            crate::snapshot::reseal(conn, &self.db_key, new_key)?;
            self.db_key = Arc::new(GuardedMemory::new(*new_key));
            return Ok(());
        }
        let _gate = crate::snapshot::gate(&self.db_path)?;
        let _exclusive = crate::snapshot::ExclusiveLease::acquire(self.lease.as_ref().unwrap())?;
        let conn = self.conn.get_mut().unwrap_or_else(|p| p.into_inner());
        checked_checkpoint(conn)?;
        // DELETE mode and an exclusive SQLite lock also exclude raw connections
        // during export. The sidecar lease spans the close/rename/reopen gap.
        conn.pragma_update(None, "journal_mode", "DELETE")?;
        conn.pragma_update(None, "locking_mode", "EXCLUSIVE")?;
        conn.execute_batch("BEGIN EXCLUSIVE; COMMIT;")?;
        let prepared = (|| {
            let temp = tempfile::Builder::new()
                .prefix(".najwa-rekey-")
                .tempfile_in(&self.data_dir)?;
            crate::snapshot::export(conn, temp.path(), new_key)?;
            let mut target = open_connection(temp.path(), new_key)?;
            crate::snapshot::reseal(&mut target, &self.db_key, new_key)?;
            checked_checkpoint(&target)?;
            target.pragma_update(None, "journal_mode", "DELETE")?;
            target.close().map_err(|(_, e)| StorageError::Sqlite(e))?;
            temp.as_file().sync_all()?;
            crate::hardening::verify_wal_encryption(temp.path())?;
            Ok::<_, StorageError>(temp)
        })();
        let temp = match prepared {
            Ok(temp) => temp,
            Err(error) => {
                conn.pragma_update(None, "locking_mode", "NORMAL")?;
                conn.pragma_update(None, "journal_mode", "WAL")?;
                return Err(error);
            }
        };
        let old = std::mem::replace(conn, Connection::open_in_memory()?);
        if let Err((old, error)) = old.close() {
            *conn = old;
            return Err(error.into());
        }
        if let Err(error) = temp.persist(&self.db_path) {
            *conn = open_connection(&self.db_path, &self.db_key)?;
            return Err(error.error.into());
        }
        // The new generation is now installed. Never claim rollback afterwards.
        self.db_key = Arc::new(GuardedMemory::new(*new_key));
        *conn = open_connection(&self.db_path, new_key)
            .map_err(|e| StorageError::RekeyCommitted(e.to_string()))?;
        crate::snapshot::sync_parent(&self.db_path)
            .map_err(|e| StorageError::RekeyCommitted(e.to_string()))?;
        Ok(())
    }

    pub fn vacuum(&self) -> Result<()> {
        self.conn().execute_batch("VACUUM")?;
        Ok(())
    }

    /// Checkpoint and truncate the WAL, returning an error if readers block it.
    pub fn wal_checkpoint(&self) -> Result<()> {
        checked_checkpoint(&self.conn())
    }

    /// Create an encrypted backup. Existing destinations are never overwritten.
    /// Disappearing messages and their keys/repair copies are excluded (S12).
    pub fn backup(&self, dest_path: &Path) -> Result<()> {
        let path = crate::snapshot::absolute_path(dest_path)?;
        let parent = path.parent().unwrap();
        // The working snapshot briefly contains disappearing keys. Give it a
        // throwaway outer key, so filesystem remnants cannot be decrypted with
        // the retained backup key. Export only the filtered live rows afterwards.
        let working_key = Zeroizing::new(najwa_crypto::random::random_bytes::<32>());
        let working = tempfile::Builder::new()
            .prefix(".najwa-backup-work-")
            .tempfile_in(parent)?;
        {
            let conn = self.conn();
            crate::snapshot::export(&conn, working.path(), &working_key)?;
        }
        let target = open_connection(working.path(), &working_key)?;
        target.execute_batch(
            "BEGIN IMMEDIATE;
            DELETE FROM outbound_repair_records WHERE content_sealed=1 OR msg_id IN
                (SELECT msg_id FROM messages WHERE disappear_timer IS NOT NULL);
            DELETE FROM messages WHERE disappear_timer IS NOT NULL;
            DELETE FROM volatile_keys;
            COMMIT;",
        )?;
        let temp = tempfile::Builder::new()
            .prefix(".najwa-backup-")
            .tempfile_in(parent)?;
        crate::snapshot::export(&target, temp.path(), &self.db_key)?;
        target.close().map_err(|(_, e)| StorageError::Sqlite(e))?;
        temp.as_file().sync_all()?;
        temp.persist_noclobber(&path)
            .map_err(|e| StorageError::Io(e.error))?;
        crate::snapshot::sync_parent(&path)?;
        Ok(())
    }

    pub fn close(self) -> Result<()> {
        let conn = self.conn.into_inner().unwrap_or_else(|p| p.into_inner());
        conn.close().map_err(|(_, e)| StorageError::Sqlite(e))?;
        Ok(())
    }
}

pub(crate) fn open_connection(path: &Path, db_key: &[u8; 32]) -> Result<Connection> {
    // cipher_memory_security below locks SQLCipher's buffers; raise the OS
    // locked-memory quota first so they can be locked (S01 §6.2).
    najwa_crypto::memory::ensure_lock_quota();
    let conn = Connection::open(path)?;

    // pragma_update builds an ordinary String containing the key. Use the
    // SQLCipher API instead, keeping the raw-key encoding in a wiping buffer.
    let hex_key = hex_encode(db_key);
    // SAFETY: this is a fresh, exclusively owned connection. The key pointer
    // stays valid for the call, and SQLCipher copies exactly the provided size.
    let rc = unsafe {
        rusqlite::ffi::sqlite3_key(conn.handle(), hex_key.as_ptr().cast(), hex_key.len() as i32)
    };
    if rc != rusqlite::ffi::SQLITE_OK {
        return Err(rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(rc), None).into());
    }

    // Security settings (S03 §4.2)
    conn.pragma_update(None, "cipher_page_size", 4096)?;
    conn.pragma_update(None, "kdf_iter", 256000)?;
    conn.pragma_update(None, "cipher_hmac_algorithm", "HMAC_SHA256")?;
    conn.pragma_update(None, "cipher_kdf_algorithm", "PBKDF2_HMAC_SHA256")?;
    // S03 §4.1: zeroize SQLCipher memory buffers. Mandated ON. On Android the
    // 64KB RLIMIT_MEMLOCK can make the underlying mlock() log ENOMEM warnings,
    // but the PRAGMA still succeeds and SQLCipher 4.7+ (we use 4.10.0)
    // continues (it also mlocks a startup pool), so DB open is unaffected.
    // See: https://github.com/sqlcipher/sqlcipher/issues/530
    conn.pragma_update(None, "cipher_memory_security", "ON")?;

    // Secure deletion (S03 §4.2): overwrite deleted data with zeros
    conn.pragma_update(None, "secure_delete", "ON")?;

    // Performance settings (with security constraints)
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "FULL")?;
    conn.pragma_update(None, "temp_store", "MEMORY")?;

    // Enable foreign key enforcement
    conn.pragma_update(None, "foreign_keys", "ON")?;

    Ok(conn)
}

impl std::fmt::Debug for SqliteStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqliteStorage")
            .field("db_path", &self.db_path)
            .finish()
    }
}

/// Consolidated schema DDL (S03 §5). `init_schema` creates it on the first
/// open and applies the supported additive repairs on later opens (S03 §8).
/// There are no group, channel or linked-device tables.
const SCHEMA_SQL: &str = include_str!("../schema.sql");

/// Create the schema, apply the additive repairs and stamp the schema version
/// (S03 §8), refusing any other stored version.
///
/// Idempotent: every statement is `IF NOT EXISTS` / `INSERT OR IGNORE` or a
/// guarded repair, so reopening a current database changes no schema.
fn init_schema(conn: &Connection) -> Result<()> {
    let tx = rusqlite::Transaction::new_unchecked(conn, rusqlite::TransactionBehavior::Immediate)?;
    let table_exists: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='db_meta')",
        [],
        |r| r.get(0),
    )?;
    let existing: Option<String> = if table_exists {
        tx.query_row(
            "SELECT value FROM db_meta WHERE key='schema_version'",
            [],
            |r| r.get(0),
        )
        .optional()?
    } else {
        None
    };
    if let Some(other) = existing.as_deref().filter(|v| *v != "2") {
        return Err(StorageError::InvalidData(format!(
            "database schema version {other} is not supported"
        )));
    }
    // DDL and the version stamp commit together. IF NOT EXISTS also repairs a
    // partially initialized pre-release database left by the old initializer.
    tx.execute_batch(SCHEMA_SQL)?;
    let has_deposit_stamp: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('outgoing_frames') WHERE name='deposited_at')",
        [], |r| r.get(0))?;
    if !has_deposit_stamp {
        tx.execute_batch("ALTER TABLE outgoing_frames ADD COLUMN deposited_at INTEGER;")?;
    }
    let has_sealed: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('outbound_repair_records') WHERE name='content_sealed')",
        [], |r| r.get(0))?;
    if !has_sealed {
        tx.execute_batch("ALTER TABLE outbound_repair_records ADD COLUMN content_sealed INTEGER NOT NULL DEFAULT 0;
            DELETE FROM outbound_repair_records WHERE NOT EXISTS
                (SELECT 1 FROM messages m WHERE m.msg_id=outbound_repair_records.msg_id);
            UPDATE outbound_repair_records SET content_sealed=1, content=
                (SELECT content FROM messages m WHERE m.msg_id=outbound_repair_records.msg_id)
            WHERE msg_id IN (SELECT msg_id FROM messages WHERE disappear_timer IS NOT NULL);")?;
    }
    let has_prev_dhs: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('ratchet_sessions') WHERE name='prev_dhs_pub')",
        [], |r| r.get(0))?;
    if !has_prev_dhs {
        tx.execute_batch("ALTER TABLE ratchet_sessions ADD COLUMN prev_dhs_pub BLOB;")?;
    }
    tx.execute(
        "INSERT OR IGNORE INTO db_meta (key,value) VALUES ('schema_version','2')",
        [],
    )?;
    tx.execute_batch("UPDATE volatile_keys SET expires_at=(SELECT disappear_at FROM messages m WHERE m.msg_id=volatile_keys.msg_id)
        WHERE msg_id IN (SELECT msg_id FROM messages WHERE disappear_at IS NOT NULL);")?;
    tx.commit()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn existing_queue_schema_gains_deposit_tracking_without_losing_profile_data() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("queue-upgrade.db");
        let key = [0x61; 32];
        {
            let db = SqliteStorage::open(&path, &key).unwrap();
            db.set_setting("upgrade-proof", &"retained").unwrap();
            let contact = db.create_contact(&crate::types::NewContact {
                pseudonym: [1; 32],
                their_ik_pub: [2; 32],
                their_device_pub: [2; 32],
                our_pseudonym: [3; 32],
                display_name: None,
            }).unwrap();
            db.conn().execute(
                "INSERT INTO outgoing_frames(contact_id,wire,dh_pub,n,requires_ack) VALUES(?1,?2,?3,0,1)",
                rusqlite::params![contact, vec![1u8, 2, 3], vec![4u8; 32]],
            ).unwrap();
            db.conn().execute_batch("ALTER TABLE outgoing_frames DROP COLUMN deposited_at;").unwrap();
        }
        let db = SqliteStorage::open(&path, &key).unwrap();
        assert_eq!(db.get_setting::<String>("upgrade-proof").unwrap().as_deref(), Some("retained"));
        assert_eq!(db.pending_deposit_count().unwrap(), 1);
        let frames = db.outgoing_frames().unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].wire, [1, 2, 3]);
        assert!(frames[0].deposited_at.is_none());
        let version: String = db.conn().query_row("SELECT value FROM db_meta WHERE key='schema_version'", [], |r| r.get(0)).unwrap();
        assert_eq!(version, "2");
    }

    /// S06 §3.10: a profile created before `prev_dhs_pub` existed gains the
    /// column on reopen; its sessions read `None` and keep working.
    #[test]
    fn existing_ratchet_sessions_gain_prev_dhs_pub_on_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("prev-dhs-upgrade.db");
        let key = [0x62; 32];
        let state = |prev: Option<Vec<u8>>| crate::types::RatchetState {
            dhs_private: Some(vec![1; 32]), dhs_public: Some(vec![2; 32]),
            dhr: Some(vec![3; 32]), rk: Some(vec![4; 32]), cks: None, ckr: None,
            ns: 0, nr: 0, pn: 0, prev_dhs_pub: prev, established_at: 1, last_activity: 1,
        };
        let contact = {
            let db = SqliteStorage::open(&path, &key).unwrap();
            let contact = db.create_contact(&crate::types::NewContact {
                pseudonym: [1; 32], their_ik_pub: [2; 32], their_device_pub: [2; 32],
                our_pseudonym: [3; 32], display_name: None,
            }).unwrap();
            db.save_ratchet_state(contact, &state(Some(vec![9; 32]))).unwrap();
            db.conn().execute_batch("ALTER TABLE ratchet_sessions DROP COLUMN prev_dhs_pub;").unwrap();
            contact
        };
        let db = SqliteStorage::open(&path, &key).unwrap();
        assert!(db.get_ratchet_state(contact).unwrap().unwrap().prev_dhs_pub.is_none());
        db.save_ratchet_state(contact, &state(Some(vec![9; 32]))).unwrap();
        assert_eq!(db.get_ratchet_state(contact).unwrap().unwrap().prev_dhs_pub, Some(vec![9; 32]));
    }

    fn test_db() -> SqliteStorage {
        let key = [0x42u8; 32];
        SqliteStorage::open_in_memory(&key).unwrap()
    }

    /// Row-14 finding: `init_schema` was not idempotent, so REOPENING a
    /// file-backed database failed with "table db_meta already exists" —
    /// invisible to the in-memory test suite, which always starts fresh.
    #[test]
    fn file_database_can_be_reopened_with_the_same_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("reopen.db");
        let key = [0x7Au8; 32];

        {
            let db = SqliteStorage::open(&path, &key).unwrap();
            let _ = db; // schema created, connection closed on drop
        }
        {
            let db = SqliteStorage::open(&path, &key).unwrap();
            let version: String = db
                .conn()
                .query_row(
                    "SELECT value FROM db_meta WHERE key = 'schema_version'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(version, "2");
        }
    }

    #[test]
    fn foreign_schema_version_is_refused_on_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("foreign.db");
        let key = [0x7Bu8; 32];
        {
            let db = SqliteStorage::open(&path, &key).unwrap();
            db.conn()
                .execute(
                    "UPDATE db_meta SET value = '9' WHERE key = 'schema_version'",
                    [],
                )
                .unwrap();
        }
        let err = SqliteStorage::open(&path, &key).unwrap_err();
        assert!(err.to_string().contains("not supported"));
    }

    #[test]
    fn open_in_memory_succeeds() {
        let _db = test_db();
    }

    #[test]
    fn schema_version_is_2_on_fresh_db() {
        // S03 §8: a fresh database carries schema_version '2'.
        let db = test_db();
        let conn = db.conn();
        let ver: String = conn
            .query_row(
                "SELECT value FROM db_meta WHERE key = 'schema_version'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(ver, "2");
    }

    // S01 §6.2: handles opened with the profile's locked key use that copy.
    #[test]
    fn shared_open_uses_the_callers_locked_key() {
        let dir = tempfile::tempdir().unwrap();
        let key = Arc::new(GuardedMemory::new([0x62; 32]));
        let db = SqliteStorage::open_shared(&dir.path().join("shared.db"), key.clone()).unwrap();
        assert!(std::ptr::eq(db.db_key(), &**key));
    }

    #[test]
    fn derive_db_key_deterministic() {
        let ik = [0xBB; 32];
        let k1 = derive_db_key(&ik).unwrap();
        let k2 = derive_db_key(&ik).unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn derive_db_key_different_inputs_differ() {
        let k1 = derive_db_key(&[0xAA; 32]).unwrap();
        let k2 = derive_db_key(&[0xBB; 32]).unwrap();
        assert_ne!(k1, k2);
    }

    #[test]
    fn vacuum_succeeds() {
        let db = test_db();
        db.vacuum().unwrap();
    }
}

/// SQLite reports busy checkpoints as a result row, not an SQL error.
fn checked_checkpoint(conn: &Connection) -> Result<()> {
    let (busy, frames, checkpointed): (i32, i32, i32) =
        conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })?;
    if busy != 0 || frames != checkpointed {
        return Err(StorageError::InvalidData(format!(
            "WAL checkpoint blocked: busy={busy}, frames={frames}, checkpointed={checkpointed}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod regression_tests {
    use super::*;
    #[test]
    fn every_connection_commits_with_full_synchronous() {
        let db = SqliteStorage::open_in_memory(&[1; 32]).unwrap();
        let sync: i32 = db
            .conn()
            .pragma_query_value(None, "synchronous", |r| r.get(0))
            .unwrap();
        assert_eq!(sync, 2);
        let dir = tempfile::tempdir().unwrap();
        let file = SqliteStorage::open(&dir.path().join("full.db"), &[2; 32]).unwrap();
        assert_eq!(
            file.conn()
                .pragma_query_value(None, "synchronous", |r| r.get::<_, i32>(0))
                .unwrap(),
            2
        );
    }

    #[test]
    fn schema_creation_rolls_back_ddl_when_a_late_statement_fails() {
        let conn = open_connection(Path::new(":memory:"), &[1; 32]).unwrap();
        // A pre-existing incompatible table fails a late schema index creation.
        conn.execute_batch("CREATE TABLE contacts(wrong_column INTEGER)")
            .unwrap();
        assert!(init_schema(&conn).is_err());
        let created: i64 = conn.query_row("SELECT count(*) FROM sqlite_master WHERE name IN ('db_meta','ratchet_sessions','messages')",[],|r|r.get(0)).unwrap();
        assert_eq!(created, 0, "no partial schema is committed");
    }
}
