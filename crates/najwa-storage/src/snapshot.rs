//! Encrypted snapshots and the exclusive file lease used by atomic rekey.
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

use fs2::FileExt;
use rusqlite::{params, Connection};
use zeroize::Zeroizing;

use crate::encrypted_field::{derive_row_key, EncryptedField};
use crate::error::{Result, StorageError};

pub(crate) fn absolute_path(path: &Path) -> Result<PathBuf> {
    if path.exists() {
        return Ok(path.canonicalize()?);
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let name = path
        .file_name()
        .ok_or_else(|| StorageError::InvalidData("database filename missing".into()))?;
    Ok(parent.canonicalize()?.join(name))
}

fn lock_file(path: &Path, suffix: &str) -> Result<File> {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    Ok(OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(Path::new(&name))?)
}

pub(crate) fn gate(path: &Path) -> Result<File> {
    let file = lock_file(path, ".gate")?;
    FileExt::lock_exclusive(&file)?;
    Ok(file)
}

pub(crate) fn lease(path: &Path) -> Result<File> {
    let file = lock_file(path, ".lease")?;
    FileExt::lock_shared(&file)?;
    Ok(file)
}

pub(crate) struct ExclusiveLease<'a>(&'a File);
impl<'a> ExclusiveLease<'a> {
    // The caller holds the gate while upgrading and downgrading. Another
    // connection therefore cannot slip into the close/replace/reopen interval.
    pub(crate) fn acquire(file: &'a File) -> Result<Self> {
        FileExt::unlock(file)?;
        if let Err(e) = FileExt::try_lock_exclusive(file) {
            FileExt::lock_shared(file)?;
            return Err(e.into());
        }
        Ok(Self(file))
    }
}
impl Drop for ExclusiveLease<'_> {
    fn drop(&mut self) {
        // Keep the exclusive lease if downgrading fails; it is safer than
        // continuing without a lease. Connection close releases either lock.
        if let Err(e) = FileExt::lock_shared(self.0) {
            tracing::error!(error=%e, "could not downgrade database lease");
        } else {
            // LockFileEx stacks a shared lock over this handle's exclusive
            // lock. The first unlock removes only the exclusive layer.
            // POSIX flock, by contrast, replaced it with the shared lock above.
            // https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-lockfileex
            #[cfg(windows)]
            if let Err(e) = FileExt::unlock(self.0) {
                tracing::error!(error=%e, "could not release exclusive database lease");
            }
        }
    }
}

/// SQLCipher deliberately disables SQLite's backup API for encrypted databases.
/// ATTACH + sqlcipher_export copies a coherent snapshot with an explicit key.
pub(crate) fn export(conn: &Connection, path: &Path, key: &[u8; 32]) -> Result<()> {
    let key = crate::database::hex_encode(key);
    let path = path
        .to_str()
        .ok_or_else(|| StorageError::InvalidData("snapshot path is not UTF-8".into()))?;
    conn.execute(
        "ATTACH DATABASE ?1 AS najwa_snapshot KEY ?2",
        params![path, key.as_str()],
    )?;
    let result: Result<()> = (|| {
        conn.execute_batch(
            "PRAGMA najwa_snapshot.cipher_page_size=4096;
            PRAGMA najwa_snapshot.kdf_iter=256000;
            PRAGMA najwa_snapshot.cipher_hmac_algorithm=HMAC_SHA256;
            PRAGMA najwa_snapshot.cipher_kdf_algorithm=PBKDF2_HMAC_SHA256;
            PRAGMA najwa_snapshot.synchronous=FULL;",
        )?;
        // Pin one read snapshot across every table copied by the export.
        let tx = conn.unchecked_transaction()?;
        tx.query_row("SELECT sqlcipher_export('najwa_snapshot')", [], |_| Ok(()))?;
        tx.commit()?;
        Ok(())
    })();
    let detach = conn.execute_batch("DETACH DATABASE najwa_snapshot");
    result?;
    detach?;
    Ok(())
}

pub(crate) fn reseal(conn: &mut Connection, old: &[u8; 32], new: &[u8; 32]) -> Result<()> {
    let tx = conn.transaction()?;
    {
        let mut select =
            tx.prepare("SELECT contact_id,dhs_private,rk,cks,ckr FROM ratchet_sessions")?;
        let rows = select.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                [
                    r.get::<_, Option<Vec<u8>>>(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                ],
            ))
        })?;
        for row in rows {
            let (id, fields) = row?;
            let old_key = derive_row_key(old, "ratchet_sessions", id)?;
            let new_key = derive_row_key(new, "ratchet_sessions", id)?;
            let mut sealed = Vec::new();
            for field in fields {
                sealed.push(
                    field
                        .map(|bytes| {
                            let plain = EncryptedField::from_bytes(bytes).decrypt(&old_key)?;
                            EncryptedField::encrypt(&plain, &new_key).map(|f| f.data)
                        })
                        .transpose()?,
                );
            }
            tx.execute("UPDATE ratchet_sessions SET dhs_private=?1,rk=?2,cks=?3,ckr=?4 WHERE contact_id=?5",
                params![sealed[0],sealed[1],sealed[2],sealed[3],id])?;
        }
    }
    {
        let mut select = tx.prepare("SELECT key_id,private_key FROM prekeys")?;
        let rows = select.query_map([], |r| {
            Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?))
        })?;
        for row in rows {
            let (id, bytes) = row?;
            let raw: [u8; 4] = id
                .as_slice()
                .try_into()
                .map_err(|_| StorageError::InvalidData("prekey id length".into()))?;
            let id_number = u32::from_be_bytes(raw) as i64;
            let old_key = derive_row_key(old, "prekeys", id_number)?;
            let new_key = derive_row_key(new, "prekeys", id_number)?;
            let plain = EncryptedField::from_bytes(bytes).decrypt(&old_key)?;
            let sealed = EncryptedField::encrypt(&plain, &new_key)?;
            tx.execute(
                "UPDATE prekeys SET private_key=?1 WHERE key_id=?2",
                params![sealed.data, id],
            )?;
        }
    }
    {
        let mut select = tx.prepare("SELECT id,encrypted_key FROM volatile_keys")?;
        let rows = select.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?)))?;
        for row in rows {
            let (id, bytes) = row?;
            if bytes.len() < 40 {
                return Err(StorageError::InvalidData(
                    "volatile key ciphertext too short".into(),
                ));
            }
            let nonce = bytes[..24].try_into().unwrap();
            let plain = Zeroizing::new(najwa_crypto::aead::decrypt(
                old,
                &nonce,
                &bytes[24..],
                b"volatile-key",
            )?);
            let nonce: [u8; 24] = najwa_crypto::random::random_bytes();
            let ciphertext = najwa_crypto::aead::encrypt(new, &nonce, &plain, b"volatile-key")?;
            let mut sealed = nonce.to_vec();
            sealed.extend_from_slice(&ciphertext);
            tx.execute(
                "UPDATE volatile_keys SET encrypted_key=?1 WHERE id=?2",
                params![sealed, id],
            )?;
        }
    }
    tx.commit()?;
    Ok(())
}

pub(crate) fn sync_parent(path: &Path) -> Result<()> {
    #[cfg(unix)]
    File::open(path.parent().unwrap())?.sync_all()?;
    // Windows does not provide directory fsync through std::fs. The encrypted
    // file is synced before rename; parent durability matches identity writes.
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn lease_upgrade_excludes_other_handles_and_drop_restores_shared_access() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lease.db");
        let _gate = gate(&path).unwrap();
        let owner = lease(&path).unwrap();
        let observer = lock_file(&path, ".lease").unwrap();
        {
            let _exclusive = ExclusiveLease::acquire(&owner).unwrap();
            assert!(FileExt::try_lock_shared(&observer).is_err());
        }
        FileExt::try_lock_shared(&observer).unwrap();
        assert!(ExclusiveLease::acquire(&owner).is_err());
        FileExt::unlock(&observer).unwrap();
        let _exclusive = ExclusiveLease::acquire(&owner).unwrap();
    }
}
