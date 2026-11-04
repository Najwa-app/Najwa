//! Atomic, mailbox-scoped prekey lifecycle persistence.
use crate::{
    database::SqliteStorage,
    encrypted_field::EncryptedField,
    error::{Result, StorageError},
    types::{Prekey, PrekeyType},
};
use rusqlite::{params, OptionalExtension};

/// Settings are keyed by receiving capability, including queues on one onion.
pub fn prekey_scope_setting(kind: &str, fetch_scope: &[u8; 32]) -> String {
    let scope: String = fetch_scope.iter().map(|b| format!("{b:02x}")).collect();
    format!("prekeys:{kind}:{scope}")
}

impl SqliteStorage {
    /// Insert-only key batch and SPK retirement in one transaction. A collision
    /// never replaces private material needed by an in-flight Initial.
    pub fn commit_prekey_batch(
        &self,
        mailbox_id: i64,
        fetch_scope: &[u8; 32],
        spk: Option<&Prekey>,
        opks: &[Prekey],
        grace_end: i64,
    ) -> Result<()> {
        if spk.is_some_and(|s| s.key_type != PrekeyType::Spk)
            || opks.iter().any(|o| o.key_type != PrekeyType::Opk)
        {
            return Err(StorageError::InvalidData("prekey type mismatch".into()));
        }
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let count: u32 = tx.query_row(
            "SELECT COUNT(*) FROM prekeys WHERE mailbox_id=?1 AND fetch_scope=?2 AND key_type=1 AND used=0 AND expires_at IS NULL",
            params![mailbox_id, fetch_scope.as_slice()],
            |r| r.get(0),
        )?;
        if count as usize + opks.len() > 200 {
            return Err(StorageError::InvalidData("OPK pool exceeds 200".into()));
        }
        for key in spk.into_iter().chain(opks.iter()) {
            if key.private_key.len() != 32 || key.public_key.len() != 32 || key.used {
                return Err(StorageError::InvalidData("invalid fresh prekey".into()));
            }
            let row_key = crate::keys::row_seal::prekey_row_key(self.db_key(), &key.key_id)?;
            let sealed = EncryptedField::encrypt(&key.private_key, &row_key)?.data;
            tx.execute(
                "INSERT INTO prekey_used_ids(key_id) VALUES (?1)",
                [key.key_id.as_slice()],
            )?;
            tx.execute("INSERT INTO prekeys (key_id,key_type,private_key,public_key,signature,
                created_at,expires_at,used,used_at,mailbox_id,fetch_scope) VALUES (?1,?2,?3,?4,?5,?6,NULL,0,NULL,?7,?8)",
                params![key.key_id.as_slice(), key.key_type as i32, sealed, key.public_key,
                    key.signature, key.created_at, mailbox_id, fetch_scope.as_slice()])?;
        }
        if let Some(spk) = spk {
            tx.execute(
                "UPDATE prekeys SET expires_at=?1 WHERE mailbox_id=?2 AND key_type=0
                AND expires_at IS NULL AND key_id != ?3 AND fetch_scope=?4",
                params![
                    grace_end,
                    mailbox_id,
                    spk.key_id.as_slice(),
                    fetch_scope.as_slice()
                ],
            )?;
        }
        tx.execute(
            "INSERT OR REPLACE INTO settings(key,value,updated_at) VALUES (?1,?2,?3)",
            params![
                prekey_scope_setting("dirty", fetch_scope),
                &[1u8][..],
                najwa_crypto::time::now() as i64
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn prekey_ids_for_mailbox(
        &self,
        mailbox_id: i64,
        fetch_scope: &[u8; 32],
    ) -> Result<Vec<[u8; 4]>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT key_id FROM prekeys WHERE mailbox_id=?1 AND fetch_scope=?2 ORDER BY created_at DESC, rowid DESC",
        )?;
        let rows = stmt.query_map(params![mailbox_id, fetch_scope.as_slice()], |r| {
            r.get::<_, Vec<u8>>(0)
        })?;
        rows.map(|r| {
            r?.try_into()
                .map_err(|_| StorageError::InvalidData("invalid prekey id".into()))
        })
        .collect()
    }

    pub fn expire_mailbox_spk(
        &self,
        mailbox_id: i64,
        fetch_scope: &[u8; 32],
        id: &[u8; 4],
        expires: i64,
    ) -> Result<()> {
        self.conn().execute(
            "UPDATE prekeys SET expires_at=?1 WHERE key_id=?2 AND mailbox_id=?3 AND key_type=0 AND fetch_scope=?4",
            params![expires, id.as_slice(), mailbox_id, fetch_scope.as_slice()],
        )?;
        Ok(())
    }

    pub fn cleanup_mailbox_prekeys(
        &self,
        mailbox_id: i64,
        fetch_scope: &[u8; 32],
        key_type: PrekeyType,
        before: i64,
    ) -> Result<u32> {
        let sql = match key_type {
            PrekeyType::Spk => {
                "DELETE FROM prekeys WHERE mailbox_id=?1 AND key_type=0 AND expires_at<=?2 AND fetch_scope=?3"
            }
            PrekeyType::Opk => {
                "DELETE FROM prekeys WHERE mailbox_id=?1 AND key_type=1 AND ((used=1 AND used_at<=?2) OR expires_at<=unixepoch()) AND fetch_scope=?3"
            }
        };
        Ok(self
            .conn()
            .execute(sql, params![mailbox_id, before, fetch_scope.as_slice()])? as u32)
    }
}

impl SqliteStorage {
    pub fn prekey_in_scope(&self, id: &[u8; 4], scope: &[u8; 32]) -> Result<bool> {
        Ok(self.conn().query_row(
            "SELECT EXISTS(SELECT 1 FROM prekeys WHERE key_id=?1 AND fetch_scope=?2)",
            params![id.as_slice(), scope.as_slice()],
            |r| r.get(0),
        )?)
    }

    /// Invalidate old key material and publish the prepared recovery generation
    /// atomically. Retain IDs, but never retain a usable pre-restore private key.
    pub fn prepare_prekey_recovery(&self, generation: &[u8; 32]) -> Result<()> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let prepared: Option<Vec<u8>> = tx
            .query_row(
                "SELECT value FROM settings WHERE key='prekeys:prepared'",
                [],
                |r| r.get(0),
            )
            .optional()?;
        if prepared.as_deref() == Some(generation.as_slice()) {
            return Ok(());
        }
        tx.execute(
            "INSERT OR IGNORE INTO prekey_used_ids SELECT key_id FROM prekeys",
            [],
        )?;
        tx.execute("DELETE FROM prekeys", [])?;
        tx.execute(
            "DELETE FROM settings WHERE key LIKE 'prekeys:last:%' OR key LIKE 'prekeys:dirty:%' OR key='prekeys:complete'",
            [],
        )?;
        tx.execute("INSERT OR REPLACE INTO settings(key,value,updated_at) VALUES ('prekeys:prepared',?1,?2)",
            params![generation.as_slice(), najwa_crypto::time::now() as i64])?;
        tx.commit()?;
        Ok(())
    }
}

impl SqliteStorage {
    /// Retire served keys from the publication pool without destroying private
    /// material needed by Initials still in flight. Never revive retired keys.
    pub fn reconcile_prekey_inventory(
        &self,
        mailbox_id: i64,
        fetch_scope: &[u8; 32],
        available: &[u32],
        grace_end: i64,
    ) -> Result<()> {
        let ids: std::collections::HashSet<u32> = available.iter().copied().collect();
        if ids.len() != available.len() || ids.len() > 200 {
            return Err(StorageError::InvalidData(
                "invalid server prekey inventory".into(),
            ));
        }
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        for id in &ids {
            let known: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM prekeys WHERE key_id=?1
                AND mailbox_id=?2 AND fetch_scope=?3 AND key_type=1 AND used=0 AND expires_at IS NULL)",
                params![id.to_be_bytes().as_slice(), mailbox_id, fetch_scope.as_slice()], |r| r.get(0))?;
            if !known {
                return Err(StorageError::InvalidData(
                    "server returned an unknown or retired OPK".into(),
                ));
            }
        }
        let active = tx
            .prepare(
                "SELECT key_id FROM prekeys WHERE mailbox_id=?1 AND fetch_scope=?2
            AND key_type=1 AND used=0 AND expires_at IS NULL",
            )?
            .query_map(params![mailbox_id, fetch_scope.as_slice()], |r| {
                r.get::<_, Vec<u8>>(0)
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut changed = false;
        for bytes in active {
            let id = u32::from_be_bytes(
                bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| StorageError::InvalidData("invalid prekey id".into()))?,
            );
            if !ids.contains(&id) {
                tx.execute(
                    "UPDATE prekeys SET expires_at=?1 WHERE key_id=?2",
                    params![grace_end, bytes],
                )?;
                changed = true;
            }
        }
        if changed {
            tx.execute(
                "INSERT OR REPLACE INTO settings(key,value,updated_at) VALUES (?1,?2,?3)",
                params![
                    prekey_scope_setting("dirty", fetch_scope),
                    &[1u8][..],
                    najwa_crypto::time::now() as i64
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }
}
