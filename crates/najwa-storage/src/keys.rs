//! Key storage operations (prekeys, ratchet state, skipped keys).
//!
//! Implements S03 §5.4 (ratchet sessions), S03 §5.5 (skipped keys), S03 §5.8 (prekeys).
//!
//! Sensitive columns are additionally sealed per-row (S03 §7 defense-in-depth):
//! `row_key = HKDF(db_key, salt=table, info=row_id)`, stored as
//! `nonce(24) || XChaCha20Poly1305(row_key, …, "field")`. Wired: the four
//! ratchet secret columns (`dhs_private`, `rk`, `cks`, `ckr`) and the prekey
//! `private_key`. Skipped-message keys are protected by SQLCipher alone
//! (S03 §7).

use rusqlite::params;
use zeroize::Zeroizing;

use crate::database::SqliteStorage;
use crate::encrypted_field::{derive_row_key, EncryptedField};
use crate::error::{Result, StorageError};
use crate::types::*;

// ---------------------------------------------------------------------------
// Ratchet Sessions
// ---------------------------------------------------------------------------

/// Per-row seal/unseal helpers (S03 §7). Free functions so both the ratchet
/// and prekey paths share them.
pub(crate) mod row_seal {
    use super::*;

    /// Row key for a `ratchet_sessions` row: the contact id is the table's
    /// stable primary key, so it is the §7 `row_id`.
    pub(crate) fn ratchet_row_key(
        db_key: &[u8; 32],
        contact_id: ContactId,
    ) -> Result<Zeroizing<[u8; 32]>> {
        derive_row_key(db_key, "ratchet_sessions", contact_id)
    }

    /// Row key for a `prekeys` row. §7's `row_id` is the row's stable identity;
    /// the autoincrement id does not exist before insert, so the row's natural
    /// business key — the 4-byte `key_id` as a big-endian u32 — is used.
    pub(crate) fn prekey_row_key(
        db_key: &[u8; 32],
        key_id: &[u8; 4],
    ) -> Result<Zeroizing<[u8; 32]>> {
        derive_row_key(db_key, "prekeys", u32::from_be_bytes(*key_id) as i64)
    }

    pub(crate) fn seal(secret: &Option<Vec<u8>>, row_key: &[u8; 32]) -> Result<Option<Vec<u8>>> {
        match secret {
            Some(s) => Ok(Some(EncryptedField::encrypt(s, row_key)?.data)),
            None => Ok(None),
        }
    }

    pub(crate) fn unseal(sealed: &Option<Vec<u8>>, row_key: &[u8; 32]) -> Result<Option<Vec<u8>>> {
        match sealed {
            Some(blob) => {
                let mut secret = EncryptedField::from_bytes(blob.clone()).decrypt(row_key)?;
                Ok(Some(std::mem::take(&mut *secret)))
            }
            None => Ok(None),
        }
    }

    pub(crate) fn unseal_state(mut state: RatchetState, key: &[u8; 32]) -> Result<RatchetState> {
        state.dhs_private = unseal(&state.dhs_private, key)?;
        state.rk = unseal(&state.rk, key)?;
        state.cks = unseal(&state.cks, key)?;
        state.ckr = unseal(&state.ckr, key)?;
        Ok(state)
    }

    /// Unseal `private_key` on every row of a prekey query (S03 §7).
    ///
    /// The item is double-wrapped (rusqlite row error, then the mapper's own
    /// crate Result) because `row_to_prekey` returns the crate Result.
    pub(crate) fn unseal_prekeys<I>(db_key: &[u8; 32], rows: I) -> Result<Vec<Prekey>>
    where
        I: Iterator<Item = rusqlite::Result<Result<Prekey>>>,
    {
        let mut prekeys = Vec::new();
        for r in rows {
            let mut pk = r??;
            let row_key = prekey_row_key(db_key, &pk.key_id)?;
            let mut plain = EncryptedField::from_bytes(std::mem::take(&mut pk.private_key))
                .decrypt(&row_key)?;
            pk.private_key = std::mem::take(&mut *plain);
            prekeys.push(pk);
        }
        Ok(prekeys)
    }
}

impl SqliteStorage {
    /// Get the ratchet state for a contact.
    ///
    /// The four secret columns come back §7-sealed and are unsealed here.
    pub fn get_ratchet_state(&self, contact_id: ContactId) -> Result<Option<RatchetState>> {
        let conn = self.conn();
        let mut stmt = conn.prepare_cached(
            "SELECT dhs_private, dhs_public, dhr, rk, cks, ckr,
                    ns, nr, pn, established_at, last_activity, prev_dhs_pub
             FROM ratchet_sessions WHERE contact_id = ?1",
        )?;

        let result = stmt.query_row(params![contact_id], |row| {
            Ok((
                row.get::<_, Option<Vec<u8>>>(0)?,
                row.get::<_, Option<Vec<u8>>>(1)?,
                row.get::<_, Option<Vec<u8>>>(2)?,
                row.get::<_, Option<Vec<u8>>>(3)?,
                row.get::<_, Option<Vec<u8>>>(4)?,
                row.get::<_, Option<Vec<u8>>>(5)?,
                row.get::<_, i32>(6)? as u32,
                row.get::<_, i32>(7)? as u32,
                row.get::<_, i32>(8)? as u32,
                row.get(9)?,
                row.get(10)?,
                row.get::<_, Option<Vec<u8>>>(11)?,
            ))
        });

        match result {
            Ok((dhs_private, dhs_public, dhr, rk, cks, ckr, ns, nr, pn, est, act, prev)) => {
                let row_key = row_seal::ratchet_row_key(self.db_key(), contact_id)?;
                let state = RatchetState {
                    dhs_private,
                    dhs_public,
                    dhr,
                    rk,
                    cks,
                    ckr,
                    ns,
                    nr,
                    pn,
                    prev_dhs_pub: prev,
                    established_at: est,
                    last_activity: act,
                };
                Ok(Some(row_seal::unseal_state(state, &row_key)?))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Save (insert or replace) a ratchet state for a contact.
    ///
    /// The four secret columns are §7-sealed before they reach SQL.
    pub fn save_ratchet_state(&self, contact_id: ContactId, state: &RatchetState) -> Result<()> {
        let row_key = row_seal::ratchet_row_key(self.db_key(), contact_id)?;
        let conn = self.conn();
        conn.execute(
            "INSERT OR REPLACE INTO ratchet_sessions
                (contact_id, dhs_private, dhs_public, dhr, rk, cks, ckr,
                 ns, nr, pn, established_at, last_activity, prev_dhs_pub)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                contact_id,
                row_seal::seal(&state.dhs_private, &row_key)?,
                state.dhs_public,
                state.dhr,
                row_seal::seal(&state.rk, &row_key)?,
                row_seal::seal(&state.cks, &row_key)?,
                row_seal::seal(&state.ckr, &row_key)?,
                state.ns as i32,
                state.nr as i32,
                state.pn as i32,
                state.established_at,
                state.last_activity,
                state.prev_dhs_pub,
            ],
        )?;
        Ok(())
    }

    /// Delete the ratchet state for a contact.
    pub fn delete_ratchet_state(&self, contact_id: ContactId) -> Result<()> {
        let conn = self.conn();
        conn.execute(
            "DELETE FROM ratchet_sessions WHERE contact_id = ?1",
            params![contact_id],
        )?;
        Ok(())
    }

    /// Look up a ratchet session by the remote DH public key (S08 §4.4 fast path).
    ///
    /// Scans `dhr` column (their current ratchet public key) for a match.
    /// Returns the contact ID and ratchet state if found.
    pub fn get_ratchet_state_by_dh_pub(
        &self,
        dh_pub: &[u8; 32],
    ) -> Result<Option<(ContactId, RatchetState)>> {
        let conn = self.conn();
        let mut stmt = conn.prepare_cached(
            "SELECT contact_id, dhs_private, dhs_public, dhr, rk, cks, ckr,
                    ns, nr, pn, established_at, last_activity, prev_dhs_pub
             FROM ratchet_sessions WHERE dhr = ?1",
        )?;

        let result = stmt.query_row(params![dh_pub.as_slice()], |row| {
            Ok((
                row.get::<_, ContactId>(0)?,
                row.get::<_, Option<Vec<u8>>>(1)?,
                row.get::<_, Option<Vec<u8>>>(2)?,
                row.get::<_, Option<Vec<u8>>>(3)?,
                row.get::<_, Option<Vec<u8>>>(4)?,
                row.get::<_, Option<Vec<u8>>>(5)?,
                row.get::<_, Option<Vec<u8>>>(6)?,
                row.get::<_, i32>(7)? as u32,
                row.get::<_, i32>(8)? as u32,
                row.get::<_, i32>(9)? as u32,
                row.get(10)?,
                row.get(11)?,
                row.get::<_, Option<Vec<u8>>>(12)?,
            ))
        });

        match result {
            Ok((cid, dhs_private, dhs_public, dhr, rk, cks, ckr, ns, nr, pn, est, act, prev)) => {
                let row_key = row_seal::ratchet_row_key(self.db_key(), cid)?;
                let state = RatchetState {
                    dhs_private,
                    dhs_public,
                    dhr,
                    rk,
                    cks,
                    ckr,
                    ns,
                    nr,
                    pn,
                    prev_dhs_pub: prev,
                    established_at: est,
                    last_activity: act,
                };
                Ok(Some((cid, row_seal::unseal_state(state, &row_key)?)))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Get the session associated data (AD) for a contact.
    pub fn get_session_ad(&self, contact_id: ContactId) -> Result<Option<Vec<u8>>> {
        let key = format!("session_ad:{contact_id}");
        let conn = self.conn();
        let result: std::result::Result<Vec<u8>, _> = conn.query_row(
            "SELECT value FROM settings WHERE key = ?1",
            params![key],
            |row| row.get(0),
        );

        match result {
            Ok(blob) => Ok(Some(blob)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Save the session associated data (AD) for a contact.
    pub fn save_session_ad(&self, contact_id: ContactId, ad: &[u8]) -> Result<()> {
        let key = format!("session_ad:{contact_id}");
        let conn = self.conn();
        let now = najwa_crypto::time::now() as i64;
        conn.execute(
            "INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?1, ?2, ?3)",
            params![key, ad, now],
        )?;
        Ok(())
    }

    /// Delete the session associated data (AD) for a contact.
    pub fn delete_session_ad(&self, contact_id: ContactId) -> Result<()> {
        let key = format!("session_ad:{contact_id}");
        let conn = self.conn();
        conn.execute("DELETE FROM settings WHERE key = ?1", params![key])?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Skipped Keys
// ---------------------------------------------------------------------------

impl SqliteStorage {
    /// Save a skipped message key.
    pub fn save_skipped_key(&self, contact_id: ContactId, key: &SkippedKey) -> Result<()> {
        let conn = self.conn();
        conn.execute(
            "INSERT OR REPLACE INTO skipped_keys
                (contact_id, dh_pub, message_number, message_key, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                contact_id,
                key.dh_pub.as_slice(),
                key.message_number as i32,
                key.message_key.as_slice(),
                key.created_at,
                key.expires_at,
            ],
        )?;
        Ok(())
    }

    /// Get a skipped message key.
    pub fn get_skipped_key(
        &self,
        contact_id: ContactId,
        dh_pub: &[u8; 32],
        msg_num: u32,
    ) -> Result<Option<[u8; 32]>> {
        let conn = self.conn();
        let mut stmt = conn.prepare_cached(
            "SELECT message_key FROM skipped_keys
             WHERE contact_id = ?1 AND dh_pub = ?2 AND message_number = ?3",
        )?;

        let result = stmt.query_row(
            params![contact_id, dh_pub.as_slice(), msg_num as i32],
            |row| {
                let blob = Zeroizing::new(row.get::<_, Vec<u8>>(0)?);
                Ok(blob)
            },
        );

        match result {
            Ok(blob) => {
                if blob.len() == 32 {
                    let mut key = [0u8; 32];
                    key.copy_from_slice(&blob);
                    Ok(Some(key))
                } else {
                    Err(StorageError::InvalidData("skipped key wrong length".into()))
                }
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Delete a skipped message key after it has been used.
    pub fn delete_skipped_key(
        &self,
        contact_id: ContactId,
        dh_pub: &[u8; 32],
        msg_num: u32,
    ) -> Result<()> {
        let conn = self.conn();
        conn.execute(
            "DELETE FROM skipped_keys
             WHERE contact_id = ?1 AND dh_pub = ?2 AND message_number = ?3",
            params![contact_id, dh_pub.as_slice(), msg_num as i32],
        )?;
        Ok(())
    }

    /// Count skipped keys for a contact.
    pub fn count_skipped_keys(&self, contact_id: ContactId) -> Result<u32> {
        let conn = self.conn();
        let count: i32 = conn.query_row(
            "SELECT COUNT(*) FROM skipped_keys WHERE contact_id = ?1",
            params![contact_id],
            |row| row.get(0),
        )?;
        Ok(count as u32)
    }

    /// Load all non-expired skipped keys for a contact.
    ///
    /// Used to populate the in-memory ratchet state after restart so that
    /// out-of-order messages received before the restart can still be decrypted.
    pub fn load_skipped_keys(&self, contact_id: ContactId) -> Result<Vec<SkippedKey>> {
        let conn = self.conn();
        let now = najwa_crypto::time::now() as i64;
        let mut stmt = conn.prepare_cached(
            "SELECT dh_pub, message_number, message_key, created_at, expires_at
             FROM skipped_keys
             WHERE contact_id = ?1 AND expires_at >= ?2",
        )?;
        let rows = stmt.query_map(params![contact_id, now], |row| {
            let dh_pub_blob: Vec<u8> = row.get(0)?;
            let msg_num: i32 = row.get(1)?;
            let mk_blob = Zeroizing::new(row.get::<_, Vec<u8>>(2)?);
            let created_at: i64 = row.get(3)?;
            let expires_at: i64 = row.get(4)?;
            Ok((dh_pub_blob, msg_num, mk_blob, created_at, expires_at))
        })?;
        let mut keys = Vec::new();
        for row in rows {
            let (dh_pub_blob, msg_num, mk_blob, created_at, expires_at) = row?;
            if dh_pub_blob.len() == 32 && mk_blob.len() == 32 {
                let mut dh_pub = [0u8; 32];
                dh_pub.copy_from_slice(&dh_pub_blob);
                let mut message_key = [0u8; 32];
                message_key.copy_from_slice(&mk_blob);
                keys.push(SkippedKey {
                    dh_pub,
                    message_number: msg_num as u32,
                    message_key,
                    created_at,
                    expires_at,
                });
            }
        }
        Ok(keys)
    }

    /// Delete expired skipped keys. Returns number of keys deleted.
    pub fn cleanup_expired_skipped_keys(&self) -> Result<u32> {
        let conn = self.conn();
        let now = najwa_crypto::time::now() as i64;
        let deleted = conn.execute(
            "DELETE FROM skipped_keys WHERE expires_at < ?1",
            params![now],
        )?;
        Ok(deleted as u32)
    }
}

// ---------------------------------------------------------------------------
// Prekeys
// ---------------------------------------------------------------------------

impl SqliteStorage {
    /// Save a prekey (SPK or OPK).
    ///
    /// `private_key` is §7-sealed with the row's natural-key-derived key.
    pub fn save_prekey(&self, prekey: &Prekey) -> Result<()> {
        let row_key = row_seal::prekey_row_key(self.db_key(), &prekey.key_id)?;
        let private_key = EncryptedField::encrypt(&prekey.private_key, &row_key)?.data;
        let conn = self.conn();
        conn.execute(
            "INSERT OR REPLACE INTO prekeys
                (key_id, key_type, private_key, public_key, signature,
                 created_at, expires_at, used, used_at, mailbox_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                prekey.key_id.as_slice(),
                prekey.key_type as i32,
                private_key,
                prekey.public_key,
                prekey.signature,
                prekey.created_at,
                prekey.expires_at,
                prekey.used as i32,
                prekey.used_at,
                prekey.mailbox_id,
            ],
        )?;
        Ok(())
    }

    /// Get a prekey by its 4-byte key ID.
    pub fn get_prekey(&self, key_id: &[u8; 4]) -> Result<Option<Prekey>> {
        let conn = self.conn();
        let mut stmt = conn.prepare_cached(
            "SELECT key_id, key_type, private_key, public_key, signature,
                    created_at, expires_at, used, used_at, mailbox_id
             FROM prekeys WHERE key_id = ?1",
        )?;

        let result = stmt.query_row(params![key_id.as_slice()], |row| Ok(row_to_prekey(row)));

        match result {
            Ok(inner) => {
                let mut pk = inner?;
                let row_key = row_seal::prekey_row_key(self.db_key(), &pk.key_id)?;
                let mut plain = EncryptedField::from_bytes(std::mem::take(&mut pk.private_key))
                    .decrypt(&row_key)?;
                pk.private_key = std::mem::take(&mut *plain);
                Ok(Some(pk))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Get the current (most recent, unused) signed prekey.
    pub fn get_current_spk(&self) -> Result<Option<Prekey>> {
        let conn = self.conn();
        let mut stmt = conn.prepare_cached(
            "SELECT key_id, key_type, private_key, public_key, signature,
                    created_at, expires_at, used, used_at, mailbox_id
             FROM prekeys
             WHERE key_type = 0 AND used = 0 AND expires_at IS NULL
             ORDER BY created_at DESC, rowid DESC LIMIT 1",
        )?;

        let result = stmt.query_row([], |row| Ok(row_to_prekey(row)));

        match result {
            Ok(inner) => {
                let mut pk = inner?;
                let row_key = row_seal::prekey_row_key(self.db_key(), &pk.key_id)?;
                let mut plain = EncryptedField::from_bytes(std::mem::take(&mut pk.private_key))
                    .decrypt(&row_key)?;
                pk.private_key = std::mem::take(&mut *plain);
                Ok(Some(pk))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// List available (unused) one-time prekeys, optionally filtered by mailbox.
    ///
    /// §7: `private_key` comes back sealed; unseal each row with its own
    /// natural-key-derived row key.
    pub fn list_available_opks(&self, mailbox_id: Option<i64>) -> Result<Vec<Prekey>> {
        let conn = self.conn();

        match mailbox_id {
            Some(mid) => {
                let mut stmt = conn.prepare_cached(
                    "SELECT key_id, key_type, private_key, public_key, signature,
                            created_at, expires_at, used, used_at, mailbox_id
                     FROM prekeys
                     WHERE key_type = 1 AND used = 0 AND mailbox_id = ?1
                     ORDER BY created_at",
                )?;
                let rows = stmt.query_map(params![mid], |row| Ok(row_to_prekey(row)))?;
                row_seal::unseal_prekeys(self.db_key(), rows)
            }
            None => {
                let mut stmt = conn.prepare_cached(
                    "SELECT key_id, key_type, private_key, public_key, signature,
                            created_at, expires_at, used, used_at, mailbox_id
                     FROM prekeys
                     WHERE key_type = 1 AND used = 0
                     ORDER BY created_at",
                )?;
                let rows = stmt.query_map([], |row| Ok(row_to_prekey(row)))?;
                row_seal::unseal_prekeys(self.db_key(), rows)
            }
        }
    }

    /// Mark a one-time prekey as used.
    pub fn mark_opk_used(&self, key_id: &[u8; 4]) -> Result<()> {
        let conn = self.conn();
        let now = najwa_crypto::time::now() as i64;
        let changed = conn.execute(
            "UPDATE prekeys SET used = 1, used_at = ?1 WHERE key_id = ?2",
            params![now, key_id.as_slice()],
        )?;
        if changed == 0 {
            return Err(StorageError::NotFound);
        }
        Ok(())
    }

    /// Delete a prekey by its 4-byte key ID.
    pub fn delete_prekey(&self, key_id: &[u8; 4]) -> Result<()> {
        let conn = self.conn();
        conn.execute(
            "DELETE FROM prekeys WHERE key_id = ?1",
            params![key_id.as_slice()],
        )?;
        Ok(())
    }

    /// Count available (unused) one-time prekeys, optionally filtered by mailbox.
    pub fn count_opks(&self, mailbox_id: Option<i64>) -> Result<u32> {
        let conn = self.conn();
        let count: i32 = match mailbox_id {
            Some(mid) => conn.query_row(
                "SELECT COUNT(*) FROM prekeys WHERE key_type = 1 AND used = 0 AND mailbox_id = ?1",
                params![mid],
                |row| row.get(0),
            )?,
            None => conn.query_row(
                "SELECT COUNT(*) FROM prekeys WHERE key_type = 1 AND used = 0",
                [],
                |row| row.get(0),
            )?,
        };
        Ok(count as u32)
    }
}

// ---------------------------------------------------------------------------
// Volatile Keys (S03 §5.13 — disappearing message key persistence)
// ---------------------------------------------------------------------------

impl SqliteStorage {
    /// Save an encrypted volatile key for a disappearing message.
    ///
    /// S12 §4.3: the row's `expires_at` MUST track the message's `disappear_at`
    /// so the unlock/background purge (`purge_expired_volatile_keys`) can drop a
    /// key whose message expired while the app was locked, before it is ever
    /// restored to memory (the §4.4 residual-key invariant). When the caller does
    /// not pass an explicit `expires_at`, it is derived from the message row so a
    /// persisted key is never left with a NULL (never-purged) expiry.
    pub fn save_volatile_key(
        &self,
        msg_id: &[u8; 16],
        encrypted_key: &[u8],
        expires_at: Option<i64>,
    ) -> Result<()> {
        let conn = self.conn();
        let now = najwa_crypto::time::now() as i64;
        conn.execute(
            "INSERT OR REPLACE INTO volatile_keys (msg_id, encrypted_key, created_at, expires_at)
             VALUES (?1, ?2, ?3,
                 COALESCE((SELECT disappear_at FROM messages WHERE msg_id = ?1), ?4))",
            params![msg_id.as_slice(), encrypted_key, now, expires_at],
        )?;
        Ok(())
    }

    /// Get an encrypted volatile key by message ID.
    pub fn get_volatile_key(&self, msg_id: &[u8; 16]) -> Result<Option<Vec<u8>>> {
        let conn = self.conn();
        let result: std::result::Result<Vec<u8>, _> = conn.query_row(
            "SELECT encrypted_key FROM volatile_keys WHERE msg_id = ?1",
            params![msg_id.as_slice()],
            |row| row.get(0),
        );
        match result {
            Ok(key) => Ok(Some(key)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// S12 §4.3/§7: delete every volatile key whose `expires_at` has passed
    /// (`expires_at <= now`), returning the number deleted. The primary deletion
    /// defence is still zeroising the in-memory key on message expiry; this is the
    /// persisted-row backstop that keeps an expired key from being restored to
    /// memory on unlock (§4.4) and reaps orphan rows.
    pub fn purge_expired_volatile_keys(&self, now: u64) -> Result<u32> {
        let conn = self.conn();
        let deleted = conn.execute(
            "DELETE FROM volatile_keys WHERE expires_at IS NOT NULL AND expires_at <= ?1",
            params![now as i64],
        )?;
        Ok(deleted as u32)
    }

    /// Delete expired volatile keys using the current wall clock. Thin wrapper
    /// over [`purge_expired_volatile_keys`] for callers without an explicit `now`.
    /// Uses milliseconds — `expires_at` mirrors the message `disappear_at`, which
    /// is stored in ms.
    pub fn cleanup_expired_volatile_keys(&self) -> Result<u32> {
        self.purge_expired_volatile_keys(najwa_crypto::time::now_ms().max(0) as u64)
    }

    /// Get all persisted volatile keys as `(msg_id, encrypted_key)` pairs.
    ///
    /// Used to restore the in-memory ephemeral-key cache on unlock (S12 §4) so
    /// disappearing messages sealed before a lock remain readable.
    pub fn get_all_volatile_keys(&self) -> Result<Vec<([u8; 16], Vec<u8>)>> {
        let conn = self.conn();
        let mut stmt = conn.prepare_cached("SELECT msg_id, encrypted_key FROM volatile_keys")?;
        let rows = stmt.query_map([], |row| {
            let id: Vec<u8> = row.get(0)?;
            let key: Vec<u8> = row.get(1)?;
            Ok((id, key))
        })?;
        let mut out = Vec::new();
        for r in rows {
            let (id, key) = r?;
            if id.len() == 16 {
                let mut a = [0u8; 16];
                a.copy_from_slice(&id);
                out.push((a, key));
            }
        }
        Ok(out)
    }

    /// Delete a volatile key by message ID.
    pub fn delete_volatile_key(&self, msg_id: &[u8; 16]) -> Result<()> {
        let conn = self.conn();
        conn.execute(
            "DELETE FROM volatile_keys WHERE msg_id = ?1",
            params![msg_id.as_slice()],
        )?;
        Ok(())
    }

    /// Atomically replace the explicit-lock key snapshot. Deleted/expired
    /// messages cannot leave orphan keys, even if their cache entry survives.
    pub fn replace_volatile_keys(&self, entries: &[([u8; 16], Vec<u8>)], now_ms: i64) -> Result<()> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM volatile_keys", [])?;
        for (id, encrypted) in entries {
            tx.execute("INSERT INTO volatile_keys(msg_id, encrypted_key, created_at, expires_at)
                SELECT msg_id, ?2, ?3 / 1000, disappear_at FROM messages
                WHERE msg_id = ?1 AND disappear_timer IS NOT NULL
                  AND (disappear_at IS NULL OR disappear_at > ?3)",
                params![id.as_slice(), encrypted, now_ms])?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Unlock's first database operation: discard expired/orphaned keys and
    /// move live keys out of persistent storage in one transaction.
    pub fn take_live_volatile_keys(&self, now_ms: i64) -> Result<Vec<([u8; 16], Vec<u8>)>> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM volatile_keys WHERE expires_at <= ?1", params![now_ms])?;
        let entries = {
            let mut stmt = tx.prepare("SELECT k.msg_id, k.encrypted_key FROM volatile_keys k
                JOIN messages m ON m.msg_id = k.msg_id
                WHERE m.disappear_timer IS NOT NULL
                  AND (m.disappear_at IS NULL OR m.disappear_at > ?1)")?;
            let rows = stmt.query_map(params![now_ms], |row| {
                let id: Vec<u8> = row.get(0)?;
                let id = id.try_into().map_err(|_| rusqlite::Error::InvalidQuery)?;
                Ok((id, row.get(1)?))
            })?;
            rows.collect::<std::result::Result<Vec<_>, _>>()?
        };
        tx.execute("DELETE FROM volatile_keys", [])?;
        tx.commit()?;
        Ok(entries)
    }
}

/// Extract a Prekey from a rusqlite Row.
fn row_to_prekey(row: &rusqlite::Row<'_>) -> Result<Prekey> {
    let key_id_blob: Vec<u8> = row.get(0)?;
    let mut key_id = [0u8; 4];
    if key_id_blob.len() == 4 {
        key_id.copy_from_slice(&key_id_blob);
    }

    Ok(Prekey {
        key_id,
        key_type: PrekeyType::from_i32(row.get(1)?),
        private_key: row.get(2)?,
        public_key: row.get(3)?,
        signature: row.get(4)?,
        created_at: row.get(5)?,
        expires_at: row.get(6)?,
        used: row.get::<_, i32>(7)? != 0,
        used_at: row.get(8)?,
        mailbox_id: row.get(9)?,
    })
}

// ---------------------------------------------------------------------------
// Epoch-reorder quarantine (S08 §6.3)
// ---------------------------------------------------------------------------

impl SqliteStorage {
    /// Persist a quarantined wire frame so it survives a crash during the repair
    /// grace window (S08 §6.3). Idempotent upsert keyed by `blob_hash` (= SHA256
    /// of the frame).
    pub fn save_quarantined_frame(
        &self,
        blob_hash: &[u8; 32],
        blob: &[u8],
        quarantined_at: i64,
    ) -> Result<()> {
        let conn = self.conn();
        conn.execute(
            "INSERT OR REPLACE INTO epoch_quarantine (blob_hash, blob, quarantined_at)
             VALUES (?1, ?2, ?3)",
            params![blob_hash.as_slice(), blob, quarantined_at],
        )?;
        Ok(())
    }

    /// Load every persisted quarantined frame as `(blob, quarantined_at)`.
    pub fn load_quarantined_frames(&self) -> Result<Vec<(Vec<u8>, i64)>> {
        let conn = self.conn();
        let mut stmt = conn.prepare_cached("SELECT blob, quarantined_at FROM epoch_quarantine")?;
        let rows = stmt
            .query_map([], |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, i64>(1)?)))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Delete a persisted quarantined frame once it is recovered or grace-expired.
    pub fn delete_quarantined_frame(&self, blob_hash: &[u8; 32]) -> Result<()> {
        let conn = self.conn();
        conn.execute(
            "DELETE FROM epoch_quarantine WHERE blob_hash = ?1",
            params![blob_hash.as_slice()],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_db() -> SqliteStorage {
        SqliteStorage::open_in_memory(&[0x42; 32]).unwrap()
    }

    fn make_contact_for_keys(db: &SqliteStorage) -> ContactId {
        db.create_contact(&NewContact {
            pseudonym: [0x01; 32],
            their_ik_pub: [0x02; 32],
            their_device_pub: [0x02; 32],
            our_pseudonym: [0x03; 32],
            display_name: None,
        })
        .unwrap()
    }

    #[test]
    fn ratchet_state_roundtrip() {
        let db = test_db();
        let cid = make_contact_for_keys(&db);

        let state = RatchetState {
            dhs_private: Some(vec![0xAA; 32]),
            dhs_public: Some(vec![0xBB; 32]),
            dhr: Some(vec![0xCC; 32]),
            rk: Some(vec![0xDD; 32]),
            cks: Some(vec![0xEE; 32]),
            ckr: None,
            ns: 5,
            nr: 3,
            pn: 2,
            prev_dhs_pub: None,
            established_at: 1000,
            last_activity: 2000,
        };

        db.save_ratchet_state(cid, &state).unwrap();
        let loaded = db.get_ratchet_state(cid).unwrap().unwrap();
        assert_eq!(loaded.ns, 5);
        assert_eq!(loaded.nr, 3);
        assert!(loaded.ckr.is_none());
        assert_eq!(loaded.dhs_private.as_deref(), Some([0xAA; 32].as_slice()));
    }

    #[test]
    fn ratchet_state_not_found() {
        let db = test_db();
        assert!(db.get_ratchet_state(9999).unwrap().is_none());
    }

    #[test]
    fn skipped_key_roundtrip() {
        let db = test_db();
        let cid = make_contact_for_keys(&db);

        let sk = SkippedKey {
            dh_pub: [0x11; 32],
            message_number: 7,
            message_key: [0x22; 32],
            created_at: 1000,
            expires_at: 999_999,
        };

        db.save_skipped_key(cid, &sk).unwrap();
        let key = db.get_skipped_key(cid, &[0x11; 32], 7).unwrap().unwrap();
        assert_eq!(key, [0x22; 32]);
    }

    #[test]
    fn count_skipped_keys_works() {
        let db = test_db();
        let cid = make_contact_for_keys(&db);

        for i in 0..5 {
            let sk = SkippedKey {
                dh_pub: [0x11; 32],
                message_number: i,
                message_key: [i as u8; 32],
                created_at: 1000,
                expires_at: 999_999,
            };
            db.save_skipped_key(cid, &sk).unwrap();
        }

        assert_eq!(db.count_skipped_keys(cid).unwrap(), 5);
    }

    #[test]
    fn prekey_roundtrip() {
        let db = test_db();

        let pk = Prekey {
            key_id: [0x01, 0x02, 0x03, 0x04],
            key_type: PrekeyType::Opk,
            private_key: vec![0xAA; 32],
            public_key: vec![0xBB; 32],
            signature: None,
            created_at: 1000,
            expires_at: None,
            used: false,
            used_at: None,
            mailbox_id: None,
        };

        db.save_prekey(&pk).unwrap();
        let loaded = db.get_prekey(&[0x01, 0x02, 0x03, 0x04]).unwrap().unwrap();
        assert_eq!(loaded.key_id, pk.key_id);
        assert!(!loaded.used);
        assert_eq!(loaded.public_key, vec![0xBB; 32]);
    }

    #[test]
    fn mark_opk_used_works() {
        let db = test_db();

        let pk = Prekey {
            key_id: [0x05, 0x06, 0x07, 0x08],
            key_type: PrekeyType::Opk,
            private_key: vec![0xAA; 32],
            public_key: vec![0xBB; 32],
            signature: None,
            created_at: 1000,
            expires_at: None,
            used: false,
            used_at: None,
            mailbox_id: None,
        };

        db.save_prekey(&pk).unwrap();
        db.mark_opk_used(&pk.key_id).unwrap();
        let loaded = db.get_prekey(&pk.key_id).unwrap().unwrap();
        assert!(loaded.used);
        assert!(loaded.used_at.is_some());
    }

    #[test]
    fn count_opks_works() {
        let db = test_db();

        for i in 0u8..3 {
            let pk = Prekey {
                key_id: [i, 0, 0, 0],
                key_type: PrekeyType::Opk,
                private_key: vec![0xAA; 32],
                public_key: vec![0xBB; 32],
                signature: None,
                created_at: 1000,
                expires_at: None,
                used: false,
                used_at: None,
                mailbox_id: None,
            };
            db.save_prekey(&pk).unwrap();
        }

        assert_eq!(db.count_opks(None).unwrap(), 3);
    }

    #[test]
    fn get_current_spk_works() {
        let db = test_db();

        let spk = Prekey {
            key_id: [0x10, 0x20, 0x30, 0x40],
            key_type: PrekeyType::Spk,
            private_key: vec![0xAA; 32],
            public_key: vec![0xBB; 32],
            signature: Some(vec![0xCC; 64]),
            created_at: 1000,
            expires_at: None,
            used: false,
            used_at: None,
            mailbox_id: None,
        };

        db.save_prekey(&spk).unwrap();
        let loaded = db.get_current_spk().unwrap().unwrap();
        assert_eq!(loaded.key_id, spk.key_id);
        assert!(loaded.signature.is_some());
    }

    #[test]
    fn epoch_quarantine_persists_and_deletes() {
        // S08 §6.3: quarantined frames round-trip through the durable
        // device-local store and can be individually deleted on recovery.
        let db = test_db();
        db.save_quarantined_frame(&[0x11; 32], b"frame-a", 1000)
            .unwrap();
        db.save_quarantined_frame(&[0x22; 32], b"frame-b", 2000)
            .unwrap();

        let mut frames = db.load_quarantined_frames().unwrap();
        frames.sort();
        assert_eq!(
            frames,
            vec![(b"frame-a".to_vec(), 1000), (b"frame-b".to_vec(), 2000)]
        );

        db.delete_quarantined_frame(&[0x11; 32]).unwrap();
        assert_eq!(
            db.load_quarantined_frames().unwrap(),
            vec![(b"frame-b".to_vec(), 2000)]
        );

        // Idempotent upsert: re-saving the same hash replaces, not duplicates.
        db.save_quarantined_frame(&[0x22; 32], b"frame-b2", 2001)
            .unwrap();
        assert_eq!(
            db.load_quarantined_frames().unwrap(),
            vec![(b"frame-b2".to_vec(), 2001)]
        );
    }
}

// ---------------------------------------------------------------------------
// S03 §7 — per-row field-encryption at-rest guarantees
// ---------------------------------------------------------------------------

#[cfg(test)]
mod field_encryption_at_rest {
    use crate::database::SqliteStorage;
    use crate::encrypted_field::{derive_row_key, EncryptedField};
    use crate::types::*;

    fn test_db() -> SqliteStorage {
        SqliteStorage::open_in_memory(&[0x42u8; 32]).unwrap()
    }

    fn sample_ratchet(contact_id: ContactId) -> (SqliteStorage, RatchetState) {
        let db = test_db();
        db.conn()
            .execute(
                "INSERT INTO contacts (id, pseudonym, their_ik_pub, their_device_pub, \
                 our_pseudonym, display_name, created_at) \
                 VALUES (?1, ?2, ?3, ?3, ?4, 't', 1)",
                rusqlite::params![contact_id, [0x21u8; 32], [0x11u8; 32], [0x31u8; 32]],
            )
            .unwrap();
        let state = RatchetState {
            dhs_private: Some(vec![0xAA; 32]),
            dhs_public: Some(vec![0xBB; 32]),
            dhr: Some(vec![0xCC; 32]),
            rk: Some(vec![0xDD; 32]),
            cks: Some(vec![0xEE; 32]),
            ckr: Some(vec![0xFF; 32]),
            ns: 0,
            nr: 0,
            pn: 0,
            prev_dhs_pub: None,
            established_at: 1,
            last_activity: 1,
        };
        db.save_ratchet_state(contact_id, &state).unwrap();
        (db, state)
    }

    /// The §7 point: a raw DB read must NOT see the secrets, even though the
    /// public API round-trips them transparently.
    #[test]
    fn ratchet_secrets_are_sealed_at_rest() {
        let (db, state) = sample_ratchet(1);
        let conn = db.conn();
        let (raw_dhs, raw_rk): (Vec<u8>, Vec<u8>) = conn
            .query_row(
                "SELECT dhs_private, rk FROM ratchet_sessions WHERE contact_id = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        // 24-byte nonce + 32-byte secret + 16-byte tag = 72.
        assert_eq!(raw_dhs.len(), 72);
        assert_eq!(raw_rk.len(), 72);
        assert!(!raw_dhs.windows(32).any(|w| w == [0xAA; 32]));
        assert!(!raw_rk.windows(32).any(|w| w == [0xDD; 32]));
        // Public columns stay plaintext (§7 covers secrets).
        let (raw_dhs_pub, raw_dhr): (Vec<u8>, Vec<u8>) = conn
            .query_row(
                "SELECT dhs_public, dhr FROM ratchet_sessions WHERE contact_id = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(raw_dhs_pub, state.dhs_public.as_deref().unwrap());
        assert_eq!(raw_dhr, state.dhr.as_deref().unwrap());
    }

    /// A different row key (other contact / other db_key) cannot unseal.
    #[test]
    fn sealed_fields_fail_under_wrong_row_key() {
        let (db, _) = sample_ratchet(1);
        let conn = db.conn();
        let raw: Vec<u8> = conn
            .query_row(
                "SELECT dhs_private FROM ratchet_sessions WHERE contact_id = 1",
                [],
                |r| r.get(0),
            )
            .unwrap();

        // Right key unseals.
        let good = derive_row_key(&[0x42u8; 32], "ratchet_sessions", 1).unwrap();
        assert_eq!(
            EncryptedField::from_bytes(raw.clone())
                .decrypt(&good)
                .unwrap()
                .as_slice(),
            vec![0xAA; 32]
        );

        // Wrong row id → wrong key → auth failure.
        let wrong_row = derive_row_key(&[0x42u8; 32], "ratchet_sessions", 2).unwrap();
        assert!(EncryptedField::from_bytes(raw.clone())
            .decrypt(&wrong_row)
            .is_err());
        // Wrong table salt → wrong key → auth failure.
        let wrong_salt = derive_row_key(&[0x42u8; 32], "prekeys", 1).unwrap();
        assert!(EncryptedField::from_bytes(raw)
            .decrypt(&wrong_salt)
            .is_err());
    }

    /// Prekey private keys are sealed too, with the key_id-derived row key.
    #[test]
    fn prekey_private_key_sealed_at_rest() {
        let db = test_db();
        db.save_prekey(&Prekey {
            key_id: [0x01, 0x02, 0x03, 0x04],
            key_type: PrekeyType::Spk,
            private_key: vec![0xAA; 32],
            public_key: vec![0xBB; 32],
            signature: Some(vec![0xCC; 64]),
            created_at: 1,
            expires_at: None,
            used: false,
            used_at: None,
            mailbox_id: None,
        })
        .unwrap();

        // Scope the connection guard — the storage mutex is not reentrant,
        // and get_prekey below takes it again.
        let raw: Vec<u8> = {
            let conn = db.conn();
            conn.query_row("SELECT private_key FROM prekeys", [], |r| r.get(0))
                .unwrap()
        };
        assert_eq!(raw.len(), 72);
        assert!(!raw.windows(32).any(|w| w == [0xAA; 32]));

        // Public API round-trips.
        let loaded = db.get_prekey(&[0x01, 0x02, 0x03, 0x04]).unwrap().unwrap();
        assert_eq!(loaded.private_key, vec![0xAA; 32]);
    }
}
