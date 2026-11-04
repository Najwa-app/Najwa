//! Message CRUD operations, message ID deduplication, and disappearing messages.
//!
//! Implements S03 §5.6 (messages), S03 §5.7 (dedup caches), and the
//! disappearing-message operations (S12).

use rusqlite::{params, OptionalExtension};

use crate::database::SqliteStorage;
use crate::keys::row_seal;

/// A per-conversation disappearing-message timer setting (S03/S12):
/// `(timer_secs, set_at, setter_key)` — `timer_secs = None` means "timer off".
type TimerSetting = (Option<u32>, u64, [u8; 32]);
use crate::error::{Result, StorageError};
use crate::types::*;

/// Serialized S12 §2.2 conversation timer setting:
/// `timer_secs(4 BE) || set_at(8 BE) || setter_ik(32)`.
const TIMER_SETTING_LEN: usize = 44;
const OUTBOUND_REPAIR_MAX_KEEP: u32 = 256;

// ---------------------------------------------------------------------------
// Messages CRUD
// ---------------------------------------------------------------------------

impl SqliteStorage {
    /// Persist one full S07 §8.5 repair item keyed by its ratchet address, then
    /// prune this contact's oldest records to the configured bound.
    pub fn buffer_outbound_repair(
        &self,
        record: &OutboundRepairRecord,
        max_keep: u32,
    ) -> Result<()> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        insert_outbound_repair(&tx, record)?;
        prune_outbound_repairs(&tx, record.contact_id, max_keep)?;
        tx.commit()?;
        Ok(())
    }

    /// Read ordinary plaintext repair content. Sealed disappearing content is
    /// available through `get_outbound_repair_entry` and requires its live key.
    pub fn get_outbound_repair(
        &self,
        contact_id: ContactId,
        dh_pub: &[u8; 32],
        message_number: u32,
    ) -> Result<Option<OutboundRepairRecord>> {
        Ok(self
            .get_outbound_repair_entry(contact_id, dh_pub, message_number)?
            .and_then(|(record, sealed)| if sealed { None } else { Some(record) }))
    }

    /// Return a repair record and whether content is sealed with its ephemeral
    /// message key. Expired or orphaned sealed records are never returned.
    pub fn get_outbound_repair_entry(
        &self,
        contact_id: ContactId,
        dh_pub: &[u8; 32],
        message_number: u32,
    ) -> Result<Option<(OutboundRepairRecord, bool)>> {
        let conn = self.conn();
        Ok(conn
            .query_row(
                "SELECT r.msg_id,r.timestamp,r.logical_seq,r.content_type,r.flags,
                r.content,r.created_at,r.content_sealed
             FROM outbound_repair_records r
             WHERE r.contact_id=?1 AND r.dh_pub=?2 AND r.message_number=?3
             AND (r.content_sealed=0 OR EXISTS(SELECT 1 FROM messages m
                WHERE m.msg_id=r.msg_id AND m.contact_id=r.contact_id
                AND (m.disappear_at IS NULL OR m.disappear_at>?4)))",
                params![
                    contact_id,
                    dh_pub.as_slice(),
                    message_number as i64,
                    najwa_crypto::time::now_ms()
                ],
                |row| {
                    let raw: Vec<u8> = row.get(0)?;
                    let msg_id = raw.try_into().map_err(|_| rusqlite::Error::InvalidQuery)?;
                    Ok((
                        OutboundRepairRecord {
                            contact_id,
                            dh_pub: *dh_pub,
                            message_number,
                            msg_id,
                            timestamp: row.get::<_, i64>(1)? as u64,
                            logical_seq: row.get::<_, i64>(2)? as u32,
                            content_type: row.get::<_, i64>(3)? as u8,
                            flags: row.get::<_, i64>(4)? as u8,
                            content: row.get(5)?,
                            created_at: row.get(6)?,
                        },
                        row.get::<_, bool>(7)?,
                    ))
                },
            )
            .optional()?)
    }

    /// Atomically commit a received message in ONE transaction (S06 §3.11 I3):
    /// advance the ratchet session, mirror its skipped keys, insert the message
    /// (when stored), and mark dedup. Either all four succeed or none.
    ///
    /// Without this, a crash between the ratchet save and the message/dedup save
    /// leaves the ratchet advanced but the message neither stored nor deduped —
    /// and on re-fetch the message is lost, because its key was consumed and the
    /// chain is now ahead of it. `message` is `None` for control messages that
    /// are handled but not stored (the ratchet + dedup still commit so the chain
    /// stays in sync and the blob is not reprocessed).
    ///
    /// The statements below mirror `save_ratchet_state`, the `skipped_keys`
    /// sync, `save_message`, and `mark_msg_id_seen` — keep them in sync.
    // The signature mirrors the atomic operation's inputs (ratchet state,
    // skipped-key sync, optional message, ids, disappearing marker) — each is
    // semantically distinct, so bundling them would obscure the call sites.
    #[allow(clippy::too_many_arguments)]
    pub fn commit_received(
        &self,
        contact_id: ContactId,
        ratchet: &RatchetState,
        skipped_now: &[SkippedKey],
        message: Option<&NewMessage>,
        transport_msg_id: &[u8; 16],
        logical_msg_id: Option<&[u8; 16]>,
        disappearing: Option<(u32, u64)>,
    ) -> Result<Option<MessageId>> {
        self.commit_received_with_confirmation(
            contact_id,
            ratchet,
            skipped_now,
            message,
            transport_msg_id,
            logical_msg_id,
            disappearing,
            None,
        )
    }

    /// Include confirmation effects in the same transaction as receive/dedup.
    #[allow(clippy::too_many_arguments)]
    pub fn commit_received_with_confirmation(
        &self,
        contact_id: ContactId,
        ratchet: &RatchetState,
        skipped_now: &[SkippedKey],
        message: Option<&NewMessage>,
        transport_msg_id: &[u8; 16],
        logical_msg_id: Option<&[u8; 16]>,
        disappearing: Option<(u32, u64)>,
        confirmation: Option<&DeliveryConfirmation>,
    ) -> Result<Option<MessageId>> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;

        // A duplicate must not overwrite newer session state or repeat effects.
        let seen: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM msg_id_cache_transport WHERE msg_id=?1)",
            params![transport_msg_id.as_slice()],
            |r| r.get(0),
        )?;
        if seen {
            return Ok(None);
        }

        // 1. Ratchet session upsert (mirrors save_ratchet_state).
        // §7: seal the four secret columns with the row's per-row key —
        // identical to save_ratchet_state, inside the same transaction.
        let row_key = row_seal::ratchet_row_key(self.db_key(), contact_id)?;
        tx.execute(
            "INSERT OR REPLACE INTO ratchet_sessions
                (contact_id, dhs_private, dhs_public, dhr, rk, cks, ckr,
                 ns, nr, pn, established_at, last_activity, prev_dhs_pub)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                contact_id,
                row_seal::seal(&ratchet.dhs_private, &row_key)?,
                ratchet.dhs_public,
                ratchet.dhr,
                row_seal::seal(&ratchet.rk, &row_key)?,
                row_seal::seal(&ratchet.cks, &row_key)?,
                row_seal::seal(&ratchet.ckr, &row_key)?,
                ratchet.ns as i32,
                ratchet.nr as i32,
                ratchet.pn as i32,
                ratchet.established_at,
                ratchet.last_activity,
                ratchet.prev_dhs_pub,
            ],
        )?;

        // 2. Skipped-key sync: delete consumed, upsert current (mirrors the
        //    bridge's load/delete/save of skipped_keys, but inside the tx).
        let mut want: std::collections::HashSet<([u8; 32], u32)> =
            std::collections::HashSet::with_capacity(skipped_now.len());
        for k in skipped_now {
            want.insert((k.dh_pub, k.message_number));
        }
        let existing: Vec<(Vec<u8>, i32)> = {
            let mut stmt = tx
                .prepare("SELECT dh_pub, message_number FROM skipped_keys WHERE contact_id = ?1")?;
            let rows = stmt.query_map(params![contact_id], |r| {
                Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, i32>(1)?))
            })?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        };
        for (dh_blob, msg_num) in &existing {
            if dh_blob.len() == 32 {
                let mut dh = [0u8; 32];
                dh.copy_from_slice(dh_blob);
                if !want.contains(&(dh, *msg_num as u32)) {
                    tx.execute(
                        "DELETE FROM skipped_keys
                         WHERE contact_id = ?1 AND dh_pub = ?2 AND message_number = ?3",
                        params![contact_id, dh_blob.as_slice(), msg_num],
                    )?;
                }
            }
        }
        for k in skipped_now {
            tx.execute(
                "INSERT OR REPLACE INTO skipped_keys
                    (contact_id, dh_pub, message_number, message_key, created_at, expires_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    contact_id,
                    k.dh_pub.as_slice(),
                    k.message_number as i32,
                    k.message_key.as_slice(),
                    k.created_at,
                    k.expires_at,
                ],
            )?;
        }

        // 3. Message insert (mirrors save_message), if this message is stored.
        let msg_id_out = if let Some(msg) = message {
            tx.execute(
                "INSERT INTO messages
                    (contact_id, msg_id, direction, content_type, flags, content,
                     file_path, timestamp, received_at, status, reply_to_msg_id,
                     disappear_timer, encrypted_blob, group_id, sender_display_name,
                     origin_timestamp_ms, retry_wire_blob)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
                params![
                    msg.contact_id,
                    msg.msg_id.as_slice(),
                    msg.direction as i32,
                    msg.content_type as i32,
                    msg.flags,
                    msg.content,
                    msg.file_path,
                    msg.timestamp,
                    msg.received_at,
                    msg.status as i32,
                    msg.reply_to_msg_id,
                    msg.disappear_timer,
                    msg.encrypted_blob,
                    msg.group_id.as_ref().map(|g| g.as_slice()),
                    msg.sender_display_name,
                    msg.origin_timestamp_ms,
                    msg.retry_wire_blob,
                ],
            )
            .map_err(|e| match e {
                rusqlite::Error::SqliteFailure(ref err, _)
                    if err.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE =>
                {
                    StorageError::AlreadyExists
                }
                other => StorageError::Sqlite(other),
            })?;
            Some(tx.last_insert_rowid())
        } else {
            None
        };

        // 4. Dedup mark (mirrors mark_msg_id_seen).
        let now = najwa_crypto::time::now() as i64;
        tx.execute(
            "INSERT OR IGNORE INTO msg_id_cache_transport (msg_id, contact_id, seen_at) \
             VALUES (?1, ?2, ?3)",
            params![transport_msg_id.as_slice(), contact_id, now],
        )?;
        // 4b. Logical dedup mark (S03 §5.7) — in the SAME transaction as the
        //     transport mark + message store, so a session-repair / gap-repair
        //     re-send of this content is deduped atomically (S08 §9.4).
        if let Some(l) = logical_msg_id {
            tx.execute(
                "INSERT OR IGNORE INTO msg_id_cache_logical (contact_id, logical_msg_id, seen_at) \
                 VALUES (?1, ?2, ?3)",
                params![contact_id, l.as_slice(), now],
            )?;
        }

        // 5. S12 §4.1: co-commit the disappearing marker (timer + fallback
        //    disappear_at) in the SAME tx as the sealed message store, so a crash
        //    can't leave a sealed row unmarked (unreadable + never expiring).
        if let (Some((secs, at)), Some(mid)) = (disappearing, msg_id_out) {
            tx.execute(
                "UPDATE messages SET disappear_timer = ?1, disappear_at = ?2 WHERE id = ?3",
                params![secs, at as i64, mid],
            )?;
        }

        if let Some(effect) = confirmation {
            apply_confirmation(&tx, contact_id, effect)?;
        }
        tx.commit()?;
        Ok(msg_id_out)
    }

    /// S08 §4.3 / S06 §3.11 (I3) atomic session ESTABLISHMENT from an Initial /
    /// SessionRepairInit. Persists the responder ratchet state, the session AD,
    /// the one-time-prekey consumption, the stored message, and the transport +
    /// logical dedup marks in ONE transaction — so a crash can never (a) burn the
    /// OPK without establishing the session, (b) leave a session without its AD,
    /// or (c) overwrite an advanced session (re-establish/adopt) without recording
    /// the dedup that gates a replay. `INSERT OR REPLACE` on the ratchet row means
    /// this both creates a fresh session and overwrites an existing one (repair /
    /// crossing-Initial adopt). Returns the new message row id when stored.
    ///
    /// ponytail: mirrors `commit_received` (deliberately, to avoid destabilising
    /// that working path) plus the session-AD upsert + OPK mark.
    /// Store an item recovered through S07 §8.5 and both dedup marks in one
    /// transaction. The repair control's own ratchet commit happens separately;
    /// this transaction makes the reconstructed user message crash-consistent.
    pub fn commit_repaired_received(
        &self,
        contact_id: ContactId,
        message: &NewMessage,
        transport_msg_id: &[u8; 16],
        logical_msg_id: &[u8; 16],
    ) -> Result<Option<MessageId>> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let transport_seen: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM msg_id_cache_transport WHERE msg_id = ?1)",
            params![transport_msg_id.as_slice()],
            |row| row.get(0),
        )?;
        let logical_seen: bool = tx.query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM msg_id_cache_logical
                 WHERE contact_id = ?1 AND logical_msg_id = ?2
             )",
            params![contact_id, logical_msg_id.as_slice()],
            |row| row.get(0),
        )?;
        if transport_seen || logical_seen {
            return Ok(None);
        }

        tx.execute(
            "INSERT INTO messages
                (contact_id, msg_id, direction, content_type, flags, content,
                 file_path, timestamp, received_at, status, reply_to_msg_id,
                 disappear_timer, encrypted_blob, group_id, sender_display_name,
                 origin_timestamp_ms, retry_wire_blob)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
            params![
                message.contact_id,
                message.msg_id.as_slice(),
                message.direction as i32,
                message.content_type as i32,
                message.flags,
                message.content,
                message.file_path,
                message.timestamp,
                message.received_at,
                message.status as i32,
                message.reply_to_msg_id,
                message.disappear_timer,
                message.encrypted_blob,
                message.group_id.as_ref().map(|g| g.as_slice()),
                message.sender_display_name,
                message.origin_timestamp_ms,
                message.retry_wire_blob,
            ],
        )?;
        let id = tx.last_insert_rowid();
        let seen_at = najwa_crypto::time::now() as i64;
        tx.execute(
            "INSERT INTO msg_id_cache_transport (msg_id, contact_id, seen_at)
             VALUES (?1, ?2, ?3)",
            params![transport_msg_id.as_slice(), contact_id, seen_at],
        )?;
        tx.execute(
            "INSERT INTO msg_id_cache_logical (contact_id, logical_msg_id, seen_at)
             VALUES (?1, ?2, ?3)",
            params![contact_id, logical_msg_id.as_slice(), seen_at],
        )?;
        tx.commit()?;
        Ok(Some(id))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn commit_initial_received(
        &self,
        contact_id: ContactId,
        ratchet: &RatchetState,
        skipped_now: &[SkippedKey],
        session_ad: &[u8],
        opk_id: Option<[u8; 4]>,
        message: Option<&NewMessage>,
        transport_msg_id: &[u8; 16],
        logical_msg_id: Option<&[u8; 16]>,
        disappearing: Option<(u32, u64)>,
        ephemeral_handshake_cap_id: Option<i64>,
    ) -> Result<Option<MessageId>> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;

        // 1. Ratchet session upsert. OR REPLACE => also overwrites an existing
        //    session (repair re-establish / crossing-Initial adopt).
        // §7: seal the four secret columns with the row's per-row key —
        // identical to save_ratchet_state, inside the same transaction.
        let row_key = row_seal::ratchet_row_key(self.db_key(), contact_id)?;
        tx.execute(
            "INSERT OR REPLACE INTO ratchet_sessions
                (contact_id, dhs_private, dhs_public, dhr, rk, cks, ckr,
                 ns, nr, pn, established_at, last_activity, prev_dhs_pub)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                contact_id,
                row_seal::seal(&ratchet.dhs_private, &row_key)?,
                ratchet.dhs_public,
                ratchet.dhr,
                row_seal::seal(&ratchet.rk, &row_key)?,
                row_seal::seal(&ratchet.cks, &row_key)?,
                row_seal::seal(&ratchet.ckr, &row_key)?,
                ratchet.ns as i32,
                ratchet.nr as i32,
                ratchet.pn as i32,
                ratchet.established_at,
                ratchet.last_activity,
                ratchet.prev_dhs_pub,
            ],
        )?;

        // 1a. Session AD upsert (mirrors save_session_ad).
        let now = najwa_crypto::time::now() as i64;
        tx.execute(
            "INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?1, ?2, ?3)",
            params![format!("session_ad:{contact_id}"), session_ad, now],
        )?;

        // 1b. Consume the one-time prekey (mirrors mark_opk_used) — only now, in
        //     the same tx that persists the session, so a forged/replayed Initial
        //     that never commits cannot burn the OPK. Lenient on 0 rows (a re-used
        //     id on a genuinely NEW msg_id is anomalous but non-fatal — the session
        //     still stands via whatever DH X3DH computed).
        if let Some(id) = opk_id {
            let _ = tx.execute(
                "UPDATE prekeys SET used = 1, used_at = ?1 WHERE key_id = ?2",
                params![now, id.as_slice()],
            )?;
        }

        // 2. Skipped-key sync: delete consumed, upsert current. For a re-establish
        //    the empty `skipped_now` clears the OLD session's stale skipped keys.
        let mut want: std::collections::HashSet<([u8; 32], u32)> =
            std::collections::HashSet::with_capacity(skipped_now.len());
        for k in skipped_now {
            want.insert((k.dh_pub, k.message_number));
        }
        let existing: Vec<(Vec<u8>, i32)> = {
            let mut stmt = tx
                .prepare("SELECT dh_pub, message_number FROM skipped_keys WHERE contact_id = ?1")?;
            let rows = stmt.query_map(params![contact_id], |r| {
                Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, i32>(1)?))
            })?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        };
        for (dh_blob, msg_num) in &existing {
            if dh_blob.len() == 32 {
                let mut dh = [0u8; 32];
                dh.copy_from_slice(dh_blob);
                if !want.contains(&(dh, *msg_num as u32)) {
                    tx.execute(
                        "DELETE FROM skipped_keys
                         WHERE contact_id = ?1 AND dh_pub = ?2 AND message_number = ?3",
                        params![contact_id, dh_blob.as_slice(), msg_num],
                    )?;
                }
            }
        }
        for k in skipped_now {
            tx.execute(
                "INSERT OR REPLACE INTO skipped_keys
                    (contact_id, dh_pub, message_number, message_key, created_at, expires_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    contact_id,
                    k.dh_pub.as_slice(),
                    k.message_number as i32,
                    k.message_key.as_slice(),
                    k.created_at,
                    k.expires_at,
                ],
            )?;
        }

        // 3. Message insert (if stored).
        let msg_id_out = if let Some(msg) = message {
            tx.execute(
                "INSERT INTO messages
                    (contact_id, msg_id, direction, content_type, flags, content,
                     file_path, timestamp, received_at, status, reply_to_msg_id,
                     disappear_timer, encrypted_blob, group_id, sender_display_name,
                     origin_timestamp_ms, retry_wire_blob)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
                params![
                    msg.contact_id,
                    msg.msg_id.as_slice(),
                    msg.direction as i32,
                    msg.content_type as i32,
                    msg.flags,
                    msg.content,
                    msg.file_path,
                    msg.timestamp,
                    msg.received_at,
                    msg.status as i32,
                    msg.reply_to_msg_id,
                    msg.disappear_timer,
                    msg.encrypted_blob,
                    msg.group_id.as_ref().map(|g| g.as_slice()),
                    msg.sender_display_name,
                    msg.origin_timestamp_ms,
                    msg.retry_wire_blob,
                ],
            )
            .map_err(|e| match e {
                rusqlite::Error::SqliteFailure(ref err, _)
                    if err.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE =>
                {
                    StorageError::AlreadyExists
                }
                other => StorageError::Sqlite(other),
            })?;
            Some(tx.last_insert_rowid())
        } else {
            None
        };

        // 4. Dedup marks (transport + logical) — gate a replayed Initial/repair.
        tx.execute(
            "INSERT OR IGNORE INTO msg_id_cache_transport (msg_id, contact_id, seen_at) \
             VALUES (?1, ?2, ?3)",
            params![transport_msg_id.as_slice(), contact_id, now],
        )?;
        if let Some(l) = logical_msg_id {
            tx.execute(
                "INSERT OR IGNORE INTO msg_id_cache_logical (contact_id, logical_msg_id, seen_at) \
                 VALUES (?1, ?2, ?3)",
                params![contact_id, l.as_slice(), now],
            )?;
        }

        // 5. Disappearing marker (S12 §4.1), same tx.
        if let (Some((secs, at)), Some(mid)) = (disappearing, msg_id_out) {
            tx.execute(
                "UPDATE messages SET disappear_timer = ?1, disappear_at = ?2 WHERE id = ?3",
                params![secs, at as i64, mid],
            )?;
        }

        // 6. S05 §5.2: consume an ephemeral handshake slot only after every
        // X3DH/decrypt/payload guard above has succeeded, and in the SAME
        // transaction as the established session. A crash can therefore never
        // commit the Initial while leaving the photographed capability locally
        // eligible for another contact.
        if let Some(capability_id) = ephemeral_handshake_cap_id {
            let changed = tx.execute(
                "UPDATE ephemeral_handshake_caps SET accepted_at = ?1
                 WHERE id = ?2 AND registered_at IS NOT NULL
                   AND accepted_at IS NULL AND deactivated_at IS NULL",
                params![now, capability_id],
            )?;
            if changed == 0 {
                return Err(StorageError::NotFound);
            }
        }

        tx.commit()?;
        Ok(msg_id_out)
    }

    /// S03 §6.1 (I2) persist-before-send: durably commit the advanced sending
    /// ratchet state AND the outgoing message row (carrying the cached wire blob
    /// for byte-identical retry) in ONE transaction, then force the WAL to disk.
    /// A crash can then only leave either the pre-send state or a fully-persisted,
    /// retryable message — never an advanced chain key without its message row.
    pub fn commit_sent(
        &self,
        contact_id: ContactId,
        ratchet: &RatchetState,
        message: &NewMessage,
        wire_blob: &[u8],
        disappearing: Option<(u32, u64)>,
        repair_record: Option<&OutboundRepairRecord>,
    ) -> Result<MessageId> {
        self.commit_sent_with_position(contact_id, ratchet, message, wire_blob, disappearing,
            repair_record, repair_record.map(|r| (r.dh_pub, r.message_number)))
    }

    /// Index the final transmitted header independently of retained repair metadata.
    #[allow(clippy::too_many_arguments)]
    pub fn commit_sent_with_position(
        &self,
        contact_id: ContactId,
        ratchet: &RatchetState,
        message: &NewMessage,
        wire_blob: &[u8],
        disappearing: Option<(u32, u64)>,
        repair_record: Option<&OutboundRepairRecord>,
        position: Option<([u8; 32], u32)>,
    ) -> Result<MessageId> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;

        // 1. Advance the sending ratchet (mirrors save_ratchet_state).
        // §7: seal the four secret columns with the row's per-row key —
        // identical to save_ratchet_state, inside the same transaction.
        let row_key = row_seal::ratchet_row_key(self.db_key(), contact_id)?;
        tx.execute(
            "INSERT OR REPLACE INTO ratchet_sessions
                (contact_id, dhs_private, dhs_public, dhr, rk, cks, ckr,
                 ns, nr, pn, established_at, last_activity, prev_dhs_pub)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                contact_id,
                row_seal::seal(&ratchet.dhs_private, &row_key)?,
                ratchet.dhs_public,
                ratchet.dhr,
                row_seal::seal(&ratchet.rk, &row_key)?,
                row_seal::seal(&ratchet.cks, &row_key)?,
                row_seal::seal(&ratchet.ckr, &row_key)?,
                ratchet.ns as i32,
                ratchet.nr as i32,
                ratchet.pn as i32,
                ratchet.established_at,
                ratchet.last_activity,
                ratchet.prev_dhs_pub,
            ],
        )?;

        // 2. Outgoing message row with its retry wire blob (mirrors save_message).
        tx.execute(
            "INSERT INTO messages
                (contact_id, msg_id, direction, content_type, flags, content,
                 file_path, timestamp, received_at, status, reply_to_msg_id,
                 disappear_timer, encrypted_blob, group_id, sender_display_name,
                 origin_timestamp_ms, retry_wire_blob)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
            params![
                message.contact_id,
                message.msg_id.as_slice(),
                message.direction as i32,
                message.content_type as i32,
                message.flags,
                message.content,
                message.file_path,
                message.timestamp,
                message.received_at,
                message.status as i32,
                message.reply_to_msg_id,
                message.disappear_timer,
                message.encrypted_blob,
                message.group_id.as_ref().map(|g| g.as_slice()),
                message.sender_display_name,
                message.origin_timestamp_ms,
                wire_blob,
            ],
        )
        .map_err(|e| match e {
            rusqlite::Error::SqliteFailure(ref err, _)
                if err.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE =>
            {
                StorageError::AlreadyExists
            }
            other => StorageError::Sqlite(other),
        })?;
        let id = tx.last_insert_rowid();

        // 3. S12 §4.1: co-commit the disappearing marker (timer + fallback
        //    disappear_at) in the SAME tx as the sealed message store, so a crash
        //    can't leave a sealed row unmarked (unreadable + never expiring).
        if let Some((secs, at)) = disappearing {
            tx.execute(
                "UPDATE messages SET disappear_timer = ?1, disappear_at = ?2 WHERE id = ?3",
                params![secs, at as i64, id],
            )?;
        }

        // 4. S07 §8.5: co-commit the complete ratchet-addressed repair source.
        // A crash must not advance the sending chain without preserving the
        // original fields needed to answer a future repair request.
        if let Some((dh_pub, n)) = position {
            tx.execute(
                "INSERT INTO outbound_message_positions (contact_id,dh_pub,message_number,msg_id)
                VALUES (?1,?2,?3,?4)",
                params![
                    contact_id,
                    dh_pub.as_slice(),
                    n as i64,
                    message.msg_id.as_slice()
                ],
            )?;
        }
        if let Some(record) = repair_record {
            insert_outbound_repair(&tx, record)?;
            prune_outbound_repairs(&tx, contact_id, OUTBOUND_REPAIR_MAX_KEEP)?;
        }

        tx.commit()?;

        // Connections use synchronous=FULL: COMMIT syncs the WAL even when a
        // concurrent reader prevents checkpointing. No fallible checkpoint
        // follows COMMIT to turn a successfully committed send into an error.

        Ok(id)
    }

    /// Save a new message. Returns the new message row ID.
    pub fn save_message(&self, msg: &NewMessage) -> Result<MessageId> {
        let conn = self.conn();
        conn.execute(
            "INSERT INTO messages
                (contact_id, msg_id, direction, content_type, flags, content,
                 file_path, timestamp, received_at, status, reply_to_msg_id,
                 disappear_timer, encrypted_blob, group_id, sender_display_name, origin_timestamp_ms,
                 retry_wire_blob)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
            params![
                msg.contact_id,
                msg.msg_id.as_slice(),
                msg.direction as i32,
                msg.content_type as i32,
                msg.flags,
                msg.content,
                msg.file_path,
                msg.timestamp,
                msg.received_at,
                msg.status as i32,
                msg.reply_to_msg_id,
                msg.disappear_timer,
                msg.encrypted_blob,
                msg.group_id.as_ref().map(|g| g.as_slice()),
                msg.sender_display_name,
                msg.origin_timestamp_ms,
                msg.retry_wire_blob,
            ],
        )
        .map_err(|e| match e {
            rusqlite::Error::SqliteFailure(ref err, _)
                if err.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE =>
            {
                StorageError::AlreadyExists
            }
            other => StorageError::Sqlite(other),
        })?;

        Ok(conn.last_insert_rowid())
    }

    /// Get a message by row ID.
    pub fn get_message(&self, id: MessageId) -> Result<Option<Message>> {
        let conn = self.conn();
        let mut stmt = conn.prepare_cached(
            "SELECT id, contact_id, msg_id, direction, content_type, flags, content,
                    file_path, timestamp, received_at, read_at, status, retry_count,
                    last_retry_at, reply_to_msg_id, disappear_timer, disappear_at,
                    encrypted_blob, group_id, sender_display_name, origin_timestamp_ms,
                    retry_wire_blob
             FROM messages WHERE id = ?1",
        )?;

        let result = stmt.query_row(params![id], |row| Ok(row_to_message(row)));

        match result {
            Ok(m) => Ok(Some(m?)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Get a message by its unique 16-byte msg_id.
    pub fn get_message_by_msg_id(&self, msg_id: &[u8; 16]) -> Result<Option<Message>> {
        let conn = self.conn();
        let mut stmt = conn.prepare_cached(
            "SELECT id, contact_id, msg_id, direction, content_type, flags, content,
                    file_path, timestamp, received_at, read_at, status, retry_count,
                    last_retry_at, reply_to_msg_id, disappear_timer, disappear_at,
                    encrypted_blob, group_id, sender_display_name, origin_timestamp_ms,
                    retry_wire_blob
             FROM messages WHERE msg_id = ?1",
        )?;

        let result = stmt.query_row(params![msg_id.as_slice()], |row| Ok(row_to_message(row)));

        match result {
            Ok(m) => Ok(Some(m?)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// List messages for a contact, newest first, with pagination.
    pub fn list_messages(
        &self,
        contact_id: ContactId,
        limit: u32,
        before: Option<(i64, i64)>,
    ) -> Result<Vec<Message>> {
        let conn = self.conn();
        let now = najwa_crypto::time::now_ms();

        match before {
            Some((ts, row_id)) => {
                // Stable cursor pagination: skip messages at or after the cursor.
                // Uses (timestamp, id) pair to handle multiple messages with the
                // same timestamp without duplicating or skipping any.
                let mut stmt = conn.prepare_cached(
                    "SELECT id, contact_id, msg_id, direction, content_type, flags, content,
                            file_path, timestamp, received_at, read_at, status, retry_count,
                            last_retry_at, reply_to_msg_id, disappear_timer, disappear_at,
                            encrypted_blob, group_id, sender_display_name, origin_timestamp_ms,
                            retry_wire_blob
                     FROM messages
                     WHERE contact_id = ?1
                       AND (timestamp < ?2 OR (timestamp = ?2 AND id < ?3))
                       AND (disappear_at IS NULL OR disappear_at > ?5)
                     ORDER BY timestamp DESC, id DESC LIMIT ?4",
                )?;
                let rows = stmt
                    .query_map(params![contact_id, ts, row_id, limit as i32, now], |row| {
                        Ok(row_to_message(row))
                    })?;
                let mut messages = Vec::new();
                for r in rows {
                    messages.push(r??);
                }
                Ok(messages)
            }
            None => {
                let mut stmt = conn.prepare_cached(
                    "SELECT id, contact_id, msg_id, direction, content_type, flags, content,
                            file_path, timestamp, received_at, read_at, status, retry_count,
                            last_retry_at, reply_to_msg_id, disappear_timer, disappear_at,
                            encrypted_blob, group_id, sender_display_name, origin_timestamp_ms,
                            retry_wire_blob
                     FROM messages
                     WHERE contact_id = ?1
                       AND (disappear_at IS NULL OR disappear_at > ?3)
                     ORDER BY timestamp DESC, id DESC LIMIT ?2",
                )?;
                let rows = stmt.query_map(params![contact_id, limit as i32, now], |row| {
                    Ok(row_to_message(row))
                })?;
                let mut messages = Vec::new();
                for r in rows {
                    messages.push(r??);
                }
                Ok(messages)
            }
        }
    }

    /// Search/export only durable plaintext rows, including before any trigger.
    pub fn list_non_disappearing_messages(&self, query: Option<&str>) -> Result<Vec<Message>> {
        let conn = self.conn();
        let mut stmt = conn.prepare_cached(
            "SELECT id, contact_id, msg_id, direction, content_type, flags, content,
                    file_path, timestamp, received_at, read_at, status, retry_count,
                    last_retry_at, reply_to_msg_id, disappear_timer, disappear_at,
                    encrypted_blob, group_id, sender_display_name, origin_timestamp_ms,
                    retry_wire_blob FROM messages
             WHERE (flags & 1) = 0 AND disappear_timer IS NULL AND disappear_at IS NULL
               AND (?1 IS NULL OR instr(CAST(content AS TEXT), ?1) > 0)
             ORDER BY timestamp, id",
        )?;
        let rows = stmt.query_map(params![query], |row| Ok(row_to_message(row)))?;
        rows.map(|row| row.map_err(StorageError::from).and_then(|row| row)).collect()
    }

    /// Update the delivery status of a message.
    pub fn update_message_status(&self, id: MessageId, status: MessageStatus) -> Result<()> {
        let conn = self.conn();
        let changed = conn.execute(
            "UPDATE messages SET status = ?1 WHERE id = ?2",
            params![status as i32, id],
        )?;
        if changed == 0 {
            return Err(StorageError::NotFound);
        }
        Ok(())
    }

    /// Delete a single message by row ID.
    pub fn delete_message(&self, id: MessageId) -> Result<()> {
        let conn = self.conn();
        let changed = conn.execute("DELETE FROM messages WHERE id = ?1", params![id])?;
        if changed == 0 {
            return Err(StorageError::NotFound);
        }
        Ok(())
    }

    /// Count unread received messages for a contact.
    pub fn count_unread_messages(&self, contact_id: ContactId) -> Result<u32> {
        let conn = self.conn();
        let count: i32 = conn.query_row(
            "SELECT COUNT(*) FROM messages WHERE contact_id = ?1 AND direction = 0 AND read_at IS NULL AND content_type IN (0,8,10)",
            params![contact_id],
            |row| row.get(0),
        )?;
        Ok(count as u32)
    }

    /// Mark all received messages for a contact as read.
    pub fn mark_messages_read(&self, contact_id: ContactId) -> Result<u32> {
        self.mark_read_subset(contact_id, None)
    }

    /// Start timers only for rows actually rendered by a paginated reader.
    pub fn mark_displayed_messages(&self, contact_id: ContactId, ids: &[MessageId]) -> Result<u32> {
        self.mark_read_subset(contact_id, Some(ids))
    }

    fn mark_read_subset(&self, contact_id: ContactId, ids: Option<&[MessageId]>) -> Result<u32> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let now = najwa_crypto::time::now_ms();
        let sql = "UPDATE messages SET read_at = ?1,
            disappear_at = CASE WHEN disappear_timer IS NULL THEN disappear_at
                ELSE MIN(COALESCE(disappear_at, ?1 + disappear_timer * 1000),
                         ?1 + disappear_timer * 1000) END
            WHERE contact_id = ?2 AND direction = 0 AND read_at IS NULL
              AND (disappear_at IS NULL OR disappear_at > ?1)
              AND (?3 IS NULL OR id = ?3)";
        let updated = match ids {
            None => tx.execute(sql, params![now, contact_id, None::<i64>])?,
            Some(ids) => {
                let mut updated = 0;
                for id in ids { updated += tx.execute(sql, params![now, contact_id, id])?; }
                updated
            }
        };
        tx.commit()?;
        Ok(updated as u32)
    }

    /// Delete all messages for a contact. Returns number deleted.
    pub fn delete_messages_for_contact(&self, contact_id: ContactId) -> Result<u32> {
        let conn = self.conn();
        let deleted = conn.execute(
            "DELETE FROM messages WHERE contact_id = ?1",
            params![contact_id],
        )?;
        Ok(deleted as u32)
    }
}

// ---------------------------------------------------------------------------
// Message ID Deduplication Cache
// ---------------------------------------------------------------------------

impl SqliteStorage {
    /// Check if a message ID has been seen before (replay prevention). The
    /// transport `msg_id` is globally unique (HKDF), so this is a bare msg_id
    /// lookup — `contact_id` is only carried for FK-cascade cleanup.
    pub fn check_msg_id_seen(&self, msg_id: &[u8; 16]) -> Result<bool> {
        let conn = self.conn();
        let count: i32 = conn.query_row(
            "SELECT COUNT(*) FROM msg_id_cache_transport WHERE msg_id = ?1",
            params![msg_id.as_slice()],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    /// Mark a transport message ID as seen (S03 §5.7 `msg_id_cache_transport`).
    pub fn mark_msg_id_seen(&self, contact_id: i64, msg_id: &[u8; 16]) -> Result<()> {
        let conn = self.conn();
        let now = najwa_crypto::time::now() as i64;
        conn.execute(
            "INSERT OR IGNORE INTO msg_id_cache_transport (msg_id, contact_id, seen_at) \
             VALUES (?1, ?2, ?3)",
            params![msg_id.as_slice(), contact_id, now],
        )?;
        Ok(())
    }

    /// Check whether a `(contact_id, logical_msg_id)` has been seen — the
    /// endpoint-invariant logical dedup (S03 §5.7).
    pub fn check_logical_msg_id_seen(
        &self,
        contact_id: i64,
        logical_msg_id: &[u8; 16],
    ) -> Result<bool> {
        let conn = self.conn();
        let count: i32 = conn.query_row(
            "SELECT COUNT(*) FROM msg_id_cache_logical WHERE contact_id = ?1 AND logical_msg_id = ?2",
            params![contact_id, logical_msg_id.as_slice()],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    /// Mark a `(contact_id, logical_msg_id)` as seen (S03 §5.7).
    pub fn mark_logical_msg_id_seen(
        &self,
        contact_id: i64,
        logical_msg_id: &[u8; 16],
    ) -> Result<()> {
        let conn = self.conn();
        let now = najwa_crypto::time::now() as i64;
        conn.execute(
            "INSERT OR IGNORE INTO msg_id_cache_logical (contact_id, logical_msg_id, seen_at) \
             VALUES (?1, ?2, ?3)",
            params![contact_id, logical_msg_id.as_slice(), now],
        )?;
        Ok(())
    }

    /// Cleanup old message IDs from the cache. Returns number deleted.
    pub fn cleanup_old_msg_ids(&self, older_than: i64) -> Result<u32> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        // Never reopen the replay window for frames the server may retain.
        let cutoff = older_than.min(najwa_crypto::time::now() as i64 - 90 * 86400);
        let mut deleted = tx.execute(
            "DELETE FROM msg_id_cache_transport WHERE seen_at < ?1",
            params![cutoff],
        )?;
        deleted += tx.execute(
            "DELETE FROM msg_id_cache_logical WHERE seen_at < ?1",
            params![cutoff],
        )?;
        tx.commit()?;
        Ok(deleted as u32)
    }

    /// Background retention pass (S03 §6.4): drop dedup entries
    /// older than 91 days and skipped keys past `expires_at`, and mark pending
    /// introductions past `expires_at` as expired. Returns rows affected.
    pub fn run_retention_cleanup(&self) -> Result<u32> {
        // 90 days (`MIN_ENTRY_TTL`) plus one day: a mailbox may still hold a
        // blob up to one cleanup interval past its 90-day cap (S16 §10.1).
        let dedup_cutoff = najwa_crypto::time::now() as i64 - 91 * 86400;
        Ok(self.cleanup_old_msg_ids(dedup_cutoff)?
            + self.cleanup_expired_skipped_keys()?
            + self.cleanup_expired_introductions()?)
    }
}

// ---------------------------------------------------------------------------
// Disappearing Messages (S12)
// ---------------------------------------------------------------------------

impl SqliteStorage {
    /// Set the default disappearing message timer for a conversation.
    ///
    /// Convenience wrapper that stamps `set_at = now()` and an all-zero setter
    /// key. Prefer [`set_conversation_timer_setting`](Self::set_conversation_timer_setting)
    /// on any path that participates in the S12 §2.2 merge — the zero setter
    /// key is lex-smallest and therefore always wins a `set_at` tie.
    pub fn set_conversation_timer(
        &self,
        contact_id: ContactId,
        timer_secs: Option<u32>,
    ) -> Result<()> {
        self.set_conversation_timer_setting(
            contact_id,
            timer_secs,
            najwa_crypto::time::now(),
            &[0u8; 32],
        )
    }

    /// Persist the full S12 §2.2 timer setting: value + `set_at` + setter IK.
    ///
    /// Stored under settings key `disappear_timer:<contact_id>` as a fixed
    /// 44-byte blob `timer_secs(4 BE) || set_at(8 BE) || setter_ik(32)`.
    ///
    /// "Off" is written as `timer_secs = 0` rather than deleting the row: off
    /// is a real setting that carries a `set_at` and competes in the merge, and
    /// deleting the row would drop `set_at` and let an older, shorter timer win
    /// the next exchange.
    pub fn set_conversation_timer_setting(
        &self,
        contact_id: ContactId,
        timer_secs: Option<u32>,
        set_at: u64,
        setter_ik: &[u8; 32],
    ) -> Result<()> {
        if timer_secs.is_some_and(|secs| (1..30).contains(&secs)) {
            return Err(StorageError::InvalidData("disappearing timers must be at least 30 seconds".into()));
        }
        let key = format!("disappear_timer:{contact_id}");
        let mut value = Vec::with_capacity(TIMER_SETTING_LEN);
        value.extend_from_slice(&timer_secs.unwrap_or(0).to_be_bytes());
        value.extend_from_slice(&set_at.to_be_bytes());
        value.extend_from_slice(setter_ik);

        let conn = self.conn();
        let now = najwa_crypto::time::now() as i64;
        conn.execute(
            "INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?1, ?2, ?3)",
            params![key, value, now],
        )?;
        Ok(())
    }

    /// Read the full S12 §2.2 timer setting for a conversation.
    ///
    /// Returns `(timer_secs, set_at, setter_ik)` with `timer_secs = None` for
    /// off. A legacy 4-byte row (written before `set_at` was persisted) reads
    /// back with `set_at = 0` and a zero setter key, so any timestamped setting
    /// supersedes it.
    pub fn get_conversation_timer_setting(
        &self,
        contact_id: ContactId,
    ) -> Result<Option<TimerSetting>> {
        let key = format!("disappear_timer:{contact_id}");
        let conn = self.conn();
        let result: std::result::Result<Vec<u8>, _> = conn.query_row(
            "SELECT value FROM settings WHERE key = ?1",
            params![key],
            |row| row.get(0),
        );

        let blob = match result {
            Ok(blob) => blob,
            Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(None),
            Err(e) => return Err(e.into()),
        };

        let (secs, set_at, setter_ik) = match blob.len() {
            TIMER_SETTING_LEN => {
                let secs = u32::from_be_bytes(blob[0..4].try_into().unwrap());
                let set_at = u64::from_be_bytes(blob[4..12].try_into().unwrap());
                let mut ik = [0u8; 32];
                ik.copy_from_slice(&blob[12..44]);
                (secs, set_at, ik)
            }
            // Legacy pre-§2.2 row: value only, no merge metadata.
            4 => (
                u32::from_be_bytes(blob[0..4].try_into().unwrap()),
                0,
                [0u8; 32],
            ),
            _ => return Ok(None),
        };

        Ok(Some((
            if secs > 0 { Some(secs) } else { None },
            set_at,
            setter_ik,
        )))
    }

    /// Get the effective disappearing message timer for a conversation.
    ///
    /// The value half of [`get_conversation_timer_setting`](Self::get_conversation_timer_setting)
    /// — `None` means off (either no setting stored, or one that says off).
    pub fn get_conversation_timer(&self, contact_id: ContactId) -> Result<Option<u32>> {
        Ok(self
            .get_conversation_timer_setting(contact_id)?
            .and_then(|(timer_secs, _, _)| timer_secs))
    }

    /// Set a pending disappear timer on a message (before it's been read).
    pub fn set_message_disappear_pending(&self, msg_id: MessageId, timer_secs: u32) -> Result<()> {
        let conn = self.conn();
        conn.execute(
            "UPDATE messages SET disappear_timer = ?1 WHERE id = ?2",
            params![timer_secs, msg_id],
        )?;
        Ok(())
    }

    /// Get the pending disappear timer for a message.
    pub fn get_message_disappear_pending(&self, msg_id: MessageId) -> Result<Option<u32>> {
        let conn = self.conn();
        let result: std::result::Result<Option<u32>, _> = conn.query_row(
            "SELECT disappear_timer FROM messages WHERE id = ?1",
            params![msg_id],
            |row| row.get(0),
        );

        match result {
            Ok(Some(secs)) if secs > 0 => Ok(Some(secs)),
            Ok(_) => Ok(None),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Set the absolute disappear_at timestamp on a message.
    pub fn set_message_disappear_at(&self, msg_id: MessageId, disappear_at: u64) -> Result<()> {
        let conn = self.conn();
        conn.execute(
            "UPDATE messages SET disappear_at = ?1 WHERE id = ?2",
            params![disappear_at as i64, msg_id],
        )?;
        Ok(())
    }

    /// Sender-side ACK trigger (S12 §3.1): when a SENT disappearing message is
    /// delivery-ACKed, start its timer from now — moving disappear_at to
    /// now + timer, earlier than the send-time no-ACK fallback deadline. Keyed by
    /// the 16-byte transport msg_id; a no-op for a non-disappearing message.
    pub fn start_sender_disappear_on_ack(&self, msg_id: &[u8; 16]) -> Result<()> {
        let conn = self.conn();
        let now = najwa_crypto::time::now_ms();
        conn.execute(
            "UPDATE messages SET disappear_at = ?1 + disappear_timer * 1000
             WHERE msg_id = ?2 AND direction = 1 AND disappear_timer IS NOT NULL",
            params![now, msg_id.as_slice()],
        )?;
        Ok(())
    }

    /// Apply fallback disappear timers for messages that have been read but
    /// don't have a disappear_at set yet. Returns number of messages updated.
    pub fn apply_fallback_disappear_timers(&self, cutoff: u64) -> Result<u32> {
        let conn = self.conn();
        let now = najwa_crypto::time::now_ms();
        let updated = conn.execute(
            "UPDATE messages SET disappear_at =
                CASE WHEN read_at IS NOT NULL AND direction = 0 THEN read_at
                     WHEN direction = 1 THEN timestamp * 1000 + 86400000
                     WHEN (flags & 4) = 0 THEN COALESCE(received_at, timestamp) * 1000
                     ELSE COALESCE(received_at, timestamp) * 1000 + 604800000 END
                + disappear_timer * 1000
             WHERE disappear_timer IS NOT NULL AND disappear_at IS NULL
               AND ((direction = 1 AND timestamp * 1000 <= ?1)
                 OR (direction = 0 AND (read_at IS NOT NULL OR (flags & 4) = 0
                    OR COALESCE(received_at, timestamp) * 1000 + 604800000 <= ?2)))",
            params![cutoff as i64, now],
        )?;
        Ok(updated as u32)
    }

    /// Get all messages whose disappear_at has passed.
    pub fn get_expired_disappearing_messages(&self, now: u64) -> Result<Vec<Message>> {
        let conn = self.conn();
        let mut stmt = conn.prepare_cached(
            "SELECT id, contact_id, msg_id, direction, content_type, flags, content,
                    file_path, timestamp, received_at, read_at, status, retry_count,
                    last_retry_at, reply_to_msg_id, disappear_timer, disappear_at,
                    encrypted_blob, group_id, sender_display_name, origin_timestamp_ms,
                    retry_wire_blob
             FROM messages
             WHERE disappear_at IS NOT NULL AND disappear_at <= ?1",
        )?;

        let rows = stmt.query_map(params![now as i64], |row| Ok(row_to_message(row)))?;
        let mut messages = Vec::new();
        for r in rows {
            messages.push(r??);
        }
        Ok(messages)
    }

    /// Overwrite message content (secure deletion of plaintext).
    pub fn overwrite_message_content(&self, msg_id: MessageId, data: &[u8]) -> Result<()> {
        let conn = self.conn();
        conn.execute(
            "UPDATE messages SET content = ?1 WHERE id = ?2",
            params![data, msg_id],
        )?;
        Ok(())
    }
}

impl SqliteStorage {
    /// Update the encrypted blob on a message (for reply metadata).
    pub fn update_message_blob(&self, id: MessageId, blob: &[u8]) -> Result<()> {
        let conn = self.conn();
        conn.execute(
            "UPDATE messages SET encrypted_blob = ?1 WHERE id = ?2",
            params![blob, id],
        )?;
        Ok(())
    }

    /// Clear the encrypted blob after successful send (free storage).
    pub fn clear_message_blob(&self, id: MessageId) -> Result<()> {
        let conn = self.conn();
        conn.execute(
            "UPDATE messages SET encrypted_blob = NULL WHERE id = ?1",
            params![id],
        )?;
        Ok(())
    }

    /// Store the fully-encrypted wire blob for send retry.
    pub fn update_retry_wire_blob(&self, id: MessageId, blob: &[u8]) -> Result<()> {
        let conn = self.conn();
        conn.execute(
            "UPDATE messages SET retry_wire_blob = ?1 WHERE id = ?2",
            params![blob, id],
        )?;
        Ok(())
    }

    /// Clear the retry wire blob after successful send or permanent failure.
    pub fn clear_retry_wire_blob(&self, id: MessageId) -> Result<()> {
        let conn = self.conn();
        conn.execute(
            "UPDATE messages SET retry_wire_blob = NULL WHERE id = ?1",
            params![id],
        )?;
        Ok(())
    }

    /// Increment retry count and update last_retry_at timestamp.
    /// Only updates messages with Failed status (guards against racing with mark_permanently_failed).
    pub fn increment_retry_count(&self, id: MessageId) -> Result<()> {
        let conn = self.conn();
        let now = najwa_crypto::time::now() as i64;
        conn.execute(
            "UPDATE messages SET retry_count = retry_count + 1, last_retry_at = ?1 WHERE id = ?2 AND status = 4",
            params![now, id],
        )?;
        Ok(())
    }
}

impl SqliteStorage {
    /// Get messages with Pending or Failed status (for retry logic).
    pub fn get_pending_messages(&self) -> Result<Vec<Message>> {
        let conn = self.conn();
        let mut stmt = conn.prepare_cached(
            "SELECT id, contact_id, msg_id, direction, content_type, flags, content,
                    file_path, timestamp, received_at, read_at, status, retry_count,
                    last_retry_at, reply_to_msg_id, disappear_timer, disappear_at,
                    encrypted_blob, group_id, sender_display_name, origin_timestamp_ms,
                    retry_wire_blob
             FROM messages WHERE status IN (0, 4)",
        )?;

        let rows = stmt.query_map([], |row| Ok(row_to_message(row)))?;
        let mut messages = Vec::new();
        for r in rows {
            messages.push(r??);
        }
        Ok(messages)
    }

    /// Get messages eligible for retry: Failed status, under max retries, and
    /// have a stored wire blob. Ordered by text-first (content_type=0), then timestamp.
    pub fn get_retryable_messages(&self, max_retries: i32) -> Result<Vec<Message>> {
        let conn = self.conn();
        let mut stmt = conn.prepare_cached(
            "SELECT id, contact_id, msg_id, direction, content_type, flags, content,
                    file_path, timestamp, received_at, read_at, status, retry_count,
                    last_retry_at, reply_to_msg_id, disappear_timer, disappear_at,
                    encrypted_blob, group_id, sender_display_name, origin_timestamp_ms,
                    retry_wire_blob
             FROM messages
             WHERE status = 4
               AND retry_count < ?1
               AND retry_wire_blob IS NOT NULL
             ORDER BY content_type ASC, timestamp ASC",
        )?;

        let rows = stmt.query_map(params![max_retries], |row| Ok(row_to_message(row)))?;
        let mut messages = Vec::new();
        for r in rows {
            messages.push(r??);
        }
        Ok(messages)
    }

    /// Mark a message as permanently failed (exceeded max retries).
    /// Also clears the retry wire blob to free storage.
    pub fn mark_permanently_failed(&self, id: MessageId) -> Result<()> {
        let conn = self.conn();
        conn.execute(
            "UPDATE messages SET status = 5, retry_wire_blob = NULL WHERE id = ?1",
            params![id],
        )?;
        Ok(())
    }
}

impl SqliteStorage {
    /// Total bytes used by message content (the `content` BLOB column).
    pub fn messages_total_bytes(&self) -> Result<u64> {
        let conn = self.conn();
        let total: i64 = conn.query_row(
            "SELECT COALESCE(SUM(LENGTH(content)), 0) FROM messages",
            [],
            |row| row.get(0),
        )?;
        Ok(total as u64)
    }
}

/// Extract a Message from a rusqlite Row.
pub(crate) fn row_to_message(row: &rusqlite::Row<'_>) -> Result<Message> {
    let msg_id_blob: Vec<u8> = row.get(2)?;
    let mut msg_id = [0u8; 16];
    if msg_id_blob.len() == 16 {
        msg_id.copy_from_slice(&msg_id_blob);
    }

    let group_id_blob: Option<Vec<u8>> = row.get(18)?;
    let group_id = group_id_blob.and_then(|b| {
        if b.len() == 32 {
            let mut gid = [0u8; 32];
            gid.copy_from_slice(&b);
            Some(gid)
        } else {
            None
        }
    });

    Ok(Message {
        id: row.get(0)?,
        contact_id: row.get(1)?,
        msg_id,
        direction: MessageDirection::from_i32(row.get(3)?),
        content_type: ContentType::from_i32(row.get(4)?),
        flags: row.get(5)?,
        content: row.get(6)?,
        file_path: row.get(7)?,
        timestamp: row.get(8)?,
        received_at: row.get(9)?,
        read_at: row.get(10)?,
        status: MessageStatus::from_i32(row.get(11)?),
        retry_count: row.get(12)?,
        last_retry_at: row.get(13)?,
        reply_to_msg_id: row.get(14)?,
        disappear_timer: row.get(15)?,
        disappear_at: row.get(16)?,
        encrypted_blob: row.get(17)?,
        group_id,
        sender_display_name: row.get(19)?,
        origin_timestamp_ms: row.get(20)?,
        retry_wire_blob: row.get(21)?,
    })
}

pub(crate) fn apply_confirmation(
    tx: &rusqlite::Transaction<'_>,
    contact_id: ContactId,
    effect: &DeliveryConfirmation,
) -> Result<()> {
    let now = najwa_crypto::time::now_ms();
    match effect {
        DeliveryConfirmation::Ack(ranges) => {
            if ranges.is_empty() || ranges.len() > 16 || ranges.iter().any(|(_, a, b)| a > b) {
                return Err(StorageError::InvalidData("invalid ACK ranges".into()));
            }
            for (dh, start, end) in ranges {
                tx.execute("DELETE FROM outgoing_frames WHERE contact_id=?1 AND dh_pub=?2 AND n BETWEEN ?3 AND ?4",
                    params![contact_id, dh.as_slice(), *start as i64, *end as i64])?;
                tx.execute("UPDATE messages SET status=2,
                    disappear_at=CASE WHEN disappear_timer IS NULL THEN disappear_at
                        ELSE MIN(COALESCE(disappear_at, ?1 + disappear_timer*1000), ?1 + disappear_timer*1000) END
                    WHERE contact_id=?2 AND direction=1 AND status NOT IN (2,3)
                    AND msg_id IN (SELECT msg_id FROM outbound_message_positions
                        WHERE contact_id=?2 AND dh_pub=?3 AND message_number BETWEEN ?4 AND ?5)",
                    params![now, contact_id, dh.as_slice(), *start as i64, *end as i64])?;
            }
        }
        DeliveryConfirmation::ReadReceipt { msg_id, .. } => {
            tx.execute("UPDATE messages SET status=3,
                disappear_at=CASE WHEN disappear_timer IS NULL OR status IN (2,3) THEN disappear_at
                    ELSE MIN(COALESCE(disappear_at, ?1 + disappear_timer*1000), ?1 + disappear_timer*1000) END
                WHERE contact_id=?2 AND msg_id=?3 AND direction=1 AND (flags & 4)!=0 AND status!=3",
                params![now, contact_id, msg_id.as_slice()])?;
        }
    }
    tx.execute("UPDATE volatile_keys SET expires_at=(SELECT disappear_at FROM messages m WHERE m.msg_id=volatile_keys.msg_id)
        WHERE msg_id IN (SELECT msg_id FROM messages WHERE contact_id=?1 AND direction=1 AND disappear_at IS NOT NULL)", params![contact_id])?;
    Ok(())
}

pub(crate) fn insert_outbound_repair(
    tx: &rusqlite::Transaction<'_>,
    record: &OutboundRepairRecord,
) -> Result<()> {
    // The message row is already present in the same transaction. Reuse its
    // ephemeral ciphertext; never retain a plaintext repair escape hatch.
    let (stored_content, timer): (Vec<u8>, Option<u32>) = tx.query_row(
        "SELECT content,disappear_timer FROM messages WHERE msg_id=?1 AND contact_id=?2",
        params![record.msg_id.as_slice(), record.contact_id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let sealed = timer.is_some();
    let content = if sealed {
        &stored_content
    } else {
        &record.content
    };
    tx.execute(
        "INSERT OR REPLACE INTO outbound_repair_records
            (contact_id, dh_pub, message_number, msg_id, timestamp, logical_seq,
             content_type, flags, content, created_at, content_sealed)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            record.contact_id,
            record.dh_pub.as_slice(),
            record.message_number as i64,
            record.msg_id.as_slice(),
            record.timestamp as i64,
            record.logical_seq as i64,
            record.content_type as i64,
            record.flags as i64,
            content,
            record.created_at,
            sealed,
        ],
    )?;
    Ok(())
}

fn prune_outbound_repairs(
    tx: &rusqlite::Transaction<'_>,
    contact_id: ContactId,
    max_keep: u32,
) -> Result<()> {
    tx.execute(
        "DELETE FROM outbound_repair_records
         WHERE contact_id = ?1
           AND rowid NOT IN (
               SELECT rowid FROM outbound_repair_records
               WHERE contact_id = ?1
               ORDER BY created_at DESC, message_number DESC
               LIMIT ?2
           )",
        params![contact_id, max_keep as i64],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    include!("row10_retention_tests.rs");
    include!("row7_confirmation_tests.rs");
    use super::*;

    fn test_db() -> SqliteStorage {
        SqliteStorage::open_in_memory(&[0x42; 32]).unwrap()
    }

    fn setup_contact(db: &SqliteStorage) -> ContactId {
        db.create_contact(&NewContact {
            pseudonym: [0x10; 32],
            their_ik_pub: [0x20; 32],
            their_device_pub: [0x20; 32],
            our_pseudonym: [0x30; 32],
            display_name: Some("Test".into()),
        })
        .unwrap()
    }

    #[test]
    fn outbound_repair_roundtrip_preserves_full_item_and_prunes() {
        let db = test_db();
        let cid = setup_contact(&db);
        for n in 1..=5u32 {
            let record = OutboundRepairRecord {
                contact_id: cid,
                dh_pub: [0xA0 + n as u8; 32],
                message_number: n,
                msg_id: [n as u8; 16],
                timestamp: 10_000 + n as u64,
                logical_seq: 20_000 + n,
                content_type: 0x10 + n as u8,
                flags: n as u8,
                content: format!("msg {n}").into_bytes(),
                created_at: 1000 + n as i64,
            };
            let mut msg = make_msg(cid, n as u8);
            msg.msg_id = record.msg_id;
            db.save_message(&msg).unwrap();
            db.buffer_outbound_repair(&record, 3).unwrap();
        }
        assert!(db
            .get_outbound_repair(cid, &[0xA2; 32], 2)
            .unwrap()
            .is_none());
        let loaded = db
            .get_outbound_repair(cid, &[0xA5; 32], 5)
            .unwrap()
            .unwrap();
        assert_eq!(
            loaded,
            OutboundRepairRecord {
                contact_id: cid,
                dh_pub: [0xA5; 32],
                message_number: 5,
                msg_id: [5; 16],
                timestamp: 10_005,
                logical_seq: 20_005,
                content_type: 0x15,
                flags: 5,
                content: b"msg 5".to_vec(),
                created_at: 1005,
            }
        );
        assert!(db
            .get_outbound_repair(cid, &[0xA3; 32], 3)
            .unwrap()
            .is_some());
    }

    fn make_msg(contact_id: ContactId, n: u8) -> NewMessage {
        let mut msg_id = [0u8; 16];
        msg_id[0] = n;
        NewMessage {
            contact_id,
            msg_id,
            direction: MessageDirection::Sent,
            content_type: ContentType::Text,
            flags: 0,
            content: format!("message {n}").into_bytes(),
            file_path: None,
            timestamp: 1000 + n as i64,
            received_at: None,
            status: MessageStatus::Pending,
            reply_to_msg_id: None,
            disappear_timer: None,
            encrypted_blob: None,
            group_id: None,
            sender_display_name: None,
            origin_timestamp_ms: None,
            retry_wire_blob: None,
        }
    }

    #[test]
    fn save_and_get_message() {
        let db = test_db();
        let cid = setup_contact(&db);
        let id = db.save_message(&make_msg(cid, 1)).unwrap();
        let msg = db.get_message(id).unwrap().unwrap();
        assert_eq!(msg.content, b"message 1");
        assert_eq!(msg.direction, MessageDirection::Sent);
    }

    #[test]
    fn volatile_key_expiry_derives_from_message_and_purges() {
        // S12 §4.3/§7: a persisted volatile key saved with no explicit expires_at
        // inherits its message's disappear_at, and purge_expired_volatile_keys
        // drops it once that time passes while keeping still-live keys.
        let db = test_db();
        let cid = setup_contact(&db);
        let id = db.save_message(&make_msg(cid, 1)).unwrap();
        let disappear_at = 5_000_000u64;
        db.set_message_disappear_at(id, disappear_at).unwrap();

        let mut msg_id = [0u8; 16];
        msg_id[0] = 1; // matches make_msg(cid, 1)'s msg_id
        db.save_volatile_key(&msg_id, b"encrypted-blob", None)
            .unwrap();

        // Before the derived expiry: kept.
        assert_eq!(db.purge_expired_volatile_keys(disappear_at - 1).unwrap(), 0);
        assert!(
            db.get_volatile_key(&msg_id).unwrap().is_some(),
            "live key kept"
        );

        // At/after the derived expiry: purged.
        assert_eq!(db.purge_expired_volatile_keys(disappear_at).unwrap(), 1);
        assert!(
            db.get_volatile_key(&msg_id).unwrap().is_none(),
            "expired key purged"
        );
    }

    #[test]
    fn commit_sent_co_commits_disappear_marker() {
        // S12 §4.1: commit_sent stores the message AND its disappear_timer +
        // disappear_at in the SAME transaction, so a sealed sent row is never
        // stored without its marker (crash-safe).
        let db = test_db();
        let cid = setup_contact(&db);
        let ratchet = RatchetState {
            dhs_private: None,
            dhs_public: None,
            dhr: None,
            rk: None,
            cks: None,
            ckr: None,
            ns: 1,
            nr: 0,
            pn: 0,
            prev_dhs_pub: None,
            established_at: 0,
            last_activity: 0,
        };
        let at = najwa_crypto::time::now_ms() as u64 + 60_000;
        let repair = OutboundRepairRecord {
            contact_id: cid,
            dh_pub: [0xA1; 32],
            message_number: 0,
            msg_id: make_msg(cid, 1).msg_id,
            timestamp: 1234,
            logical_seq: 77,
            content_type: 1,
            flags: 4,
            content: b"original".to_vec(),
            created_at: 1234,
        };
        let id = db
            .commit_sent(
                cid,
                &ratchet,
                &make_msg(cid, 1),
                b"wireblob",
                Some((30, at)),
                Some(&repair),
            )
            .unwrap();
        let m = db.get_message(id).unwrap().unwrap();
        assert_eq!(m.disappear_timer, Some(30));
        assert_eq!(m.disappear_at, Some(at as i64));
        let (entry, sealed) = db
            .get_outbound_repair_entry(cid, &[0xA1; 32], 0)
            .unwrap()
            .unwrap();
        assert!(sealed);
        assert_eq!(entry.content, m.content);
        assert_ne!(entry.content, repair.content);
        assert!(db
            .get_outbound_repair(cid, &[0xA1; 32], 0)
            .unwrap()
            .is_none());

        // No timer => no marker written.
        let id2 = db
            .commit_sent(cid, &ratchet, &make_msg(cid, 2), b"wireblob", None, None)
            .unwrap();
        let m2 = db.get_message(id2).unwrap().unwrap();
        assert!(m2.disappear_timer.is_none());
        assert!(m2.disappear_at.is_none());
    }

    #[test]
    fn commit_initial_received_persists_session_ad_message_and_dedup() {
        // S08 §4.3 / I3: one atomic call persists the responder ratchet state, the
        // session AD, the stored message, and the transport dedup mark. (OPK
        // consumption is exercised by mark_opk_used; here opk_id is None.)
        let db = test_db();
        let cid = setup_contact(&db);
        let mailbox_id = db
            .save_mailbox(&NewMailbox {
                onion_address: "initial-cap-test".into(),
                fetch_capability: vec![0x71; 32],
                deposit_capability: vec![0x72; 32],
                envelope_secret: vec![0x73; 32],
                cover_deposit_capability: None,
                cover_fetch_capability: None,
                cover_envelope_secret: None,
                priority: 1,
                created_at: 1,
            })
            .unwrap();
        let ephemeral_id = db
            .save_ephemeral_handshake_cap(&NewEphemeralHandshakeCap {
                mailbox_id,
                deposit_capability: vec![0x81; 32],
                fetch_capability: vec![0x82; 32],
                envelope_secret: vec![0x83; 32],
                capability_type: 1,
                created_at: 1,
                expires_at: i64::MAX,
            })
            .unwrap();
        db.mark_ephemeral_handshake_cap_registered(ephemeral_id, 2)
            .unwrap();
        let ratchet = RatchetState {
            dhs_private: None,
            dhs_public: None,
            dhr: None,
            rk: None,
            cks: None,
            ckr: Some(vec![0x11u8; 32]),
            ns: 0,
            nr: 1,
            pn: 0,
            prev_dhs_pub: None,
            established_at: 0,
            last_activity: 0,
        };
        let ad = [0x42u8; 64];
        let mut m = make_msg(cid, 1);
        m.direction = MessageDirection::Received;
        let mut transport_id = [0u8; 16];
        transport_id[0] = 0xAA;

        let id = db
            .commit_initial_received(
                cid,
                &ratchet,
                &[],
                &ad,
                None,
                Some(&m),
                &transport_id,
                None,
                None,
                Some(ephemeral_id),
            )
            .unwrap();

        assert!(id.is_some(), "message stored");
        assert!(
            db.get_ratchet_state(cid).unwrap().is_some(),
            "ratchet persisted"
        );
        assert_eq!(
            db.get_session_ad(cid).unwrap().as_deref(),
            Some(&ad[..]),
            "session AD persisted"
        );
        assert!(
            db.get_message_by_msg_id(&m.msg_id).unwrap().is_some(),
            "message row persisted"
        );
        assert!(
            db.get_ephemeral_handshake_cap(ephemeral_id)
                .unwrap()
                .unwrap()
                .accepted_at
                .is_some(),
            "valid Initial atomically consumes its ephemeral slot"
        );
        assert!(
            db.check_msg_id_seen(&transport_id).unwrap(),
            "transport dedup marked — gates a replayed Initial/repair"
        );
    }

    #[test]
    fn mark_read_display_triggers_disappear_at() {
        // S12 §3.2: a received disappearing message's timer starts on
        // DISPLAY. It carries a far never-read fallback deadline at receive;
        // mark_messages_read must move disappear_at to read_at + timer (sooner),
        // so it can't vanish before being read.
        let db = test_db();
        let cid = setup_contact(&db);

        let mut msg = make_msg(cid, 1);
        msg.direction = MessageDirection::Received;
        msg.received_at = Some(1_000_000);
        msg.disappear_timer = Some(30);
        let id = db.save_message(&msg).unwrap();
        let fallback_at = 9_999_999_999_999i64; // far never-read deadline
        db.set_message_disappear_at(id, fallback_at as u64).unwrap();

        // Unread: disappear_at is the far fallback deadline.
        let before = db.get_message(id).unwrap().unwrap();
        assert_eq!(before.disappear_at, Some(fallback_at));
        assert!(before.read_at.is_none());

        // Display it → timer starts from read_at.
        assert_eq!(db.mark_messages_read(cid).unwrap(), 1);
        let after = db.get_message(id).unwrap().unwrap();
        let read_at = after.read_at.expect("read_at set on display");
        assert_eq!(after.disappear_at, Some(read_at + 30 * 1000));
        assert!(
            after.disappear_at.unwrap() < fallback_at,
            "moved earlier than fallback"
        );
        assert!(
            after.disappear_at.unwrap() >= read_at,
            "never before it was read"
        );

        // A non-disappearing received message is unaffected.
        let mut plain = make_msg(cid, 2);
        plain.direction = MessageDirection::Received;
        let pid = db.save_message(&plain).unwrap();
        db.mark_messages_read(cid).unwrap();
        assert!(db.get_message(pid).unwrap().unwrap().disappear_at.is_none());
    }

    #[test]
    fn ack_starts_sender_disappear_timer() {
        // S12 §3.1: a sent disappearing message carries a far no-ACK fallback
        // deadline; the delivery ACK moves disappear_at to now + timer (sooner),
        // so the sender's own copy vanishes shortly after delivery, not before.
        let db = test_db();
        let cid = setup_contact(&db);

        let mut msg = make_msg(cid, 7); // direction: Sent (make_msg default)
        msg.disappear_timer = Some(30);
        let id = db.save_message(&msg).unwrap();
        let mut mid = [0u8; 16];
        mid[0] = 7;
        let fallback_at = 9_999_999_999_999i64;
        db.set_message_disappear_at(id, fallback_at as u64).unwrap();
        assert_eq!(
            db.get_message(id).unwrap().unwrap().disappear_at,
            Some(fallback_at)
        );

        // Delivery ACK → timer starts from now.
        db.start_sender_disappear_on_ack(&mid).unwrap();
        let da = db
            .get_message(id)
            .unwrap()
            .unwrap()
            .disappear_at
            .expect("disappear_at set");
        let now = najwa_crypto::time::now_ms();
        assert!(da < fallback_at, "moved earlier than the no-ACK fallback");
        assert!(
            da <= now + 30 * 1000 && da >= now + 30 * 1000 - 5000,
            "disappear_at is ~now + timer (da={da}, now={now})"
        );

        // A non-disappearing sent message is unaffected.
        let plain_id = db.save_message(&make_msg(cid, 8)).unwrap();
        let mut pmid = [0u8; 16];
        pmid[0] = 8;
        db.start_sender_disappear_on_ack(&pmid).unwrap();
        assert!(db
            .get_message(plain_id)
            .unwrap()
            .unwrap()
            .disappear_at
            .is_none());
    }

    #[test]
    fn get_message_by_msg_id_works() {
        let db = test_db();
        let cid = setup_contact(&db);
        db.save_message(&make_msg(cid, 5)).unwrap();
        let mut mid = [0u8; 16];
        mid[0] = 5;
        let msg = db.get_message_by_msg_id(&mid).unwrap().unwrap();
        assert_eq!(msg.content, b"message 5");
    }

    #[test]
    fn list_messages_pagination() {
        let db = test_db();
        let cid = setup_contact(&db);
        for i in 1..=10 {
            db.save_message(&make_msg(cid, i)).unwrap();
        }
        let page1 = db.list_messages(cid, 5, None).unwrap();
        assert_eq!(page1.len(), 5);
        // Newest first
        assert_eq!(page1[0].content, b"message 10");

        let last = page1.last().unwrap();
        let page2 = db
            .list_messages(cid, 5, Some((last.timestamp, last.id)))
            .unwrap();
        assert_eq!(page2.len(), 5);
    }

    #[test]
    fn update_message_status_works() {
        let db = test_db();
        let cid = setup_contact(&db);
        let id = db.save_message(&make_msg(cid, 1)).unwrap();
        db.update_message_status(id, MessageStatus::Delivered)
            .unwrap();
        let msg = db.get_message(id).unwrap().unwrap();
        assert_eq!(msg.status, MessageStatus::Delivered);
    }

    #[test]
    fn delete_messages_for_contact_works() {
        let db = test_db();
        let cid = setup_contact(&db);
        for i in 1..=5 {
            db.save_message(&make_msg(cid, i)).unwrap();
        }
        let deleted = db.delete_messages_for_contact(cid).unwrap();
        assert_eq!(deleted, 5);
    }

    #[test]
    fn encrypted_blob_roundtrip() {
        let db = test_db();
        let cid = setup_contact(&db);
        let id = db.save_message(&make_msg(cid, 1)).unwrap();

        // Initially no blob
        let msg = db.get_message(id).unwrap().unwrap();
        assert!(msg.encrypted_blob.is_none());

        // Store a blob
        let blob = b"encrypted wire message bytes for retry";
        db.update_message_blob(id, blob).unwrap();
        let msg = db.get_message(id).unwrap().unwrap();
        assert_eq!(msg.encrypted_blob.as_deref(), Some(blob.as_slice()));

        // Clear the blob
        db.clear_message_blob(id).unwrap();
        let msg = db.get_message(id).unwrap().unwrap();
        assert!(msg.encrypted_blob.is_none());
    }

    #[test]
    fn encrypted_blob_stored_on_save() {
        let db = test_db();
        let cid = setup_contact(&db);
        let mut msg = make_msg(cid, 2);
        msg.encrypted_blob = Some(b"wire bytes".to_vec());
        let id = db.save_message(&msg).unwrap();

        let loaded = db.get_message(id).unwrap().unwrap();
        assert_eq!(
            loaded.encrypted_blob.as_deref(),
            Some(b"wire bytes".as_slice())
        );
    }

    #[test]
    fn increment_retry_count_works() {
        let db = test_db();
        let cid = setup_contact(&db);
        let id = db.save_message(&make_msg(cid, 3)).unwrap();

        let msg = db.get_message(id).unwrap().unwrap();
        assert_eq!(msg.retry_count, 0);

        // increment_retry_count only applies to Failed messages (status = 4) —
        // retries are for failed deposits. Mark it failed first.
        db.update_message_status(id, MessageStatus::Failed).unwrap();

        db.increment_retry_count(id).unwrap();
        let msg = db.get_message(id).unwrap().unwrap();
        assert_eq!(msg.retry_count, 1);
        assert!(msg.last_retry_at.is_some());

        db.increment_retry_count(id).unwrap();
        let msg = db.get_message(id).unwrap().unwrap();
        assert_eq!(msg.retry_count, 2);
    }

    #[test]
    fn msg_id_dedup_works() {
        let db = test_db();
        let cid = setup_contact(&db);
        let mid = [0xAA; 16];
        assert!(!db.check_msg_id_seen(&mid).unwrap());
        db.mark_msg_id_seen(cid, &mid).unwrap();
        assert!(db.check_msg_id_seen(&mid).unwrap());
    }

    #[test]
    fn cleanup_old_msg_ids_works() {
        let db = test_db();
        let cid = setup_contact(&db);
        let mid = [0xBB; 16];
        db.mark_msg_id_seen(cid, &mid).unwrap();
        // A mistaken future cutoff cannot shorten the 90-day replay window.
        assert_eq!(db.cleanup_old_msg_ids(i64::MAX).unwrap(), 0);
        assert!(db.check_msg_id_seen(&mid).unwrap());
        db.conn()
            .execute("UPDATE msg_id_cache_transport SET seen_at=0", [])
            .unwrap();
        assert_eq!(db.cleanup_old_msg_ids(i64::MAX).unwrap(), 1);
        assert!(!db.check_msg_id_seen(&mid).unwrap());
    }

    #[test]
    fn conversation_timer_roundtrip() {
        let db = test_db();
        let cid = setup_contact(&db);
        assert!(db.get_conversation_timer(cid).unwrap().is_none());
        db.set_conversation_timer(cid, Some(3600)).unwrap();
        assert_eq!(db.get_conversation_timer(cid).unwrap(), Some(3600));
        db.set_conversation_timer(cid, None).unwrap();
        assert!(db.get_conversation_timer(cid).unwrap().is_none());
    }

    // S12 §2.2: set_at and the setter IK must survive a round-trip — they are
    // the merge inputs, so losing them means the two sides cannot converge.
    #[test]
    fn conversation_timer_setting_persists_merge_metadata() {
        let db = test_db();
        let cid = setup_contact(&db);
        let ik = [0x7Au8; 32];

        assert!(db.get_conversation_timer_setting(cid).unwrap().is_none());
        db.set_conversation_timer_setting(cid, Some(300), 1_234_567, &ik)
            .unwrap();
        assert_eq!(
            db.get_conversation_timer_setting(cid).unwrap(),
            Some((Some(300), 1_234_567, ik))
        );
    }

    // S12 §2.2: "off" is a stored setting carrying its own set_at, NOT a
    // deleted row — deleting would drop set_at and let an older, shorter
    // timer win the next merge.
    #[test]
    fn off_setting_is_stored_with_its_set_at() {
        let db = test_db();
        let cid = setup_contact(&db);
        let ik = [0x5Cu8; 32];

        db.set_conversation_timer_setting(cid, Some(300), 1_000, &ik)
            .unwrap();
        db.set_conversation_timer_setting(cid, None, 2_000, &ik)
            .unwrap();

        assert_eq!(db.get_conversation_timer(cid).unwrap(), None);
        assert_eq!(
            db.get_conversation_timer_setting(cid).unwrap(),
            Some((None, 2_000, ik)),
            "off must persist with its set_at, not delete the row"
        );
    }

    // A legacy 4-byte row (written before set_at was persisted) reads back as
    // set_at = 0 so any timestamped setting supersedes it.
    #[test]
    fn legacy_four_byte_timer_row_reads_as_oldest() {
        let db = test_db();
        let cid = setup_contact(&db);
        let conn = db.conn();
        conn.execute(
            "INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?1, ?2, ?3)",
            params![
                format!("disappear_timer:{cid}"),
                3600u32.to_be_bytes().to_vec(),
                0i64
            ],
        )
        .unwrap();
        drop(conn);

        assert_eq!(db.get_conversation_timer(cid).unwrap(), Some(3600));
        assert_eq!(
            db.get_conversation_timer_setting(cid).unwrap(),
            Some((Some(3600), 0, [0u8; 32]))
        );
    }
}
