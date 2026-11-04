//! Durable messaging queues and atomic control effects (S08).

use crate::{
    database::SqliteStorage,
    error::{Result, StorageError},
    keys::row_seal,
    types::*,
};
use rusqlite::{params, OptionalExtension, Transaction};

pub type ChainRange = ([u8; 32], u32, u32);

#[derive(Debug, Clone)]
pub struct OutgoingFrame {
    pub id: i64,
    pub contact_id: ContactId,
    pub message_id: Option<MessageId>,
    pub wire: Vec<u8>,
    pub dh_pub: [u8; 32],
    pub n: u32,
    pub requires_ack: bool,
    pub attempts: u32,
    pub next_attempt: u64,
    pub deposited_at: Option<u64>,
}

/// S08 §7.1: a deleted contact's RevocationNotice. `targets` is the core's
/// serialized deposit routes; the contact row no longer exists.
#[derive(Debug, Clone)]
pub struct RevocationFrame {
    pub id: i64,
    pub wire: Vec<u8>,
    pub targets: Vec<u8>,
    pub attempts: u32,
}

/// An undeposited RevocationNotice is abandoned after 90 days (S08 §7.1).
pub const REVOCATION_LIFETIME_SECS: i64 = 90 * 86_400;

#[derive(Debug, Clone)]
pub struct ReceivedFrame {
    pub contact_id: ContactId,
    pub dh_pub: [u8; 32],
    pub n: u32,
    pub ack_required: bool,
}

#[derive(Debug, Clone)]
pub struct InboundWork {
    pub id: i64,
    pub contact_id: ContactId,
    pub body: Vec<u8>,
    pub cursor: i64,
}

#[derive(Debug, Clone)]
pub struct HistoryMessage {
    pub message: Message,
    pub logical_seq: u32,
    pub logical_msg_id: [u8; 16],
}

#[derive(Debug, Clone)]
pub enum ReceiveEffect {
    Timer {
        secs: Option<u32>,
        set_at: u64,
        setter: [u8; 32],
    },
    Settings(Vec<(String, Vec<u8>)>),
    Identity {
        old: [u8; 32],
        new: [u8; 32],
    },
    Reset,
    Revoke,
    Introduction(NewPendingIntroduction),
    Message {
        message: Box<NewMessage>,
        logical_id: Option<[u8; 16]>,
        disappearing: Option<(u32, u64)>,
    },
    ForgetSkipped(ChainRange),
    RepairedPosition {
        dh_pub: [u8; 32],
        n: u32,
    },
    Work(Vec<u8>),
    Confirmation(DeliveryConfirmation),
}

pub struct Incoming<'a> {
    pub contact_id: ContactId,
    pub ratchet: &'a RatchetState,
    pub skipped: &'a [SkippedKey],
    pub ad: Option<&'a [u8]>,
    pub opk_id: Option<[u8; 4]>,
    pub ephemeral_cap_id: Option<i64>,
    pub message: Option<&'a NewMessage>,
    pub transport_id: &'a [u8; 16],
    pub logical_id: Option<&'a [u8; 16]>,
    pub disappearing: Option<(u32, u64)>,
    pub header_id: &'a [u8; 16],
    pub frame: &'a ReceivedFrame,
    pub effects: &'a [ReceiveEffect],
}

pub struct Outgoing<'a> {
    pub existing_message_id: Option<MessageId>,
    pub contact_id: ContactId,
    pub ratchet: &'a RatchetState,
    pub skipped: &'a [SkippedKey],
    pub ad: Option<&'a [u8]>,
    pub message: Option<&'a NewMessage>,
    pub wire: &'a [u8],
    pub dh_pub: [u8; 32],
    pub n: u32,
    pub requires_ack: bool,
    pub disappearing: Option<(u32, u64)>,
    pub repair: Option<&'a OutboundRepairRecord>,
    pub logical_id: Option<[u8; 16]>,
    pub acknowledging: &'a [ChainRange],
}

fn setting(tx: &Transaction<'_>, key: &str, value: &[u8]) -> Result<()> {
    tx.execute(
        "INSERT OR REPLACE INTO settings(key,value,updated_at) VALUES(?1,?2,?3)",
        params![key, value, najwa_crypto::time::now() as i64],
    )?;
    Ok(())
}

fn ratchet(
    tx: &Transaction<'_>,
    key: &[u8; 32],
    cid: ContactId,
    state: &RatchetState,
    skipped: &[SkippedKey],
) -> Result<()> {
    let row_key = row_seal::ratchet_row_key(key, cid)?;
    tx.execute(
        "INSERT OR REPLACE INTO ratchet_sessions
        (contact_id,dhs_private,dhs_public,dhr,rk,cks,ckr,ns,nr,pn,established_at,last_activity,prev_dhs_pub)
        VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
        params![
            cid,
            row_seal::seal(&state.dhs_private, &row_key)?,
            state.dhs_public,
            state.dhr,
            row_seal::seal(&state.rk, &row_key)?,
            row_seal::seal(&state.cks, &row_key)?,
            row_seal::seal(&state.ckr, &row_key)?,
            state.ns as i64,
            state.nr as i64,
            state.pn as i64,
            state.established_at,
            state.last_activity,
            state.prev_dhs_pub
        ],
    )?;
    tx.execute("DELETE FROM skipped_keys WHERE contact_id=?1", params![cid])?;
    for k in skipped {
        tx.execute("INSERT INTO skipped_keys(contact_id,dh_pub,message_number,message_key,created_at,expires_at)
            VALUES(?1,?2,?3,?4,?5,?6)",params![cid,k.dh_pub.as_slice(),k.message_number as i64,
            k.message_key.as_slice(),k.created_at,k.expires_at])?;
    }
    Ok(())
}

fn seen(
    tx: &Transaction<'_>,
    cid: ContactId,
    transport: &[u8; 16],
    logical: Option<&[u8; 16]>,
) -> Result<bool> {
    let transport_seen: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM msg_id_cache_transport WHERE msg_id=?1)",
        params![transport.as_slice()],
        |r| r.get(0),
    )?;
    let logical_seen = match logical {
        Some(id) => tx.query_row("SELECT EXISTS(SELECT 1 FROM msg_id_cache_logical WHERE contact_id=?1 AND logical_msg_id=?2)",params![cid,id.as_slice()],|r|r.get(0))?,
        None => false,
    };
    Ok(transport_seen || logical_seen)
}

fn mark_seen(
    tx: &Transaction<'_>,
    cid: ContactId,
    transport: &[u8; 16],
    logical: Option<&[u8; 16]>,
) -> Result<()> {
    let now = najwa_crypto::time::now() as i64;
    tx.execute(
        "INSERT OR IGNORE INTO msg_id_cache_transport(msg_id,contact_id,seen_at) VALUES(?1,?2,?3)",
        params![transport.as_slice(), cid, now],
    )?;
    if let Some(id) = logical {
        tx.execute("INSERT OR IGNORE INTO msg_id_cache_logical(contact_id,logical_msg_id,seen_at) VALUES(?1,?2,?3)",params![cid,id.as_slice(),now])?;
    }
    Ok(())
}

fn message(
    tx: &Transaction<'_>,
    msg: &NewMessage,
    disappearing: Option<(u32, u64)>,
) -> Result<MessageId> {
    tx.execute(
        "INSERT INTO messages(contact_id,msg_id,direction,content_type,flags,content,file_path,
        timestamp,received_at,status,reply_to_msg_id,disappear_timer,disappear_at,encrypted_blob,
        group_id,sender_display_name,origin_timestamp_ms,retry_wire_blob)
        VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18)",
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
            disappearing
                .map(|v| v.0 as i64)
                .or(msg.disappear_timer.map(i64::from)),
            disappearing.map(|v| v.1 as i64),
            msg.encrypted_blob,
            msg.group_id.as_ref().map(|g| g.as_slice()),
            msg.sender_display_name,
            msg.origin_timestamp_ms,
            msg.retry_wire_blob
        ],
    )?;
    Ok(tx.last_insert_rowid())
}

fn apply_effect(tx: &Transaction<'_>, cid: ContactId, effect: &ReceiveEffect) -> Result<()> {
    match effect {
        ReceiveEffect::Timer {
            secs,
            set_at,
            setter,
        } => {
            let mut bytes = secs.unwrap_or(0).to_be_bytes().to_vec();
            bytes.extend_from_slice(&set_at.to_be_bytes());
            bytes.extend_from_slice(setter);
            setting(tx, &format!("disappear_timer:{cid}"), &bytes)?;
        }
        ReceiveEffect::Settings(entries) => {
            for (key, value) in entries {
                setting(tx, key, value)?;
            }
        }
        ReceiveEffect::Identity { old, new } => {
            let changed = tx.execute(
                "UPDATE contacts SET their_ik_pub=?1 WHERE id=?2 AND their_ik_pub=?3",
                params![new.as_slice(), cid, old.as_slice()],
            )?;
            if changed != 1 {
                return Err(StorageError::InvalidData(
                    "identity changed during receive".into(),
                ));
            }
            tx.execute("INSERT INTO identity_history(contact_id,old_ik_pub,new_ik_pub,rotated_at,reason) VALUES(?1,?2,?3,?4,'rotation')",params![cid,old.as_slice(),new.as_slice(),najwa_crypto::time::now() as i64])?;
        }
        ReceiveEffect::Reset | ReceiveEffect::Revoke => {
            tx.execute(
                "DELETE FROM ratchet_sessions WHERE contact_id=?1",
                params![cid],
            )?;
            tx.execute(
                "DELETE FROM settings WHERE key=?1",
                params![format!("session_ad:{cid}")],
            )?;
            tx.execute(
                "DELETE FROM outgoing_frames WHERE contact_id=?1",
                params![cid],
            )?;
            if matches!(effect, ReceiveEffect::Revoke) {
                tx.execute(
                    "DELETE FROM settings WHERE key IN (?1,?2)",
                    params![
                        format!("contact_target:{cid}"),
                        format!("contact_targets:{cid}")
                    ],
                )?;
                tx.execute("DELETE FROM contacts WHERE id=?1", params![cid])?;
            }
        }
        ReceiveEffect::Introduction(intro) => {
            tx.execute("INSERT INTO pending_introductions(introducer_contact_id,introduced_ik_pub,introduced_display_name,introducer_ik_pub,payload_blob,is_anonymous,status,created_at,expires_at)
                SELECT ?1,?2,?3,?4,?5,0,0,?6,?7 WHERE NOT EXISTS(SELECT 1 FROM pending_introductions WHERE introduced_ik_pub=?2 AND status=0)",params![cid,intro.introduced_ik_pub.as_slice(),intro.introduced_display_name,intro.introducer_ik_pub.as_slice(),intro.payload_blob,intro.created_at,intro.expires_at])?;
        }
        ReceiveEffect::Message {
            message: msg,
            logical_id,
            disappearing,
        } => {
            if !seen(tx, cid, &msg.msg_id, logical_id.as_ref())?
                && !crate::transfers::orphan_part_refused(tx, msg, *disappearing)?
            {
                message(tx, msg, *disappearing)?;
            }
            mark_seen(tx, cid, &msg.msg_id, logical_id.as_ref())?;
        }
        ReceiveEffect::ForgetSkipped((dh, start, end)) => {
            tx.execute("DELETE FROM skipped_keys WHERE contact_id=?1 AND dh_pub=?2 AND message_number BETWEEN ?3 AND ?4",params![cid,dh.as_slice(),*start as i64,*end as i64])?;
        }
        ReceiveEffect::RepairedPosition { dh_pub, n } => {
            let mut preimage = dh_pub.to_vec();
            preimage.extend_from_slice(&n.to_be_bytes());
            let header: [u8; 16] = najwa_crypto::hash::sha256(&preimage)[..16]
                .try_into()
                .expect("hash prefix");
            mark_seen(tx, cid, &header, None)?;
            tx.execute("INSERT INTO received_frames(header_id,contact_id,dh_pub,n,ack_required,ack_pending,received_at) VALUES(?1,?2,?3,?4,1,1,?5) ON CONFLICT(header_id) DO UPDATE SET ack_pending=1",params![header.as_slice(),cid,dh_pub.as_slice(),*n as i64,najwa_crypto::time::now() as i64])?;
        }
        ReceiveEffect::Work(body) => {
            tx.execute(
                "INSERT INTO inbound_work(contact_id,body,cursor) VALUES(?1,?2,0)",
                params![cid, body],
            )?;
        }
        ReceiveEffect::Confirmation(effect) => {
            crate::messages::apply_confirmation(tx, cid, effect)?
        }
    }
    Ok(())
}

impl SqliteStorage {
    pub fn commit_incoming(&self, input: &Incoming<'_>) -> Result<Option<MessageId>> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let cid = input.contact_id;
        if seen(&tx, cid, input.header_id, None)? {
            return Ok(None);
        }
        ratchet(&tx, self.db_key(), cid, input.ratchet, input.skipped)?;
        if let Some(ad) = input.ad {
            setting(&tx, &format!("session_ad:{cid}"), ad)?;
        }
        if let Some(opk) = input.opk_id {
            tx.execute(
                "UPDATE prekeys SET used=1,used_at=?1 WHERE key_id=?2",
                params![najwa_crypto::time::now() as i64, opk.as_slice()],
            )?;
        }
        if let Some(id) = input.ephemeral_cap_id {
            if tx.execute("UPDATE ephemeral_handshake_caps SET accepted_at=?1 WHERE id=?2 AND accepted_at IS NULL AND registered_at IS NOT NULL AND deactivated_at IS NULL",params![najwa_crypto::time::now() as i64,id])? != 1 { return Err(StorageError::NotFound); }
        }
        let id = if let Some(msg) = input.message {
            if seen(&tx, cid, input.transport_id, input.logical_id)?
                || crate::transfers::orphan_part_refused(&tx, msg, input.disappearing)?
            {
                None
            } else {
                Some(message(&tx, msg, input.disappearing)?)
            }
        } else {
            None
        };
        mark_seen(&tx, cid, input.transport_id, input.logical_id)?;
        mark_seen(&tx, cid, input.header_id, None)?;
        tx.execute("INSERT INTO received_frames(header_id,contact_id,dh_pub,n,ack_required,ack_pending,received_at) VALUES(?1,?2,?3,?4,?5,?5,?6)",params![input.header_id.as_slice(),cid,input.frame.dh_pub.as_slice(),input.frame.n as i64,input.frame.ack_required,najwa_crypto::time::now() as i64])?;
        for effect in input.effects {
            apply_effect(&tx, cid, effect)?;
        }
        tx.commit()?;
        Ok(id)
    }

    pub fn commit_outgoing(&self, input: &Outgoing<'_>) -> Result<(i64, Option<MessageId>)> {
        self.commit_outgoing_impl(input, None, None)
    }

    pub fn commit_outgoing_timer(
        &self,
        input: &Outgoing<'_>,
        timer: (Option<u32>, u64, [u8; 32]),
    ) -> Result<(i64, Option<MessageId>)> {
        if timer.0.is_some_and(|secs| secs < 30) {
            return Err(StorageError::InvalidData("disappearing timers must be at least 30 seconds".into()));
        }
        self.commit_outgoing_impl(input, Some(timer), None)
    }

    /// Consume a display intent atomically with its ratchet advance and frame.
    pub fn commit_read_receipt(&self, input: &Outgoing<'_>, msg_id: [u8; 16]) -> Result<(i64, Option<MessageId>)> {
        self.commit_outgoing_impl(input, None, Some(msg_id))
    }

    /// A peer ACK removes the exact frame in the receive transaction. The marker
    /// remains harmless after that, and is replaced by the next local timer change.
    pub fn timer_change_pending(&self, contact_id: ContactId) -> Result<bool> {
        let conn = self.conn();
        let marker: Option<Vec<u8>> = conn.query_row(
            "SELECT value FROM settings WHERE key=?1", params![format!("pending_timer:{contact_id}")], |r| r.get(0)
        ).optional()?;
        let Some(marker) = marker else { return Ok(false); };
        let id = i64::from_be_bytes(marker.try_into().map_err(|_| StorageError::InvalidData("invalid timer outbox marker".into()))?);
        Ok(conn.query_row("SELECT EXISTS(SELECT 1 FROM outgoing_frames WHERE id=?1 AND contact_id=?2)",
            params![id, contact_id], |r| r.get(0))?)
    }

    fn commit_outgoing_impl(
        &self,
        input: &Outgoing<'_>,
        timer: Option<(Option<u32>, u64, [u8; 32])>,
        receipt: Option<[u8; 16]>,
    ) -> Result<(i64, Option<MessageId>)> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let cid = input.contact_id;
        if let Some(msg_id) = receipt {
            if tx.execute("DELETE FROM settings WHERE key=?1", params![crate::read_receipts::receipt_key(cid, &msg_id)])? != 1 {
                return Err(StorageError::NotFound);
            }
        }
        ratchet(&tx, self.db_key(), cid, input.ratchet, input.skipped)?;
        if let Some(ad) = input.ad {
            setting(&tx, &format!("session_ad:{cid}"), ad)?;
        }
        let mid = if let Some(msg) = input.message {
            let id = message(&tx, msg, input.disappearing)?;
            tx.execute(
                "UPDATE messages SET retry_wire_blob=?1 WHERE id=?2",
                params![input.wire, id],
            )?;
            tx.execute("INSERT INTO outbound_message_positions(contact_id,dh_pub,message_number,msg_id) VALUES(?1,?2,?3,?4)",params![cid,input.dh_pub.as_slice(),input.n as i64,msg.msg_id.as_slice()])?;
            if let Some(record) = input.repair {
                crate::messages::insert_outbound_repair(&tx, record)?;
                tx.execute("DELETE FROM outbound_repair_records WHERE contact_id=?1 AND rowid NOT IN (SELECT rowid FROM outbound_repair_records WHERE contact_id=?1 ORDER BY created_at DESC,message_number DESC LIMIT 256)",params![cid])?;
                if let Some(logical_id) = input.logical_id {
                    tx.execute("INSERT INTO outbound_history(message_id,contact_id,logical_id,logical_seq) VALUES(?1,?2,?3,?4)",params![id,cid,logical_id.as_slice(),record.logical_seq as i64])?;
                }
            }
            Some(id)
        } else if let Some(id) = input.existing_message_id {
            let old:Vec<u8>=tx.query_row("SELECT msg_id FROM messages WHERE id=?1 AND contact_id=?2 AND direction=1 AND (disappear_at IS NULL OR disappear_at>?3)",params![id,cid,najwa_crypto::time::now_ms()],|r|r.get(0))?;
            tx.execute("INSERT INTO outbound_message_positions(contact_id,dh_pub,message_number,msg_id) VALUES(?1,?2,?3,?4)",params![cid,input.dh_pub.as_slice(),input.n as i64,old])?;
            Some(id)
        } else {
            None
        };
        tx.execute("INSERT INTO outgoing_frames(contact_id,message_id,wire,dh_pub,n,requires_ack,is_replay,attempts,next_attempt) VALUES(?1,?2,?3,?4,?5,?6,?7,0,0)",params![cid,mid,input.wire,input.dh_pub.as_slice(),input.n as i64,input.requires_ack,input.existing_message_id.is_some()])?;
        let frame_id = tx.last_insert_rowid();
        for (dh, start, end) in input.acknowledging {
            tx.execute("UPDATE received_frames SET ack_pending=0 WHERE contact_id=?1 AND dh_pub=?2 AND n BETWEEN ?3 AND ?4",params![cid,dh.as_slice(),*start as i64,*end as i64])?;
        }
        if let Some((secs, set_at, setter)) = timer {
            apply_effect(&tx, cid, &ReceiveEffect::Timer { secs, set_at, setter })?;
            setting(&tx, &format!("pending_timer:{cid}"), &frame_id.to_be_bytes())?;
        }
        tx.commit()?;
        Ok((frame_id, mid))
    }

    /// Saved introductions that have not yet become an encrypted Initial frame.
    pub fn pending_contact_preparations(&self) -> Result<Vec<ContactId>> {
        let conn = self.conn();
        let mut statement = conn.prepare("SELECT c.id FROM contacts c JOIN settings s ON s.key='desktop:reciprocal:' || c.id WHERE c.blocked=0 AND NOT EXISTS(SELECT 1 FROM ratchet_sessions r WHERE r.contact_id=c.id)")?;
        let rows = statement.query_map([], |row| row.get(0))?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// The introduction is protocol metadata, distinct from visible chat text.
    pub fn contact_setup_message(&self, contact: ContactId) -> Result<Option<Message>> {
        let id: Option<MessageId> = self.conn().query_row(
            "SELECT id FROM messages WHERE contact_id=?1 AND direction=1 AND content_type=?2 ORDER BY id DESC LIMIT 1",
            params![contact, ContentType::ReciprocalHandshake as i32],
            |row| row.get(0),
        ).optional()?;
        match id {
            Some(id) => self.get_message(id),
            None => Ok(None),
        }
    }

    /// A concurrent deposit wins over retirement; preserve the ratchet for late replies.
    pub fn retire_undeposited_contact_setup(&self, message: MessageId) -> Result<bool> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let changed = tx.execute("UPDATE messages SET status=5 WHERE id=?1 AND direction=1 AND content_type=?2 AND status NOT IN (1,2,3)", params![message, ContentType::ReciprocalHandshake as i32])?;
        if changed > 0 {
            tx.execute(
                "DELETE FROM outgoing_frames WHERE message_id=?1",
                params![message],
            )?;
        }
        tx.commit()?;
        Ok(changed > 0)
    }

    pub fn outgoing_frames(&self) -> Result<Vec<OutgoingFrame>> {
        let conn = self.conn();
        let mut stmt=conn.prepare("SELECT f.id,f.contact_id,f.message_id,f.wire,f.dh_pub,f.n,f.requires_ack,f.attempts,f.next_attempt,f.deposited_at FROM outgoing_frames f LEFT JOIN messages m ON m.id=f.message_id WHERE f.message_id IS NULL OR ((f.is_replay=1 OR m.status NOT IN (2,3,5)) AND (m.disappear_at IS NULL OR m.disappear_at>?1)) ORDER BY f.id")?;
        let rows = stmt.query_map(params![najwa_crypto::time::now_ms()], |r| {
            let dh: Vec<u8> = r.get(4)?;
            Ok(OutgoingFrame {
                id: r.get(0)?,
                contact_id: r.get(1)?,
                message_id: r.get(2)?,
                wire: r.get(3)?,
                dh_pub: dh.try_into().map_err(|_| rusqlite::Error::InvalidQuery)?,
                n: r.get::<_, i64>(5)? as u32,
                requires_ack: r.get(6)?,
                attempts: r.get::<_, i64>(7)? as u32,
                next_attempt: r.get::<_, i64>(8)? as u64,
                deposited_at: r.get::<_, Option<i64>>(9)?.map(|at| at.max(0) as u64),
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn outgoing_frame_live(&self, id: i64) -> Result<bool> {
        Ok(self.conn().query_row("SELECT EXISTS(SELECT 1 FROM outgoing_frames f LEFT JOIN messages m ON m.id=f.message_id WHERE f.id=?1 AND (f.message_id IS NULL OR ((f.is_replay=1 OR m.status NOT IN (2,3,5)) AND (m.disappear_at IS NULL OR m.disappear_at>?2))))",params![id,najwa_crypto::time::now_ms()],|r|r.get(0))?)
    }
    /// First deposit remains distinct from a later peer acknowledgement.
    pub fn pending_deposit_count(&self) -> Result<u64> {
        Ok(self.conn().query_row("SELECT COUNT(*) FROM outgoing_frames f LEFT JOIN messages m ON m.id=f.message_id WHERE f.deposited_at IS NULL AND (f.message_id IS NULL OR ((f.is_replay=1 OR m.status NOT IN (2,3,5)) AND (m.disappear_at IS NULL OR m.disappear_at>?1)))",params![najwa_crypto::time::now_ms()],|r|r.get::<_, i64>(0))? as u64)
    }
    pub fn finish_outgoing(&self, id: i64, success: bool, next_attempt: u64) -> Result<()> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let row: Option<(Option<i64>, bool, bool)> = tx
            .query_row(
                "SELECT message_id,requires_ack,is_replay FROM outgoing_frames WHERE id=?1",
                params![id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        let Some((mid, requires_ack, replay)) = row else {
            return Ok(());
        };
        // A temporary outage never consumes a finite retry budget. Keep the
        // ciphertext until deposit, authenticated acknowledgement or expiry.
        if let Some(mid) = mid.filter(|_| !replay) {
            tx.execute("UPDATE messages SET status=CASE WHEN ?1 THEN 1 WHEN status=1 THEN 1 ELSE 4 END,retry_count=MIN(retry_count+?2,4294967295),last_retry_at=?3,retry_wire_blob=CASE WHEN ?1 THEN NULL ELSE retry_wire_blob END WHERE id=?4 AND status NOT IN (2,3,5)",params![success,i64::from(!success),najwa_crypto::time::now() as i64,mid])?;
        }
        if success && !requires_ack {
            tx.execute("DELETE FROM outgoing_frames WHERE id=?1", params![id])?;
        } else {
            tx.execute(
                "UPDATE outgoing_frames SET attempts=MIN(attempts+1,4294967295),next_attempt=?1,deposited_at=CASE WHEN ?3 THEN COALESCE(deposited_at,?4) ELSE deposited_at END WHERE id=?2",
                params![next_attempt as i64, id, success, najwa_crypto::time::now() as i64],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// S08 §7.1: delete the contact and, in the same transaction, keep its
    /// still-undeposited RevocationNotice frame with `targets` outside the
    /// contact row. Everything else queued for the contact is deleted with it.
    pub fn delete_contact_with_revocation(
        &self,
        id: ContactId,
        frame_id: i64,
        targets: &[u8],
    ) -> Result<()> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        tx.execute("INSERT INTO revocation_frames(wire,targets,created_at) SELECT wire,?1,?2 FROM outgoing_frames WHERE id=?3 AND contact_id=?4 AND deposited_at IS NULL",
            params![targets, najwa_crypto::time::now() as i64, frame_id, id])?;
        crate::contacts::delete_contact_in(&tx, id)?;
        tx.commit()?;
        Ok(())
    }

    /// Due RevocationNotices.
    pub fn revocation_frames(&self) -> Result<Vec<RevocationFrame>> {
        let conn = self.conn();
        let mut stmt = conn.prepare("SELECT id,wire,targets,attempts FROM revocation_frames WHERE next_attempt<=?1 ORDER BY id")?;
        let rows = stmt.query_map(params![najwa_crypto::time::now() as i64], |r| {
            Ok(RevocationFrame {
                id: r.get(0)?,
                wire: r.get(1)?,
                targets: r.get(2)?,
                attempts: r.get::<_, i64>(3)? as u32,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// The peer never ACKs a RevocationNotice, so the first deposit ends it. A
    /// failed attempt older than `REVOCATION_LIFETIME_SECS` ends it too.
    pub fn finish_revocation(&self, id: i64, success: bool, next_attempt: u64) -> Result<()> {
        let conn = self.conn();
        let expired = najwa_crypto::time::now() as i64 - REVOCATION_LIFETIME_SECS;
        conn.execute("DELETE FROM revocation_frames WHERE id=?1 AND (?2 OR created_at<?3)",
            params![id, success, expired])?;
        conn.execute("UPDATE revocation_frames SET attempts=MIN(attempts+1,4294967295),next_attempt=?1 WHERE id=?2",
            params![next_attempt as i64, id])?;
        Ok(())
    }

    pub fn received_frame(&self, header_id: &[u8; 16]) -> Result<Option<ReceivedFrame>> {
        Ok(self
            .conn()
            .query_row(
                "SELECT contact_id,dh_pub,n,ack_required FROM received_frames WHERE header_id=?1",
                params![header_id.as_slice()],
                |r| {
                    let dh: Vec<u8> = r.get(1)?;
                    Ok(ReceivedFrame {
                        contact_id: r.get(0)?,
                        dh_pub: dh.try_into().map_err(|_| rusqlite::Error::InvalidQuery)?,
                        n: r.get::<_, i64>(2)? as u32,
                        ack_required: r.get(3)?,
                    })
                },
            )
            .optional()?)
    }
    pub fn pending_ack_ranges(&self, cid: ContactId) -> Result<Vec<ChainRange>> {
        let conn = self.conn();
        let mut stmt=conn.prepare("SELECT dh_pub,n FROM received_frames WHERE contact_id=?1 AND ack_pending=1 ORDER BY received_at,dh_pub,n LIMIT 128")?;
        let rows = stmt.query_map(params![cid], |r| {
            Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, i64>(1)? as u32))
        })?;
        let mut ranges: Vec<ChainRange> = Vec::new();
        for row in rows {
            let (dh, n) = row?;
            let dh: [u8; 32] = dh
                .try_into()
                .map_err(|_| StorageError::InvalidData("bad chain key".into()))?;
            if let Some(last) = ranges.last_mut() {
                if last.0 == dh && last.2.checked_add(1) == Some(n) {
                    last.2 = n;
                    continue;
                }
            }
            if ranges.len() == 16 {
                break;
            }
            ranges.push((dh, n, n));
        }
        Ok(ranges)
    }
    pub fn repeat_ack(&self, header_id: &[u8; 16]) -> Result<()> {
        self.conn().execute(
            "UPDATE received_frames SET ack_pending=1 WHERE header_id=?1 AND ack_required=1",
            params![header_id.as_slice()],
        )?;
        Ok(())
    }
    pub fn pending_ack_contacts(&self) -> Result<Vec<ContactId>> {
        let conn = self.conn();
        let mut stmt =
            conn.prepare("SELECT DISTINCT contact_id FROM received_frames WHERE ack_pending=1")?;
        let rows = stmt.query_map([], |r| r.get(0))?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }
    pub fn inbound_work(&self) -> Result<Vec<InboundWork>> {
        let conn = self.conn();
        let mut stmt =
            conn.prepare("SELECT id,contact_id,body,cursor FROM inbound_work ORDER BY id")?;
        let rows = stmt.query_map([], |r| {
            Ok(InboundWork {
                id: r.get(0)?,
                contact_id: r.get(1)?,
                body: r.get(2)?,
                cursor: r.get(3)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }
    pub fn advance_inbound_work(&self, id: i64, cursor: Option<i64>) -> Result<()> {
        let conn = self.conn();
        match cursor {
            Some(cursor) => {
                conn.execute(
                    "UPDATE inbound_work SET cursor=?1 WHERE id=?2",
                    params![cursor, id],
                )?;
            }
            None => {
                conn.execute("DELETE FROM inbound_work WHERE id=?1", params![id])?;
            }
        }
        Ok(())
    }
    pub fn outbound_history(
        &self,
        cid: ContactId,
        anchor: Option<[u8; 16]>,
        from: u64,
        to: u64,
        cursor: i64,
    ) -> Result<Vec<HistoryMessage>> {
        let (floor, rows) = {
            let conn = self.conn();
            let floor = if let Some(anchor) = anchor.filter(|a| *a != [0; 16]) {
                conn.query_row("SELECT m.timestamp FROM outbound_history h JOIN messages m ON m.id=h.message_id WHERE h.contact_id=?1 AND h.logical_id=?2 LIMIT 1",params![cid,anchor.as_slice()],|r|r.get::<_,i64>(0)).optional()?.map(|t|t as u64).unwrap_or(from)
            } else if anchor == Some([0; 16]) {
                0
            } else {
                from
            };
            let mut stmt=conn.prepare("SELECT h.message_id,h.logical_seq,h.logical_id FROM outbound_history h JOIN messages m ON m.id=h.message_id WHERE h.contact_id=?1 AND h.message_id>?2 AND m.direction=1 AND m.timestamp>=?3 AND m.timestamp<=?4 AND (m.disappear_at IS NULL OR m.disappear_at>?5) AND (?6 IS NULL OR h.logical_id!=?6) ORDER BY h.message_id LIMIT 100")?;
            let rows = stmt
                .query_map(
                    params![
                        cid,
                        cursor,
                        floor.min(i64::MAX as u64) as i64,
                        to.min(i64::MAX as u64) as i64,
                        najwa_crypto::time::now_ms(),
                        anchor.as_ref().map(|a| a.as_slice())
                    ],
                    |r| {
                        Ok((
                            r.get::<_, i64>(0)?,
                            r.get::<_, i64>(1)? as u32,
                            r.get::<_, Vec<u8>>(2)?,
                        ))
                    },
                )?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            (floor, rows)
        };
        let _ = floor;
        let mut result = Vec::new();
        for (id, seq, logical) in rows {
            let logical_msg_id: [u8; 16] = logical
                .try_into()
                .map_err(|_| StorageError::InvalidData("bad logical id".into()))?;
            if anchor == Some(logical_msg_id) {
                continue;
            }
            if let Some(message) = self.get_message(id)? {
                result.push(HistoryMessage {
                    message,
                    logical_seq: seq,
                    logical_msg_id,
                });
            }
        }
        Ok(result)
    }

    pub fn remote_mailbox_enabled(&self, onion: &str) -> Result<bool> {
        Ok(self
            .conn()
            .query_row(
                "SELECT enabled FROM remote_mailbox_health WHERE onion=?1",
                params![onion],
                |r| r.get(0),
            )
            .optional()?
            .unwrap_or(true))
    }
    pub fn record_remote_mailbox(&self, onion: &str, success: bool) -> Result<()> {
        let conn = self.conn();
        conn.execute("INSERT INTO remote_mailbox_health(onion,failures,enabled) VALUES(?1,?2,1) ON CONFLICT(onion) DO UPDATE SET failures=CASE WHEN ?3 THEN 0 ELSE MIN(failures+1,4294967295) END, enabled=1",params![onion,i64::from(!success),success])?;
        Ok(())
    }

    /// Upgrade the old automatic five-failure pauses once for desktop profiles.
    /// Registered desktop receive routes were never user-disabled in the UI.
    /// Other disabled routes and blocked contacts retain their explicit state.
    pub fn resume_legacy_delivery_pauses(&self) -> Result<()> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let done: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM settings WHERE key='desktop:auto-retry-v1')",
            [],
            |row| row.get(0),
        )?;
        if !done {
            tx.execute(
                "UPDATE remote_mailbox_health SET enabled=1 WHERE enabled=0 AND failures>=5",
                [],
            )?;
            tx.execute("UPDATE mailboxes SET enabled=1,failure_count=0 WHERE enabled=0 AND failure_count>=5 AND EXISTS(SELECT 1 FROM settings s WHERE s.key='desktop:mailbox:' || mailboxes.id AND CAST(s.value AS TEXT)='true')", [])?;
            setting(&tx, "desktop:auto-retry-v1", b"true")?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Temporary failures are informative; delivery workers retry automatically.
    pub fn retrying_mailboxes(&self) -> Result<Vec<String>> {
        let conn = self.conn();
        let mut statement = conn.prepare("SELECT onion FROM remote_mailbox_health WHERE enabled=1 AND failures>0 UNION SELECT onion_address FROM mailboxes WHERE enabled=1 AND failure_count>0 ORDER BY 1")?;
        let rows = statement.query_map([], |row| row.get(0))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    /// Remote routes paused after repeated delivery failures.
    pub fn paused_remote_mailboxes(&self) -> Result<Vec<String>> {
        let conn = self.conn();
        let mut statement = conn.prepare("SELECT onion FROM remote_mailbox_health WHERE enabled=0 ORDER BY onion")?;
        let rows = statement.query_map([], |row| row.get(0))?;
        rows.collect::<std::result::Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Explicit user recovery after repairing/replacing a remote endpoint.
    pub fn enable_remote_mailbox(&self, onion: &str) -> Result<()> {
        self.conn().execute(
            "DELETE FROM remote_mailbox_health WHERE onion=?1",
            params![onion],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn temporary_failures_keep_the_same_frame_beyond_five_attempts() {
        let db = db();
        let (id, message) = queue(&db, 1, 10, None);
        let original = db.outgoing_frames().unwrap()[0].wire.clone();
        for attempt in 1..=12 {
            db.finish_outgoing(id, false, attempt * 10).unwrap();
            let frames = db.outgoing_frames().unwrap();
            assert_eq!(
                frames.len(),
                1,
                "temporary failure {attempt} must retain queued work"
            );
            assert_eq!(frames[0].wire, original);
            assert_eq!(frames[0].attempts, attempt as u32);
            assert_eq!(frames[0].next_attempt, attempt * 10);
            assert_eq!(
                db.get_message(message).unwrap().unwrap().status,
                MessageStatus::Failed
            );
        }
        db.finish_outgoing(id, true, 0).unwrap();
        assert!(db.outgoing_frames().unwrap().is_empty());
        assert_eq!(
            db.get_message(message).unwrap().unwrap().status,
            MessageStatus::Sent
        );
    }

    #[test]
    fn failed_retransmission_keeps_a_confirmed_deposit_and_late_reply_state() {
        let db = db();
        let (id, message) = queue(&db, 1, 10, None);
        db.conn()
            .execute(
                "UPDATE outgoing_frames SET requires_ack=1 WHERE id=?1",
                params![id],
            )
            .unwrap();
        db.finish_outgoing(id, true, 10).unwrap();
        let deposited = db.outgoing_frames().unwrap()[0].deposited_at;
        for _ in 0..12 {
            db.finish_outgoing(id, false, 20).unwrap();
        }
        assert_eq!(
            db.get_message(message).unwrap().unwrap().status,
            MessageStatus::Sent
        );
        assert_eq!(db.outgoing_frames().unwrap()[0].deposited_at, deposited);
        assert_eq!(db.pending_deposit_count().unwrap(), 0);
    }

    #[test]
    fn desktop_upgrade_resumes_old_automatic_pauses_once_and_preserves_other_state() {
        let db = db();
        let (frame, _) = queue(&db, 1, 10, None);
        let wire = db.outgoing_frames().unwrap()[0].wire.clone();
        let mut ids = Vec::new();
        for letter in ['a', 'b', 'c'] {
            ids.push(
                db.save_mailbox(&crate::types::NewMailbox::with_cover_caps(
                    letter.to_string().repeat(56),
                    vec![1; 32],
                    vec![2; 32],
                    0,
                    1,
                ))
                .unwrap(),
            );
        }
        db.set_setting(&format!("desktop:mailbox:{}", ids[0]), &true)
            .unwrap();
        db.set_setting(&format!("desktop:mailbox:{}", ids[1]), &true)
            .unwrap();
        db.conn()
            .execute(
                "UPDATE mailboxes SET enabled=0,failure_count=CASE WHEN id=?1 THEN 0 ELSE 5 END",
                params![ids[1]],
            )
            .unwrap();
        db.conn()
            .execute(
                "INSERT INTO remote_mailbox_health VALUES(?1,5,0)",
                params!["a".repeat(56)],
            )
            .unwrap();
        db.conn()
            .execute("UPDATE contacts SET blocked=1 WHERE id=1", [])
            .unwrap();
        db.resume_legacy_delivery_pauses().unwrap();
        assert!(db.remote_mailbox_enabled(&"a".repeat(56)).unwrap());
        assert!(db.get_mailbox(ids[0]).unwrap().unwrap().enabled);
        assert!(!db.get_mailbox(ids[1]).unwrap().unwrap().enabled);
        assert!(!db.get_mailbox(ids[2]).unwrap().unwrap().enabled);
        assert!(db.get_contact(1).unwrap().unwrap().blocked);
        assert_eq!(db.outgoing_frames().unwrap()[0].id, frame);
        assert_eq!(db.outgoing_frames().unwrap()[0].wire, wire);
        db.disable_mailbox(ids[0]).unwrap();
        db.resume_legacy_delivery_pauses().unwrap();
        assert!(
            !db.get_mailbox(ids[0]).unwrap().unwrap().enabled,
            "upgrade must not re-enable a later explicit disable"
        );
        for _ in 0..12 {
            db.record_remote_mailbox(&"a".repeat(56), false).unwrap();
        }
        assert!(db.remote_mailbox_enabled(&"a".repeat(56)).unwrap());
        assert_eq!(db.retrying_mailboxes().unwrap(), vec!["a".repeat(56)]);
        db.record_remote_mailbox(&"a".repeat(56), true).unwrap();
        assert!(db.retrying_mailboxes().unwrap().is_empty());
    }
    #[test]
    fn local_timer_outbox_failure_rolls_back_setting_ratchet_and_frame() {
        let db = db();
        db.set_conversation_timer_setting(1, Some(300), 1, &[1; 32]).unwrap();
        db.save_ratchet_state(1, &state(1)).unwrap();
        db.conn().execute_batch("CREATE TRIGGER fail_timer BEFORE INSERT ON settings WHEN NEW.key='disappear_timer:1' BEGIN SELECT RAISE(ABORT,'synthetic timer failure'); END;").unwrap();
        let next = state(2);
        let input = Outgoing {
            contact_id: 1, ratchet: &next, skipped: &[], ad: Some(b"timer session"),
            message: None, existing_message_id: None, wire: b"exact encrypted timer frame",
            dh_pub: [5; 32], n: 1, requires_ack: true, disappearing: None, repair: None,
            logical_id: None, acknowledging: &[],
        };
        assert!(db.commit_outgoing_timer(&input, (Some(30), 2, [1; 32])).is_err());
        assert_eq!(db.get_ratchet_state(1).unwrap().unwrap().ns, 1);
        assert_eq!(db.get_conversation_timer(1).unwrap(), Some(300));
        assert!(db.outgoing_frames().unwrap().is_empty());
        assert!(!db.timer_change_pending(1).unwrap());
        assert!(db.get_setting_raw("session_ad:1").unwrap().is_none());
        db.conn().execute_batch("DROP TRIGGER fail_timer;").unwrap();
        db.commit_outgoing_timer(&input, (Some(30), 2, [1; 32])).unwrap();
        assert_eq!(db.get_ratchet_state(1).unwrap().unwrap().ns, 2);
        assert_eq!(db.get_conversation_timer(1).unwrap(), Some(30));
        assert!(db.timer_change_pending(1).unwrap());
        assert_eq!(db.outgoing_frames().unwrap()[0].wire, input.wire);
    }
    #[test]
    fn max_timer_survives_store_and_reload_and_conversation_still_lists() {
        // S12 §2.1: timers run to u32::MAX seconds. Read back as i32, one long
        // timer made the message, and so the whole conversation, unloadable.
        let db = db();
        let at = najwa_crypto::time::now_ms() as u64 + 60_000;
        let (_, timed) = queue(&db, 1, 10, Some((u32::MAX, at)));
        let (_, pending) = queue(&db, 2, 20, None);
        db.set_message_disappear_pending(pending, u32::MAX).unwrap();
        for id in [timed, pending] {
            assert_eq!(db.get_message_disappear_pending(id).unwrap(), Some(u32::MAX));
        }
        let listed = db.list_messages(1, 10, None).unwrap();
        assert_eq!(listed.len(), 2);
        assert!(listed
            .iter()
            .all(|m| m.disappear_timer.map(i64::from) == Some(u32::MAX as i64)));
        assert_eq!(db.list_contacts_with_preview().unwrap().len(), 1);
    }
    #[test]
    fn expiring_an_unsent_setup_removes_only_its_frame_and_cannot_overwrite_a_deposit() {
        let db = db();
        let (frame, message) = queue(&db, 1, 10, None);
        assert!(
            !db.retire_undeposited_contact_setup(message).unwrap(),
            "ordinary chat text is never a setup request"
        );
        db.conn()
            .execute(
                "UPDATE messages SET content_type=?1 WHERE id=?2",
                params![ContentType::ReciprocalHandshake as i32, message],
            )
            .unwrap();
        assert!(db.retire_undeposited_contact_setup(message).unwrap());
        assert!(!db.outgoing_frame_live(frame).unwrap());
        db.finish_outgoing(frame, false, 99).unwrap();
        assert_eq!(
            db.get_message(message).unwrap().unwrap().status,
            MessageStatus::PermanentlyFailed
        );
        assert!(db.get_ratchet_state(1).unwrap().is_some());
        let (deposited_frame, deposited_message) = queue(&db, 2, 20, None);
        db.conn()
            .execute(
                "UPDATE messages SET content_type=?1 WHERE id=?2",
                params![ContentType::ReciprocalHandshake as i32, deposited_message],
            )
            .unwrap();
        db.finish_outgoing(deposited_frame, true, 99).unwrap();
        assert!(!db
            .retire_undeposited_contact_setup(deposited_message)
            .unwrap());
        assert_eq!(
            db.get_message(deposited_message).unwrap().unwrap().status,
            MessageStatus::Sent
        );
    }

    fn db() -> SqliteStorage {
        let db = SqliteStorage::open_in_memory(&[81; 32]).unwrap();
        db.create_contact(&NewContact {
            pseudonym: [1; 32],
            their_ik_pub: [2; 32],
            their_device_pub: [2; 32],
            our_pseudonym: [3; 32],
            display_name: None,
        })
        .unwrap();
        db
    }
    fn state(n: u32) -> RatchetState {
        RatchetState {
            dhs_private: Some(vec![4; 32]),
            dhs_public: Some(vec![5; 32]),
            dhr: Some(vec![6; 32]),
            rk: Some(vec![7; 32]),
            cks: Some(vec![8; 32]),
            ckr: Some(vec![9; 32]),
            ns: n,
            nr: n,
            pn: 0,
            prev_dhs_pub: None,
            established_at: 1,
            last_activity: 1,
        }
    }
    fn msg(n: u8, timestamp: i64) -> NewMessage {
        NewMessage {
            contact_id: 1,
            msg_id: [n; 16],
            direction: MessageDirection::Sent,
            content_type: ContentType::Text,
            flags: 0,
            content: vec![n; 10],
            file_path: None,
            timestamp,
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
    fn queue(
        db: &SqliteStorage,
        n: u8,
        timestamp: i64,
        expiry: Option<(u32, u64)>,
    ) -> (i64, MessageId) {
        let message = msg(n, timestamp);
        let state = state(n as u32 + 1);
        let record = OutboundRepairRecord {
            contact_id: 1,
            dh_pub: [5; 32],
            message_number: n as u32,
            msg_id: message.msg_id,
            timestamp: timestamp as u64,
            logical_seq: n as u32,
            content_type: 1,
            flags: 0,
            content: message.content.clone(),
            created_at: 1,
        };
        let (fid, mid) = db
            .commit_outgoing(&Outgoing {
                contact_id: 1,
                ratchet: &state,
                skipped: &[],
                ad: Some(b"AD"),
                message: Some(&message),
                existing_message_id: None,
                wire: &[n; 100],
                dh_pub: [5; 32],
                n: n as u32,
                requires_ack: false,
                disappearing: expiry,
                repair: Some(&record),
                logical_id: Some([n; 16]),
                acknowledging: &[],
            })
            .unwrap();
        (fid, mid.unwrap())
    }
    #[test]
    fn revocation_notice_outlives_its_deleted_contact_until_deposit_or_expiry() {
        let db = db();
        queue(&db, 1, 10, None);
        let state = state(3);
        let (notice, _) = db
            .commit_outgoing(&Outgoing {
                contact_id: 1, ratchet: &state, skipped: &[], ad: None, message: None,
                existing_message_id: None, wire: b"notice", dh_pub: [5; 32], n: 2,
                requires_ack: true, disappearing: None, repair: None, logical_id: None,
                acknowledging: &[],
            })
            .unwrap();
        db.delete_contact_with_revocation(1, notice, b"routes").unwrap();
        assert!(db.get_contact(1).unwrap().is_none());
        assert!(db.outgoing_frames().unwrap().is_empty(), "only the notice survives");
        let kept = db.revocation_frames().unwrap();
        assert_eq!((kept.len(), &kept[0].wire[..], &kept[0].targets[..]), (1, &b"notice"[..], &b"routes"[..]));
        db.finish_revocation(kept[0].id, false, i64::MAX as u64).unwrap();
        assert!(db.revocation_frames().unwrap().is_empty(), "a failed attempt backs off");
        db.conn().execute("UPDATE revocation_frames SET next_attempt=0", []).unwrap();
        db.finish_revocation(kept[0].id, true, 0).unwrap();
        assert!(db.revocation_frames().unwrap().is_empty());
        let old = najwa_crypto::time::now() as i64 - REVOCATION_LIFETIME_SECS - 1;
        db.conn().execute("INSERT INTO revocation_frames(wire,targets,created_at) VALUES(x'00',x'00',?1)", params![old]).unwrap();
        let expired = db.revocation_frames().unwrap()[0].id;
        db.finish_revocation(expired, false, 0).unwrap();
        assert!(db.revocation_frames().unwrap().is_empty(), "an expired notice is discarded");
    }
    #[test]
    fn row8_outbox_failure_rolls_back_first_session_message_and_history() {
        let db = db();
        db.conn().execute_batch("CREATE TRIGGER fail_queue BEFORE INSERT ON outgoing_frames BEGIN SELECT RAISE(ABORT,'injected disk failure'); END;").unwrap();
        let state = state(1);
        let message = msg(1, 1);
        let input = Outgoing {
            contact_id: 1,
            ratchet: &state,
            skipped: &[],
            ad: Some(b"AD"),
            message: Some(&message),
            existing_message_id: None,
            wire: b"wire",
            dh_pub: [5; 32],
            n: 0,
            requires_ack: false,
            disappearing: None,
            repair: None,
            logical_id: None,
            acknowledging: &[],
        };
        assert!(db.commit_outgoing(&input).is_err());
        assert!(db.get_ratchet_state(1).unwrap().is_none());
        assert!(db.get_setting_raw("session_ad:1").unwrap().is_none());
        assert!(db.get_message_by_msg_id(&message.msg_id).unwrap().is_none());
        assert!(db.outgoing_frames().unwrap().is_empty());
        db.conn().execute_batch("DROP TRIGGER fail_queue;").unwrap();
        assert!(db.commit_outgoing(&input).is_ok());
    }
    #[test]
    fn row8_control_effect_failure_rolls_back_ratchet_dedup_timer_and_repaired_rows() {
        let db = db();
        let before = state(1);
        db.save_ratchet_state(1, &before).unwrap();
        let next = state(2);
        let valid = msg(2, 2);
        let mut invalid = msg(3, 3);
        invalid.contact_id = 999;
        let effects = vec![
            ReceiveEffect::Timer {
                secs: Some(30),
                set_at: 2,
                setter: [2; 32],
            },
            ReceiveEffect::Message {
                message: Box::new(valid.clone()),
                logical_id: Some([2; 16]),
                disappearing: None,
            },
            ReceiveEffect::Message {
                message: Box::new(invalid),
                logical_id: Some([3; 16]),
                disappearing: None,
            },
        ];
        let frame = ReceivedFrame {
            contact_id: 1,
            dh_pub: [6; 32],
            n: 1,
            ack_required: true,
        };
        let input = Incoming {
            contact_id: 1,
            ratchet: &next,
            skipped: &[],
            ad: Some(b"new AD"),
            opk_id: None,
            ephemeral_cap_id: None,
            message: None,
            transport_id: &[11; 16],
            logical_id: None,
            disappearing: None,
            header_id: &[12; 16],
            frame: &frame,
            effects: &effects,
        };
        assert!(db.commit_incoming(&input).is_err());
        assert_eq!(db.get_ratchet_state(1).unwrap().unwrap().nr, 1);
        assert!(!db.check_msg_id_seen(&[11; 16]).unwrap());
        assert!(!db.check_msg_id_seen(&[12; 16]).unwrap());
        assert!(db.get_setting_raw("disappear_timer:1").unwrap().is_none());
        assert!(db.get_setting_raw("session_ad:1").unwrap().is_none());
        assert!(db.get_message_by_msg_id(&valid.msg_id).unwrap().is_none());
        assert!(db.pending_ack_contacts().unwrap().is_empty());
    }
    #[test]
    fn row8_response_work_and_ack_intent_commit_with_incoming_frame() {
        let db = db();
        let state = state(2);
        let frame = ReceivedFrame {
            contact_id: 1,
            dh_pub: [6; 32],
            n: 1,
            ack_required: true,
        };
        let effects = [ReceiveEffect::Work(b"resend request".to_vec())];
        let input = Incoming {
            contact_id: 1,
            ratchet: &state,
            skipped: &[],
            ad: None,
            opk_id: None,
            ephemeral_cap_id: None,
            message: None,
            transport_id: &[11; 16],
            logical_id: None,
            disappearing: None,
            header_id: &[12; 16],
            frame: &frame,
            effects: &effects,
        };
        db.commit_incoming(&input).unwrap();
        db.commit_incoming(&input).unwrap();
        assert_eq!(db.inbound_work().unwrap().len(), 1);
        assert_eq!(db.pending_ack_ranges(1).unwrap(), vec![([6; 32], 1, 1)]);
        let ranges = db.pending_ack_ranges(1).unwrap();
        let (id, _) = db
            .commit_outgoing(&Outgoing {
                contact_id: 1,
                ratchet: &state,
                skipped: &[],
                ad: None,
                message: None,
                existing_message_id: None,
                wire: b"ACK",
                dh_pub: [5; 32],
                n: 2,
                requires_ack: false,
                disappearing: None,
                repair: None,
                logical_id: None,
                acknowledging: &ranges,
            })
            .unwrap();
        assert!(db.pending_ack_ranges(1).unwrap().is_empty());
        assert!(db.outgoing_frame_live(id).unwrap());
        db.repeat_ack(&[12; 16]).unwrap();
        assert!(!db.pending_ack_ranges(1).unwrap().is_empty());
    }
    #[test]
    fn row8_history_anchor_ties_fallback_floor_and_expiry() {
        let db = db();
        queue(&db, 1, 10, None);
        let (_, anchor) = queue(&db, 2, 20, None);
        queue(&db, 3, 20, None);
        queue(&db, 4, 30, None);
        queue(&db, 5, 40, Some((30, 1)));
        let ids = |items: Vec<HistoryMessage>| {
            items
                .into_iter()
                .map(|h| h.message.msg_id[0])
                .collect::<Vec<_>>()
        };
        assert_eq!(
            ids(db.outbound_history(1, Some([2; 16]), 999, 100, 0).unwrap()),
            vec![3, 4]
        );
        assert_eq!(
            ids(db.outbound_history(1, Some([99; 16]), 25, 100, 0).unwrap()),
            vec![4]
        );
        assert_eq!(
            ids(db.outbound_history(1, Some([0; 16]), 999, 100, 0).unwrap()),
            vec![1, 2, 3, 4]
        );
        assert_eq!(
            ids(db.outbound_history(1, None, 20, 20, 0).unwrap()),
            vec![2, 3]
        );
        assert_eq!(
            ids(db
                .outbound_history(1, Some([2; 16]), 0, 100, anchor)
                .unwrap()),
            vec![3, 4]
        );
    }
    #[test]
    fn row8_secure_overwrite_removes_history_and_queued_ciphertext() {
        let db = db();
        let (fid, mid) = queue(&db, 1, 1, None);
        db.conn()
            .execute(
                "UPDATE messages SET content=zeroblob(length(content)) WHERE id=?1",
                params![mid],
            )
            .unwrap();
        assert!(!db.outgoing_frame_live(fid).unwrap());
        assert!(db
            .outbound_history(1, Some([0; 16]), 0, u64::MAX, 0)
            .unwrap()
            .is_empty());
    }
    #[test]
    fn row8_control_outbox_survives_database_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("queue.db");
        let db = SqliteStorage::open(&path, &[81; 32]).unwrap();
        db.create_contact(&NewContact {
            pseudonym: [1; 32],
            their_ik_pub: [2; 32],
            their_device_pub: [2; 32],
            our_pseudonym: [3; 32],
            display_name: None,
        })
        .unwrap();
        let state = state(1);
        let (id, _) = db
            .commit_outgoing(&Outgoing {
                contact_id: 1,
                ratchet: &state,
                skipped: &[],
                ad: Some(b"AD"),
                message: None,
                existing_message_id: None,
                wire: b"control ciphertext",
                dh_pub: [5; 32],
                n: 0,
                requires_ack: true,
                disappearing: None,
                repair: None,
                logical_id: None,
                acknowledging: &[],
            })
            .unwrap();
        db.finish_outgoing(id, true, 0).unwrap();
        drop(db);
        let db = SqliteStorage::open(&path, &[81; 32]).unwrap();
        let frames = db.outgoing_frames().unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].wire, b"control ciphertext");
        assert_eq!(db.get_ratchet_state(1).unwrap().unwrap().ns, 1);
    }
    #[test]
    fn orphan_file_parts_are_capped_per_contact_and_expire() {
        use crate::transfers::{ORPHAN_PART_BYTES, ORPHAN_PART_SECS};
        let db = db();
        let now = najwa_crypto::time::now() as i64;
        let part = |n: u8, session: u8, len: usize, received_at: i64| {
            let mut m = msg(n, 1);
            m.direction = MessageDirection::Received;
            m.content_type = ContentType::FileChunk;
            m.received_at = Some(received_at);
            m.content = vec![session; len];
            m
        };
        let old = db.save_message(&part(1, 1, 1000, now - ORPHAN_PART_SECS - 1)).unwrap();
        let fresh = db.save_message(&part(2, 2, 1000, now)).unwrap();
        let mut meta = part(3, 3, 64, now);
        meta.content_type = ContentType::FileMetadata;
        db.save_message(&meta).unwrap();
        let state = state(2);
        let commit = |m: &NewMessage, n: u8| {
            db.commit_incoming(&Incoming {
                contact_id: 1,
                ratchet: &state,
                skipped: &[],
                ad: None,
                opk_id: None,
                ephemeral_cap_id: None,
                message: Some(m),
                transport_id: &[n; 16],
                logical_id: None,
                disappearing: None,
                header_id: &[n + 100; 16],
                frame: &ReceivedFrame { contact_id: 1, dh_pub: [6; 32], n: n.into(), ack_required: true },
                effects: &[],
            })
            .unwrap()
        };
        // The fresh 1,000-byte orphan plus this part is one byte over the cap.
        let over = part(4, 0, (ORPHAN_PART_BYTES - 999) as usize, now);
        assert!(commit(&over, 4).is_none());
        assert!(db.get_message(old).unwrap().is_none(), "expired orphan kept");
        assert!(db.get_message(fresh).unwrap().is_some());
        assert!(commit(&part(5, 5, 1000, now), 5).is_some());
        assert!(commit(&part(6, 3, 1000, now), 6).is_some(), "part with metadata");
    }
}
