//! Display acknowledgements and their durable, idempotent receipt obligations.
use crate::{
    database::SqliteStorage,
    error::{Result, StorageError},
    types::{ContactId, MessageId},
};
use rusqlite::params;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadReceiptIntent {
    pub contact_id: ContactId,
    pub msg_id: [u8; 16],
    pub timestamp: u64,
}

pub(crate) fn receipt_key(contact: ContactId, msg_id: &[u8; 16]) -> String {
    let hex: String = msg_id.iter().map(|b| format!("{b:02x}")).collect();
    format!("desktop:read-receipt:{contact}:{hex}")
}

impl SqliteStorage {
    /// Save the read time, timer start and receipt intent in one transaction.
    /// Fetching history never calls this; only the focused, visible reader does.
    pub fn mark_displayed_with_receipts(
        &self,
        contact: ContactId,
        ids: &[MessageId],
    ) -> Result<u32> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let now = najwa_crypto::time::now_ms();
        let timestamp = (now / 1000).to_be_bytes();
        let mut updated = 0;
        for id in ids {
            tx.execute(
                "INSERT INTO settings(key,value,updated_at)
                 SELECT 'desktop:read-receipt:' || contact_id || ':' || lower(hex(msg_id)),
                        CAST(msg_id || ?4 AS BLOB), ?5
                 FROM messages WHERE id=?1 AND contact_id=?2 AND direction=0
                   AND read_at IS NULL AND (flags & 4)!=0 AND content_type IN (0,8)
                   AND (disappear_at IS NULL OR disappear_at>?3)
                   AND EXISTS(SELECT 1 FROM contacts WHERE id=?2 AND blocked=0)
                 ON CONFLICT(key) DO NOTHING",
                params![id, contact, now, timestamp.as_slice(), now / 1000],
            )?;
            updated += tx.execute(
                "UPDATE messages SET read_at=?3,
                   disappear_at=CASE WHEN disappear_timer IS NULL THEN disappear_at
                     ELSE MIN(COALESCE(disappear_at,?3+disappear_timer*1000),?3+disappear_timer*1000) END
                 WHERE id=?1 AND contact_id=?2 AND direction=0 AND read_at IS NULL
                   AND (disappear_at IS NULL OR disappear_at>?3)",
                params![id, contact, now],
            )?;
        }
        tx.commit()?;
        Ok(updated as u32)
    }

    /// The compact intent survives message expiry and restart. Blocking pauses
    /// preparation; deleting a contact removes its intents with its other work.
    pub fn pending_read_receipts(&self) -> Result<Vec<ReadReceiptIntent>> {
        let conn = self.conn();
        let mut statement = conn.prepare(
            "SELECT c.id,s.value FROM settings s JOIN contacts c
               ON s.key GLOB 'desktop:read-receipt:' || c.id || ':*'
             WHERE c.blocked=0 ORDER BY s.key LIMIT 200",
        )?;
        let rows =
            statement.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?)))?;
        rows.map(|row| {
            let (contact_id, bytes) = row?;
            if bytes.len() != 24 {
                return Err(StorageError::InvalidData(
                    "invalid read receipt intent".into(),
                ));
            }
            Ok(ReadReceiptIntent {
                contact_id,
                msg_id: bytes[..16].try_into().unwrap(),
                timestamp: u64::from_be_bytes(bytes[16..].try_into().unwrap()),
            })
        })
        .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;
    fn contact(db: &SqliteStorage, tag: u8) -> ContactId {
        db.create_contact(&NewContact {
            pseudonym: [tag; 32],
            their_ik_pub: [tag; 32],
            their_device_pub: [tag; 32],
            our_pseudonym: [tag + 1; 32],
            display_name: None,
        })
        .unwrap()
    }
    fn received(db: &SqliteStorage, contact: ContactId, tag: u8, flags: i32) -> MessageId {
        db.save_message(&NewMessage {
            contact_id: contact,
            msg_id: [tag; 16],
            direction: MessageDirection::Received,
            content_type: ContentType::Text,
            flags,
            content: b"visible".to_vec(),
            file_path: None,
            timestamp: 1,
            received_at: Some(2),
            status: MessageStatus::Delivered,
            reply_to_msg_id: None,
            disappear_timer: None,
            encrypted_blob: None,
            group_id: None,
            sender_display_name: None,
            origin_timestamp_ms: None,
            retry_wire_blob: None,
        })
        .unwrap()
    }
    #[test]
    fn read_receipt_intents_require_display_opt_in_direction_and_contact() {
        let db = SqliteStorage::open_in_memory(&[42; 32]).unwrap();
        let a = contact(&db, 1);
        let b = contact(&db, 3);
        let visible = received(&db, a, 0, 4);
        let unread = received(&db, a, 2, 4);
        let unrequested = received(&db, a, 3, 0);
        let other = received(&db, b, 4, 4);
        let expired = received(&db, a, 5, 4);
        let outgoing = received(&db, a, 6, 4);
        let control = received(&db, a, 7, 4);
        db.conn()
            .execute(
                "UPDATE messages SET disappear_at=1 WHERE id=?1",
                params![expired],
            )
            .unwrap();
        db.conn()
            .execute(
                "UPDATE messages SET direction=1 WHERE id=?1",
                params![outgoing],
            )
            .unwrap();
        db.conn()
            .execute(
                "UPDATE messages SET content_type=10 WHERE id=?1",
                params![control],
            )
            .unwrap();
        assert!(db.pending_read_receipts().unwrap().is_empty());
        db.mark_displayed_with_receipts(
            a,
            &[
                visible,
                visible,
                unrequested,
                other,
                expired,
                outgoing,
                control,
            ],
        )
        .unwrap();
        let pending = db.pending_read_receipts().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].msg_id, [0; 16]);
        assert_eq!(
            pending[0].timestamp,
            db.get_message(visible).unwrap().unwrap().read_at.unwrap() as u64 / 1000
        );
        assert!(db.get_message(unread).unwrap().unwrap().read_at.is_none());
        assert!(db.get_message(other).unwrap().unwrap().read_at.is_none());
        assert!(db.get_message(expired).unwrap().unwrap().read_at.is_none());
        db.mark_displayed_with_receipts(a, &[visible]).unwrap();
        assert_eq!(db.pending_read_receipts().unwrap(), pending);
    }
    #[test]
    fn read_receipt_intents_survive_restart_expiry_and_pause_for_blocking() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("receipts.db");
        let db = SqliteStorage::open(&path, &[42; 32]).unwrap();
        let a = contact(&db, 1);
        let visible = received(&db, a, 255, 4);
        db.mark_displayed_with_receipts(a, &[visible]).unwrap();
        let intent = db.pending_read_receipts().unwrap();
        db.delete_message(visible).unwrap();
        drop(db);
        let db = SqliteStorage::open(&path, &[42; 32]).unwrap();
        assert_eq!(db.pending_read_receipts().unwrap(), intent);
        db.conn()
            .execute("UPDATE contacts SET blocked=1 WHERE id=?1", params![a])
            .unwrap();
        assert!(db.pending_read_receipts().unwrap().is_empty());
        db.conn()
            .execute("UPDATE contacts SET blocked=0 WHERE id=?1", params![a])
            .unwrap();
        assert_eq!(db.pending_read_receipts().unwrap(), intent);
        db.delete_contact(a).unwrap();
        let remaining: i64 = db
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM settings WHERE key GLOB 'desktop:read-receipt:*'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(remaining, 0);
    }
    #[test]
    fn read_receipt_outbox_commit_rolls_back_and_consumes_intent_once() {
        let db = SqliteStorage::open_in_memory(&[42; 32]).unwrap();
        let a = contact(&db, 1);
        let visible = received(&db, a, 2, 4);
        db.mark_displayed_with_receipts(a, &[visible]).unwrap();
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
        let input = crate::messaging::Outgoing {
            existing_message_id: None,
            contact_id: a,
            ratchet: &ratchet,
            skipped: &[],
            ad: None,
            message: None,
            wire: b"encrypted read receipt",
            dh_pub: [1; 32],
            n: 0,
            requires_ack: false,
            disappearing: None,
            repair: None,
            logical_id: None,
            acknowledging: &[],
        };
        db.conn().execute_batch("CREATE TRIGGER fail_receipt BEFORE INSERT ON outgoing_frames BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
        assert!(db.commit_read_receipt(&input, [2; 16]).is_err());
        assert_eq!(db.pending_read_receipts().unwrap().len(), 1);
        assert!(db.get_ratchet_state(a).unwrap().is_none());
        db.conn()
            .execute_batch("DROP TRIGGER fail_receipt")
            .unwrap();
        db.commit_read_receipt(&input, [2; 16]).unwrap();
        assert!(db.pending_read_receipts().unwrap().is_empty());
        assert_eq!(db.get_ratchet_state(a).unwrap().unwrap().ns, 1);
        assert!(db.commit_read_receipt(&input, [2; 16]).is_err());
        assert_eq!(db.outgoing_frames().unwrap().len(), 1);
        db.mark_displayed_with_receipts(a, &[visible]).unwrap();
        assert!(db.pending_read_receipts().unwrap().is_empty());
    }

    #[test]
    fn displayed_read_time_timer_and_receipt_commit_or_rollback_together() {
        let db = SqliteStorage::open_in_memory(&[42; 32]).unwrap();
        let a = contact(&db, 1);
        let visible = received(&db, a, 2, 4);
        db.conn().execute("UPDATE messages SET disappear_timer=30,disappear_at=?2 WHERE id=?1", params![visible,najwa_crypto::time::now_ms()+86_400_000]).unwrap();
        db.conn().execute_batch("CREATE TRIGGER fail_display BEFORE UPDATE OF read_at ON messages BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
        assert!(db.mark_displayed_with_receipts(a, &[visible]).is_err());
        assert!(db.pending_read_receipts().unwrap().is_empty());
        assert!(db.get_message(visible).unwrap().unwrap().read_at.is_none());
        db.conn().execute_batch("DROP TRIGGER fail_display").unwrap();
        db.mark_displayed_with_receipts(a, &[visible]).unwrap();
        let row = db.get_message(visible).unwrap().unwrap();
        assert_eq!(row.disappear_at, row.read_at.map(|at| at+30_000));
        assert_eq!(db.pending_read_receipts().unwrap().len(), 1);
        db.mark_displayed_with_receipts(a, &[visible]).unwrap();
        assert_eq!(db.get_message(visible).unwrap().unwrap().disappear_at, row.disappear_at);
    }
}
