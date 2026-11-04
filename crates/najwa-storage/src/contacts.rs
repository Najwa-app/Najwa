//! Contact CRUD operations.
//!
//! Implements S03 §5.2 contacts table CRUD and S03 §6 trait methods.

use rusqlite::params;

use crate::database::SqliteStorage;
use crate::error::{Result, StorageError};
use crate::types::*;

/// The body of `delete_contact`, shared with the S08 §7.1 revocation delete.
pub(crate) fn delete_contact_in(tx: &rusqlite::Transaction<'_>, id: ContactId) -> Result<()> {
    tx.execute("DELETE FROM volatile_keys WHERE msg_id IN (SELECT msg_id FROM messages WHERE contact_id=?1)", params![id])?;
    let changed = tx.execute("DELETE FROM contacts WHERE id = ?1", params![id])?;
    if changed == 0 {
        return Err(StorageError::NotFound);
    }
    // S05 remote credentials live in settings for the core routing adapter,
    // so they do not participate in the capability table's FK cascade.
    tx.execute(
        "DELETE FROM settings WHERE key IN (?1, ?2, ?3)",
        params![
            format!("contact_target:{id}"),
            format!("contact_targets:{id}"),
            format!("contact_handshake:{id}"),
        ],
    )?;
    for prefix in [
        "session_ad",
        "disappear_timer",
        "pending_timer",
        "desktop:reciprocal",
        "desktop:announced",
        "desktop:announced-current",
    ] {
        tx.execute(
            "DELETE FROM settings WHERE key=?1",
            params![format!("{prefix}:{id}")],
        )?;
    }
    for prefix in ["desktop:announced-v2", "desktop:attachment-job", "desktop:read-receipt"] {
        tx.execute(
            "DELETE FROM settings WHERE key GLOB ?1",
            params![format!("{prefix}:{id}:*")],
        )?;
    }
    Ok(())
}

impl SqliteStorage {
    /// Atomically increment and return this contact's outbound sequence counter
    /// (Phase 3 / D4). The returned value is stamped into the message's
    /// `logical_seq`; the first message to a contact gets 1.
    pub fn next_outbound_seq(&self, contact_id: ContactId) -> Result<u32> {
        let conn = self.conn();
        let seq: i64 = conn.query_row(
            "UPDATE contacts SET next_outbound_seq = next_outbound_seq + 1
             WHERE id = ?1 AND next_outbound_seq < 4294967295
             RETURNING next_outbound_seq",
            params![contact_id],
            |r| r.get(0),
        )?;
        Ok(seq as u32)
    }

    /// Create a new contact. Returns the new contact ID.
    pub fn create_contact(&self, contact: &NewContact) -> Result<ContactId> {
        let conn = self.conn();
        let now = najwa_crypto::time::now() as i64;

        conn.execute(
            "INSERT INTO contacts (pseudonym, their_ik_pub, their_device_pub, our_pseudonym, display_name, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                contact.pseudonym.as_slice(),
                contact.their_ik_pub.as_slice(),
                contact.their_device_pub.as_slice(),
                contact.our_pseudonym.as_slice(),
                contact.display_name,
                now,
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

    /// Get a contact by its row ID.
    pub fn get_contact(&self, id: ContactId) -> Result<Option<Contact>> {
        let conn = self.conn();
        let mut stmt = conn.prepare_cached(
            "SELECT id, pseudonym, their_ik_pub, our_pseudonym, display_name, avatar_hash,
                    created_at, last_message_at, verified, blocked, their_device_pub
             FROM contacts WHERE id = ?1",
        )?;

        let result = stmt.query_row(params![id], |row| Ok(row_to_contact(row)));

        match result {
            Ok(c) => Ok(Some(c?)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Get a contact by their pseudonym (32 bytes).
    pub fn get_contact_by_pseudonym(&self, pseudonym: &[u8; 32]) -> Result<Option<Contact>> {
        let conn = self.conn();
        let mut stmt = conn.prepare_cached(
            "SELECT id, pseudonym, their_ik_pub, our_pseudonym, display_name, avatar_hash,
                    created_at, last_message_at, verified, blocked, their_device_pub
             FROM contacts WHERE pseudonym = ?1",
        )?;

        let result = stmt.query_row(params![pseudonym.as_slice()], |row| Ok(row_to_contact(row)));

        match result {
            Ok(c) => Ok(Some(c?)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Get a contact by their identity public key (32 bytes).
    pub fn get_contact_by_ik(&self, ik_pub: &[u8; 32]) -> Result<Option<Contact>> {
        let conn = self.conn();
        let mut stmt = conn.prepare_cached(
            "SELECT id, pseudonym, their_ik_pub, our_pseudonym, display_name, avatar_hash,
                    created_at, last_message_at, verified, blocked, their_device_pub
             FROM contacts WHERE their_ik_pub = ?1",
        )?;

        let result = stmt.query_row(params![ik_pub.as_slice()], |row| Ok(row_to_contact(row)));

        match result {
            Ok(c) => Ok(Some(c?)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// List all contacts, ordered by last message timestamp (newest first).
    pub fn list_contacts(&self) -> Result<Vec<Contact>> {
        let conn = self.conn();
        let mut stmt = conn.prepare_cached(
            "SELECT id, pseudonym, their_ik_pub, our_pseudonym, display_name, avatar_hash,
                    created_at, last_message_at, verified, blocked, their_device_pub
             FROM contacts ORDER BY last_message_at DESC NULLS LAST, created_at DESC",
        )?;

        let rows = stmt.query_map([], |row| Ok(row_to_contact(row)))?;
        let mut contacts = Vec::new();
        for r in rows {
            contacts.push(r??);
        }
        Ok(contacts)
    }

    /// List all contacts with last message preview and unread count in a
    /// single query (avoids N+1 per-contact queries).
    pub fn list_contacts_with_preview(&self) -> Result<Vec<(Contact, Option<String>, u32)>> {
        let conn = self.conn();
        let mut stmt = conn.prepare_cached(
            "SELECT c.id, c.pseudonym, c.their_ik_pub, c.our_pseudonym,
                    c.display_name, c.avatar_hash, c.created_at,
                    c.last_message_at, c.verified, c.blocked, c.their_device_pub,
                    m.content_type, m.content,
                    COALESCE(u.cnt, 0) AS unread_count,
                    m.flags, m.disappear_timer, m.timestamp
             FROM contacts c
             LEFT JOIN (
                 SELECT contact_id, content_type,
                        CASE WHEN (flags & 1)!=0 OR disappear_timer IS NOT NULL THEN NULL ELSE content END AS content,
                        flags, disappear_timer, timestamp,
                        ROW_NUMBER() OVER (PARTITION BY contact_id ORDER BY timestamp DESC,id DESC) AS rn
                 FROM messages
                 WHERE content_type IN (0,8,10) AND (disappear_at IS NULL OR disappear_at>?1)
             ) m ON m.contact_id = c.id AND m.rn = 1
             LEFT JOIN (
                 SELECT contact_id, COUNT(*) AS cnt
                 FROM messages
                 WHERE direction = 0 AND read_at IS NULL AND content_type IN (0,8,10)
                   AND (disappear_at IS NULL OR disappear_at>?1)
                 GROUP BY contact_id
             ) u ON u.contact_id = c.id
             ORDER BY m.timestamp DESC NULLS LAST, c.created_at DESC",
        )?;

        let rows = stmt.query_map(params![najwa_crypto::time::now_ms()], |row| {
            let content_type: Option<i32> = row.get(11)?;
            let content_blob: Option<Vec<u8>> = row.get(12)?;
            let unread: i32 = row.get(13)?;

            let disappearing = row.get::<_, Option<i32>>(14)?.is_some_and(|flags| flags & 1 != 0)
                || row.get::<_, Option<u32>>(15)?.is_some();
            let last_msg = if disappearing { Some("Disappearing message".into()) } else { match (content_type, content_blob) {
                (Some(0), Some(blob)) => String::from_utf8(blob).ok(), // Text
                (Some(8), Some(blob)) => blob
                    .get(18..)
                    .and_then(|text| String::from_utf8(text.to_vec()).ok()),
                (Some(ct), Some(_)) => {
                    use crate::types::ContentType;
                    let label = match ContentType::from_i32(ct) {
                        ContentType::Image => "\u{1f4f7} Image",
                        ContentType::Audio => "\u{1f3b5} Audio",
                        ContentType::Video => "\u{1f3ac} Video",
                        ContentType::File
                        | ContentType::Binary
                        | ContentType::FileMetadata
                        | ContentType::FileChunk => "\u{1f4ce} File",
                        ContentType::Location => "\u{1f4cd} Location",
                        ContentType::Contact => "\u{1f464} Contact",
                        ContentType::System
                        | ContentType::ReciprocalHandshake
                        | ContentType::Control => "System message",
                        ContentType::Text | ContentType::TextReply => "", // Already handled above
                    };
                    Some(label.to_string())
                }
                _ => None,
            }};
            // row_to_contact returns Result<Contact, StorageError>,
            // wrap in Ok to match query_map's expected rusqlite::Result.
            let last_message_at = row.get(16)?;
            let contact = row_to_contact(row).map(|mut contact| {
                contact.last_message_at = last_message_at;
                contact
            });
            Ok((contact, last_msg, unread as u32))
        })?;

        let mut results = Vec::new();
        for r in rows {
            let (contact_result, last_msg, unread) = r?;
            results.push((contact_result?, last_msg, unread));
        }
        Ok(results)
    }

    /// Update an existing contact.
    pub fn update_contact(&self, contact: &Contact) -> Result<()> {
        let conn = self.conn();
        let changed = conn.execute(
            "UPDATE contacts SET
                pseudonym = ?1, their_ik_pub = ?2, our_pseudonym = ?3,
                display_name = ?4, avatar_hash = ?5, last_message_at = ?6,
                verified = ?7, blocked = ?8, their_device_pub = ?10
             WHERE id = ?9",
            params![
                contact.pseudonym.as_slice(),
                contact.their_ik_pub.as_slice(),
                contact.our_pseudonym.as_slice(),
                contact.display_name,
                contact.avatar_hash,
                contact.last_message_at,
                contact.verified as i32,
                contact.blocked as i32,
                contact.id,
                contact.their_device_pub.as_slice(),
            ],
        )?;

        if changed == 0 {
            return Err(StorageError::NotFound);
        }
        Ok(())
    }

    /// S03 §5.2: lookup by identity and device key — at most one row per
    /// `(their_ik_pub, their_device_pub)`.
    pub fn get_contact_by_ik_device(
        &self,
        ik_pub: &[u8; 32],
        device_pub: &[u8; 32],
    ) -> Result<Option<Contact>> {
        let conn = self.conn();
        let mut stmt = conn.prepare_cached(
            "SELECT id, pseudonym, their_ik_pub, our_pseudonym, display_name, avatar_hash,
                    created_at, last_message_at, verified, blocked, their_device_pub
             FROM contacts WHERE their_ik_pub = ?1 AND their_device_pub = ?2",
        )?;
        let result = stmt.query_row(params![ik_pub.as_slice(), device_pub.as_slice()], |row| {
            Ok(row_to_contact(row))
        });
        match result {
            Ok(c) => Ok(Some(c?)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// S03 §5.2: all rows with this identity key (identity-rotation
    /// announcements, S02 §18.1). Single-device peers return one row.
    pub fn get_contacts_by_ik(&self, ik_pub: &[u8; 32]) -> Result<Vec<Contact>> {
        let conn = self.conn();
        let mut stmt = conn.prepare_cached(
            "SELECT id, pseudonym, their_ik_pub, our_pseudonym, display_name, avatar_hash,
                    created_at, last_message_at, verified, blocked, their_device_pub
             FROM contacts WHERE their_ik_pub = ?1",
        )?;
        let rows = stmt.query_map(params![ik_pub.as_slice()], |row| Ok(row_to_contact(row)))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r??);
        }
        Ok(out)
    }

    /// Delete a contact by ID. Cascades to sessions, keys, and messages.
    pub fn delete_contact(&self, id: ContactId) -> Result<()> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        delete_contact_in(&tx, id)?;
        tx.commit()?;
        Ok(())
    }

    /// Change one user preference without overwriting concurrent ratchet/identity work.
    pub fn rename_contact(&self, id: ContactId, name: &str) -> Result<()> {
        let changed = self.conn().execute(
            "UPDATE contacts SET display_name=?2 WHERE id=?1",
            params![id, name],
        )?;
        if changed == 0 {
            return Err(StorageError::NotFound);
        }
        Ok(())
    }

    pub fn set_contact_blocked(&self, id: ContactId, blocked: bool) -> Result<()> {
        let changed = self.conn().execute(
            "UPDATE contacts SET blocked=?2 WHERE id=?1",
            params![id, blocked],
        )?;
        if changed == 0 {
            return Err(StorageError::NotFound);
        }
        Ok(())
    }

    pub fn verify_contact_identity(
        &self,
        id: ContactId,
        identity: &[u8; 32],
        verified: bool,
    ) -> Result<()> {
        let changed = self.conn().execute(
            "UPDATE contacts SET verified=?3 WHERE id=?1 AND their_ik_pub=?2",
            params![id, identity.as_slice(), verified],
        )?;
        if changed == 0 {
            return Err(StorageError::NotFound);
        }
        Ok(())
    }

    pub fn contact_message_ids(&self, id: ContactId) -> Result<Vec<[u8; 16]>> {
        let conn = self.conn();
        let mut stmt = conn.prepare("SELECT msg_id FROM messages WHERE contact_id=?1")?;
        let rows = stmt.query_map(params![id], |r| r.get::<_, Vec<u8>>(0))?;
        rows.map(|r| {
            r?.try_into()
                .map_err(|_| StorageError::InvalidData("message id".into()))
        })
        .collect()
    }

    /// Update per-contact pseudonyms.
    pub fn update_contact_pseudonyms(
        &self,
        contact_id: ContactId,
        our_pseudo: [u8; 32],
        their_pseudo: [u8; 32],
    ) -> Result<()> {
        let conn = self.conn();
        let changed = conn.execute(
            "UPDATE contacts SET our_pseudonym = ?1, pseudonym = ?2 WHERE id = ?3",
            params![our_pseudo.as_slice(), their_pseudo.as_slice(), contact_id,],
        )?;
        if changed == 0 {
            return Err(StorageError::NotFound);
        }
        Ok(())
    }
}

/// Extract a Contact from a rusqlite Row.
fn row_to_contact(row: &rusqlite::Row<'_>) -> Result<Contact> {
    let pseudonym_blob: Vec<u8> = row.get(1)?;
    let ik_blob: Vec<u8> = row.get(2)?;
    let our_blob: Vec<u8> = row.get(3)?;
    // their_device_pub is appended as the LAST selected column (index 10) so the
    // existing 0..9 indices are unchanged across every SELECT.
    let device_blob: Vec<u8> = row.get(10)?;

    let mut pseudonym = [0u8; 32];
    let mut their_ik_pub = [0u8; 32];
    let mut our_pseudonym = [0u8; 32];
    let mut their_device_pub = [0u8; 32];

    if pseudonym_blob.len() == 32 {
        pseudonym.copy_from_slice(&pseudonym_blob);
    }
    if ik_blob.len() == 32 {
        their_ik_pub.copy_from_slice(&ik_blob);
    }
    if our_blob.len() == 32 {
        our_pseudonym.copy_from_slice(&our_blob);
    }
    if device_blob.len() == 32 {
        their_device_pub.copy_from_slice(&device_blob);
    }

    Ok(Contact {
        id: row.get(0)?,
        pseudonym,
        their_ik_pub,
        their_device_pub,
        our_pseudonym,
        display_name: row.get(4)?,
        avatar_hash: row.get(5)?,
        created_at: row.get(6)?,
        last_message_at: row.get(7)?,
        verified: row.get::<_, i32>(8)? != 0,
        blocked: row.get::<_, i32>(9)? != 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_db() -> SqliteStorage {
        SqliteStorage::open_in_memory(&[0x42; 32]).unwrap()
    }

    fn make_contact(n: u8) -> NewContact {
        NewContact {
            pseudonym: [n; 32],
            their_ik_pub: [n + 100; 32],
            their_device_pub: [n + 100; 32],
            our_pseudonym: [n + 200; 32],
            display_name: Some(format!("Contact {n}")),
        }
    }

    #[test]
    fn create_and_get_contact() {
        let db = test_db();
        let id = db.create_contact(&make_contact(1)).unwrap();
        let c = db.get_contact(id).unwrap().unwrap();
        assert_eq!(c.pseudonym, [1; 32]);
        assert_eq!(c.display_name.as_deref(), Some("Contact 1"));
        assert!(!c.verified);
        assert!(!c.blocked);
    }

    #[test]
    fn next_outbound_seq_is_monotonic_per_contact() {
        let db = test_db();
        let a = db.create_contact(&make_contact(1)).unwrap();
        let b = db.create_contact(&make_contact(2)).unwrap();
        // First message to a contact is seq 1; counters are independent.
        assert_eq!(db.next_outbound_seq(a).unwrap(), 1);
        assert_eq!(db.next_outbound_seq(a).unwrap(), 2);
        assert_eq!(db.next_outbound_seq(b).unwrap(), 1);
        assert_eq!(db.next_outbound_seq(a).unwrap(), 3);
        assert_eq!(db.next_outbound_seq(b).unwrap(), 2);
    }

    #[test]
    fn get_contact_by_pseudonym() {
        let db = test_db();
        db.create_contact(&make_contact(2)).unwrap();
        let c = db.get_contact_by_pseudonym(&[2; 32]).unwrap().unwrap();
        assert_eq!(c.their_ik_pub, [102; 32]);
    }

    #[test]
    fn get_contact_by_ik() {
        let db = test_db();
        db.create_contact(&make_contact(3)).unwrap();
        let c = db.get_contact_by_ik(&[103; 32]).unwrap().unwrap();
        assert_eq!(c.pseudonym, [3; 32]);
    }

    #[test]
    fn duplicate_pseudonym_fails() {
        let db = test_db();
        db.create_contact(&make_contact(4)).unwrap();
        let err = db.create_contact(&make_contact(4)).unwrap_err();
        assert!(matches!(err, StorageError::AlreadyExists));
    }

    #[test]
    fn list_contacts_returns_all() {
        let db = test_db();
        db.create_contact(&make_contact(1)).unwrap();
        db.create_contact(&make_contact(2)).unwrap();
        db.create_contact(&make_contact(3)).unwrap();
        let all = db.list_contacts().unwrap();
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn update_contact_works() {
        let db = test_db();
        let id = db.create_contact(&make_contact(5)).unwrap();
        let mut c = db.get_contact(id).unwrap().unwrap();
        c.display_name = Some("Updated".into());
        c.verified = true;
        db.update_contact(&c).unwrap();
        let c2 = db.get_contact(id).unwrap().unwrap();
        assert_eq!(c2.display_name.as_deref(), Some("Updated"));
        assert!(c2.verified);
    }

    #[test]
    fn delete_contact_works() {
        let db = test_db();
        let id = db.create_contact(&make_contact(6)).unwrap();
        db.delete_contact(id).unwrap();
        assert!(db.get_contact(id).unwrap().is_none());
    }

    #[test]
    fn delete_nonexistent_fails() {
        let db = test_db();
        let err = db.delete_contact(9999).unwrap_err();
        assert!(matches!(err, StorageError::NotFound));
    }
}
