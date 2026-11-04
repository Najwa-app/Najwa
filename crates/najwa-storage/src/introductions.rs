//! Pending introduction CRUD operations (S05 §11).
//!
//! Stores received contact introductions awaiting user approval.

use rusqlite::params;

use crate::database::SqliteStorage;
use crate::error::{Result, StorageError};
use crate::types::*;

impl SqliteStorage {
    /// Save a new pending introduction. Returns the row ID.
    ///
    /// Rejects duplicates where `introduced_ik_pub` already has a pending entry.
    pub fn save_pending_introduction(
        &self,
        intro: &NewPendingIntroduction,
    ) -> Result<IntroductionId> {
        let conn = self.conn();

        // Check for existing pending introduction with same introduced IK
        let already: bool = conn.query_row(
            "SELECT COUNT(*) > 0 FROM pending_introductions
             WHERE introduced_ik_pub = ?1 AND status = 0",
            params![intro.introduced_ik_pub.as_slice()],
            |r| r.get(0),
        )?;
        if already {
            return Err(StorageError::AlreadyExists);
        }

        conn.execute(
            "INSERT INTO pending_introductions
                (introducer_contact_id, introduced_ik_pub, introduced_display_name,
                 introducer_ik_pub, payload_blob, is_anonymous, status,
                 created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, ?7, ?8)",
            params![
                intro.introducer_contact_id,
                intro.introduced_ik_pub.as_slice(),
                intro.introduced_display_name,
                intro.introducer_ik_pub.as_slice(),
                intro.payload_blob,
                intro.is_anonymous as i32,
                intro.created_at,
                intro.expires_at,
            ],
        )?;

        Ok(conn.last_insert_rowid())
    }

    /// Get a pending introduction by row ID.
    pub fn get_pending_introduction(
        &self,
        id: IntroductionId,
    ) -> Result<Option<PendingIntroduction>> {
        let conn = self.conn();
        let mut stmt = conn.prepare_cached(
            "SELECT id, introducer_contact_id, introduced_ik_pub, introduced_display_name,
                    introducer_ik_pub, payload_blob, is_anonymous, status,
                    created_at, expires_at, resolved_at
             FROM pending_introductions WHERE id = ?1",
        )?;

        let result = stmt.query_row(params![id], |row| Ok(row_to_introduction(row)));
        match result {
            Ok(i) => Ok(Some(i?)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// List all pending introductions (status = 0), newest first.
    pub fn list_pending_introductions(&self) -> Result<Vec<PendingIntroduction>> {
        let conn = self.conn();
        let mut stmt = conn.prepare_cached(
            "SELECT id, introducer_contact_id, introduced_ik_pub, introduced_display_name,
                    introducer_ik_pub, payload_blob, is_anonymous, status,
                    created_at, expires_at, resolved_at
             FROM pending_introductions WHERE status = 0
             ORDER BY created_at DESC",
        )?;

        let rows = stmt.query_map([], |row| Ok(row_to_introduction(row)))?;
        let mut intros = Vec::new();
        for r in rows {
            intros.push(r??);
        }
        Ok(intros)
    }

    /// List introductions from a specific introducer contact (all statuses).
    pub fn list_introductions_for_contact(
        &self,
        introducer_contact_id: ContactId,
    ) -> Result<Vec<PendingIntroduction>> {
        let conn = self.conn();
        let mut stmt = conn.prepare_cached(
            "SELECT id, introducer_contact_id, introduced_ik_pub, introduced_display_name,
                    introducer_ik_pub, payload_blob, is_anonymous, status,
                    created_at, expires_at, resolved_at
             FROM pending_introductions WHERE introducer_contact_id = ?1
             ORDER BY created_at DESC",
        )?;

        let rows = stmt.query_map(params![introducer_contact_id], |row| {
            Ok(row_to_introduction(row))
        })?;
        let mut intros = Vec::new();
        for r in rows {
            intros.push(r??);
        }
        Ok(intros)
    }

    /// Update the status of a pending introduction.
    pub fn update_introduction_status(
        &self,
        id: IntroductionId,
        status: IntroductionStatus,
    ) -> Result<()> {
        let conn = self.conn();
        let now = najwa_crypto::time::now() as i64;
        let changed = conn.execute(
            "UPDATE pending_introductions SET status = ?1, resolved_at = ?2 WHERE id = ?3",
            params![status as i32, now, id],
        )?;
        if changed == 0 {
            return Err(StorageError::NotFound);
        }
        Ok(())
    }

    /// Count pending introductions (status = 0).
    pub fn count_pending_introductions(&self) -> Result<u32> {
        let conn = self.conn();
        let count: u32 = conn.query_row(
            "SELECT COUNT(*) FROM pending_introductions WHERE status = 0",
            [],
            |r| r.get(0),
        )?;
        Ok(count)
    }

    /// Mark expired introductions as expired. Returns number affected.
    pub fn cleanup_expired_introductions(&self) -> Result<u32> {
        let conn = self.conn();
        let now = najwa_crypto::time::now() as i64;
        let changed = conn.execute(
            "UPDATE pending_introductions SET status = ?1, resolved_at = ?2
             WHERE status = 0 AND expires_at < ?2",
            params![IntroductionStatus::Expired as i32, now],
        )?;
        Ok(changed as u32)
    }
}

/// Extract a PendingIntroduction from a rusqlite Row.
fn row_to_introduction(row: &rusqlite::Row<'_>) -> Result<PendingIntroduction> {
    let ik_blob: Vec<u8> = row.get(2)?;
    let introducer_blob: Vec<u8> = row.get(4)?;

    let mut introduced_ik_pub = [0u8; 32];
    let mut introducer_ik_pub = [0u8; 32];

    if ik_blob.len() == 32 {
        introduced_ik_pub.copy_from_slice(&ik_blob);
    }
    if introducer_blob.len() == 32 {
        introducer_ik_pub.copy_from_slice(&introducer_blob);
    }

    Ok(PendingIntroduction {
        id: row.get(0)?,
        introducer_contact_id: row.get(1)?,
        introduced_ik_pub,
        introduced_display_name: row.get(3)?,
        introducer_ik_pub,
        payload_blob: row.get(5)?,
        is_anonymous: row.get::<_, i32>(6)? != 0,
        status: IntroductionStatus::from_i32(row.get(7)?),
        created_at: row.get(8)?,
        expires_at: row.get(9)?,
        resolved_at: row.get(10)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_db() -> SqliteStorage {
        SqliteStorage::open_in_memory(&[0x42; 32]).unwrap()
    }

    fn setup_introducer(db: &SqliteStorage) -> ContactId {
        db.create_contact(&NewContact {
            pseudonym: [0x01; 32],
            their_ik_pub: [0x11; 32],
            their_device_pub: [0x11; 32],
            our_pseudonym: [0x21; 32],
            display_name: Some("Alice".into()),
        })
        .unwrap()
    }

    fn make_intro(introducer_id: ContactId, n: u8) -> NewPendingIntroduction {
        NewPendingIntroduction {
            introducer_contact_id: introducer_id,
            introduced_ik_pub: [n; 32],
            introduced_display_name: format!("Contact {n}"),
            introducer_ik_pub: [0x11; 32],
            payload_blob: vec![0xAA; 64],
            is_anonymous: false,
            created_at: 1000,
            expires_at: 1000 + 7 * 86400,
        }
    }

    #[test]
    fn save_and_get_introduction() {
        let db = test_db();
        let alice = setup_introducer(&db);
        let intro = make_intro(alice, 0x50);
        let id = db.save_pending_introduction(&intro).unwrap();

        let got = db.get_pending_introduction(id).unwrap().unwrap();
        assert_eq!(got.introduced_display_name, "Contact 80");
        assert_eq!(got.introducer_contact_id, alice);
        assert_eq!(got.status, IntroductionStatus::Pending);
        assert!(!got.is_anonymous);
    }

    #[test]
    fn duplicate_pending_rejected() {
        let db = test_db();
        let alice = setup_introducer(&db);
        let intro = make_intro(alice, 0x60);
        db.save_pending_introduction(&intro).unwrap();
        let err = db.save_pending_introduction(&intro).unwrap_err();
        assert!(matches!(err, StorageError::AlreadyExists));
    }

    #[test]
    fn list_pending_introductions() {
        let db = test_db();
        let alice = setup_introducer(&db);
        db.save_pending_introduction(&make_intro(alice, 0x70))
            .unwrap();
        db.save_pending_introduction(&make_intro(alice, 0x71))
            .unwrap();

        let list = db.list_pending_introductions().unwrap();
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn update_status_to_accepted() {
        let db = test_db();
        let alice = setup_introducer(&db);
        let id = db
            .save_pending_introduction(&make_intro(alice, 0x80))
            .unwrap();

        db.update_introduction_status(id, IntroductionStatus::Accepted)
            .unwrap();
        let got = db.get_pending_introduction(id).unwrap().unwrap();
        assert_eq!(got.status, IntroductionStatus::Accepted);
        assert!(got.resolved_at.is_some());
    }

    #[test]
    fn accepted_not_in_pending_list() {
        let db = test_db();
        let alice = setup_introducer(&db);
        let id = db
            .save_pending_introduction(&make_intro(alice, 0x90))
            .unwrap();
        db.update_introduction_status(id, IntroductionStatus::Accepted)
            .unwrap();

        let list = db.list_pending_introductions().unwrap();
        assert!(list.is_empty());
    }

    #[test]
    fn count_pending() {
        let db = test_db();
        let alice = setup_introducer(&db);
        assert_eq!(db.count_pending_introductions().unwrap(), 0);

        db.save_pending_introduction(&make_intro(alice, 0xA0))
            .unwrap();
        db.save_pending_introduction(&make_intro(alice, 0xA1))
            .unwrap();
        assert_eq!(db.count_pending_introductions().unwrap(), 2);
    }

    #[test]
    fn list_for_contact() {
        let db = test_db();
        let alice = setup_introducer(&db);
        let id = db
            .save_pending_introduction(&make_intro(alice, 0xB0))
            .unwrap();
        db.update_introduction_status(id, IntroductionStatus::Accepted)
            .unwrap();
        db.save_pending_introduction(&make_intro(alice, 0xB1))
            .unwrap();

        // Returns all statuses for this introducer
        let list = db.list_introductions_for_contact(alice).unwrap();
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn cascade_delete_on_contact_removal() {
        let db = test_db();
        let alice = setup_introducer(&db);
        let id = db
            .save_pending_introduction(&make_intro(alice, 0xC0))
            .unwrap();

        db.delete_contact(alice).unwrap();
        assert!(db.get_pending_introduction(id).unwrap().is_none());
    }

    #[test]
    fn get_nonexistent_returns_none() {
        let db = test_db();
        assert!(db.get_pending_introduction(9999).unwrap().is_none());
    }

    #[test]
    fn update_nonexistent_fails() {
        let db = test_db();
        let err = db
            .update_introduction_status(9999, IntroductionStatus::Rejected)
            .unwrap_err();
        assert!(matches!(err, StorageError::NotFound));
    }
}
