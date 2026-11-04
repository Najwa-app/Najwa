//! Mailbox configuration and per-contact capabilities storage.
//!
//! Implements S03 §5.9 (mailboxes), S03 §5.10 (contact_mailbox_caps).

use rusqlite::params;

use crate::database::SqliteStorage;
use crate::error::{Result, StorageError};
use crate::types::*;

// ---------------------------------------------------------------------------
// Mailboxes
// ---------------------------------------------------------------------------

impl SqliteStorage {
    /// Save a new mailbox. Returns the new mailbox ID.
    pub fn save_mailbox(&self, mailbox: &NewMailbox) -> Result<MailboxId> {
        let conn = self.conn();
        conn.execute(
            "INSERT INTO mailboxes
                (onion_address, fetch_capability, deposit_capability, envelope_secret,
                 cover_deposit_capability, cover_fetch_capability, cover_envelope_secret,
                 priority, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                mailbox.onion_address,
                mailbox.fetch_capability,
                mailbox.deposit_capability,
                mailbox.envelope_secret,
                mailbox.cover_deposit_capability,
                mailbox.cover_fetch_capability,
                mailbox.cover_envelope_secret,
                mailbox.priority,
                mailbox.created_at,
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

    /// Get a mailbox by ID.
    pub fn get_mailbox(&self, id: MailboxId) -> Result<Option<Mailbox>> {
        let conn = self.conn();
        let mut stmt = conn.prepare_cached(
            "SELECT id, onion_address, fetch_capability, deposit_capability, envelope_secret,
                    cover_deposit_capability, cover_fetch_capability, cover_envelope_secret,
                    cover_registered_at, priority, last_success, last_failure, failure_count, messages_stored,
                    quota_limit, enabled, created_at, last_seen_id
             FROM mailboxes WHERE id = ?1",
        )?;

        let result = stmt.query_row(params![id], |row| Ok(row_to_mailbox(row)));

        match result {
            Ok(m) => Ok(Some(m?)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// List all mailboxes, ordered by priority (highest first).
    pub fn list_mailboxes(&self) -> Result<Vec<Mailbox>> {
        let conn = self.conn();
        let mut stmt = conn.prepare_cached(
            "SELECT id, onion_address, fetch_capability, deposit_capability, envelope_secret,
                    cover_deposit_capability, cover_fetch_capability, cover_envelope_secret,
                    cover_registered_at, priority, last_success, last_failure, failure_count, messages_stored,
                    quota_limit, enabled, created_at, last_seen_id
             FROM mailboxes ORDER BY priority DESC, created_at ASC",
        )?;

        let rows = stmt.query_map([], |row| Ok(row_to_mailbox(row)))?;
        let mut mailboxes = Vec::new();
        for r in rows {
            mailboxes.push(r??);
        }
        Ok(mailboxes)
    }

    /// Update mailbox health after a fetch/deposit attempt.
    pub fn update_mailbox_health(&self, id: MailboxId, success: bool) -> Result<()> {
        let conn = self.conn();
        let now = najwa_crypto::time::now() as i64;
        if success {
            conn.execute(
                "UPDATE mailboxes SET last_success = ?1, failure_count = 0 WHERE id = ?2",
                params![now, id],
            )?;
        } else {
            conn.execute(
                "UPDATE mailboxes SET last_failure = ?1, failure_count = failure_count + 1 WHERE id = ?2",
                params![now, id],
            )?;
        }
        Ok(())
    }

    /// Disable a mailbox (S08 §9.3).
    pub fn disable_mailbox(&self, id: MailboxId) -> Result<()> {
        let conn = self.conn();
        let changed = conn.execute(
            "UPDATE mailboxes SET enabled = 0 WHERE id = ?1",
            params![id],
        )?;
        if changed == 0 {
            return Err(StorageError::NotFound);
        }
        Ok(())
    }

    /// Re-enable a mailbox (set enabled = true, reset failure count).
    pub fn enable_mailbox(&self, id: MailboxId) -> Result<()> {
        let conn = self.conn();
        let changed = conn.execute(
            "UPDATE mailboxes SET enabled = 1, failure_count = 0 WHERE id = ?1",
            params![id],
        )?;
        if changed == 0 {
            return Err(StorageError::NotFound);
        }
        Ok(())
    }

    /// Stamp a cover capability pair as registered on its mailbox server.
    pub fn mark_cover_capabilities_registered(
        &self,
        id: MailboxId,
        registered_at: i64,
    ) -> Result<()> {
        let conn = self.conn();
        let changed = conn.execute(
            "UPDATE mailboxes SET cover_registered_at = ?1 WHERE id = ?2",
            params![registered_at, id],
        )?;
        if changed == 0 {
            return Err(StorageError::NotFound);
        }
        Ok(())
    }

    /// Install a freshly minted dedicated cover capability pair and envelope
    /// secret. Registration is deliberately reset to NULL until the server
    /// accepts the pair.
    pub fn set_cover_capabilities(
        &self,
        id: MailboxId,
        deposit_capability: &[u8; 32],
        fetch_capability: &[u8; 32],
        envelope_secret: &[u8; 32],
    ) -> Result<()> {
        let conn = self.conn();
        let changed = conn.execute(
            "UPDATE mailboxes
             SET cover_deposit_capability = ?1, cover_fetch_capability = ?2,
                 cover_envelope_secret = ?3, cover_registered_at = NULL
             WHERE id = ?4",
            params![deposit_capability, fetch_capability, envelope_secret, id],
        )?;
        if changed == 0 {
            return Err(StorageError::NotFound);
        }
        Ok(())
    }



    /// Delete a mailbox by ID.
    pub fn delete_mailbox(&self, id: MailboxId) -> Result<()> {
        let conn = self.conn();
        let changed = conn.execute("DELETE FROM mailboxes WHERE id = ?1", params![id])?;
        if changed == 0 {
            return Err(StorageError::NotFound);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Contact Mailbox Capabilities
// ---------------------------------------------------------------------------

impl SqliteStorage {
    /// Save a per-contact mailbox capability.
    pub fn save_contact_capability(&self, cap: &NewContactMailboxCap) -> Result<()> {
        let conn = self.conn();
        conn.execute(
            "INSERT OR REPLACE INTO contact_mailbox_caps
                (contact_id, mailbox_id, deposit_capability, fetch_capability,
                 their_deposit_capability, their_envelope_secret, envelope_secret,
                 capability_type, expires_at, registered_at, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                cap.contact_id,
                cap.mailbox_id,
                cap.deposit_capability,
                cap.fetch_capability,
                cap.their_deposit_capability,
                cap.their_envelope_secret,
                cap.envelope_secret,
                cap.capability_type,
                cap.expires_at,
                cap.registered_at,
                cap.created_at,
            ],
        )?;
        Ok(())
    }

    /// Get all capabilities for a contact.
    pub fn get_contact_capabilities(
        &self,
        contact_id: ContactId,
    ) -> Result<Vec<ContactMailboxCap>> {
        let conn = self.conn();
        let mut stmt = conn.prepare_cached(
            "SELECT id, contact_id, mailbox_id, deposit_capability,
                    fetch_capability, their_deposit_capability, their_envelope_secret,
                    envelope_secret, capability_type, expires_at, registered_at,
                    created_at, revoked_at
             FROM contact_mailbox_caps
             WHERE contact_id = ?1 AND revoked_at IS NULL",
        )?;

        let rows = stmt.query_map(params![contact_id], |row| {
            Ok(ContactMailboxCap {
                id: row.get(0)?,
                contact_id: row.get(1)?,
                mailbox_id: row.get(2)?,
                deposit_capability: row.get(3)?,
                fetch_capability: row.get(4)?,
                their_deposit_capability: row.get(5)?,
                their_envelope_secret: row.get(6)?,
                envelope_secret: row.get(7)?,
                capability_type: row.get(8)?,
                expires_at: row.get(9)?,
                registered_at: row.get(10)?,
                created_at: row.get(11)?,
                revoked_at: row.get(12)?,
            })
        })?;

        let mut caps = Vec::new();
        for r in rows {
            caps.push(r?);
        }
        Ok(caps)
    }

    /// Get all capabilities for a specific mailbox (across all contacts).
    ///
    /// Used by the core layer to build the cap_hint → deposit_capability map
    /// for envelope decryption (S07 §3.2).
    pub fn get_capabilities_for_mailbox(
        &self,
        mailbox_id: MailboxId,
    ) -> Result<Vec<ContactMailboxCap>> {
        let conn = self.conn();
        let mut stmt = conn.prepare_cached(
            "SELECT id, contact_id, mailbox_id, deposit_capability,
                    fetch_capability, their_deposit_capability, their_envelope_secret,
                    envelope_secret, capability_type, expires_at, registered_at,
                    created_at, revoked_at
             FROM contact_mailbox_caps
             WHERE mailbox_id = ?1 AND revoked_at IS NULL",
        )?;

        let rows = stmt.query_map(params![mailbox_id], |row| {
            Ok(ContactMailboxCap {
                id: row.get(0)?,
                contact_id: row.get(1)?,
                mailbox_id: row.get(2)?,
                deposit_capability: row.get(3)?,
                fetch_capability: row.get(4)?,
                their_deposit_capability: row.get(5)?,
                their_envelope_secret: row.get(6)?,
                envelope_secret: row.get(7)?,
                capability_type: row.get(8)?,
                expires_at: row.get(9)?,
                registered_at: row.get(10)?,
                created_at: row.get(11)?,
                revoked_at: row.get(12)?,
            })
        })?;

        let mut caps = Vec::new();
        for r in rows {
            caps.push(r?);
        }
        Ok(caps)
    }

    /// Mark a per-contact capability as registered on its mailbox server.
    ///
    /// Until this succeeds, `registered_at` remains NULL and callers must not
    /// advertise the capability (S05 §8 step 10).
    pub fn mark_contact_capability_registered(
        &self,
        capability_id: i64,
        registered_at: i64,
    ) -> Result<()> {
        let conn = self.conn();
        let changed = conn.execute(
            "UPDATE contact_mailbox_caps SET registered_at = ?1
             WHERE id = ?2 AND revoked_at IS NULL",
            params![registered_at, capability_id],
        )?;
        if changed == 0 {
            return Err(StorageError::NotFound);
        }
        Ok(())
    }

    /// Revoke a contact's capability for a specific mailbox.
    pub fn revoke_contact_capability(
        &self,
        contact_id: ContactId,
        mailbox_id: MailboxId,
    ) -> Result<()> {
        let conn = self.conn();
        let now = najwa_crypto::time::now() as i64;
        conn.execute(
            "UPDATE contact_mailbox_caps SET revoked_at = ?1
             WHERE contact_id = ?2 AND mailbox_id = ?3 AND revoked_at IS NULL",
            params![now, contact_id, mailbox_id],
        )?;
        Ok(())
    }

    /// Persist a freshly minted pre-contact capability with `registered_at`
    /// deliberately NULL. The caller may advertise it only after the server
    /// registration succeeds and [`mark_ephemeral_handshake_cap_registered`]
    /// stamps the row.
    pub fn save_ephemeral_handshake_cap(&self, cap: &NewEphemeralHandshakeCap) -> Result<i64> {
        let conn = self.conn();
        conn.execute(
            "INSERT INTO ephemeral_handshake_caps
                (mailbox_id, deposit_capability, fetch_capability, envelope_secret,
                 capability_type, expires_at, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                cap.mailbox_id,
                cap.deposit_capability,
                cap.fetch_capability,
                cap.envelope_secret,
                cap.capability_type,
                cap.expires_at,
                cap.created_at,
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// Load one ephemeral capability by its local row id.
    pub fn get_ephemeral_handshake_cap(
        &self,
        capability_id: i64,
    ) -> Result<Option<EphemeralHandshakeCap>> {
        let conn = self.conn();
        let result = conn.query_row(
            "SELECT id, mailbox_id, deposit_capability, fetch_capability,
                    envelope_secret, capability_type, expires_at, registered_at,
                    accepted_at, deactivated_at, created_at
             FROM ephemeral_handshake_caps WHERE id = ?1",
            params![capability_id],
            row_to_ephemeral_handshake_cap,
        );
        match result {
            Ok(cap) => Ok(Some(cap)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    /// List registered, unexpired, not-yet-deactivated handshake receive queues.
    pub fn get_active_ephemeral_handshake_caps_for_mailbox(
        &self,
        mailbox_id: MailboxId,
        now: i64,
    ) -> Result<Vec<EphemeralHandshakeCap>> {
        let conn = self.conn();
        let mut stmt = conn.prepare_cached(
            "SELECT id, mailbox_id, deposit_capability, fetch_capability,
                    envelope_secret, capability_type, expires_at, registered_at,
                    accepted_at, deactivated_at, created_at
             FROM ephemeral_handshake_caps
             WHERE mailbox_id = ?1
               AND registered_at IS NOT NULL
               AND expires_at > ?2
               AND deactivated_at IS NULL
             ORDER BY id",
        )?;
        let rows = stmt.query_map(params![mailbox_id, now], row_to_ephemeral_handshake_cap)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    /// Stamp successful server registration. A NULL `registered_at` is the
    /// load-bearing advertisement gate shared with per-contact capabilities.
    pub fn mark_ephemeral_handshake_cap_registered(
        &self,
        capability_id: i64,
        registered_at: i64,
    ) -> Result<()> {
        let conn = self.conn();
        let changed = conn.execute(
            "UPDATE ephemeral_handshake_caps SET registered_at = ?1
             WHERE id = ?2 AND registered_at IS NULL AND deactivated_at IS NULL",
            params![registered_at, capability_id],
        )?;
        if changed == 0 {
            return Err(StorageError::NotFound);
        }
        Ok(())
    }

    /// Consume the slot locally after a valid X3DH Initial. Production receive
    /// uses the transaction in `commit_initial_received`; this standalone form
    /// supports the core trait's sequential default implementation.
    pub fn mark_ephemeral_handshake_cap_accepted(
        &self,
        capability_id: i64,
        accepted_at: i64,
    ) -> Result<()> {
        let conn = self.conn();
        let changed = conn.execute(
            "UPDATE ephemeral_handshake_caps SET accepted_at = ?1
             WHERE id = ?2 AND registered_at IS NOT NULL
               AND accepted_at IS NULL AND deactivated_at IS NULL",
            params![accepted_at, capability_id],
        )?;
        if changed == 0 {
            return Err(StorageError::NotFound);
        }
        Ok(())
    }

    /// Mark server-side deactivation after using the FETCH capability endpoint.
    pub fn mark_ephemeral_handshake_cap_deactivated(
        &self,
        capability_id: i64,
        deactivated_at: i64,
    ) -> Result<()> {
        let conn = self.conn();
        let changed = conn.execute(
            "UPDATE ephemeral_handshake_caps SET deactivated_at = ?1
             WHERE id = ?2 AND accepted_at IS NOT NULL AND deactivated_at IS NULL",
            params![deactivated_at, capability_id],
        )?;
        if changed == 0 {
            return Err(StorageError::NotFound);
        }
        Ok(())
    }

    /// Persist a self-generated dummy pair before registering it (S08 §6.1.1).
    pub fn save_dummy_capability(
        &self,
        mailbox_id: MailboxId,
        fetch_capability: &[u8; 32],
        deposit_capability: &[u8; 32],
    ) -> Result<i64> {
        let conn = self.conn();
        conn.execute(
            "INSERT INTO dummy_capabilities (mailbox_id, fetch_capability, deposit_capability)
             VALUES (?1, ?2, ?3)",
            params![mailbox_id, fetch_capability, deposit_capability],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// A mailbox's dummy pairs in creation order, which is their pool order.
    pub fn list_dummy_capabilities(&self, mailbox_id: MailboxId) -> Result<Vec<DummyCapability>> {
        let conn = self.conn();
        let mut stmt = conn.prepare_cached(
            "SELECT id, mailbox_id, fetch_capability, deposit_capability, registered_at
             FROM dummy_capabilities WHERE mailbox_id = ?1 ORDER BY id",
        )?;
        let rows = stmt.query_map(params![mailbox_id], |row| {
            Ok(DummyCapability {
                id: row.get(0)?,
                mailbox_id: row.get(1)?,
                fetch_capability: row.get(2)?,
                deposit_capability: row.get(3)?,
                registered_at: row.get(4)?,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    /// Stamp a dummy pair as accepted by its mailbox server.
    pub fn mark_dummy_capability_registered(&self, id: i64, registered_at: i64) -> Result<()> {
        let conn = self.conn();
        let changed = conn.execute(
            "UPDATE dummy_capabilities SET registered_at = ?1 WHERE id = ?2",
            params![registered_at, id],
        )?;
        if changed == 0 {
            return Err(StorageError::NotFound);
        }
        Ok(())
    }
}

fn row_to_ephemeral_handshake_cap(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<EphemeralHandshakeCap> {
    Ok(EphemeralHandshakeCap {
        id: row.get(0)?,
        mailbox_id: row.get(1)?,
        deposit_capability: row.get(2)?,
        fetch_capability: row.get(3)?,
        envelope_secret: row.get(4)?,
        capability_type: row.get(5)?,
        expires_at: row.get(6)?,
        registered_at: row.get(7)?,
        accepted_at: row.get(8)?,
        deactivated_at: row.get(9)?,
        created_at: row.get(10)?,
    })
}

/// Extract a Mailbox from a rusqlite Row.
/// Column order must match SELECT: id, onion_address, fetch_capability,
/// deposit_capability, envelope_secret, cover_deposit_capability,
/// cover_fetch_capability, cover_envelope_secret, cover_registered_at, priority, last_success,
/// last_failure, failure_count, messages_stored, quota_limit, enabled,
/// created_at, last_seen_id
fn row_to_mailbox(row: &rusqlite::Row<'_>) -> Result<Mailbox> {
    Ok(Mailbox {
        id: row.get(0)?,
        onion_address: row.get(1)?,
        fetch_capability: row.get(2)?,
        deposit_capability: row.get(3)?,
        // NULL for rows created before the D3 migration → empty.
        envelope_secret: row.get::<_, Option<Vec<u8>>>(4)?.unwrap_or_default(),
        cover_deposit_capability: row.get(5)?,
        cover_fetch_capability: row.get(6)?,
        cover_envelope_secret: row.get(7)?,
        cover_registered_at: row.get(8)?,
        priority: row.get(9)?,
        last_success: row.get(10)?,
        last_failure: row.get(11)?,
        failure_count: row.get(12)?,
        messages_stored: row.get(13)?,
        quota_limit: row.get(14)?,
        enabled: row.get::<_, i32>(15)? != 0,
        created_at: row.get(16)?,
        last_seen_id: row.get(17)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_db() -> SqliteStorage {
        SqliteStorage::open_in_memory(&[0x42; 32]).unwrap()
    }

    fn make_mailbox(n: u8) -> NewMailbox {
        NewMailbox {
            onion_address: format!("test{n}.onion"),
            fetch_capability: vec![n; 32],
            deposit_capability: vec![n + 100; 32],
            envelope_secret: vec![n + 50; 32],
            cover_fetch_capability: None,
            cover_deposit_capability: None,
            cover_envelope_secret: Some(vec![n + 60; 32]),
            priority: 1,
            created_at: 1000,
        }
    }

    #[test]
    fn mailbox_roundtrip() {
        let db = test_db();
        let id = db.save_mailbox(&make_mailbox(1)).unwrap();
        let mb = db.get_mailbox(id).unwrap().unwrap();
        assert_eq!(mb.onion_address, "test1.onion");
        assert!(mb.enabled);
        assert_eq!(mb.failure_count, 0);
        // S10 §5: cover envelope secret round-trips.
        assert_eq!(mb.cover_envelope_secret, Some(vec![61; 32]));
        assert_eq!(mb.cover_registered_at, None);
    }

    #[test]
    fn cover_registration_stamp_roundtrips() {
        let db = test_db();
        let id = db.save_mailbox(&make_mailbox(9)).unwrap();
        db.mark_cover_capabilities_registered(id, 1_234).unwrap();
        assert_eq!(
            db.get_mailbox(id).unwrap().unwrap().cover_registered_at,
            Some(1_234)
        );
    }

    #[test]
    fn setting_cover_caps_clears_registration_stamp() {
        let db = test_db();
        let id = db.save_mailbox(&make_mailbox(10)).unwrap();
        db.mark_cover_capabilities_registered(id, 1_234).unwrap();
        db.set_cover_capabilities(id, &[0xA1; 32], &[0xA2; 32], &[0xA3; 32])
            .unwrap();
        let mailbox = db.get_mailbox(id).unwrap().unwrap();
        assert_eq!(mailbox.cover_deposit_capability, Some(vec![0xA1; 32]));
        assert_eq!(mailbox.cover_fetch_capability, Some(vec![0xA2; 32]));
        assert_eq!(mailbox.cover_envelope_secret, Some(vec![0xA3; 32]));
        assert_eq!(mailbox.cover_registered_at, None);
    }

    #[test]
    fn list_mailboxes_works() {
        let db = test_db();
        db.save_mailbox(&make_mailbox(1)).unwrap();
        db.save_mailbox(&make_mailbox(2)).unwrap();
        let all = db.list_mailboxes().unwrap();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn ephemeral_handshake_cap_registration_and_lifecycle_gates() {
        let db = test_db();
        let mailbox_id = db.save_mailbox(&make_mailbox(12)).unwrap();
        let id = db
            .save_ephemeral_handshake_cap(&NewEphemeralHandshakeCap {
                mailbox_id,
                deposit_capability: vec![0xA1; 32],
                fetch_capability: vec![0xA2; 32],
                envelope_secret: vec![0xA3; 32],
                capability_type: 1,
                created_at: 1_000,
                expires_at: 1_900,
            })
            .unwrap();

        assert!(db
            .get_active_ephemeral_handshake_caps_for_mailbox(mailbox_id, 1_001)
            .unwrap()
            .is_empty());
        db.mark_ephemeral_handshake_cap_registered(id, 1_002)
            .unwrap();
        let active = db
            .get_active_ephemeral_handshake_caps_for_mailbox(mailbox_id, 1_003)
            .unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].fetch_capability, vec![0xA2; 32]);
        assert_eq!(active[0].envelope_secret, vec![0xA3; 32]);
        assert!(db
            .get_active_ephemeral_handshake_caps_for_mailbox(mailbox_id, 1_900)
            .unwrap()
            .is_empty());

        db.mark_ephemeral_handshake_cap_accepted(id, 1_100).unwrap();
        db.mark_ephemeral_handshake_cap_deactivated(id, 1_101)
            .unwrap();
        assert!(db
            .get_active_ephemeral_handshake_caps_for_mailbox(mailbox_id, 1_200)
            .unwrap()
            .is_empty());
        let stored = db.get_ephemeral_handshake_cap(id).unwrap().unwrap();
        assert_eq!(stored.accepted_at, Some(1_100));
        assert_eq!(stored.deactivated_at, Some(1_101));
    }

    #[test]
    fn ephemeral_handshake_caps_require_fresh_fetch_deposit_and_secret() {
        let db = test_db();
        let mailbox_id = db.save_mailbox(&make_mailbox(13)).unwrap();
        let make = |byte| NewEphemeralHandshakeCap {
            mailbox_id,
            deposit_capability: vec![byte; 32],
            fetch_capability: vec![byte.wrapping_add(1); 32],
            envelope_secret: vec![byte.wrapping_add(2); 32],
            capability_type: 1,
            created_at: 1_000,
            expires_at: 1_900,
        };
        let original = make(0x20);
        db.save_ephemeral_handshake_cap(&original).unwrap();

        let mut duplicate_deposit = make(0x30);
        duplicate_deposit.deposit_capability = original.deposit_capability.clone();
        assert!(db.save_ephemeral_handshake_cap(&duplicate_deposit).is_err());

        let mut duplicate_fetch = make(0x40);
        duplicate_fetch.fetch_capability = original.fetch_capability.clone();
        assert!(db.save_ephemeral_handshake_cap(&duplicate_fetch).is_err());

        let mut duplicate_secret = make(0x50);
        duplicate_secret.envelope_secret = original.envelope_secret;
        assert!(db.save_ephemeral_handshake_cap(&duplicate_secret).is_err());

        db.save_ephemeral_handshake_cap(&make(0x60)).unwrap();
    }

    #[test]
    fn update_mailbox_health_success() {
        let db = test_db();
        let id = db.save_mailbox(&make_mailbox(3)).unwrap();
        db.update_mailbox_health(id, true).unwrap();
        let mb = db.get_mailbox(id).unwrap().unwrap();
        assert!(mb.last_success.is_some());
        assert_eq!(mb.failure_count, 0);
    }

    #[test]
    fn update_mailbox_health_failure() {
        let db = test_db();
        let id = db.save_mailbox(&make_mailbox(4)).unwrap();
        db.update_mailbox_health(id, false).unwrap();
        db.update_mailbox_health(id, false).unwrap();
        let mb = db.get_mailbox(id).unwrap().unwrap();
        assert_eq!(mb.failure_count, 2);
    }

    #[test]
    fn disable_mailbox_works() {
        let db = test_db();
        let id = db.save_mailbox(&make_mailbox(5)).unwrap();
        db.disable_mailbox(id).unwrap();
        let mb = db.get_mailbox(id).unwrap().unwrap();
        assert!(!mb.enabled);
    }

    #[test]
    fn contact_capability_roundtrip() {
        let db = test_db();

        // Create contact and mailbox first
        let cid = db
            .create_contact(&NewContact {
                pseudonym: [0x50; 32],
                their_ik_pub: [0x51; 32],
                their_device_pub: [0x51; 32],
                our_pseudonym: [0x52; 32],
                display_name: None,
            })
            .unwrap();
        let mid = db.save_mailbox(&make_mailbox(6)).unwrap();

        let cap = NewContactMailboxCap {
            contact_id: cid,
            mailbox_id: mid,
            deposit_capability: vec![0xAA; 32],
            fetch_capability: Some(vec![0xDD; 32]),
            their_deposit_capability: Some(vec![0xBB; 32]),
            their_envelope_secret: Some(vec![0xEE; 32]),
            envelope_secret: Some(vec![0x77; 32]),
            capability_type: 2,
            expires_at: None,
            registered_at: None,
            created_at: 2000,
        };
        db.save_contact_capability(&cap).unwrap();

        let caps = db.get_contact_capabilities(cid).unwrap();
        assert_eq!(caps.len(), 1);
        assert_eq!(caps[0].deposit_capability, vec![0xAA; 32]);
        assert_eq!(caps[0].their_envelope_secret, Some(vec![0xEE; 32]));
        // S05 §8 step 10: OUR envelope secret round-trips too — without it a
        // per-contact deposit cap can be minted but never actually used, since
        // the contact would have no key to envelope-encrypt with.
        assert_eq!(caps[0].envelope_secret, Some(vec![0x77; 32]));
        assert_eq!(caps[0].capability_type, 2);
        assert!(
            caps[0].registered_at.is_none(),
            "a cap that was never registered must not claim to be"
        );

        db.mark_contact_capability_registered(caps[0].id, 2_100)
            .unwrap();
        let registered = db.get_contact_capabilities(cid).unwrap();
        assert_eq!(registered[0].registered_at, Some(2_100));
    }

    // S05 §8 step 10: the whole point of per-contact capabilities is that two
    // contacts must NOT share a deposit cap — a shared one lets the mailbox
    // operator group a user's contacts. This pins that the storage layer keeps
    // them distinct per contact rather than collapsing them.
    #[test]
    fn per_contact_caps_are_distinct_across_contacts() {
        let db = test_db();
        let mid = db.save_mailbox(&make_mailbox(9)).unwrap();

        let mut deposit_caps = Vec::new();
        for n in 0..3u8 {
            let cid = db
                .create_contact(&NewContact {
                    pseudonym: [0x70 + n; 32],
                    their_ik_pub: [0x80 + n; 32],
                    their_device_pub: [0x80 + n; 32],
                    our_pseudonym: [0x90 + n; 32],
                    display_name: None,
                })
                .unwrap();
            let dep = najwa_crypto::random::random_bytes_vec(32);
            db.save_contact_capability(&NewContactMailboxCap {
                contact_id: cid,
                mailbox_id: mid,
                deposit_capability: dep.clone(),
                fetch_capability: Some(najwa_crypto::random::random_bytes_vec(32)),
                their_deposit_capability: None,
                their_envelope_secret: None,
                envelope_secret: Some(najwa_crypto::random::random_bytes_vec(32)),
                capability_type: 2,
                expires_at: None,
                registered_at: None,
                created_at: 1000,
            })
            .unwrap();
            deposit_caps.push(dep);
        }

        // All three distinct, and none is the all-zero placeholder the FFI
        // used to store for every contact.
        let unique: std::collections::HashSet<_> = deposit_caps.iter().collect();
        assert_eq!(unique.len(), 3, "contacts must not share a deposit cap");
        for cap in &deposit_caps {
            assert_ne!(cap, &vec![0u8; 32], "placeholder cap must not be stored");
        }

        // And the mailbox-wide view returns one row per contact.
        let for_mailbox = db.get_capabilities_for_mailbox(mid).unwrap();
        assert_eq!(for_mailbox.len(), 3);
    }

    #[test]
    fn revoke_capability_works() {
        let db = test_db();
        let cid = db
            .create_contact(&NewContact {
                pseudonym: [0x60; 32],
                their_ik_pub: [0x61; 32],
                their_device_pub: [0x61; 32],
                our_pseudonym: [0x62; 32],
                display_name: None,
            })
            .unwrap();
        let mid = db.save_mailbox(&make_mailbox(7)).unwrap();

        db.save_contact_capability(&NewContactMailboxCap {
            contact_id: cid,
            mailbox_id: mid,
            deposit_capability: vec![0xCC; 32],
            fetch_capability: None,
            their_deposit_capability: None,
            their_envelope_secret: None,
            envelope_secret: Some(vec![0x77; 32]),
            capability_type: 2,
            expires_at: None,
            registered_at: None,
            created_at: 3000,
        })
        .unwrap();

        db.revoke_contact_capability(cid, mid).unwrap();
        // Active (non-revoked) should be empty
        let caps = db.get_contact_capabilities(cid).unwrap();
        assert_eq!(caps.len(), 0);
    }
}
