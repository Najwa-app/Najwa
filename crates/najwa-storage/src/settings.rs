//! Settings storage, identity history, and onion pinning.
//!
//! Implements S03 §5.16 (settings), S03 §5.14 (identity history) and
//! S03 §5.15 (onion pin) operations.

use rusqlite::params;
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::database::SqliteStorage;
use crate::error::Result;
use crate::types::*;

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

impl SqliteStorage {
    /// Replace both primary and full remote routing coordinates together.
    pub fn replace_remote_targets<T: Serialize>(
        &self,
        contact_id: ContactId,
        targets: &[T],
    ) -> Result<()> {
        let first = targets.first().ok_or_else(|| {
            crate::error::StorageError::InvalidData("empty mailbox update".into())
        })?;
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM contacts WHERE id=?1)",
            params![contact_id],
            |r| r.get(0),
        )?;
        if !exists {
            return Err(crate::error::StorageError::NotFound);
        }
        for (prefix, value) in [
            ("contact_target", serde_json::to_vec(first)?),
            ("contact_targets", serde_json::to_vec(targets)?),
        ] {
            tx.execute(
                "INSERT OR REPLACE INTO settings (key,value,updated_at) VALUES (?1,?2,?3)",
                params![
                    format!("{prefix}:{contact_id}"),
                    value,
                    najwa_crypto::time::now() as i64
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }
    /// Get a setting value, deserialized from JSON.
    pub fn get_setting<T: DeserializeOwned>(&self, key: &str) -> Result<Option<T>> {
        let conn = self.conn();
        let result: std::result::Result<Vec<u8>, _> = conn.query_row(
            "SELECT value FROM settings WHERE key = ?1",
            params![key],
            |row| row.get(0),
        );

        match result {
            Ok(blob) => {
                let value: T = serde_json::from_slice(&blob)?;
                Ok(Some(value))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Get a raw setting value as bytes.
    pub fn get_setting_raw(&self, key: &str) -> Result<Option<Vec<u8>>> {
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

    /// Set a setting value, serialized to JSON.
    pub fn set_setting<T: Serialize>(&self, key: &str, value: &T) -> Result<()> {
        let blob = serde_json::to_vec(value)?;
        let conn = self.conn();
        let now = najwa_crypto::time::now() as i64;
        conn.execute(
            "INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?1, ?2, ?3)",
            params![key, blob, now],
        )?;
        Ok(())
    }

    /// Set a raw setting value as bytes.
    pub fn set_setting_raw(&self, key: &str, value: &[u8]) -> Result<()> {
        let conn = self.conn();
        let now = najwa_crypto::time::now() as i64;
        conn.execute(
            "INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?1, ?2, ?3)",
            params![key, value, now],
        )?;
        Ok(())
    }

    /// Delete a setting.
    pub fn delete_setting(&self, key: &str) -> Result<()> {
        let conn = self.conn();
        conn.execute("DELETE FROM settings WHERE key = ?1", params![key])?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Identity History (S02 §18.1: contact identity rotation)
// ---------------------------------------------------------------------------

impl SqliteStorage {
    /// Save an identity history entry.
    pub fn save_identity_history(&self, entry: &IdentityHistoryEntry) -> Result<()> {
        let conn = self.conn();
        conn.execute(
            "INSERT INTO identity_history (contact_id, old_ik_pub, new_ik_pub, rotated_at, reason)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                entry.contact_id,
                entry.old_ik_pub,
                entry.new_ik_pub,
                entry.rotated_at,
                entry.reason,
            ],
        )?;
        Ok(())
    }

    /// List all identity history entries, newest first.
    pub fn list_identity_history(&self) -> Result<Vec<IdentityHistoryEntry>> {
        let conn = self.conn();
        let mut stmt = conn.prepare_cached(
            "SELECT id, contact_id, old_ik_pub, new_ik_pub, rotated_at, reason
             FROM identity_history ORDER BY rotated_at DESC",
        )?;

        let rows = stmt.query_map([], |row| {
            Ok(IdentityHistoryEntry {
                id: row.get(0)?,
                contact_id: row.get(1)?,
                old_ik_pub: row.get(2)?,
                new_ik_pub: row.get(3)?,
                rotated_at: row.get(4)?,
                reason: row.get(5)?,
            })
        })?;

        let mut entries = Vec::new();
        for r in rows {
            entries.push(r?);
        }
        Ok(entries)
    }
}

// ---------------------------------------------------------------------------
// Onion Pinning (S03 §5.15; the application does not use this table)
// ---------------------------------------------------------------------------

impl SqliteStorage {
    /// Get an onion pin by address.
    pub fn get_onion_pin(&self, onion_address: &str) -> Result<Option<OnionPin>> {
        let conn = self.conn();
        let mut stmt = conn.prepare_cached(
            "SELECT onion_address, expected_key_hash, first_seen, last_verified, pin_count
             FROM onion_pins WHERE onion_address = ?1",
        )?;

        let result = stmt.query_row(params![onion_address], |row| {
            Ok(OnionPin {
                onion_address: row.get(0)?,
                expected_key_hash: row.get(1)?,
                first_seen: row.get(2)?,
                last_verified: row.get(3)?,
                pin_count: row.get(4)?,
            })
        });

        match result {
            Ok(pin) => Ok(Some(pin)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Save or update an onion pin.
    pub fn save_onion_pin(&self, pin: &OnionPin) -> Result<()> {
        let conn = self.conn();
        conn.execute(
            "INSERT OR REPLACE INTO onion_pins
                (onion_address, expected_key_hash, first_seen, last_verified, pin_count)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                pin.onion_address,
                pin.expected_key_hash,
                pin.first_seen,
                pin.last_verified,
                pin.pin_count,
            ],
        )?;
        Ok(())
    }

    /// Update the last_verified timestamp for a pin.
    pub fn update_pin_verified(&self, onion_address: &str, timestamp: u64) -> Result<()> {
        let conn = self.conn();
        conn.execute(
            "UPDATE onion_pins SET last_verified = ?1, pin_count = pin_count + 1
             WHERE onion_address = ?2",
            params![timestamp as i64, onion_address],
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

    #[test]
    fn setting_json_roundtrip() {
        let db = test_db();
        db.set_setting("test_key", &42i32).unwrap();
        let val: Option<i32> = db.get_setting("test_key").unwrap();
        assert_eq!(val, Some(42));
    }

    #[test]
    fn setting_string_roundtrip() {
        let db = test_db();
        db.set_setting("name", &"hello".to_string()).unwrap();
        let val: Option<String> = db.get_setting("name").unwrap();
        assert_eq!(val.as_deref(), Some("hello"));
    }

    #[test]
    fn setting_not_found() {
        let db = test_db();
        let val: Option<i32> = db.get_setting("nonexistent").unwrap();
        assert!(val.is_none());
    }

    #[test]
    fn setting_raw_roundtrip() {
        let db = test_db();
        db.set_setting_raw("raw_key", &[0x01, 0x02, 0x03]).unwrap();
        let val = db.get_setting_raw("raw_key").unwrap().unwrap();
        assert_eq!(val, vec![0x01, 0x02, 0x03]);
    }

    #[test]
    fn identity_history_per_contact_and_cascade() {
        // S03 §5.14: history is per-contact and CASCADE-removed on contact delete.
        let db = test_db();
        let cid = db
            .create_contact(&crate::types::NewContact {
                pseudonym: [0x10; 32],
                their_ik_pub: [0x20; 32],
                their_device_pub: [0x20; 32],
                our_pseudonym: [0x30; 32],
                display_name: Some("Peer".into()),
            })
            .unwrap();

        db.save_identity_history(&IdentityHistoryEntry {
            id: None,
            contact_id: cid,
            old_ik_pub: vec![0xAA; 32],
            new_ik_pub: vec![0xBB; 32],
            rotated_at: 1000,
            reason: Some("rotation".into()),
        })
        .unwrap();
        let history = db.list_identity_history().unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].contact_id, cid);
        assert_eq!(history[0].old_ik_pub, vec![0xAA; 32]);

        // Deleting the contact CASCADE-removes its rotation history.
        db.delete_contact(cid).unwrap();
        assert_eq!(
            db.list_identity_history().unwrap().len(),
            0,
            "history must cascade on contact delete"
        );
    }

    #[test]
    fn onion_pin_roundtrip() {
        let db = test_db();
        let pin = OnionPin {
            onion_address: "test.onion".into(),
            expected_key_hash: vec![0xCC; 32],
            first_seen: 1000,
            last_verified: 1000,
            pin_count: 1,
        };
        db.save_onion_pin(&pin).unwrap();
        let loaded = db.get_onion_pin("test.onion").unwrap().unwrap();
        assert_eq!(loaded.expected_key_hash, vec![0xCC; 32]);
        assert_eq!(loaded.pin_count, 1);
    }

    #[test]
    fn update_pin_verified_works() {
        let db = test_db();
        let pin = OnionPin {
            onion_address: "verify.onion".into(),
            expected_key_hash: vec![0xDD; 32],
            first_seen: 1000,
            last_verified: 1000,
            pin_count: 1,
        };
        db.save_onion_pin(&pin).unwrap();
        db.update_pin_verified("verify.onion", 2000).unwrap();
        let loaded = db.get_onion_pin("verify.onion").unwrap().unwrap();
        assert_eq!(loaded.last_verified, 2000);
        assert_eq!(loaded.pin_count, 2);
    }
}
