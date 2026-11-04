//! Atomic S05 contact establishment. Remote destinations are not local mailbox IDs.

use crate::{
    database::SqliteStorage,
    error::{Result, StorageError},
    types::{ContactId, MailboxId, NewContact},
};
use rusqlite::params;
use serde::{Deserialize, Serialize};

/// Fresh local receive credentials; registration is a later, explicit operation.
#[derive(Clone)]
pub struct LocalContactCapability {
    pub mailbox_id: MailboxId,
    pub deposit_capability: [u8; 32],
    pub fetch_capability: [u8; 32],
    pub envelope_secret: [u8; 32],
}

/// Authenticated remote coordinates. JSON field names also serve the core's
/// existing contact_target reader. The complete entry preserves certificate data.
#[derive(Clone, Serialize, Deserialize)]
pub struct ContactTarget {
    pub onion: String,
    #[serde(rename = "deposit_cap_hex", with = "hex32")]
    pub deposit_capability: [u8; 32],
    #[serde(rename = "envelope_secret_hex", with = "hex32")]
    pub envelope_secret: [u8; 32],
    pub mailbox_entry: Vec<u8>,
}

mod hex32 {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(
        value: &[u8; 32],
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use std::fmt::Write;
        let mut text = zeroize::Zeroizing::new(String::with_capacity(64));
        for byte in value {
            write!(text, "{byte:02x}").expect("writing to String");
        }
        serializer.serialize_str(&text)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<[u8; 32], D::Error> {
        let text = zeroize::Zeroizing::new(String::deserialize(deserializer)?);
        if text.len() != 64 || !text.is_ascii() {
            return Err(serde::de::Error::custom("expected 32-byte hex value"));
        }
        let mut bytes = [0; 32];
        for (i, pair) in text.as_bytes().as_chunks::<2>().0.iter().enumerate() {
            bytes[i] = u8::from_str_radix(
                std::str::from_utf8(pair).map_err(serde::de::Error::custom)?,
                16,
            )
            .map_err(serde::de::Error::custom)?;
        }
        Ok(bytes)
    }
}

impl SqliteStorage {
    /// Commit all contact state in one SQLite transaction. Failure (including a
    /// missing local mailbox or duplicate identity) leaves no partial contact,
    /// credentials, or settings. Local credentials remain unregistered.
    pub fn commit_contact_establishment(
        &self,
        contact: &NewContact,
        local_capabilities: &[LocalContactCapability],
        remote_targets: &[ContactTarget],
        signed_handshake: &[u8],
    ) -> Result<ContactId> {
        let primary = remote_targets
            .first()
            .ok_or_else(|| StorageError::InvalidData("missing remote mailbox".into()))?;
        if local_capabilities.is_empty() {
            return Err(StorageError::InvalidData("missing local mailbox".into()));
        }
        let now = najwa_crypto::time::now() as i64;
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        tx.execute(
            "INSERT INTO contacts (pseudonym, their_ik_pub, their_device_pub, our_pseudonym, display_name, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![contact.pseudonym.as_slice(), contact.their_ik_pub.as_slice(), contact.their_device_pub.as_slice(),
                contact.our_pseudonym.as_slice(), contact.display_name, now],
        ).map_err(|e| match e {
            rusqlite::Error::SqliteFailure(ref err, _) if err.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE => StorageError::AlreadyExists,
            other => StorageError::Sqlite(other),
        })?;
        let id = tx.last_insert_rowid();
        for (prefix, blob) in [
            ("contact_target", serde_json::to_vec(primary)?),
            ("contact_targets", serde_json::to_vec(remote_targets)?),
            ("contact_handshake", signed_handshake.to_vec()),
        ] {
            let blob = zeroize::Zeroizing::new(blob);
            tx.execute(
                "INSERT INTO settings (key, value, updated_at) VALUES (?1, ?2, ?3)",
                params![format!("{prefix}:{id}"), blob.as_slice(), now],
            )?;
        }
        for cap in local_capabilities {
            tx.execute(
                "INSERT INTO contact_mailbox_caps
                 (contact_id, mailbox_id, deposit_capability, fetch_capability, their_deposit_capability,
                  their_envelope_secret, envelope_secret, capability_type, expires_at, registered_at, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 2, NULL, NULL, ?8)",
                params![id, cap.mailbox_id, cap.deposit_capability.as_slice(), cap.fetch_capability.as_slice(),
                    primary.deposit_capability.as_slice(), primary.envelope_secret.as_slice(), cap.envelope_secret.as_slice(), now],
            )?;
        }
        tx.commit()?;
        Ok(id)
    }
}
