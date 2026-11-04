//! Ephemeral key volatile cache for disappearing messages (S12 §4).
//!
//! Per-message CSPRNG ephemeral keys encrypt disappearing message content.
//! Keys are held in an in-memory cache during normal operation. On lock,
//! keys are encrypted with db_key and persisted to the `volatile_keys` table.
//! On unlock, keys are restored from the table. On message expiry, the key
//! is zeroized and removed.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

use najwa_crypto::prelude::*;

type EphemeralKeys = HashMap<[u8; 16], Zeroizing<[u8; 32]>>;

/// In-memory cache of ephemeral keys for disappearing messages (S12 §4).
///
/// Keys are never written to disk in plaintext. On lock, they are encrypted
/// with `db_key` and stored in the `volatile_keys` table. On expiry, they
/// are zeroized.
#[derive(Clone)]
pub struct VolatileKeyCache {
    keys: Arc<Mutex<EphemeralKeys>>,
}

impl VolatileKeyCache {
    /// Create a new empty cache.
    pub fn new() -> Self {
        Self {
            keys: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Generate and store a new ephemeral key for a message.
    ///
    /// Returns the generated key for immediate use (encryption).
    pub fn generate_key(&self, msg_id: &[u8; 16]) -> [u8; 32] {
        let key: [u8; 32] = random_bytes();
        self.keys.lock().unwrap().insert(*msg_id, Zeroizing::new(key));
        key
    }

    /// Store an existing key (e.g., after restoring from volatile_keys table).
    pub fn insert_key(&self, msg_id: &[u8; 16], key: [u8; 32]) {
        self.keys.lock().unwrap().insert(*msg_id, Zeroizing::new(key));
    }

    /// Get a key for decryption/re-encryption.
    pub fn get_key(&self, msg_id: &[u8; 16]) -> Option<[u8; 32]> {
        self.keys.lock().unwrap().get(msg_id).map(|key| **key)
    }

    /// Zeroize and remove a key (message expired or was read).
    pub fn remove_key(&self, msg_id: &[u8; 16]) {
        // Zeroizing also covers replacement and the last cache owner's drop.
        self.keys.lock().unwrap().remove(msg_id);
    }

    /// Persist all keys to storage, encrypted with db_key (called on lock).
    ///
    /// Returns `(msg_id, encrypted_key)` pairs for the caller to save
    /// to the `volatile_keys` table.
    pub fn persist_all(&self, db_key: &[u8; 32]) -> Vec<([u8; 16], Vec<u8>)> {
        let keys = self.keys.lock().unwrap();
        let mut result = Vec::with_capacity(keys.len());

        for (msg_id, key) in keys.iter() {
            let nonce: [u8; 24] = random_bytes();
            if let Ok(encrypted) = aead::encrypt(db_key, &nonce, key.as_ref(), b"volatile-key") {
                let mut blob = Vec::with_capacity(24 + encrypted.len());
                blob.extend_from_slice(&nonce);
                blob.extend_from_slice(&encrypted);
                result.push((*msg_id, blob));
            }
        }

        result
    }

    /// Restore keys from encrypted blobs (called on unlock).
    ///
    /// Takes `(msg_id, encrypted_blob)` pairs from the `volatile_keys` table.
    pub fn restore_all(&self, db_key: &[u8; 32], entries: &[([u8; 16], Vec<u8>)]) -> u32 {
        let mut keys = self.keys.lock().unwrap();
        let mut count = 0u32;

        for (msg_id, blob) in entries {
            if blob.len() < 24 {
                continue;
            }
            let mut nonce = [0u8; 24];
            nonce.copy_from_slice(&blob[..24]);
            let ciphertext = &blob[24..];

            if let Ok(plaintext) = aead::decrypt(db_key, &nonce, ciphertext, b"volatile-key") {
                let plaintext = Zeroizing::new(plaintext);
                if plaintext.len() == 32 {
                    let mut key = Zeroizing::new([0u8; 32]);
                    key.copy_from_slice(&plaintext);
                    keys.insert(*msg_id, key);
                    count += 1;
                }
            }
        }

        count
    }

    /// Zeroize all keys in memory (called on lock after persist).
    pub fn zeroize_all(&self) {
        self.keys.lock().unwrap().clear();
    }

    /// Number of keys currently cached.
    pub fn len(&self) -> usize {
        self.keys.lock().unwrap().len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.keys.lock().unwrap().is_empty()
    }
}

impl Default for VolatileKeyCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_and_retrieve_key() {
        let cache = VolatileKeyCache::new();
        let msg_id = [0x01; 16];
        let key = cache.generate_key(&msg_id);
        assert_eq!(cache.get_key(&msg_id), Some(key));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn remove_key_zeroizes() {
        let cache = VolatileKeyCache::new();
        let msg_id = [0x02; 16];
        cache.generate_key(&msg_id);
        cache.remove_key(&msg_id);
        assert!(cache.get_key(&msg_id).is_none());
        assert!(cache.is_empty());
    }

    #[test]
    fn persist_and_restore_roundtrip() {
        let db_key = [0x42u8; 32];
        let cache = VolatileKeyCache::new();

        let msg1 = [0x01; 16];
        let msg2 = [0x02; 16];
        let key1 = cache.generate_key(&msg1);
        let key2 = cache.generate_key(&msg2);

        // Persist
        let entries = cache.persist_all(&db_key);
        assert_eq!(entries.len(), 2);

        // Zeroize
        cache.zeroize_all();
        assert!(cache.is_empty());

        // Restore
        let count = cache.restore_all(&db_key, &entries);
        assert_eq!(count, 2);
        assert_eq!(cache.get_key(&msg1), Some(key1));
        assert_eq!(cache.get_key(&msg2), Some(key2));
    }

    #[test]
    fn persist_to_db_and_restore_reopens_sealed_content() {
        // The exact loop lock/unlock performs (S12 §4): seal → persist_all →
        // save_volatile_key rows → (lock drops the cache) → get_all_volatile_keys
        // → restore_all → the message reopens under the restored key.
        use crate::disappearing::{open_sealed_content, seal_content, Opened};
        use najwa_storage::database::SqliteStorage;

        let db_key = [0x42u8; 32];
        let db = SqliteStorage::open_in_memory(&db_key).unwrap();

        let cache1 = VolatileKeyCache::new();
        let msg_id = [0x09u8; 16];
        let blob = seal_content(&cache1, &msg_id, b"survives lock").unwrap();

        for (id, enc) in cache1.persist_all(&db_key) {
            db.save_volatile_key(&id, &enc, None).unwrap();
        }

        // Lock drops cache1; unlock restores into a fresh cache from the DB.
        let cache2 = VolatileKeyCache::new();
        let rows = db.get_all_volatile_keys().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(cache2.restore_all(&db_key, &rows), 1);

        match open_sealed_content(&cache2, &msg_id, &blob).unwrap() {
            Opened::Plaintext(p) => assert_eq!(p, b"survives lock"),
            Opened::Expired => panic!("restored key must reopen the sealed content"),
        }
    }

    #[test]
    fn restore_with_wrong_key_fails_gracefully() {
        let db_key = [0x42u8; 32];
        let wrong_key = [0xFF; 32];
        let cache = VolatileKeyCache::new();

        cache.generate_key(&[0x01; 16]);
        let entries = cache.persist_all(&db_key);
        cache.zeroize_all();

        // Restore with wrong key — should silently fail
        let count = cache.restore_all(&wrong_key, &entries);
        assert_eq!(count, 0);
        assert!(cache.is_empty());
    }
}
