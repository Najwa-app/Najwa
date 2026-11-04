//! Defense-in-depth field-level encryption within SQLCipher.
//!
//! Implements S03 §7 — per-row encryption for sensitive fields
//! like private keys stored inside the already-encrypted database.

use najwa_crypto::prelude::*;
use zeroize::Zeroizing;

use crate::error::{Result, StorageError};

/// Derive a per-row encryption key for defense-in-depth field encryption.
///
/// `row_key = HKDF-SHA256(ikm=db_key, salt=table_name, info=row_id_bytes, len=32)`
pub fn derive_row_key(
    db_key: &[u8; 32],
    table_name: &str,
    row_id: i64,
) -> Result<Zeroizing<[u8; 32]>> {
    let salt = table_name.as_bytes();
    let info = row_id.to_be_bytes();
    let output = hkdf_sha256(db_key, salt, &info, 32)?;
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&output);
    Ok(key)
}

/// Wrapper for sensitive database fields with an additional encryption layer.
///
/// Format: `nonce (24 bytes) || ciphertext (plaintext + 16-byte tag)`
#[derive(Debug, Clone)]
pub struct EncryptedField {
    pub data: Vec<u8>,
}

impl EncryptedField {
    /// Encrypt sensitive data with a per-row key.
    ///
    /// `row_key` is obtained from `derive_row_key()`.
    pub fn encrypt(plaintext: &[u8], row_key: &[u8; 32]) -> Result<Self> {
        let nonce: [u8; 24] = random_bytes();
        let ciphertext = aead::encrypt(row_key, &nonce, plaintext, b"field")?;

        let mut data = Vec::with_capacity(24 + ciphertext.len());
        data.extend_from_slice(&nonce);
        data.extend_from_slice(&ciphertext);
        Ok(Self { data })
    }

    /// Decrypt sensitive data with a per-row key.
    pub fn decrypt(&self, row_key: &[u8; 32]) -> Result<Zeroizing<Vec<u8>>> {
        if self.data.len() < 24 {
            return Err(StorageError::FieldEncryption(
                "encrypted field too short".into(),
            ));
        }
        let nonce: [u8; 24] = self.data[..24]
            .try_into()
            .map_err(|_| StorageError::FieldEncryption("invalid nonce".into()))?;
        let ciphertext = &self.data[24..];
        let plaintext = aead::decrypt(row_key, &nonce, ciphertext, b"field")?;
        Ok(Zeroizing::new(plaintext))
    }

    /// Create from raw database bytes.
    pub fn from_bytes(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Get the raw bytes for database storage.
    pub fn to_bytes(&self) -> &[u8] {
        &self.data
    }
}

/// Encrypt a sensitive field value for storage (S03 §7).
///
/// Combines `derive_row_key` + `EncryptedField::encrypt` into a single call.
/// Use for all sensitive BLOB columns: ratchet keys, prekey privates, chain keys.
pub fn encrypt_field(
    db_key: &[u8; 32],
    table_name: &str,
    row_id: i64,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let row_key = derive_row_key(db_key, table_name, row_id)?;
    let field = EncryptedField::encrypt(plaintext, &row_key)?;
    Ok(field.data)
}

/// Decrypt a sensitive field value from storage (S03 §7).
///
/// Inverse of `encrypt_field`.
pub fn decrypt_field(
    db_key: &[u8; 32],
    table_name: &str,
    row_id: i64,
    encrypted: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let row_key = derive_row_key(db_key, table_name, row_id)?;
    let field = EncryptedField::from_bytes(encrypted.to_vec());
    field.decrypt(&row_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypted_field_roundtrip() {
        let db_key = [0x42u8; 32];
        let row_key = derive_row_key(&db_key, "ratchet_sessions", 1).unwrap();
        let plaintext = b"secret private key material";

        let field = EncryptedField::encrypt(plaintext, &row_key).unwrap();
        let decrypted = field.decrypt(&row_key).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn encrypted_field_wrong_key_fails() {
        let db_key = [0x42u8; 32];
        let row_key = derive_row_key(&db_key, "ratchet_sessions", 1).unwrap();
        let wrong_key = derive_row_key(&db_key, "ratchet_sessions", 2).unwrap();

        let field = EncryptedField::encrypt(b"secret", &row_key).unwrap();
        assert!(field.decrypt(&wrong_key).is_err());
    }

    #[test]
    fn derive_row_key_unique_per_row() {
        let db_key = [0xAA; 32];
        let k1 = derive_row_key(&db_key, "contacts", 1).unwrap();
        let k2 = derive_row_key(&db_key, "contacts", 2).unwrap();
        assert_ne!(k1, k2);
    }

    #[test]
    fn derive_row_key_unique_per_table() {
        let db_key = [0xAA; 32];
        let k1 = derive_row_key(&db_key, "contacts", 1).unwrap();
        let k2 = derive_row_key(&db_key, "ratchet_sessions", 1).unwrap();
        assert_ne!(k1, k2);
    }
}
