//! Error types for the `najwa-storage` crate.

use thiserror::Error;

/// Errors returned by storage operations.
#[derive(Debug, Error)]
pub enum StorageError {
    /// Record not found.
    #[error("record not found")]
    NotFound,

    /// Record already exists (unique constraint violation).
    #[error("record already exists")]
    AlreadyExists,

    /// Invalid data encountered during deserialization.
    #[error("invalid data: {0}")]
    InvalidData(String),

    /// Schema migration failed.
    #[error("migration failed: {0}")]
    MigrationFailed(String),

    /// Encryption/decryption error for field-level encryption.
    #[error("field encryption error: {0}")]
    FieldEncryption(String),

    /// Database is not open or has been closed.
    #[error("database not open")]
    NotOpen,

    /// WAL file is not encrypted (plaintext SQLite WAL header detected).
    #[error("WAL file is not encrypted")]
    WalNotEncrypted,

    /// SQLite / SQLCipher error.
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),

    /// Cryptographic error from `najwa-crypto`.
    #[error(transparent)]
    Crypto(#[from] najwa_crypto::error::CryptoError),

    /// The new key is installed; callers must not roll identity state back.
    #[error("database rekey committed, but reopening or syncing failed: {0}")]
    RekeyCommitted(String),

    /// I/O error.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// JSON serialization error (for settings).
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

/// Convenience alias used throughout this crate.
pub type Result<T> = std::result::Result<T, StorageError>;
