//! Prekey management error types (S06 §5).

use thiserror::Error;

/// Errors during prekey lifecycle operations.
#[derive(Debug, Error)]
pub enum PrekeyError {
    /// No current signed prekey found.
    #[error("no current signed prekey available")]
    NoCurrentSpk,

    /// Prekey not found by ID.
    #[error("prekey not found: {0:?}")]
    NotFound([u8; 4]),

    /// Key generation failed.
    #[error("key generation error: {0}")]
    KeyGenError(String),

    /// Signature error.
    #[error("signature error: {0}")]
    SignatureError(String),

    /// Storage operation failed.
    #[error("storage error: {0}")]
    StorageError(String),

    /// Mailbox upload failed.
    #[error("upload error: {0}")]
    UploadError(String),
}

impl From<najwa_crypto::error::CryptoError> for PrekeyError {
    fn from(e: najwa_crypto::error::CryptoError) -> Self {
        Self::KeyGenError(e.to_string())
    }
}

/// Convenience Result alias.
pub type Result<T> = std::result::Result<T, PrekeyError>;
