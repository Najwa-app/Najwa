//! Error types for disappearing messages (S12 §8).

use thiserror::Error;

/// Errors during disappearing message operations.
#[derive(Debug, Error)]
pub enum DisappearError {
    /// Storage operation failed.
    #[error("storage error: {0}")]
    StorageError(String),

    /// I/O error during secure file deletion.
    #[error("io error: {0}")]
    IoError(#[from] std::io::Error),

    /// Timer value invalid.
    #[error("invalid timer value: {0}")]
    InvalidTimer(String),

    /// Ephemeral-key seal/open (XChaCha20-Poly1305) failed — malformed blob or
    /// failed AEAD authentication (S12 §4.1/§4.2).
    #[error("ephemeral crypto error: {0}")]
    CryptoError(String),
}

/// Convenience Result alias.
pub type Result<T> = std::result::Result<T, DisappearError>;
