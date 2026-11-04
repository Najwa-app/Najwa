//! Contact establishment error types (S05 §13).

use thiserror::Error;

/// Errors during handshake payload operations.
#[derive(Debug, Error)]
pub enum HandshakeError {
    /// Payload has expired.
    #[error("handshake payload expired")]
    Expired,

    /// Payload format is invalid (bad prefix, truncated, etc.).
    #[error("invalid handshake format: {0}")]
    InvalidFormat(String),

    /// Signature verification failed.
    #[error("invalid signature: {0}")]
    InvalidSignature(String),

    /// SPK signature verification failed.
    #[error("invalid SPK signature: {0}")]
    InvalidSpkSignature(String),

    /// Payload version is unsupported.
    #[error("unsupported payload version: {0}")]
    UnsupportedVersion(u8),

    /// Compression failed.
    #[error("compression failed: {0}")]
    CompressionFailed(String),

    /// Decompression failed.
    #[error("decompression failed: {0}")]
    DecompressionFailed(String),

    /// Base45 decoding error.
    #[error("base45 decode error: {0}")]
    Base45DecodeError(String),

    /// Base64URL decoding error.
    #[error("base64url decode error: {0}")]
    Base64DecodeError(String),

    /// Underlying crypto error.
    #[error("crypto error: {0}")]
    CryptoError(String),
}

/// Errors during contact acceptance flow.
#[derive(Debug, Error)]
pub enum ContactError {
    /// Contact already exists.
    #[error("contact already exists")]
    AlreadyExists,

    /// Handshake verification failed.
    #[error("handshake error: {0}")]
    HandshakeError(#[from] HandshakeError),

    /// Pseudonym derivation failed.
    #[error("pseudonym error: {0}")]
    PseudonymError(String),

    /// Storage operation failed.
    #[error("storage error: {0}")]
    StorageError(String),

    /// Mailbox operation failed.
    #[error("mailbox error: {0}")]
    MailboxError(String),
}

impl From<najwa_crypto::error::CryptoError> for HandshakeError {
    fn from(e: najwa_crypto::error::CryptoError) -> Self {
        Self::CryptoError(e.to_string())
    }
}

impl From<crate::pseudonym::PseudonymError> for ContactError {
    fn from(e: crate::pseudonym::PseudonymError) -> Self {
        Self::PseudonymError(e.to_string())
    }
}
