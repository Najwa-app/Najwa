//! Pseudonym error types (§9).

use thiserror::Error;

/// Errors that can occur during pseudonym operations.
#[derive(Debug, Error)]
pub enum PseudonymError {
    /// Ed25519 → X25519 key conversion failed.
    #[error("key conversion failed: {0}")]
    KeyConversionFailed(String),

    /// HKDF key derivation failed.
    #[error("key derivation failed: {0}")]
    KeyDerivationFailed(String),

    /// Pseudonym not found in lookup table.
    #[error("unknown pseudonym")]
    UnknownPseudonym,

    /// Underlying crypto error.
    #[error("crypto error: {0}")]
    CryptoError(String),
}

/// Convenience alias for pseudonym results.
pub type Result<T> = std::result::Result<T, PseudonymError>;

impl From<najwa_crypto::error::CryptoError> for PseudonymError {
    fn from(e: najwa_crypto::error::CryptoError) -> Self {
        Self::CryptoError(e.to_string())
    }
}
