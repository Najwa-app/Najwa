//! Error types for the `najwa-crypto` crate.

use thiserror::Error;

/// Errors returned by cryptographic operations.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// The supplied key has an invalid length.
    #[error("invalid key length: expected {expected}, got {got}")]
    InvalidKeyLength { expected: usize, got: usize },

    /// The supplied nonce has an invalid length.
    #[error("invalid nonce length: expected {expected}, got {got}")]
    InvalidNonceLength { expected: usize, got: usize },

    /// The supplied salt has an invalid length.
    #[error("invalid salt length: expected {expected}, got {got}")]
    InvalidSaltLength { expected: usize, got: usize },

    /// A public key could not be decoded (not on curve, wrong format).
    #[error("invalid public key")]
    InvalidPublicKey,

    /// A signature could not be decoded.
    #[error("invalid signature")]
    InvalidSignature,

    /// Signature verification failed.
    #[error("signature verification failed")]
    SignatureVerificationFailed,

    /// AEAD encryption failed (internal cipher error).
    #[error("AEAD encryption failed")]
    EncryptionFailed,

    /// AEAD decryption failed (ciphertext tampered or wrong key).
    #[error("AEAD decryption failed")]
    DecryptionFailed,

    /// Argon2id parameter validation failed.
    #[error("invalid Argon2 parameters: {0}")]
    InvalidArgon2Params(String),

    /// Argon2id hashing failed.
    #[error("Argon2 hashing failed: {0}")]
    Argon2Failed(String),

    /// A fallible allocation for Argon2 could not be satisfied.
    #[error("cannot allocate {bytes} bytes for Argon2")]
    Argon2AllocationFailed { bytes: usize },

    /// The operating system entropy source failed or returned all zeros.
    #[error("CSPRNG unavailable or not seeded")]
    EntropyUnavailable,

    /// HKDF expand produced invalid output length.
    #[error("HKDF invalid output length: {0}")]
    HkdfInvalidLength(String),

    /// Memory locking (mlock) failed.
    #[error("mlock failed: {0}")]
    MlockFailed(String),

    /// Memory unlocking (munlock) failed.
    #[error("munlock failed: {0}")]
    MunlockFailed(String),

    /// Core dump disabling failed.
    #[error("failed to disable core dumps: {0}")]
    CoreDumpDisableFailed(String),

    /// Ed25519 → X25519 key conversion failed.
    #[error("key conversion failed: {0}")]
    KeyConversionFailed(String),
}

/// Convenience alias used throughout the crate.
pub type Result<T> = std::result::Result<T, CryptoError>;
