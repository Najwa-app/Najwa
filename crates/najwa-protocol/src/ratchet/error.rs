//! Double Ratchet error types (S06 §3.12).

use thiserror::Error;

/// Errors that can occur during Double Ratchet operations.
#[derive(Debug, Error)]
pub enum RatchetError {
    /// No sending chain key available (encrypt before first ratchet step).
    #[error("no sending chain key")]
    NoSendingChain,

    /// No receiving chain key available.
    #[error("no receiving chain key")]
    NoReceivingChain,

    /// No DH ratchet public key from the remote peer.
    #[error("no remote DH ratchet key")]
    NoDHR,

    /// Too many skipped messages — exceeds MAX_SKIP limit.
    #[error("too many skipped messages (limit: {limit}, requested: {requested})")]
    TooManySkipped { limit: u32, requested: u32 },

    /// Incoming message's `epoch_link` does not match the receiver's current
    /// `dhr` (S06 §3.5 step 3). The receiver has missed an entire
    /// sending epoch; Layer 2 (session repair) is required.
    #[error("missed epoch boundary")]
    MissedEpochBoundary,

    /// AEAD decryption failed (wrong key or tampered ciphertext).
    #[error("decryption failed")]
    DecryptionFailed,

    /// AEAD encryption failed.
    #[error("encryption failed")]
    EncryptionFailed,

    /// Ratchet state could not be deserialized (corrupted data).
    #[error("corrupted ratchet state")]
    CorruptedState,

    /// Header deserialization failed.
    #[error("invalid header: {0}")]
    InvalidHeader(String),

    /// KDF derivation failed.
    #[error("key derivation failed: {0}")]
    KeyDerivationFailed(String),

    /// Underlying crypto error.
    #[error("crypto error: {0}")]
    CryptoError(#[from] najwa_crypto::error::CryptoError),
}

/// Convenience alias for ratchet results.
pub type Result<T> = std::result::Result<T, RatchetError>;
