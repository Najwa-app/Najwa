//! X3DH error types (S06 §2.7).

use thiserror::Error;

/// Errors that can occur during X3DH key agreement.
#[derive(Debug, Error)]
pub enum X3DHError {
    /// The signed prekey signature is invalid — MUST hard-abort (S06 §2.2 step 1c).
    #[error("invalid SPK signature: possible impersonation")]
    InvalidSignature,

    /// The bundle manifest signature or spk_id binding is invalid (S06 §2.2 1a).
    #[error("invalid bundle manifest: possible tampering")]
    ManifestInvalid,

    /// The signed manifest commits to OPKs (opk_count > 0) but the mailbox served
    /// none — a silent 3-DH-downgrade attempt (S06 §2.2 1b). MUST abort + retry
    /// the fetch on a different mailbox.
    #[error("mailbox withheld OPKs (manifest opk_count > 0, none served)")]
    OpkWithheld,

    /// Ed25519 → X25519 key conversion failed.
    #[error("key conversion failed: {0}")]
    KeyConversionFailed(String),

    /// HKDF derivation failed.
    #[error("key derivation failed: {0}")]
    KeyDerivationFailed(String),

    /// The prekey bundle could not be fetched from the mailbox.
    #[error("bundle fetch failed: {0}")]
    BundleFetchFailed(String),

    /// The signed prekey in the bundle is stale (older than acceptable).
    #[error("stale prekey bundle: SPK age {spk_age_secs}s")]
    StaleBundle {
        /// Age of the signed prekey in seconds.
        spk_age_secs: u64,
    },

    /// Underlying crypto error.
    #[error("crypto error: {0}")]
    CryptoError(#[from] najwa_crypto::error::CryptoError),
}

/// Convenience alias for X3DH results.
pub type Result<T> = std::result::Result<T, X3DHError>;
