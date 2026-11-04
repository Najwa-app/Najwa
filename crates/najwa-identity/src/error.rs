//! Error types for the `najwa-identity` crate.

use thiserror::Error;

/// Errors returned by identity operations.
#[derive(Debug, Error)]
pub enum IdentityError {
    /// Password is empty.
    #[error("password must not be empty")]
    EmptyPassword,

    /// New passphrase is shorter than the S02 §11.1 minimum (12 characters).
    #[error("password too short: minimum {0} characters")]
    PasswordTooShort(usize),

    /// New passphrase is longer than the S02 §11.1 maximum (1024 bytes).
    #[error("password too long: maximum {0} bytes")]
    PasswordTooLong(usize),

    /// New passphrase is below the S02 §11.1 strength rule. `hint` is zxcvbn's
    /// generic warning; it never contains the input.
    #[error("passphrase is too easy to guess; use a longer phrase of several unrelated words")]
    WeakPassphrase { hint: Option<String> },

    /// Identity record has invalid magic bytes.
    #[error("invalid record magic")]
    InvalidMagic,

    /// Identity record version is unsupported.
    #[error("unsupported record version: {0}")]
    UnsupportedVersion(u8),

    /// Identity record is too short to parse.
    #[error("record too short")]
    RecordTooShort,

    /// Record checksum mismatch.
    #[error("record checksum mismatch")]
    ChecksumMismatch,

    /// Reserved bytes are not `0x000000` (S02 §7.3 / §9.1 — verified on parse).
    #[error("record reserved bytes must be zero")]
    ReservedNotZero,

    /// Decrypted public key doesn't match the stored public key.
    #[error("public key mismatch after decryption")]
    PublicKeyMismatch,

    /// Paper/seed key doesn't match the stored public key.
    #[error("paper key does not match stored identity")]
    PaperKeyMismatch,

    /// Identity already exists at the configured path.
    #[error("identity already exists")]
    AlreadyExists,

    /// No identity record found.
    #[error("no identity record found")]
    NotFound,

    /// Identity is locked (must unlock first).
    #[error("identity is locked")]
    Locked,

    /// Rate limiter: too many failed attempts.
    #[error("too many failed attempts; wait {delay_ms} ms")]
    RateLimited { delay_ms: u64 },

    /// Rate limiter: account locked out after max attempts.
    #[error("account locked out after {0} failed attempts")]
    LockedOut(u32),

    /// Generic unlock failure (S02 §9 — single error for all failure modes).
    #[error("unable to unlock identity")]
    UnlockFailed,

    /// DKM storage operation failed.
    #[error("DKM storage error: {0}")]
    DkmError(String),

    /// Atomic file write failed.
    #[error("atomic write failed: {0}")]
    AtomicWriteFailed(String),

    /// Hardware security module error.
    #[error("hardware module error: {0}")]
    HardwareError(String),

    /// Internal / unexpected error.
    #[error("internal error: {0}")]
    InternalError(String),

    /// No recovery-record sidecar found (S02 §13.2 step 4).
    #[error("no recovery record found — create the identity via create_with_recovery_record, or supply the <record>.recovery file")]
    RecoveryRecordMissing,

    /// Wrapped recovery/backup error (S02 §13). Boxed: `BackupError`
    /// itself can hold an `IdentityError`, so a direct embedding is infinite.
    #[error(transparent)]
    Backup(Box<crate::backup::BackupError>),

    /// Wrapped cryptographic error from `najwa-crypto`.
    #[error(transparent)]
    Crypto(#[from] najwa_crypto::error::CryptoError),

    /// I/O error.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// JNI error (Android only).
    #[cfg(target_os = "android")]
    #[error("JNI error: {0}")]
    Jni(#[from] jni::errors::Error),
}

/// Convenience alias used throughout this crate.
pub type Result<T> = std::result::Result<T, IdentityError>;

impl From<crate::backup::BackupError> for IdentityError {
    fn from(e: crate::backup::BackupError) -> Self {
        IdentityError::Backup(Box::new(e))
    }
}
