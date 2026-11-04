//! FFI error codes (S17 §2).
//!
//! This enum is the implementation of record for S17 §2
//! (docs/specs/17-ffi-bindings.md). The hand-maintained C header
//! (include/najwa.h, S17 §6) carries the matching `NAJWA_*` macros.
//!
//! Negative codes are argument/lifecycle errors; positive codes are domain
//! errors carried by the same `i32` return.

/// Every FFI error the thin surface can return (S17 §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum FfiErrorCode {
    Success = 0,
    NullPointer = -1,
    InvalidUtf8 = -2,
    NotInitialized = -3,
    AlreadyInitialized = -4,
    InternalError = -5,
    Panic = -99,

    ContactNotFound = 1,
    ContactBlocked = 2,
    NoMailboxCapability = 3,
    NoSignedPrekey = 4,
    PseudonymMismatch = 5,
    UnknownPseudonym = 6,
    DuplicateMessage = 7,
    NoMatchingSession = 8,
    TimestampOutOfRange = 9,
    RateLimitExceeded = 10,
    RatchetError = 11,
    MessageError = 12,
    X3DHError = 13,
    MailboxError = 14,
    StorageError = 15,
    SerializationError = 16,
    TransportError = 17,
    IdentityError = 18,
    CryptoError = 19,
    FileTransferError = 20,
    SanitizeError = 21,
    GroupError = 22,
    /// A new passphrase fails the S02 §11.1 length or strength rule.
    WeakPassphrase = 23,
}

impl FfiErrorCode {
    pub fn as_i32(self) -> i32 {
        self as i32
    }
}

/// Map a core messaging error onto the S17 §2 table (one mapping, shared —
/// `najwa_core::error_to_ffi_code` delegates here so the two can never drift).
pub fn code_from_messaging(err: &najwa_core::error::MessagingError) -> i32 {
    use najwa_core::error::MessagingError as E;
    match err {
        E::ContactNotFound => FfiErrorCode::ContactNotFound,
        E::ContactBlocked => FfiErrorCode::ContactBlocked,
        E::NoMailboxCapability => FfiErrorCode::NoMailboxCapability,
        E::NoSignedPrekey => FfiErrorCode::NoSignedPrekey,
        E::PseudonymMismatch => FfiErrorCode::PseudonymMismatch,
        E::UnknownPseudonym => FfiErrorCode::UnknownPseudonym,
        E::DuplicateMessage => FfiErrorCode::DuplicateMessage,
        E::NoMatchingSession => FfiErrorCode::NoMatchingSession,
        E::TimestampOutOfRange => FfiErrorCode::TimestampOutOfRange,
        E::RateLimitExceeded { .. } => FfiErrorCode::RateLimitExceeded,
        E::RatchetError(_) => FfiErrorCode::RatchetError,
        E::MessageError(_) => FfiErrorCode::MessageError,
        E::X3DHError(_) => FfiErrorCode::X3DHError,
        E::MailboxError(_) => FfiErrorCode::MailboxError,
        E::StorageError(_) => FfiErrorCode::StorageError,
        E::SerializationError(_) => FfiErrorCode::SerializationError,
        // Failure on every mailbox of a contact, or a disabled mailbox, maps
        // to a mailbox error; MessagingError has no transport variant.
        E::AllMailboxesFailed(_) | E::MailboxDisabled(_) => FfiErrorCode::MailboxError,
        E::IntroducerMismatch
        | E::InvalidIntroduction(_)
        | E::KeepLocalSession
        | E::InternalError(_) => {
            FfiErrorCode::InternalError
        }
    }
    .as_i32()
}
