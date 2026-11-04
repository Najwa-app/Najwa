//! Core messaging error types (S08 §11).

use thiserror::Error;

/// Errors during messaging operations.
#[derive(Debug, Error)]
pub enum MessagingError {
    /// Contact not found.
    #[error("contact not found")]
    ContactNotFound,

    /// Contact is blocked (S08 §7.1).
    #[error("contact is blocked")]
    ContactBlocked,

    /// No mailbox capability for the contact.
    #[error("no mailbox capability for contact")]
    NoMailboxCapability,

    /// No signed prekey available.
    #[error("no signed prekey available")]
    NoSignedPrekey,

    /// Sender pseudonym does not match contact.
    #[error("pseudonym mismatch")]
    PseudonymMismatch,

    /// An introduction's `introducer_ik_pub` does not match the delivering
    /// contact's known identity key (S05 §11). Introductions MUST be attributed
    /// and signature-verified; a mismatch is rejected, never accepted as
    /// "anonymous".
    #[error("introducer IK does not match the delivering contact")]
    IntroducerMismatch,

    /// An introduction failed its structure, expiry or signature check (S05 §11.4).
    #[error("invalid introduction: {0}")]
    InvalidIntroduction(String),

    /// Unknown pseudonym (no matching contact).
    #[error("unknown pseudonym")]
    UnknownPseudonym,

    /// Duplicate message (already processed) (S08 §9.4).
    #[error("duplicate message")]
    DuplicateMessage,

    /// Crossing-Initial tiebreak (S08 §4.3): an incoming Initial collided with our
    /// own un-answered outbound Initial and ours carried the larger `EK_pub`, so we
    /// keep our local session and discard the incoming candidate (the peer, with
    /// the smaller `EK_pub`, adopts ours; both converge). A terminal drop.
    #[error("crossing-Initial tiebreak: keeping local session")]
    KeepLocalSession,

    /// No matching ratchet session for decryption (S08 §4.4).
    #[error("no matching session")]
    NoMatchingSession,

    /// Message timestamp out of tolerance (S08 §6.3).
    #[error("timestamp out of range")]
    TimestampOutOfRange,

    /// Rate limit exceeded (S08 §8).
    #[error("rate limit exceeded, retry after {retry_after_ms}ms")]
    RateLimitExceeded { retry_after_ms: u64 },

    /// Ratchet error.
    #[error("ratchet error: {0}")]
    RatchetError(#[from] najwa_protocol::ratchet::error::RatchetError),

    /// Message format error.
    #[error("message error: {0}")]
    MessageError(#[from] najwa_protocol::message::error::MessageError),

    /// X3DH error.
    #[error("x3dh error: {0}")]
    X3DHError(#[from] najwa_protocol::x3dh::error::X3DHError),

    /// Mailbox error.
    #[error("mailbox error: {0}")]
    MailboxError(#[from] najwa_protocol::mailbox::error::MailboxError),

    /// All mailboxes failed during multi-path delivery (S08 §9.2).
    #[error("all mailboxes failed: {0} attempts")]
    AllMailboxesFailed(usize),

    /// Mailbox disabled. The app never disables a mailbox automatically (S08 §9.3).
    #[error("mailbox {0} disabled")]
    MailboxDisabled(i64),

    /// Storage error.
    #[error("storage error: {0}")]
    StorageError(String),

    /// Serialization error.
    #[error("serialization error: {0}")]
    SerializationError(String),

    /// Internal error (lock poisoning, invariant violation).
    #[error("internal error: {0}")]
    InternalError(String),
}

/// Convenience Result alias.
pub type Result<T> = std::result::Result<T, MessagingError>;
