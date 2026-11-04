//! Message format error types (S07 §10.1).

use thiserror::Error;

/// Errors that can occur during message operations.
#[derive(Debug, Error)]
pub enum MessageError {
    /// Message is too short to parse.
    #[error("message too short")]
    TooShort,

    /// Message payload is truncated.
    #[error("truncated payload")]
    TruncatedPayload,

    /// Empty or zero-length message.
    #[error("empty message")]
    EmptyMessage,

    /// Invalid padding.
    #[error("invalid padding")]
    InvalidPadding,

    /// Content exceeds maximum allowed size.
    #[error("content too large: {size} bytes (max {max})")]
    ContentTooLarge { size: usize, max: usize },

    /// Unknown message type byte.
    #[error("unknown message type: 0x{0:02x}")]
    UnknownMessageType(u8),

    /// Unknown content type byte.
    #[error("unknown content type: 0x{0:02x}")]
    UnknownContentType(u8),

    /// Unknown control message subtype.
    #[error("unknown control subtype: 0x{0:02x}")]
    UnknownControlSubtype(u8),

    /// A version-dispatched body follows S07 §10 after authentication.
    #[error("unknown nested version at offset {offset}: 0x{value:02x}")]
    UnknownNestedVersion { offset: usize, value: u8 },

    /// Unsupported wire protocol version.
    #[error("unsupported wire version: 0x{0:02x}")]
    UnsupportedVersion(u8),

    /// Timestamp is out of acceptable range.
    #[error("timestamp out of range: {diff}s skew")]
    TimestampOutOfRange { diff: u64 },

    /// Invalid header for the given message type.
    #[error("invalid header: {0}")]
    InvalidHeader(String),

    /// Invalid content in a control message payload.
    #[error("invalid content: {0}")]
    InvalidContent(String),

    /// Slice conversion error.
    #[error("slice conversion error")]
    SliceError,

    /// Payload flags have a reserved bit (3–7) set — MUST be zero (S07 §4.2).
    #[error("invalid payload flags: 0x{0:02x}")]
    InvalidFlags(u8),

    /// Content that must be UTF-8 (e.g. TextReply text) was not valid UTF-8.
    #[error("invalid UTF-8 content")]
    InvalidUtf8,
}

/// Convenience alias for message results.
pub type Result<T> = std::result::Result<T, MessageError>;

impl From<std::array::TryFromSliceError> for MessageError {
    fn from(_: std::array::TryFromSliceError) -> Self {
        Self::SliceError
    }
}
