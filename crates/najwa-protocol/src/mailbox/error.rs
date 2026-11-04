//! Mailbox protocol error types; status mapping per S16 §3.

use thiserror::Error;

use super::types::PowChallenge;

/// Errors that can occur during mailbox protocol operations.
#[derive(Debug, Error)]
pub enum MailboxError {
    /// Underlying transport layer error.
    #[error("transport error: {0}")]
    TransportError(#[from] najwa_transport::error::TransportError),

    /// Server responded with 429 — client is rate-limited.
    #[error("rate limited by mailbox server")]
    RateLimited,

    /// Server requires Proof-of-Work before accepting the request.
    #[error("proof-of-work required")]
    PowRequired(PowChallenge),

    /// PoW solver exceeded the challenge deadline.
    #[error("proof-of-work timed out")]
    PowTimeout,

    /// PoW solver exhausted all possible nonces without finding a solution.
    #[error("proof-of-work exhausted (no solution found)")]
    PowExhausted,

    /// The requested capability was not found on the server.
    #[error("capability not found")]
    CapabilityNotFound,

    /// The mailbox quota has been exceeded.
    #[error("mailbox quota exceeded")]
    QuotaExceeded,

    /// The message exceeds the maximum allowed size.
    #[error("message too large")]
    MessageTooLarge,

    /// Server returned an unexpected HTTP status code.
    #[error("server error: HTTP {0}")]
    ServerError(u16),

    /// Failed to deserialize a server response.
    #[error("deserialization error: {0}")]
    DeserializationError(String),

    /// Onion address pin has changed since first use.
    #[error("onion address pin changed (first seen at {first_seen})")]
    PinChanged {
        /// Unix timestamp when the address was first pinned.
        first_seen: u64,
    },

    /// JSON serialization/deserialization error.
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),
}

/// Convenience alias for mailbox results.
pub type Result<T> = std::result::Result<T, MailboxError>;

/// Retry strategy for mailbox operations.
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum number of retries. Default: 3.
    pub max_retries: u32,
    /// Base delay in milliseconds for exponential backoff. Default: 1000.
    pub base_delay_ms: u64,
    /// Maximum delay in milliseconds. Default: 30000.
    pub max_delay_ms: u64,
    /// Whether to automatically solve PoW challenges and retry. Default: true.
    pub retry_on_pow: bool,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            base_delay_ms: 1000,
            max_delay_ms: 30_000,
            retry_on_pow: true,
        }
    }
}
