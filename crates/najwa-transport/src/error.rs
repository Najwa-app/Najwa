//! Transport error types.

use thiserror::Error;

/// Errors that can occur in the transport layer.
#[derive(Debug, Error)]
pub enum TransportError {
    /// Transport has not been bootstrapped yet.
    #[error("transport not bootstrapped")]
    NotBootstrapped,

    /// Tor bootstrap process failed.
    #[error("bootstrap failed: {0}")]
    BootstrapFailed(String),

    /// Circuit creation or operation failed.
    #[error("circuit failed: {0}")]
    CircuitFailed(String),

    /// URL is not a `.onion` address (S04 §5.4).
    #[error("URL is not a .onion address")]
    NotOnionAddress,

    /// DNS leak detected during self-test (S04 §6).
    #[error("DNS leak detected: a clearnet DNS path is available")]
    DnsLeakDetected,

    /// Connection or operation timed out.
    #[error("connection timed out")]
    Timeout,

    /// Remote host refused the connection.
    #[error("connection refused")]
    ConnectionRefused,

    /// Connection or setup failed with a descriptive message.
    #[error("connection failed: {0}")]
    ConnectionFailed(String),

    /// HTTP-level error from the remote server.
    #[error("HTTP error: {0}")]
    HttpError(String),

    /// Failed to parse an HTTP response.
    #[error("HTTP parse error: {0}")]
    HttpParseError(String),

    /// Generic Tor subsystem error.
    #[error("Tor error: {0}")]
    TorError(String),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Convenience alias for transport results.
pub type Result<T> = std::result::Result<T, TransportError>;
