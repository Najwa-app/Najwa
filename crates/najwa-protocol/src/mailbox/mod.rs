//! Mailbox protocol client (S16).
//!
//! Implements the client-side mailbox protocol for communicating with
//! store-and-forward mailbox servers via Tor onion services.
//!
//! - Capability registration
//! - Message deposit and fetch
//! - Prekey bundle upload/fetch
//! - Proof-of-Work computation for anti-spam
//! - Onion address pinning (trust-on-first-use)
//! - Retry logic with exponential backoff

pub mod client;
pub mod error;
pub mod http;
pub mod pinning;
pub mod pow;
pub mod types;

/// Convenience re-exports for common mailbox types.
pub mod prelude {
    pub use crate::mailbox::client::{MailboxClient, Transport};
    pub use crate::mailbox::error::{MailboxError, Result, RetryConfig};
    pub use crate::mailbox::http::HttpMailboxClient;
    pub use crate::mailbox::pinning::{verify_pin, OnionPin, PinStore};
    pub use crate::mailbox::pow::{solve_pow, verify_pow};
    pub use crate::mailbox::types::{
        CapabilitySettings, CapabilityStatus, DepositResult, FetchResponse, MailboxConfig,
        MailboxMessage, OneTimePrekey, PinVerification, PowChallenge, PowSolution, PrekeyBundle,
    };
}
