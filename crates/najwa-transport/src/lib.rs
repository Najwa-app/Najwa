//! Tor transport layer for Najwa (S04).
//!
//! Single source of truth for all network operations.
//! All traffic MUST transit through Tor — no clearnet fallback.
//!
//! Provides:
//! - Arti embedded Tor bootstrap ([`tor`]) — S04 §10
//! - Circuit isolation: per-mailbox, per-contact, cover, one-shot ([`circuit`]) — S04 §4
//! - Raw HTTP/1.1 over Tor with header stripping ([`http`]) — S04 §5
//! - `.onion`-only URL validation ([`http`]) — S04 §5.4
//! - DNS leak prevention self-test ([`dns_leak`]) — S04 §6
//! - Clock synchronization from Tor consensus ([`clock`]) — S04 §7
//! - Version fingerprinting prevention ([`version`]) — S04 §8
//! - Managed pluggable-transport subprocess helpers ([`pt`]); not used by the
//!   application, whose bridges run through Arti's own transport manager
//! - Tor and bridge configuration ([`config`]) — S04 §3, §11

pub mod circuit;
pub mod clock;
pub mod config;
pub mod dns_leak;
pub mod error;
pub mod http;
pub mod pt;
pub mod tor;
pub mod version;

/// Convenience re-exports for common types.
pub mod prelude {
    pub use crate::circuit::{CircuitHandle, CircuitIsolation};
    pub use crate::clock::{
        ClockError, ClockSyncConfig, TorClockSync, HANDSHAKE_SKEW_TOLERANCE,
        MESSAGE_SKEW_TOLERANCE, PREKEY_SKEW_TOLERANCE,
    };
    pub use crate::config::{
        BridgeConfig, BridgeType, PluggableTransportConfig, TorConfig, TorMode, VpnModeTorConfig,
    };
    pub use crate::dns_leak::{verify_no_dns_leak, verify_no_dns_leak_strict};
    pub use crate::error::{Result, TransportError};
    pub use crate::http::HttpResponse;
    pub use crate::tor::TorTransport;
    pub use crate::version::{DistributionChannel, UpdateChecker, UpdateError, UpdateInfo};
}
