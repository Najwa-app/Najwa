//! Najwa mailbox server — store-and-forward Tor onion service (S16).
//!
//! Library crate so the binary (`main.rs`), the integration tests, and the
//! live-mailbox harness (najwa-core `tests/live_mailbox.rs`) all drive the
//! same router and database layer.
//!
//! Scope notes:
//! - Fetch returns only real stored blobs; the server adds no noise (S16 §3.4).
//! - No channel-feed endpoints or tables.
//! - No capability-link endpoint; S16 §1 lists the endpoints.

pub mod api;
pub mod config;
pub mod db;
pub mod pow;
pub mod quota;
pub mod retention;
pub mod state;
