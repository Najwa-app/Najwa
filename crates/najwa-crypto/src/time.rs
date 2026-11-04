//! Timestamp utility for the Najwa protocol.
//!
//! Uses `SystemTime::now()` as the default clock source.
//! For networked operations, callers SHOULD use `TorClockSync.now()`
//! from `najwa-transport` which applies a Tor-consensus-derived offset
//! (S04 §7). This module provides the fallback for non-networked contexts.

use std::time::{SystemTime, UNIX_EPOCH};

/// Return the current Unix timestamp in seconds.
///
/// This is the canonical time source used across all crates.
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_secs()
}

/// Return the current Unix timestamp in milliseconds.
///
/// Used for message timestamps to give sub-second ordering.
pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_millis()
        .try_into()
        .unwrap_or(i64::MAX)
}

/// Timestamp acceptance tolerance (±5 minutes), compared against the protocol
/// clock (S04 §7.1).
pub const TIMESTAMP_TOLERANCE_NORMAL_SECS: u64 = 300; // 5 minutes

/// Wider timestamp acceptance tolerance (30 minutes) for callers that run on an
/// uncorrected system clock. No release code path uses it; clock-sync failure
/// falls back to system time without widening any window (S04 §7.5).
pub const TIMESTAMP_TOLERANCE_FALLBACK_SECS: u64 = 1800; // 30 minutes

/// AUD-16: Check if a timestamp is within acceptable range of `reference_time`.
/// Uses `tolerance` to define the acceptance window.
pub fn is_timestamp_valid(timestamp: u64, reference_time: u64, tolerance: u64) -> bool {
    timestamp.abs_diff(reference_time) <= tolerance
}
