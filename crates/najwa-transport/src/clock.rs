//! Secure clock synchronization over Tor (S04 §7).
//!
//! Provides clock offset estimation using Tor consensus time, with no NTP or
//! application-server time sources.

use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Clock skew tolerance (±5 minutes) for `is_message_time_valid`. Message
/// acceptance windows are defined by S07 (S04 §7.3).
pub const MESSAGE_SKEW_TOLERANCE: u64 = 300;

/// Clock skew tolerance (±1 hour) for `is_prekey_time_valid`.
pub const PREKEY_SKEW_TOLERANCE: u64 = 3600;

/// Clock skew tolerance (±24 hours) for `is_handshake_time_valid`; also the
/// longest consensus validity interval accepted for clock sync (S04 §7.2).
pub const HANDSHAKE_SKEW_TOLERANCE: u64 = 86400;

/// Error type for clock synchronization operations.
#[derive(Debug, thiserror::Error)]
pub enum ClockError {
    /// No external time sources available.
    #[error("no external time sources available")]
    NoTimeSources,

    /// Server response did not contain a Date header.
    #[error("no Date header in server response")]
    NoDateHeader,

    /// Failed to parse HTTP Date header.
    #[error("failed to parse Date header: {0}")]
    ParseError(String),

    /// Transport error during time fetch.
    #[error("transport error: {0}")]
    TransportError(String),
}

/// Secure clock synchronization via Tor (S04 §7).
///
/// Estimates clock offset using validated Tor consensus timestamps. Never uses
/// NTP or mailbox-server timestamps.
pub struct TorClockSync {
    /// Estimated offset in seconds (system_time + offset = real_time).
    offset: AtomicI64,
}

impl TorClockSync {
    /// Create a new clock sync instance with zero offset.
    pub fn new() -> Self {
        Self {
            offset: AtomicI64::new(0),
        }
    }

    /// Get the current estimated offset in seconds.
    pub fn offset(&self) -> i64 {
        self.offset.load(Ordering::Relaxed)
    }

    /// Get current time adjusted by the estimated offset.
    pub fn now(&self) -> u64 {
        let system = system_time_secs();
        let offset = self.offset.load(Ordering::Relaxed);
        apply_offset(system, offset)
    }

    /// A consensus attests a validity interval, not an instant. Preserve an
    /// already-plausible system clock; otherwise apply only the minimum shift
    /// into that interval. This is a coarse bound, never a precise time sample.
    pub fn synchronize_from_consensus(
        &self,
        valid_after: u64,
        valid_until: u64,
    ) -> Result<i64, ClockError> {
        if valid_after >= valid_until
            || valid_until > i64::MAX as u64
            || valid_until - valid_after > HANDSHAKE_SKEW_TOLERANCE
        {
            return Err(ClockError::ParseError("invalid consensus interval".into()));
        }
        let system = system_time_secs();
        let estimate = system.clamp(valid_after, valid_until - 1);
        let offset = checked_offset(estimate, system)?;
        self.offset.store(offset, Ordering::Relaxed);
        Ok(offset)
    }

    /// Update the offset from a set of external time estimates.
    ///
    /// Takes a list of UNIX timestamps from external sources,
    /// computes the median, and updates the stored offset.
    ///
    /// Returns the new offset.
    pub fn synchronize_from_estimates(&self, estimates: &[u64]) -> Result<i64, ClockError> {
        if estimates.is_empty() {
            // Fallback to system clock (no NTP over clearnet!)
            self.offset.store(0, Ordering::Relaxed);
            tracing::warn!("Clock sync unavailable — using system time");
            return Ok(0);
        }

        // Take median to resist outliers
        let mut sorted = estimates.to_vec();
        sorted.sort_unstable();
        let median = sorted[sorted.len() / 2];

        let system_time = system_time_secs();
        let offset = checked_offset(median, system_time)?;

        self.offset.store(offset, Ordering::Relaxed);

        tracing::info!(
            offset_secs = offset,
            sources = estimates.len(),
            "Clock synchronized"
        );

        Ok(offset)
    }

    /// Check if a timestamp is within tolerance of the current adjusted time.
    pub fn is_within_tolerance(&self, timestamp: u64, tolerance: u64) -> bool {
        let current = self.now();
        let diff = current.abs_diff(timestamp);
        diff <= tolerance
    }

    /// Check if a message timestamp is valid (within ±5 minutes).
    pub fn is_message_time_valid(&self, timestamp: u64) -> bool {
        self.is_within_tolerance(timestamp, MESSAGE_SKEW_TOLERANCE)
    }

    /// Check if a prekey timestamp is valid (within ±1 hour).
    pub fn is_prekey_time_valid(&self, timestamp: u64) -> bool {
        self.is_within_tolerance(timestamp, PREKEY_SKEW_TOLERANCE)
    }

    /// Check if a handshake timestamp is valid (within ±24 hours).
    pub fn is_handshake_time_valid(&self, timestamp: u64) -> bool {
        self.is_within_tolerance(timestamp, HANDSHAKE_SKEW_TOLERANCE)
    }
}

fn apply_offset(system: u64, offset: i64) -> u64 {
    (system as i128 + offset as i128).clamp(0, u64::MAX as i128) as u64
}

fn checked_offset(estimate: u64, system: u64) -> Result<i64, ClockError> {
    if estimate > i64::MAX as u64 || system > i64::MAX as u64 {
        return Err(ClockError::ParseError("time estimate out of range".into()));
    }
    i64::try_from(estimate as i128 - system as i128)
        .map_err(|_| ClockError::ParseError("clock offset out of range".into()))
}

impl Default for TorClockSync {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse a UNIX timestamp from an HTTP Date header value.
///
/// Expected format: `Thu, 01 Jan 2026 00:00:00 GMT`
/// (RFC 7231 / IMF-fixdate).
pub fn parse_http_date(date_str: &str) -> Result<u64, ClockError> {
    let malformed = || ClockError::ParseError("invalid IMF-fixdate".into());
    if date_str.len() != 29
        || !date_str.is_ascii()
        || &date_str[3..5] != ", "
        || &date_str[7..8] != " "
        || &date_str[11..12] != " "
        || &date_str[16..17] != " "
        || &date_str[19..20] != ":"
        || &date_str[22..23] != ":"
        || &date_str[25..] != " GMT"
        || [5..7, 12..16, 17..19, 20..22, 23..25]
            .iter()
            .any(|r| !date_str[r.clone()].bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(malformed());
    }
    // Parse: "Day, DD Mon YYYY HH:MM:SS GMT"
    let parts: Vec<&str> = date_str.split_whitespace().collect();
    if parts.len() != 6 {
        return Err(ClockError::ParseError(format!(
            "expected at least 6 parts, got {}",
            parts.len()
        )));
    }

    let day: u32 = parts[1]
        .parse()
        .map_err(|e| ClockError::ParseError(format!("invalid day: {}", e)))?;

    let month = match parts[2] {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        other => return Err(ClockError::ParseError(format!("invalid month: {}", other))),
    };

    let year: i32 = parts[3]
        .parse()
        .map_err(|e| ClockError::ParseError(format!("invalid year: {}", e)))?;

    let time_parts: Vec<&str> = parts[4].split(':').collect();
    if time_parts.len() != 3 {
        return Err(ClockError::ParseError("invalid time format".to_string()));
    }

    let hour: u32 = time_parts[0]
        .parse()
        .map_err(|e| ClockError::ParseError(format!("invalid hour: {}", e)))?;
    let minute: u32 = time_parts[1]
        .parse()
        .map_err(|e| ClockError::ParseError(format!("invalid minute: {}", e)))?;
    let second: u32 = time_parts[2]
        .parse()
        .map_err(|e| ClockError::ParseError(format!("invalid second: {}", e)))?;

    if !(1970..=9999).contains(&year) || hour > 23 || minute > 59 || second > 59 {
        return Err(malformed());
    }
    let days_in_month = [
        31,
        if is_leap_year(year) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if day == 0 || day > days_in_month[(month - 1) as usize] {
        return Err(malformed());
    }
    let timestamp = date_to_unix_timestamp(year, month, day, hour, minute, second);
    let weekday =
        ["Thu,", "Fri,", "Sat,", "Sun,", "Mon,", "Tue,", "Wed,"][(timestamp / 86400 % 7) as usize];
    if parts[0] != weekday {
        return Err(malformed());
    }
    Ok(timestamp)
}

/// Convert a date/time to a UNIX timestamp.
///
/// Uses a simplified algorithm valid for dates from 1970 onwards.
fn date_to_unix_timestamp(year: i32, month: u32, day: u32, hour: u32, min: u32, sec: u32) -> u64 {
    let y = year as i64 - 1;
    let epoch_y = 1969i64;
    let mut days = 365 * (y - epoch_y) + (y / 4 - epoch_y / 4) - (y / 100 - epoch_y / 100)
        + (y / 400 - epoch_y / 400);

    // Days from start of year to start of month
    let month_days = [0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    for m in 1..month {
        days += month_days[m as usize] as i64;
        if m == 2 && is_leap_year(year) {
            days += 1;
        }
    }

    // Add day of month (1-indexed)
    days += (day as i64) - 1;

    let secs = days * 86400 + (hour as i64) * 3600 + (min as i64) * 60 + (sec as i64);
    secs.max(0) as u64
}

/// Check if a year is a leap year.
fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

/// Get current system time as UNIX seconds.
pub fn system_time_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Clock sync configuration (serializable for settings).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClockSyncConfig {
    /// Whether automatic clock sync is enabled.
    pub enabled: bool,
    /// Maximum number of mailbox sources to query.
    pub max_mailbox_sources: usize,
}

impl Default for ClockSyncConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_mailbox_sources: 5,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_clock_sync_has_zero_offset() {
        let clock = TorClockSync::new();
        assert_eq!(clock.offset(), 0);
    }

    #[test]
    fn now_returns_system_time_with_zero_offset() {
        let clock = TorClockSync::new();
        let now = clock.now();
        let sys = system_time_secs();
        // Should be within 1 second
        assert!(now.abs_diff(sys) <= 1);
    }

    #[test]
    fn synchronize_with_positive_offset() {
        let clock = TorClockSync::new();
        let sys = system_time_secs();
        // Simulate external sources 60 seconds ahead
        let estimates = vec![sys + 60, sys + 58, sys + 62];
        let offset = clock.synchronize_from_estimates(&estimates).unwrap();
        assert!((offset - 60).abs() <= 2);
    }

    #[test]
    fn synchronize_with_negative_offset() {
        let clock = TorClockSync::new();
        let sys = system_time_secs();
        // Simulate external sources 30 seconds behind
        let estimates = vec![sys - 30, sys - 28, sys - 32];
        let offset = clock.synchronize_from_estimates(&estimates).unwrap();
        assert!((offset + 30).abs() <= 2);
    }

    #[test]
    fn synchronize_empty_estimates_returns_zero() {
        let clock = TorClockSync::new();
        let sys = system_time_secs();
        clock.synchronize_from_estimates(&[sys + 60]).unwrap();
        let offset = clock.synchronize_from_estimates(&[]).unwrap();
        assert_eq!(offset, 0);
        assert_eq!(clock.offset(), 0);
    }

    #[test]
    fn synchronize_uses_median() {
        let clock = TorClockSync::new();
        let sys = system_time_secs();
        // One outlier at +1000, median should be around +10
        let estimates = vec![sys + 10, sys + 1000, sys + 10];
        let offset = clock.synchronize_from_estimates(&estimates).unwrap();
        assert!((offset - 10).abs() <= 1);
    }

    #[test]
    fn message_time_within_tolerance() {
        let clock = TorClockSync::new();
        let now = clock.now();
        assert!(clock.is_message_time_valid(now));
        assert!(clock.is_message_time_valid(now - 200)); // within 5 min
        assert!(!clock.is_message_time_valid(now - 400)); // outside 5 min
    }

    #[test]
    fn prekey_time_within_tolerance() {
        let clock = TorClockSync::new();
        let now = clock.now();
        assert!(clock.is_prekey_time_valid(now - 1800)); // 30 min, within 1 hour
        assert!(!clock.is_prekey_time_valid(now - 7200)); // 2 hours, outside
    }

    #[test]
    fn handshake_time_within_tolerance() {
        let clock = TorClockSync::new();
        let now = clock.now();
        assert!(clock.is_handshake_time_valid(now - 43200)); // 12 hours, within 24
        assert!(!clock.is_handshake_time_valid(now - 100000)); // >24 hours
    }

    #[test]
    fn parse_http_date_valid() {
        let ts = parse_http_date("Thu, 01 Jan 2026 00:00:00 GMT").unwrap();
        // 2026-01-01 00:00:00 UTC
        assert_eq!(ts, 1767225600);
    }

    #[test]
    fn parse_http_date_with_time() {
        let ts = parse_http_date("Wed, 11 Feb 2026 19:00:00 GMT").unwrap();
        // 2026-02-11 19:00:00 UTC = 1739300400
        // Jan(31) + 10 days = 41 days from Jan 1
        // 1767225600 + 41*86400 + 19*3600 = 1767225600 + 3542400 + 68400 = 1770836400
        assert_eq!(ts, 1770836400);
    }

    #[test]
    fn parse_http_date_invalid_format() {
        assert!(parse_http_date("not a date").is_err());
    }

    #[test]
    fn parse_http_date_invalid_month() {
        assert!(parse_http_date("Thu, 01 Foo 2026 00:00:00 GMT").is_err());
    }

    #[test]
    fn default_clock_sync_config() {
        let config = ClockSyncConfig::default();
        assert!(config.enabled);
        assert_eq!(config.max_mailbox_sources, 5);
    }

    #[test]
    fn skew_tolerance_constants() {
        assert_eq!(MESSAGE_SKEW_TOLERANCE, 300);
        assert_eq!(PREKEY_SKEW_TOLERANCE, 3600);
        assert_eq!(HANDSHAKE_SKEW_TOLERANCE, 86400);
    }

    #[test]
    fn is_leap_year_checks() {
        assert!(is_leap_year(2000));
        assert!(is_leap_year(2024));
        assert!(!is_leap_year(2023));
        assert!(!is_leap_year(1900));
    }
}

#[cfg(test)]
#[path = "clock_tests.rs"]
mod regression_tests;
