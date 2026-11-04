//! Timestamp validation (§7.1).

use super::error::{MessageError, Result};

/// Maximum acceptable FUTURE clock skew (5 minutes) (§7.1). A message dated more
/// than this ahead of the local clock is never legitimate.
pub const MAX_FUTURE_SKEW_SECS: u64 = 300;

/// Maximum acceptable PAST skew (90 days = `MAX_RETENTION_DAYS`) (§7.1). The past
/// window is wide so a receiver offline up to the server's retention limit does
/// NOT discard legitimately retained messages.
pub const MAX_PAST_SKEW_SECS: u64 = 7_776_000;

/// Validate a message timestamp for replay/resurrection protection (§7.1).
///
/// Rejects a timestamp more than [`MAX_FUTURE_SKEW_SECS`] in the future or more
/// than [`MAX_PAST_SKEW_SECS`] in the past — an asymmetric window, not a
/// symmetric ±skew.
///
/// **Re-send / gap-repair carve-out (§7.1):** content re-delivered from durable
/// history (session-repair re-sends, `GapRepairBundle` items, `ReSendRequest`
/// replies) carries its **original** timestamp for `logical_msg_id` stability
/// and may legitimately exceed [`MAX_PAST_SKEW_SECS`]. Such callers MUST NOT
/// reject on the past window alone — freshness there is established by the
/// enclosing ratchet message and at-most-once by logical dedup. The future
/// bound has no carve-out and always applies.
pub fn validate_timestamp(msg_timestamp: u64, local_time: u64) -> Result<()> {
    if msg_timestamp > local_time.saturating_add(MAX_FUTURE_SKEW_SECS) {
        return Err(MessageError::TimestampOutOfRange {
            diff: msg_timestamp - local_time,
        });
    }
    if msg_timestamp < local_time.saturating_sub(MAX_PAST_SKEW_SECS) {
        return Err(MessageError::TimestampOutOfRange {
            diff: local_time - msg_timestamp,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_700_000_000;

    #[test]
    fn accept_now_and_boundaries() {
        assert!(validate_timestamp(NOW, NOW).is_ok());
        // Exactly the future/past boundaries are accepted.
        assert!(validate_timestamp(NOW + MAX_FUTURE_SKEW_SECS, NOW).is_ok());
        assert!(validate_timestamp(NOW - MAX_PAST_SKEW_SECS, NOW).is_ok());
    }

    #[test]
    fn reject_too_far_future() {
        assert!(validate_timestamp(NOW + MAX_FUTURE_SKEW_SECS + 1, NOW).is_err());
    }

    #[test]
    fn reject_older_than_90_days() {
        assert!(validate_timestamp(NOW - MAX_PAST_SKEW_SECS - 1, NOW).is_err());
    }

    #[test]
    fn accept_offline_retained_message() {
        // A message minutes-to-days old is retained, not rejected (the old
        // symmetric ±300s window wrongly rejected anything > 5 minutes old).
        assert!(validate_timestamp(NOW - 3600, NOW).is_ok()); // 1 hour
        assert!(validate_timestamp(NOW - 89 * 86_400, NOW).is_ok()); // 89 days
    }

    #[test]
    fn zero_timestamps_accepted() {
        assert!(validate_timestamp(0, 0).is_ok());
    }
}
