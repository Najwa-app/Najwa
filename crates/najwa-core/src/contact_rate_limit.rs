//! Contact addition rate limit (AUD-03, S05 §8.1).
//!
//! Counts contacts added in the last 24 hours from their durable `created_at`,
//! so a restart or lock does not reset the count. Once `DAILY_CONTACT_LIMIT`
//! contacts were added, the user must confirm before accepting another
//! invitation. This limits enumeration of which invitations a target accepts.

/// Contacts that may be added in a rolling 24-hour window without confirmation.
pub const DAILY_CONTACT_LIMIT: usize = 10;

/// Rolling window duration in seconds (24 hours).
const WINDOW_SECS: i64 = 86_400;

/// True when `DAILY_CONTACT_LIMIT` or more of `created_at` (Unix seconds) fall
/// in the 24 hours before `now`. Timestamps ahead of `now` count as recent.
pub fn confirmation_required(created_at: impl IntoIterator<Item = i64>, now: i64) -> bool {
    created_at
        .into_iter()
        .filter(|added| now.saturating_sub(*added) < WINDOW_SECS)
        .count()
        >= DAILY_CONTACT_LIMIT
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tenth_recent_contact_requires_confirmation_for_the_next() {
        let now = 1_000_000;
        assert!(!confirmation_required(vec![now - 60; 9], now));
        assert!(confirmation_required(vec![now - 60; 10], now));
        // Contacts older than 24 hours drop out of the window.
        let mut mixed = vec![now - WINDOW_SECS; 5];
        mixed.extend([now - WINDOW_SECS + 1; 9]);
        assert!(!confirmation_required(mixed, now));
    }
}
