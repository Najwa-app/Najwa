//! Rate limiting for outbound and inbound messages (S08 §8).

use std::sync::Mutex;

use crate::error::{MessagingError, Result};
use crate::types::ContactId;

// ---------------------------------------------------------------------------
// Outbound rate limiter — token bucket (S08 §8.1)
// ---------------------------------------------------------------------------

/// Default outbound rate: 10 messages per second.
pub const DEFAULT_OUTBOUND_RATE: f64 = 10.0;

/// Default outbound burst capacity.
pub const DEFAULT_OUTBOUND_BURST: u32 = 20;

/// Token-bucket rate limiter for outbound messages (S08 §8.1).
///
/// Prevents the local client from sending faster than the configured
/// rate, which would be suspicious traffic analysis–wise.
pub struct OutboundRateLimiter {
    inner: Mutex<TokenBucket>,
}

impl OutboundRateLimiter {
    /// Create a new outbound rate limiter.
    pub fn new(rate_per_sec: f64, burst: u32) -> Self {
        Self {
            inner: Mutex::new(TokenBucket::new(rate_per_sec, burst)),
        }
    }

    /// Check if a send is allowed. Returns `Ok(())` if allowed,
    /// or `Err(RateLimitExceeded)` with a retry-after hint.
    pub fn check(&self) -> Result<()> {
        let mut bucket = self.inner.lock().unwrap();
        bucket.try_consume()
    }
}

impl Default for OutboundRateLimiter {
    fn default() -> Self {
        Self::new(DEFAULT_OUTBOUND_RATE, DEFAULT_OUTBOUND_BURST)
    }
}

// ---------------------------------------------------------------------------
// Inbound rate limiter — per-contact sliding window (S08 §8.2)
// ---------------------------------------------------------------------------

/// Default inbound rate: 50 messages per minute per contact.
pub const DEFAULT_INBOUND_RATE_PER_CONTACT: u32 = 50;

/// Default inbound window in seconds.
pub const DEFAULT_INBOUND_WINDOW_SECS: u64 = 60;

/// Per-contact inbound rate limiter (S08 §8.2).
///
/// Limits the number of messages accepted from each contact within
/// a sliding time window to mitigate spam/DoS from a single contact.
pub struct InboundRateLimiter {
    max_per_window: u32,
    window_secs: u64,
    counters: Mutex<std::collections::HashMap<ContactId, Vec<u64>>>,
}

impl InboundRateLimiter {
    /// Create a new inbound rate limiter.
    pub fn new(max_per_window: u32, window_secs: u64) -> Self {
        Self {
            max_per_window,
            window_secs,
            counters: Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Record a message from a contact and check if the rate limit is exceeded.
    ///
    /// Returns `Ok(())` if within limits, `Err(RateLimitExceeded)` if exceeded.
    pub fn check(&self, contact_id: ContactId) -> Result<()> {
        let now = najwa_crypto::time::now();
        let window_start = now.saturating_sub(self.window_secs);

        let mut counters = self.counters.lock().unwrap();
        let timestamps = counters.entry(contact_id).or_default();

        // Remove timestamps outside the window
        timestamps.retain(|&ts| ts >= window_start);

        if timestamps.len() as u32 >= self.max_per_window {
            let oldest = timestamps.first().copied().unwrap_or(now);
            let retry_after_ms = (oldest + self.window_secs).saturating_sub(now) * 1000;
            return Err(MessagingError::RateLimitExceeded { retry_after_ms });
        }

        timestamps.push(now);
        Ok(())
    }

    /// Clear rate limit state for a contact (e.g., after unblock).
    pub fn clear(&self, contact_id: ContactId) {
        let mut counters = self.counters.lock().unwrap();
        counters.remove(&contact_id);
    }
}

impl Default for InboundRateLimiter {
    fn default() -> Self {
        Self::new(
            DEFAULT_INBOUND_RATE_PER_CONTACT,
            DEFAULT_INBOUND_WINDOW_SECS,
        )
    }
}

// ---------------------------------------------------------------------------
// Token bucket implementation
// ---------------------------------------------------------------------------

struct TokenBucket {
    rate_per_sec: f64,
    burst: u32,
    tokens: f64,
    last_refill: u64,
}

impl TokenBucket {
    fn new(rate_per_sec: f64, burst: u32) -> Self {
        Self {
            rate_per_sec,
            burst,
            tokens: burst as f64,
            last_refill: najwa_crypto::time::now(),
        }
    }

    fn try_consume(&mut self) -> Result<()> {
        let now = najwa_crypto::time::now();
        let elapsed = now.saturating_sub(self.last_refill) as f64;
        self.last_refill = now;

        // Refill tokens
        self.tokens = (self.tokens + elapsed * self.rate_per_sec).min(self.burst as f64);

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            Ok(())
        } else {
            let wait_secs = (1.0 - self.tokens) / self.rate_per_sec;
            let retry_after_ms = (wait_secs * 1000.0) as u64;
            Err(MessagingError::RateLimitExceeded { retry_after_ms })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outbound_allows_burst() {
        let limiter = OutboundRateLimiter::new(10.0, 5);
        for _ in 0..5 {
            assert!(limiter.check().is_ok());
        }
        // 6th should fail (burst exhausted, no time elapsed for refill)
        assert!(limiter.check().is_err());
    }

    #[test]
    fn inbound_per_contact_limit() {
        let limiter = InboundRateLimiter::new(3, 60);
        // Allow 3 from contact 1
        assert!(limiter.check(1).is_ok());
        assert!(limiter.check(1).is_ok());
        assert!(limiter.check(1).is_ok());
        // 4th from contact 1 should fail
        assert!(limiter.check(1).is_err());
        // Contact 2 should be independent
        assert!(limiter.check(2).is_ok());
    }

    #[test]
    fn inbound_clear_resets_contact() {
        let limiter = InboundRateLimiter::new(2, 60);
        assert!(limiter.check(1).is_ok());
        assert!(limiter.check(1).is_ok());
        assert!(limiter.check(1).is_err());
        limiter.clear(1);
        assert!(limiter.check(1).is_ok());
    }

    #[test]
    fn outbound_default_has_sensible_values() {
        let limiter = OutboundRateLimiter::default();
        // Should allow at least DEFAULT_OUTBOUND_BURST sends
        for _ in 0..DEFAULT_OUTBOUND_BURST {
            assert!(limiter.check().is_ok());
        }
    }

    #[test]
    fn inbound_default_has_sensible_values() {
        let limiter = InboundRateLimiter::default();
        // Should allow DEFAULT_INBOUND_RATE_PER_CONTACT messages
        for _ in 0..DEFAULT_INBOUND_RATE_PER_CONTACT {
            assert!(limiter.check(42).is_ok());
        }
        assert!(limiter.check(42).is_err());
    }
}
