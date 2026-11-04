//! Quota and rate-limit enforcement (S16 §8, §9).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

/// Sliding-window rate limiter keyed by capability bytes (S16 §8).
pub struct RateLimiter {
    /// Map from key → list of request timestamps within the window.
    windows: Mutex<HashMap<[u8; 32], Vec<Instant>>>,
    /// Window duration in seconds.
    window_secs: u64,
}

impl RateLimiter {
    pub fn new(window_secs: u64) -> Self {
        Self {
            windows: Mutex::new(HashMap::new()),
            window_secs,
        }
    }

    /// Record a request and return the count within the current window.
    /// Returns the count *after* recording this request.
    pub fn record(&self, key: &[u8; 32]) -> u32 {
        let mut map = self.windows.lock().unwrap();
        let now = Instant::now();
        let cutoff = now - std::time::Duration::from_secs(self.window_secs);

        let entry = map.entry(*key).or_default();
        entry.retain(|&t| t > cutoff);
        entry.push(now);
        entry.len() as u32
    }

    /// Check the current count without recording a new request.
    #[allow(dead_code)] // diagnostic API — not called in main flow but useful for metrics
    pub fn count(&self, key: &[u8; 32]) -> u32 {
        let mut map = self.windows.lock().unwrap();
        let cutoff = Instant::now() - std::time::Duration::from_secs(self.window_secs);

        if let Some(entry) = map.get_mut(key) {
            entry.retain(|&t| t > cutoff);
            entry.len() as u32
        } else {
            0
        }
    }

    /// Periodically evict stale entries to bound memory usage.
    pub fn evict_stale(&self) {
        let mut map = self.windows.lock().unwrap();
        let cutoff = Instant::now() - std::time::Duration::from_secs(self.window_secs);
        map.retain(|_, timestamps| {
            timestamps.retain(|&t| t > cutoff);
            !timestamps.is_empty()
        });
    }
}

/// Per-capability quota checker.
pub struct QuotaChecker {
    pub max_messages: u64,
    pub max_blob_size: usize,
    pub max_storage_bytes: u64,
    pub max_opks: u32,
}

impl QuotaChecker {
    /// Check if a deposit would exceed the message count quota.
    pub fn check_message_count(&self, current: u64) -> Result<(), QuotaExceeded> {
        if current >= self.max_messages {
            Err(QuotaExceeded::MessageCount {
                current,
                max: self.max_messages,
            })
        } else {
            Ok(())
        }
    }

    /// Check if a blob exceeds the max size.
    pub fn check_blob_size(&self, size: usize) -> Result<(), QuotaExceeded> {
        if size > self.max_blob_size {
            Err(QuotaExceeded::BlobSize {
                size,
                max: self.max_blob_size,
            })
        } else {
            Ok(())
        }
    }

    /// Check if a deposit would exceed the storage quota.
    pub fn check_storage(&self, current_bytes: u64, new_bytes: usize) -> Result<(), QuotaExceeded> {
        let total = current_bytes + new_bytes as u64;
        if total > self.max_storage_bytes {
            Err(QuotaExceeded::Storage {
                total,
                max: self.max_storage_bytes,
            })
        } else {
            Ok(())
        }
    }

    /// Check if uploading new OPKs would exceed the per-capability limit (S16 §3.6, §9).
    pub fn check_opk_count(&self, current: u32, uploading: u32) -> Result<(), QuotaExceeded> {
        let total = current + uploading;
        if total > self.max_opks {
            Err(QuotaExceeded::OPKLimit {
                current,
                uploading,
                max: self.max_opks,
            })
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum QuotaExceeded {
    #[error("message count quota exceeded: {current}/{max}")]
    MessageCount { current: u64, max: u64 },
    #[error("blob size exceeds maximum: {size}/{max} bytes")]
    BlobSize { size: usize, max: usize },
    #[error("storage quota exceeded: {total}/{max} bytes")]
    Storage { total: u64, max: u64 },
    #[error("OPK limit exceeded: {current} stored + {uploading} new > {max} max")]
    OPKLimit {
        current: u32,
        uploading: u32,
        max: u32,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter_basic() {
        let limiter = RateLimiter::new(60);
        let key = [1u8; 32];
        assert_eq!(limiter.record(&key), 1);
        assert_eq!(limiter.record(&key), 2);
        assert_eq!(limiter.count(&key), 2);
    }

    #[test]
    fn test_quota_checker() {
        let checker = QuotaChecker {
            max_messages: 10,
            max_blob_size: 1024,
            max_storage_bytes: 10240,
            max_opks: 100,
        };
        assert!(checker.check_message_count(9).is_ok());
        assert!(checker.check_message_count(10).is_err());
        assert!(checker.check_blob_size(512).is_ok());
        assert!(checker.check_blob_size(2048).is_err());
        assert!(checker.check_storage(5000, 5000).is_ok());
        assert!(checker.check_storage(5000, 6000).is_err());
    }

    #[test]
    fn test_check_opk_count() {
        let checker = QuotaChecker {
            max_messages: 10,
            max_blob_size: 1024,
            max_storage_bytes: 10240,
            max_opks: 100,
        };
        assert!(checker.check_opk_count(90, 10).is_ok()); // exactly at limit
        assert!(checker.check_opk_count(90, 11).is_err()); // would exceed
        assert!(checker.check_opk_count(0, 100).is_ok()); // full upload from empty
        assert!(checker.check_opk_count(0, 101).is_err()); // over limit from empty
        assert!(checker.check_opk_count(100, 0).is_ok()); // no new, at limit
    }
}
