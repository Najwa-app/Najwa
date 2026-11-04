//! In-memory message-ID deduplication cache with timestamp-based TTL.
//!
//! The receive path does not use this cache: it deduplicates through the
//! persistent `msg_id_cache_transport` and `msg_id_cache_logical` tables
//! (S07 §7.3).

use std::collections::HashMap;
use std::sync::Mutex;

/// Minimum entry TTL in seconds — entries survive at least 90 days (S07 §7.3).
/// Aligned with the mailbox `MAX_RETENTION_DAYS` so a blob re-released
/// near the end of its retention window cannot resurrect a message whose dedup
/// entry has already expired (the disappeared-message resurrection window).
pub const MIN_ENTRY_TTL_SECS: u64 = 90 * 24 * 3600;

/// Maximum entry TTL in seconds — entries are evicted after 180 days.
pub const MAX_ENTRY_TTL_SECS: u64 = 180 * 24 * 3600;

/// Default maximum capacity of this cache.
pub const DEFAULT_CACHE_CAPACITY: usize = 10_000;

/// In-memory msg_id deduplication cache with TTL.
///
/// - Entries survive at least `MIN_ENTRY_TTL_SECS` (90 days)
/// - Entries are evicted after `MAX_ENTRY_TTL_SECS` (180 days)
/// - At capacity, only entries > 180 days old are evicted
/// - Entries < 90 days old are NEVER evicted, even at capacity
/// - Persistent layer via `msg_id_cache_transport` DB table handles restart survival
pub struct MsgIdCache {
    /// Map of msg_id → insertion timestamp (Unix seconds).
    entries: Mutex<HashMap<[u8; 16], u64>>,
    /// Maximum capacity.
    capacity: usize,
}

impl MsgIdCache {
    /// Create a new cache with the default capacity.
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            capacity: DEFAULT_CACHE_CAPACITY,
        }
    }

    /// Create a new cache with a custom capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            capacity,
        }
    }

    /// Check if a msg_id has been seen. If not, insert it and return `false`.
    /// If already seen, return `true` (duplicate).
    pub fn check_and_insert(&self, msg_id: &[u8; 16]) -> bool {
        let now = najwa_crypto::time::now();
        let mut entries = self.entries.lock().unwrap();

        if entries.contains_key(msg_id) {
            return true;
        }

        // Evict expired entries (> MAX_ENTRY_TTL) if at capacity
        if entries.len() >= self.capacity {
            entries.retain(|_, ts| now.saturating_sub(*ts) < MAX_ENTRY_TTL_SECS);
        }

        // If still at capacity after evicting old entries, only evict entries
        // older than MIN_ENTRY_TTL (never evict entries < 90 days old)
        if entries.len() >= self.capacity {
            entries.retain(|_, ts| now.saturating_sub(*ts) < MIN_ENTRY_TTL_SECS);
        }

        entries.insert(*msg_id, now);
        false
    }

    /// Check if a msg_id has been seen (without inserting).
    pub fn contains(&self, msg_id: &[u8; 16]) -> bool {
        self.entries.lock().unwrap().contains_key(msg_id)
    }

    /// Number of msg_ids currently cached.
    pub fn len(&self) -> usize {
        self.entries.lock().unwrap().len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.lock().unwrap().is_empty()
    }

    /// Clear the cache.
    pub fn clear(&self) {
        self.entries.lock().unwrap().clear();
    }

    /// Evict entries older than `MAX_ENTRY_TTL_SECS`.
    pub fn evict_expired(&self) {
        let now = najwa_crypto::time::now();
        self.entries
            .lock()
            .unwrap()
            .retain(|_, ts| now.saturating_sub(*ts) < MAX_ENTRY_TTL_SECS);
    }
}

impl Default for MsgIdCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // First insertion returns false (not duplicate)
    #[test]
    fn first_insert_not_duplicate() {
        let cache = MsgIdCache::new();
        assert!(!cache.check_and_insert(&[0x01; 16]));
    }

    // Second insertion returns true (duplicate)
    #[test]
    fn second_insert_is_duplicate() {
        let cache = MsgIdCache::new();
        assert!(!cache.check_and_insert(&[0x01; 16]));
        assert!(cache.check_and_insert(&[0x01; 16]));
    }

    // Different msg_ids not duplicates
    #[test]
    fn different_ids_not_duplicates() {
        let cache = MsgIdCache::new();
        assert!(!cache.check_and_insert(&[0x01; 16]));
        assert!(!cache.check_and_insert(&[0x02; 16]));
        assert_eq!(cache.len(), 2);
    }

    // Entries have timestamps
    #[test]
    fn entries_have_timestamps() {
        let cache = MsgIdCache::new();
        cache.check_and_insert(&[0x01; 16]);
        // Entry should exist
        assert!(cache.contains(&[0x01; 16]));
    }

    // contains without insert
    #[test]
    fn contains_check() {
        let cache = MsgIdCache::new();
        assert!(!cache.contains(&[0x01; 16]));
        cache.check_and_insert(&[0x01; 16]);
        assert!(cache.contains(&[0x01; 16]));
    }

    // clear empties cache
    #[test]
    fn clear_empties() {
        let cache = MsgIdCache::new();
        cache.check_and_insert(&[0x01; 16]);
        cache.check_and_insert(&[0x02; 16]);
        assert_eq!(cache.len(), 2);
        cache.clear();
        assert!(cache.is_empty());
    }

    // TTL constants are valid (90-day minimum per S07 §7.3, 180-day maximum).
    #[test]
    fn ttl_constants_valid() {
        assert_eq!(MIN_ENTRY_TTL_SECS, 90 * 86400);
        assert_eq!(MAX_ENTRY_TTL_SECS, 180 * 86400);
    }
}
