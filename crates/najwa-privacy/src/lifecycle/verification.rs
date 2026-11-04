//! Library mailbox server verification and capability expiration monitoring;
//! the application does not use this module.
//!
//! Extends S05's onion address pinning with lifecycle-aware
//! capability expiration monitoring. The core pin-on-first-use and
//! verification logic lives in `najwa-protocol::mailbox::pinning` —
//! this module wraps it with account lifecycle awareness.
//!
//! See S05 pinning for onion address pinning requirements.

use najwa_crypto::hash::sha256;
use najwa_crypto::time::now;

/// Result of an onion address pin verification (mirrors S05's PinVerification).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinStatus {
    /// First time seeing this address — pin was created.
    FirstUse,
    /// Pin matches — address is trusted.
    Verified,
    /// Pin has changed — possible MITM or server migration.
    Changed {
        /// Unix timestamp when the address was first pinned.
        first_seen: u64,
        /// Unix timestamp when the pin was last verified.
        last_verified: u64,
    },
}

/// Status of a mailbox capability's expiration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExpirationStatus {
    /// Capability is active and not near expiration.
    Active,
    /// Capability is nearing expiration (inactive >25 days).
    ExpirationWarning {
        /// Days remaining before capability expires.
        days_remaining: u32,
    },
    /// Capability has expired (inactive >30 days).
    Expired,
}

/// A stored onion address pin record.
#[derive(Debug, Clone)]
pub struct OnionPinRecord {
    /// The onion address.
    pub onion_address: String,
    /// Unix timestamp when this address was first seen.
    pub first_seen: u64,
    /// Unix timestamp when the pin was last verified.
    pub last_verified: u64,
    /// SHA-256 hash of the onion address bytes.
    pub pin_hash: [u8; 32],
}

/// Mailbox verifier with lifecycle awareness.
///
/// Wraps onion address pinning and adds capability
/// expiration monitoring for account lifecycle management.
pub struct MailboxVerifier {
    /// Stored onion pins (in-memory cache; real impl persists via storage).
    pins: std::collections::HashMap<String, OnionPinRecord>,
}

impl MailboxVerifier {
    /// Create a new mailbox verifier.
    pub fn new() -> Self {
        Self {
            pins: std::collections::HashMap::new(),
        }
    }

    /// Create a verifier with pre-loaded pins (e.g. from persistent storage).
    pub fn with_pins(pins: Vec<OnionPinRecord>) -> Self {
        let map = pins
            .into_iter()
            .map(|p| (p.onion_address.clone(), p))
            .collect();
        Self { pins: map }
    }

    /// Verify onion address pin on connection (S05 pinning).
    ///
    /// - **First use**: creates and stores a new pin, returns `FirstUse`.
    /// - **Pin matches**: updates `last_verified`, returns `Verified`.
    /// - **Pin changed**: returns `Changed` with original timestamps.
    ///
    /// This wraps S05's pin-on-first-use logic with lifecycle tracking.
    pub fn verify_on_connect(&mut self, onion_address: &str) -> PinStatus {
        let current_hash = sha256(onion_address.as_bytes());

        match self.pins.get_mut(onion_address) {
            None => {
                // First use — pin it
                let pin = OnionPinRecord {
                    onion_address: onion_address.to_string(),
                    first_seen: now(),
                    last_verified: now(),
                    pin_hash: current_hash,
                };
                self.pins.insert(onion_address.to_string(), pin);
                tracing::info!(address = onion_address, "Onion address pinned (first use)");
                PinStatus::FirstUse
            }
            Some(existing) => {
                if existing.pin_hash == current_hash {
                    // Pin matches — update last_verified
                    existing.last_verified = now();
                    tracing::debug!(address = onion_address, "Onion pin verified");
                    PinStatus::Verified
                } else {
                    // PIN CHANGE — possible MITM!
                    tracing::warn!(
                        address = onion_address,
                        first_seen = existing.first_seen,
                        "Onion address pin CHANGED — possible MITM"
                    );
                    PinStatus::Changed {
                        first_seen: existing.first_seen,
                        last_verified: existing.last_verified,
                    }
                }
            }
        }
    }

    /// Check capability expiration based on last activity.
    ///
    /// Mailbox capabilities expire after 30 days of inactivity.
    /// Returns a warning when >25 days inactive.
    ///
    /// `last_activity_ts` is the Unix timestamp of last mailbox activity.
    pub fn check_capability_expiration(&self, last_activity_ts: u64) -> ExpirationStatus {
        let current = now();

        if current <= last_activity_ts {
            return ExpirationStatus::Active;
        }

        let days_inactive = (current - last_activity_ts) / 86400;

        if days_inactive > 30 {
            ExpirationStatus::Expired
        } else if days_inactive > 25 {
            let days_remaining = 30u64.saturating_sub(days_inactive) as u32;
            ExpirationStatus::ExpirationWarning { days_remaining }
        } else {
            ExpirationStatus::Active
        }
    }

    /// Get a stored pin record for an onion address, if any.
    pub fn get_pin(&self, onion_address: &str) -> Option<&OnionPinRecord> {
        self.pins.get(onion_address)
    }

    /// Get the number of stored pins.
    pub fn pin_count(&self) -> usize {
        self.pins.len()
    }

    /// Remove a pin (e.g. on account deletion).
    pub fn remove_pin(&mut self, onion_address: &str) -> bool {
        self.pins.remove(onion_address).is_some()
    }

    /// Remove all pins (e.g. on account deletion).
    pub fn clear_pins(&mut self) {
        self.pins.clear();
    }
}

impl Default for MailboxVerifier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_connect_creates_pin() {
        let mut verifier = MailboxVerifier::new();
        let status = verifier.verify_on_connect("abc123def456.onion");
        assert_eq!(status, PinStatus::FirstUse);
        assert_eq!(verifier.pin_count(), 1);
    }

    #[test]
    fn second_connect_verifies_pin() {
        let mut verifier = MailboxVerifier::new();

        let s1 = verifier.verify_on_connect("abc123def456.onion");
        assert_eq!(s1, PinStatus::FirstUse);

        let s2 = verifier.verify_on_connect("abc123def456.onion");
        assert_eq!(s2, PinStatus::Verified);
    }

    #[test]
    fn changed_pin_detected() {
        let mut verifier = MailboxVerifier::new();

        // Insert a pin with a different hash (simulating address change)
        let fake_pin = OnionPinRecord {
            onion_address: "abc123def456.onion".to_string(),
            first_seen: 1000,
            last_verified: 2000,
            pin_hash: [0xFF; 32], // Wrong hash
        };
        verifier
            .pins
            .insert("abc123def456.onion".to_string(), fake_pin);

        let status = verifier.verify_on_connect("abc123def456.onion");
        match status {
            PinStatus::Changed {
                first_seen,
                last_verified,
            } => {
                assert_eq!(first_seen, 1000);
                assert_eq!(last_verified, 2000);
            }
            _ => panic!("expected Changed, got {:?}", status),
        }
    }

    #[test]
    fn with_pins_constructor() {
        let pins = vec![OnionPinRecord {
            onion_address: "test.onion".to_string(),
            first_seen: 100,
            last_verified: 200,
            pin_hash: sha256(b"test.onion"),
        }];
        let verifier = MailboxVerifier::with_pins(pins);
        assert_eq!(verifier.pin_count(), 1);
        assert!(verifier.get_pin("test.onion").is_some());
    }

    #[test]
    fn capability_active_when_recent() {
        let verifier = MailboxVerifier::new();
        // Activity 1 day ago
        let last_activity = now() - 86400;
        let status = verifier.check_capability_expiration(last_activity);
        assert_eq!(status, ExpirationStatus::Active);
    }

    #[test]
    fn capability_warning_when_nearing_expiry() {
        let verifier = MailboxVerifier::new();
        // Activity 27 days ago
        let last_activity = now() - (27 * 86400);
        let status = verifier.check_capability_expiration(last_activity);
        match status {
            ExpirationStatus::ExpirationWarning { days_remaining } => {
                assert!(days_remaining <= 5);
            }
            _ => panic!("expected ExpirationWarning, got {:?}", status),
        }
    }

    #[test]
    fn capability_expired_after_30_days() {
        let verifier = MailboxVerifier::new();
        // Activity 31 days ago
        let last_activity = now() - (31 * 86400);
        let status = verifier.check_capability_expiration(last_activity);
        assert_eq!(status, ExpirationStatus::Expired);
    }

    #[test]
    fn capability_active_when_future_timestamp() {
        let verifier = MailboxVerifier::new();
        // Future timestamp (clock skew)
        let last_activity = now() + 1000;
        let status = verifier.check_capability_expiration(last_activity);
        assert_eq!(status, ExpirationStatus::Active);
    }

    #[test]
    fn remove_pin_works() {
        let mut verifier = MailboxVerifier::new();
        verifier.verify_on_connect("test.onion");
        assert_eq!(verifier.pin_count(), 1);

        assert!(verifier.remove_pin("test.onion"));
        assert_eq!(verifier.pin_count(), 0);

        // Removing again returns false
        assert!(!verifier.remove_pin("test.onion"));
    }

    #[test]
    fn clear_pins_removes_all() {
        let mut verifier = MailboxVerifier::new();
        verifier.verify_on_connect("a.onion");
        verifier.verify_on_connect("b.onion");
        assert_eq!(verifier.pin_count(), 2);

        verifier.clear_pins();
        assert_eq!(verifier.pin_count(), 0);
    }

    #[test]
    fn multiple_addresses_independent() {
        let mut verifier = MailboxVerifier::new();

        let s1 = verifier.verify_on_connect("first.onion");
        assert_eq!(s1, PinStatus::FirstUse);

        let s2 = verifier.verify_on_connect("second.onion");
        assert_eq!(s2, PinStatus::FirstUse);

        // First address should still verify
        let s3 = verifier.verify_on_connect("first.onion");
        assert_eq!(s3, PinStatus::Verified);

        assert_eq!(verifier.pin_count(), 2);
    }
}
