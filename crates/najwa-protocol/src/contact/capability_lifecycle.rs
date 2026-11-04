//! Capability lifecycle constants and helpers (S05 §5).
//!
//! Implements:
//! - Ephemeral capability creation with 48h TTL (S05 §5)
//! - Ephemeral → long-term upgrade helper (library code; the app does not call it)
//! - Deposit capability rotation helper (library code; the app does not call it)

use najwa_crypto::prelude::*;

/// Ephemeral capability TTL: 48 hours in seconds.
pub const EPHEMERAL_CAP_TTL_SECS: u64 = 48 * 3600;

/// Capability type: ephemeral (48h TTL, registered at handshake creation).
pub const CAP_TYPE_EPHEMERAL: u8 = 0x01;

/// Capability type: long-term (generated after X3DH success).
pub const CAP_TYPE_LONG_TERM: u8 = 0x02;

/// An ephemeral capability pair with expiry (S05 §5).
#[derive(Debug, Clone)]
pub struct EphemeralCapability {
    /// Deposit capability token (32 bytes).
    pub deposit_cap: [u8; 32],
    /// Fetch capability token (32 bytes).
    pub fetch_cap: [u8; 32],
    /// Unix timestamp when this capability was created.
    pub created_at: u64,
    /// Unix timestamp when this capability expires (created_at + 48h).
    pub expires_at: u64,
    /// Capability type (0x01 = ephemeral).
    pub cap_type: u8,
}

impl EphemeralCapability {
    /// Create a new ephemeral capability pair with 48h TTL.
    pub fn new() -> Self {
        let now = now();
        Self {
            deposit_cap: random_bytes(),
            fetch_cap: random_bytes(),
            created_at: now,
            expires_at: now + EPHEMERAL_CAP_TTL_SECS,
            cap_type: CAP_TYPE_EPHEMERAL,
        }
    }

    /// Check if this capability has expired.
    pub fn is_expired(&self) -> bool {
        now() > self.expires_at
    }
}

impl Default for EphemeralCapability {
    fn default() -> Self {
        Self::new()
    }
}

/// A long-term capability pair (generated after X3DH success).
#[derive(Debug, Clone)]
pub struct LongTermCapability {
    /// Deposit capability token (32 bytes).
    pub deposit_cap: [u8; 32],
    /// Fetch capability token (32 bytes).
    pub fetch_cap: [u8; 32],
    /// Unix timestamp when created.
    pub created_at: u64,
    /// Capability type (0x02 = long-term).
    pub cap_type: u8,
}

impl LongTermCapability {
    /// Generate a new long-term capability pair.
    pub fn new() -> Self {
        Self {
            deposit_cap: random_bytes(),
            fetch_cap: random_bytes(),
            created_at: now(),
            cap_type: CAP_TYPE_LONG_TERM,
        }
    }
}

impl Default for LongTermCapability {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of a capability upgrade from ephemeral to long-term.
#[derive(Debug, Clone)]
pub struct CapabilityUpgrade {
    /// The new long-term capability to register on the mailbox.
    pub long_term: LongTermCapability,
    /// The old ephemeral capability to deactivate after switchover.
    pub old_ephemeral_deposit: [u8; 32],
    /// The old ephemeral fetch capability.
    pub old_ephemeral_fetch: [u8; 32],
}

/// Upgrade an ephemeral capability to long-term after X3DH success.
///
/// The caller should:
/// 1. Register the new long-term capability on the mailbox server
/// 2. Send a MailboxUpdate (0x20) control message to the contact
/// 3. Wait for confirmation
/// 4. Deactivate the old ephemeral capability
pub fn upgrade_to_long_term(ephemeral: &EphemeralCapability) -> CapabilityUpgrade {
    CapabilityUpgrade {
        long_term: LongTermCapability::new(),
        old_ephemeral_deposit: ephemeral.deposit_cap,
        old_ephemeral_fetch: ephemeral.fetch_cap,
    }
}

/// Rotate a deposit capability.
///
/// Returns a new deposit capability. The caller should:
/// 1. Register the new cap on the mailbox server
/// 2. Send a MailboxUpdate (0x20) to the contact with the new cap
/// 3. Accept messages on both old and new caps during transition
/// 4. Deactivate the old cap after confirmation
pub fn rotate_deposit_capability() -> [u8; 32] {
    random_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ephemeral_cap_has_48h_ttl() {
        let cap = EphemeralCapability::new();
        assert_eq!(cap.expires_at - cap.created_at, EPHEMERAL_CAP_TTL_SECS);
        assert_eq!(cap.cap_type, CAP_TYPE_EPHEMERAL);
        assert!(!cap.is_expired());
    }

    #[test]
    fn long_term_cap_type() {
        let cap = LongTermCapability::new();
        assert_eq!(cap.cap_type, CAP_TYPE_LONG_TERM);
    }

    #[test]
    fn upgrade_produces_new_caps() {
        let ephemeral = EphemeralCapability::new();
        let upgrade = upgrade_to_long_term(&ephemeral);
        assert_eq!(upgrade.old_ephemeral_deposit, ephemeral.deposit_cap);
        assert_ne!(upgrade.long_term.deposit_cap, ephemeral.deposit_cap);
        assert_eq!(upgrade.long_term.cap_type, CAP_TYPE_LONG_TERM);
    }

    #[test]
    fn rotate_produces_random_cap() {
        let cap1 = rotate_deposit_capability();
        let cap2 = rotate_deposit_capability();
        assert_ne!(cap1, cap2);
    }
}
