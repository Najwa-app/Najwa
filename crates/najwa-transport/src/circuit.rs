//! Tor circuit management and isolation.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Global circuit ID counter.
static NEXT_CIRCUIT_ID: AtomicU64 = AtomicU64::new(1);

/// Determines how a Tor circuit is isolated (S04 §4.1).
///
/// Different isolation keys guarantee different Tor circuits,
/// preventing cross-contact/mailbox correlation (S04 §4.1.1).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CircuitIsolation {
    /// Per-mailbox `.onion` — one circuit per mailbox server.
    ByMailbox(String),
    /// Per-contact pseudonym — one circuit per contact.
    ByContact([u8; 32]),
    /// Responsive-mode attachment, scoped to one file, contact and destination.
    /// Timing privacy deposits continue to use `OneShot`.
    FileTransfer([u8; 32]),
    /// Per-mailbox cover circuits (S04 §4.1, S10 §4.2–4.3) — one token per
    /// mailbox `.onion`. Cover streams to different mailboxes MUST NOT share a
    /// circuit, or guard-side correlation links streams absorption keeps apart.
    CoverTraffic(String),
    /// Single-use circuit (discarded after one request).
    OneShot,
}

impl CircuitIsolation {
    /// Return a stable string key for reusable isolation types.
    /// Returns `None` for `OneShot` (never reused).
    pub(crate) fn reuse_key(&self) -> Option<String> {
        match self {
            Self::ByMailbox(m) => Some(format!("mailbox:{m}")),
            Self::ByContact(c) => Some(format!("contact:{}", hex::encode(c))),
            Self::FileTransfer(f) => Some(format!("file:{}", hex::encode(f))),
            Self::CoverTraffic(m) => Some(format!("cover:{m}")),
            Self::OneShot => None,
        }
    }
}

/// Handle to an active Tor circuit.
pub struct CircuitHandle {
    /// Unique circuit identifier.
    pub id: u64,
    /// Isolation category this circuit belongs to.
    pub isolation: CircuitIsolation,
    /// When this circuit was created.
    pub created_at: Instant,
}

impl CircuitHandle {
    /// Maximum age of a circuit before rotation (S04 §4.4: 10 minutes).
    pub const MAX_AGE_SECS: u64 = 600;

    /// Create a dummy handle for testing (direct HTTP, no Tor).
    pub fn dummy() -> Self {
        Self {
            id: 0,
            isolation: CircuitIsolation::CoverTraffic(String::new()),
            created_at: Instant::now(),
        }
    }

    /// Create a new handle with a fresh ID.
    pub fn new(isolation: CircuitIsolation) -> Self {
        Self {
            id: NEXT_CIRCUIT_ID.fetch_add(1, Ordering::Relaxed),
            isolation,
            created_at: Instant::now(),
        }
    }

    /// Check if this circuit should be rotated due to age.
    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed().as_secs() >= Self::MAX_AGE_SECS
    }
}

/// Hex-encode helper (avoids pulling in the `hex` crate).
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn attachment_reuse_is_domain_separated_and_rotates_with_the_normal_age_limit() {
        let file=CircuitIsolation::FileTransfer([7;32]);
        assert_eq!(file.reuse_key(),file.clone().reuse_key());
        assert_ne!(file.reuse_key(),CircuitIsolation::FileTransfer([8;32]).reuse_key());
        assert_ne!(file.reuse_key(),CircuitIsolation::ByContact([7;32]).reuse_key());
        assert_ne!(file.reuse_key(),CircuitIsolation::ByMailbox("file".into()).reuse_key());
        assert_ne!(file.reuse_key(),CircuitIsolation::CoverTraffic("file".into()).reuse_key());
        assert_eq!(CircuitIsolation::OneShot.reuse_key(),None);
        let mut handle=CircuitHandle::new(file);
        assert!(!handle.is_expired());
        handle.created_at=Instant::now()-std::time::Duration::from_secs(CircuitHandle::MAX_AGE_SECS);
        assert!(handle.is_expired());
    }
}
