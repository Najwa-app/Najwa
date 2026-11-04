//! Pseudonym and contact types (§9.2).

use std::fmt;

/// A 32-byte pairwise or group pseudonym (§9.2).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Pseudonym(pub [u8; 32]);

impl Pseudonym {
    /// Create a pseudonym from raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Return the raw 32-byte pseudonym.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for Pseudonym {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Pseudonym({:02x}{:02x}..)", self.0[0], self.0[1])
    }
}

/// Opaque contact identifier for pseudonym table lookups.
///
/// This is a lightweight, copyable ID that can reference a contact record
/// in storage. The actual contact data lives in the storage layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ContactId(pub u64);
