//! Pseudonym lookup table (§9.3).
//!
//! # Security Note — Timing Side-Channel (Open-Items §8.2)
//!
//! `PseudonymTable` uses `HashMap` for O(1) lookup performance. The `Hash`
//! and `PartialEq` implementations on `Pseudonym` are **not** constant-time.
//! An attacker who can observe lookup timing could theoretically distinguish
//! known pseudonyms from unknown ones.
//!
//! **Current risk:** Low. The table is local-only — pseudonyms arrive from
//! already-decrypted messages over Tor, so remote timing observation requires
//! compromising the local device. If the threat model changes (e.g., server-
//! side pseudonym resolution), replace `HashMap` with a linear constant-time
//! scan using `subtle::ConstantTimeEq`.

use std::collections::HashMap;

use super::error::Result;
use super::types::{ContactId, Pseudonym};

/// Fast pseudonym → contact lookup (§9.3).
///
/// Maps their_pseudonym_for_us → contact_id for O(1) message routing.
/// Built from contact storage at startup and updated when contacts are
/// added or removed.
pub struct PseudonymTable {
    /// their_pseudonym_for_us → contact_id
    by_their_pseudo: HashMap<Pseudonym, ContactId>,
}

impl PseudonymTable {
    /// Create an empty table.
    pub fn new() -> Self {
        Self {
            by_their_pseudo: HashMap::new(),
        }
    }

    /// Create a table with pre-populated entries.
    pub fn with_entries(entries: Vec<(Pseudonym, ContactId)>) -> Self {
        let mut table = HashMap::with_capacity(entries.len());
        for (pseudo, id) in entries {
            table.insert(pseudo, id);
        }
        Self {
            by_their_pseudo: table,
        }
    }

    /// Register a contact's pseudonym.
    pub fn insert(&mut self, their_pseudo: Pseudonym, contact_id: ContactId) {
        self.by_their_pseudo.insert(their_pseudo, contact_id);
    }

    /// Remove a contact's pseudonym (e.g., on contact deletion).
    pub fn remove(&mut self, their_pseudo: &Pseudonym) -> Option<ContactId> {
        self.by_their_pseudo.remove(their_pseudo)
    }

    /// Look up a contact by their pseudonym (used when receiving messages) (§9.3).
    pub fn lookup(&self, pseudo: &Pseudonym) -> Option<ContactId> {
        self.by_their_pseudo.get(pseudo).copied()
    }

    /// Reject message from unknown pseudonym (spam protection) (§9.3).
    pub fn is_known(&self, pseudo: &Pseudonym) -> bool {
        self.by_their_pseudo.contains_key(pseudo)
    }

    /// Number of registered contacts.
    pub fn len(&self) -> usize {
        self.by_their_pseudo.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.by_their_pseudo.is_empty()
    }

    /// Validate that a received pseudonym maps to a known contact,
    /// returning the ContactId or an error for unknown pseudonyms.
    pub fn resolve(&self, pseudo: &Pseudonym) -> Result<ContactId> {
        self.lookup(pseudo)
            .ok_or(super::error::PseudonymError::UnknownPseudonym)
    }
}

impl Default for PseudonymTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_table_rejects_all() {
        let table = PseudonymTable::new();
        let pseudo = Pseudonym([0xAA; 32]);
        assert!(!table.is_known(&pseudo));
        assert!(table.lookup(&pseudo).is_none());
        assert!(table.resolve(&pseudo).is_err());
    }

    #[test]
    fn insert_and_lookup() {
        let mut table = PseudonymTable::new();
        let pseudo = Pseudonym([0xBB; 32]);
        let contact = ContactId(42);
        table.insert(pseudo.clone(), contact);

        assert!(table.is_known(&pseudo));
        assert_eq!(table.lookup(&pseudo), Some(contact));
        assert_eq!(table.resolve(&pseudo).unwrap(), contact);
    }

    #[test]
    fn remove_works() {
        let mut table = PseudonymTable::new();
        let pseudo = Pseudonym([0xCC; 32]);
        table.insert(pseudo.clone(), ContactId(1));
        assert!(table.is_known(&pseudo));

        table.remove(&pseudo);
        assert!(!table.is_known(&pseudo));
    }

    #[test]
    fn with_entries() {
        let entries = vec![
            (Pseudonym([0x01; 32]), ContactId(1)),
            (Pseudonym([0x02; 32]), ContactId(2)),
        ];
        let table = PseudonymTable::with_entries(entries);
        assert_eq!(table.len(), 2);
        assert_eq!(table.lookup(&Pseudonym([0x01; 32])), Some(ContactId(1)));
        assert_eq!(table.lookup(&Pseudonym([0x02; 32])), Some(ContactId(2)));
    }

    #[test]
    fn unknown_pseudonym_rejected() {
        let mut table = PseudonymTable::new();
        table.insert(Pseudonym([0xAA; 32]), ContactId(1));

        let unknown = Pseudonym([0xFF; 32]);
        assert!(!table.is_known(&unknown));
        assert!(table.resolve(&unknown).is_err());
    }
}
