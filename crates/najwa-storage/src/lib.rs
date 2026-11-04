//! Encrypted storage layer (SQLCipher) for Najwa (S03).
//!
//! Single source of truth for all persistent data operations.
//!
//! Provides:
//! - SQLCipher database with hardening pragmas ([`database`]) — S03 §4
//! - Consolidated schema version 2 (`schema.sql`), created and checked on open ([`database`]) — S03 §5, §8
//! - CRUD for contacts, messages, prekeys, mailboxes — S03 §5.2–§5.11
//! - Message ID deduplication cache ([`messages`]) — S03 §5.7
//! - Per-row field encryption for sensitive columns ([`encrypted_field`]) — S03 §7
//! - WAL encryption verification and temp file cleanup ([`hardening`]) — S03 §4.3–§4.4
//! - Settings, identity history, onion pinning ([`settings`]) — S03 §5.14–§5.16
//! - Type aliases: `ContactId`, `MessageId`, `MailboxId` ([`types`])

pub mod contacts;
mod browser;
pub mod contact_establishment;
pub mod database;
pub mod encrypted_field;
pub mod error;
pub mod hardening;
pub mod introductions;
pub mod keys;
pub mod prekey_lifecycle;
pub mod mailboxes;
pub mod messages;
pub mod messaging;
pub mod read_receipts;
pub mod transfers;
pub mod settings;
pub mod types;
mod snapshot;

/// Re-exports for convenient usage.
pub mod prelude {
    pub use crate::database::{derive_db_key, SqliteStorage};
    pub use crate::encrypted_field::{derive_row_key, EncryptedField};
    pub use crate::error::{Result, StorageError};
    pub use crate::hardening::{
        apply_hardening_pragmas, cleanup_temp_files, verify_hardening, verify_wal_encryption,
    };
    pub use crate::types::*;
}
