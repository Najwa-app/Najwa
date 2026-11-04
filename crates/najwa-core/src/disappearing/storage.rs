//! Storage trait extension for disappearing messages (S12 §7).

use async_trait::async_trait;

use crate::types::{ContactId, MessageId};

/// A message that has expired and needs secure deletion.
#[derive(Debug, Clone)]
pub struct ExpiredMessage {
    /// Database row ID.
    pub id: MessageId,
    /// Transport ID identifying the per-message decryption key.
    pub msg_id: [u8; 16],
    /// Optional path to associated media file.
    pub file_path: Option<String>,
}

/// Storage operations specific to disappearing messages.
///
/// Extends the base `CoreStorage` trait with disappearing-message-specific
/// queries and mutations.
#[async_trait]
pub trait DisappearingStorage: Send + Sync {
    // -- Conversation timer (S12 §2.2) --

    /// Set or clear the disappearing timer for a conversation.
    async fn set_conversation_timer(
        &self,
        contact_id: ContactId,
        timer_secs: Option<u32>,
    ) -> std::result::Result<(), String>;

    /// Get the current disappearing timer for a conversation.
    async fn get_conversation_timer(
        &self,
        contact_id: ContactId,
    ) -> std::result::Result<Option<u32>, String>;

    /// Persist the full S12 §2.2 timer setting (value + `set_at` + setter IK).
    async fn set_conversation_timer_setting(
        &self,
        contact_id: ContactId,
        timer_secs: Option<u32>,
        set_at: u64,
        setter_ik: &[u8; 32],
    ) -> std::result::Result<(), String>;

    /// Read the full S12 §2.2 timer setting: `(timer_secs, set_at, setter_ik)`.
    async fn get_conversation_timer_setting(
        &self,
        contact_id: ContactId,
    ) -> std::result::Result<Option<(Option<u32>, u64, [u8; 32])>, String>;

    // -- Sender-side scheduling (S12 §3.1) --

    /// Mark a sent message as pending disappearance (timer starts on ACK).
    async fn set_message_disappear_pending(
        &self,
        msg_id: MessageId,
        timer_secs: u32,
    ) -> std::result::Result<(), String>;

    /// Get the pending disappear timer for a sent message (if ACK not yet received).
    async fn get_message_disappear_pending(
        &self,
        msg_id: MessageId,
    ) -> std::result::Result<Option<u32>, String>;

    /// Set the absolute disappear_at timestamp for a message.
    async fn set_message_disappear_at(
        &self,
        msg_id: MessageId,
        disappear_at: u64,
    ) -> std::result::Result<(), String>;

    /// Apply 24h fallback: for messages pending disappearance that were sent
    /// before `cutoff`, set their disappear_at = now + pending_timer_secs.
    /// Returns the number of messages updated.
    async fn apply_fallback_disappear_timers(
        &self,
        cutoff: u64,
    ) -> std::result::Result<u32, String>;

    // -- Secure deletion (S12 §5.1) --

    /// Get all messages where disappear_at <= now.
    async fn get_expired_disappearing_messages(
        &self,
        now: u64,
    ) -> std::result::Result<Vec<ExpiredMessage>, String>;

    /// Overwrite message content with empty bytes (secure erase step 1).
    async fn overwrite_message_content(
        &self,
        msg_id: MessageId,
        zeroed: &[u8],
    ) -> std::result::Result<(), String>;

    /// Delete a message row from the database (secure erase step 3).
    async fn delete_message(&self, msg_id: MessageId) -> std::result::Result<(), String>;

    /// S12 §4.3/§7: delete every persisted volatile key whose `expires_at <= now`.
    /// Returns the number purged. Run on unlock (before restoring keys to memory)
    /// and by the background cleanup pass, so an expired disappearing message's
    /// key never re-enters memory (the §4.4 residual-key invariant).
    async fn purge_expired_volatile_keys(&self, now: u64) -> std::result::Result<u32, String>;

    /// WAL checkpoint to flush overwrites to disk (S12 §5.1 step 6).
    async fn wal_checkpoint(&self) -> std::result::Result<(), String>;

    // -- Search & backup exclusion (S12 §9.1, §9.2) --

    /// Search messages, excluding those with a disappear_at timestamp set.
    async fn search_messages_excluding_disappearing(
        &self,
        query: &str,
        now: u64,
    ) -> std::result::Result<Vec<crate::types::Message>, String>;

    /// Get messages for backup export, excluding those with disappear_at set.
    async fn get_messages_for_backup(
        &self,
        now: u64,
    ) -> std::result::Result<Vec<crate::types::Message>, String>;
}
