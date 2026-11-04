//! Production S12 storage adapter. All deadlines are local milliseconds.
use super::{DisappearingStorage, ExpiredMessage};
use crate::types::{ContactId, Message, MessageId};
use async_trait::async_trait;
use najwa_storage::database::SqliteStorage;
use std::sync::Arc;

#[async_trait]
impl DisappearingStorage for Arc<SqliteStorage> {
    async fn set_conversation_timer(
        &self,
        contact_id: ContactId,
        timer_secs: Option<u32>,
    ) -> Result<(), String> {
        self.as_ref()
            .set_conversation_timer(contact_id as i64, timer_secs)
            .map_err(|e| e.to_string())
    }
    async fn get_conversation_timer(&self, contact_id: ContactId) -> Result<Option<u32>, String> {
        self.as_ref()
            .get_conversation_timer(contact_id as i64)
            .map_err(|e| e.to_string())
    }
    async fn set_conversation_timer_setting(
        &self,
        contact_id: ContactId,
        timer_secs: Option<u32>,
        set_at: u64,
        setter_ik: &[u8; 32],
    ) -> Result<(), String> {
        self.as_ref()
            .set_conversation_timer_setting(contact_id as i64, timer_secs, set_at, setter_ik)
            .map_err(|e| e.to_string())
    }
    async fn get_conversation_timer_setting(
        &self,
        contact_id: ContactId,
    ) -> Result<Option<(Option<u32>, u64, [u8; 32])>, String> {
        self.as_ref()
            .get_conversation_timer_setting(contact_id as i64)
            .map_err(|e| e.to_string())
    }
    async fn set_message_disappear_pending(
        &self,
        msg_id: MessageId,
        timer_secs: u32,
    ) -> Result<(), String> {
        self.as_ref()
            .set_message_disappear_pending(msg_id, timer_secs)
            .map_err(|e| e.to_string())
    }
    async fn get_message_disappear_pending(
        &self,
        msg_id: MessageId,
    ) -> Result<Option<u32>, String> {
        self.as_ref()
            .get_message_disappear_pending(msg_id)
            .map_err(|e| e.to_string())
    }
    async fn set_message_disappear_at(
        &self,
        msg_id: MessageId,
        disappear_at: u64,
    ) -> Result<(), String> {
        self.as_ref()
            .set_message_disappear_at(msg_id, disappear_at)
            .map_err(|e| e.to_string())
    }
    async fn apply_fallback_disappear_timers(&self, cutoff: u64) -> Result<u32, String> {
        self.as_ref()
            .apply_fallback_disappear_timers(cutoff)
            .map_err(|e| e.to_string())
    }
    async fn get_expired_disappearing_messages(
        &self,
        now: u64,
    ) -> Result<Vec<ExpiredMessage>, String> {
        self.as_ref()
            .get_expired_disappearing_messages(now)
            .map(|rows| {
                rows.into_iter()
                    .map(|m| ExpiredMessage {
                        id: m.id,
                        msg_id: m.msg_id,
                        file_path: m.file_path,
                    })
                    .collect()
            })
            .map_err(|e| e.to_string())
    }
    async fn overwrite_message_content(
        &self,
        msg_id: MessageId,
        zeroed: &[u8],
    ) -> Result<(), String> {
        self.as_ref()
            .overwrite_message_content(msg_id, zeroed)
            .map_err(|e| e.to_string())
    }
    async fn delete_message(&self, msg_id: MessageId) -> Result<(), String> {
        self.as_ref()
            .delete_message(msg_id)
            .map_err(|e| e.to_string())
    }
    async fn purge_expired_volatile_keys(&self, now: u64) -> Result<u32, String> {
        self.as_ref()
            .purge_expired_volatile_keys(now)
            .map_err(|e| e.to_string())
    }
    async fn wal_checkpoint(&self) -> Result<(), String> {
        self.as_ref().wal_checkpoint().map_err(|e| e.to_string())
    }
    async fn search_messages_excluding_disappearing(
        &self,
        query: &str,
        _now: u64,
    ) -> Result<Vec<Message>, String> {
        self.as_ref()
            .list_non_disappearing_messages(Some(query))
            .map(|rows| {
                rows.iter()
                    .map(crate::bridge::storage_to_core_message)
                    .collect()
            })
            .map_err(|e| e.to_string())
    }
    async fn get_messages_for_backup(&self, _now: u64) -> Result<Vec<Message>, String> {
        self.as_ref()
            .list_non_disappearing_messages(None)
            .map(|rows| {
                rows.iter()
                    .map(crate::bridge::storage_to_core_message)
                    .collect()
            })
            .map_err(|e| e.to_string())
    }
}
