//! Disappearing messages timer and deletion (S12).
//!
//! Provides:
//! - Per-conversation timer configuration via control messages (S12 §2)
//! - Sender-side timer (starts on ACK or 24h fallback) (S12 §3.1)
//! - Recipient-side timer (starts on display or decryption) (S12 §3.2)
//! - Secure deletion: overwrite content, not just mark deleted (S12 §5)
//! - Background cleanup task (S12 §6)
//! - Search and backup exclusion for disappearing messages (S12 §9.1, §9.2)

pub mod cleanup;
pub mod config;
pub mod delete;
pub mod ephemeral;
pub mod error;
pub mod lifecycle;
pub mod storage;
pub mod volatile_cache;
mod sqlite;

// -- Public re-exports -------------------------------------------------------

pub use cleanup::{DisappearingCleanupTask, DEFAULT_CLEANUP_INTERVAL_SECS};
pub use config::{
    timer_below_minimum, timer_setting_wins, ConversationTimerSetting, DisappearTimer, TimerSetBy,
    TimerSetting, MIN_TIMER_SECS, RECIPIENT_FALLBACK_SECS, SENDER_FALLBACK_SECS,
};
pub use delete::{delete_expired_messages, secure_delete_file};
pub use ephemeral::{open_sealed_content, seal_content, Opened};
pub use error::{DisappearError, Result};
pub use lifecycle::{DisappearingMessageManager, FALLBACK_TIMEOUT_MS};
pub use storage::{DisappearingStorage, ExpiredMessage};
pub use volatile_cache::VolatileKeyCache;

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use async_trait::async_trait;

    use super::config::*;
    use super::delete::delete_expired_messages;
    use super::lifecycle::*;
    use super::storage::*;
    use crate::types::{Direction, Message, MessageId, MessageStatus};

    // -----------------------------------------------------------------------
    // Mock DisappearingStorage
    // -----------------------------------------------------------------------

    /// (timer_secs, set_at, setter_ik) — S12 §2.2.
    type TimerSettingTuple = (Option<u32>, u64, [u8; 32]);
    struct MockDisappearingStorage {
        /// contact_id -> (timer_secs, set_at, setter_ik) — the full S12 §2.2
        /// setting, so merge behaviour is exercised, not just the value.
        timers: Mutex<HashMap<u64, TimerSettingTuple>>,
        pending: Mutex<HashMap<MessageId, u32>>,
        disappear_at: Mutex<HashMap<MessageId, u64>>,
        messages: Mutex<HashMap<MessageId, MockMessage>>,
        wal_checkpointed: Mutex<bool>,
        /// Persisted volatile keys: id -> expires_at (S12 §4.3 purge test surface).
        volatile_keys: Mutex<HashMap<MessageId, u64>>,
        fail_overwrite: bool,
    }

    #[derive(Clone)]
    struct MockMessage {
        id: MessageId,
        content: Vec<u8>,
        file_path: Option<String>,
        sent_at: u64,
    }

    impl MockDisappearingStorage {
        fn new() -> Self {
            Self {
                timers: Mutex::new(HashMap::new()),
                pending: Mutex::new(HashMap::new()),
                disappear_at: Mutex::new(HashMap::new()),
                messages: Mutex::new(HashMap::new()),
                wal_checkpointed: Mutex::new(false),
                volatile_keys: Mutex::new(HashMap::new()),
                fail_overwrite: false,
            }
        }

        fn add_volatile_key(&self, id: MessageId, expires_at: u64) {
            self.volatile_keys.lock().unwrap().insert(id, expires_at);
        }

        fn volatile_key_count(&self) -> usize {
            self.volatile_keys.lock().unwrap().len()
        }

        fn add_message(
            &self,
            id: MessageId,
            content: &[u8],
            file_path: Option<String>,
            sent_at: u64,
        ) {
            self.messages.lock().unwrap().insert(
                id,
                MockMessage {
                    id,
                    content: content.to_vec(),
                    file_path,
                    sent_at,
                },
            );
        }

        fn was_wal_checkpointed(&self) -> bool {
            *self.wal_checkpointed.lock().unwrap()
        }

        fn message_exists(&self, id: MessageId) -> bool {
            self.messages.lock().unwrap().contains_key(&id)
        }

        fn get_disappear_at(&self, id: MessageId) -> Option<u64> {
            self.disappear_at.lock().unwrap().get(&id).copied()
        }
    }

    #[async_trait]
    impl DisappearingStorage for MockDisappearingStorage {
        async fn set_conversation_timer(
            &self,
            contact_id: u64,
            timer_secs: Option<u32>,
        ) -> std::result::Result<(), String> {
            self.timers.lock().unwrap().insert(
                contact_id,
                (timer_secs, najwa_crypto::prelude::now(), [0u8; 32]),
            );
            Ok(())
        }

        async fn get_conversation_timer(
            &self,
            contact_id: u64,
        ) -> std::result::Result<Option<u32>, String> {
            Ok(self
                .timers
                .lock()
                .unwrap()
                .get(&contact_id)
                .and_then(|(timer_secs, _, _)| *timer_secs))
        }

        async fn set_conversation_timer_setting(
            &self,
            contact_id: u64,
            timer_secs: Option<u32>,
            set_at: u64,
            setter_ik: &[u8; 32],
        ) -> std::result::Result<(), String> {
            self.timers
                .lock()
                .unwrap()
                .insert(contact_id, (timer_secs, set_at, *setter_ik));
            Ok(())
        }

        async fn get_conversation_timer_setting(
            &self,
            contact_id: u64,
        ) -> std::result::Result<Option<(Option<u32>, u64, [u8; 32])>, String> {
            Ok(self.timers.lock().unwrap().get(&contact_id).copied())
        }

        async fn set_message_disappear_pending(
            &self,
            msg_id: MessageId,
            timer_secs: u32,
        ) -> std::result::Result<(), String> {
            self.pending.lock().unwrap().insert(msg_id, timer_secs);
            Ok(())
        }

        async fn get_message_disappear_pending(
            &self,
            msg_id: MessageId,
        ) -> std::result::Result<Option<u32>, String> {
            Ok(self.pending.lock().unwrap().get(&msg_id).copied())
        }

        async fn set_message_disappear_at(
            &self,
            msg_id: MessageId,
            disappear_at: u64,
        ) -> std::result::Result<(), String> {
            self.disappear_at
                .lock()
                .unwrap()
                .insert(msg_id, disappear_at);
            Ok(())
        }

        async fn apply_fallback_disappear_timers(
            &self,
            cutoff: u64,
        ) -> std::result::Result<u32, String> {
            let pending = self.pending.lock().unwrap().clone();
            let messages = self.messages.lock().unwrap();
            let mut count = 0u32;

            for (msg_id, timer_secs) in &pending {
                // Check if message was sent before cutoff
                if let Some(msg) = messages.get(msg_id) {
                    if msg.sent_at <= cutoff {
                        let now = najwa_crypto::prelude::now();
                        self.disappear_at
                            .lock()
                            .unwrap()
                            .insert(*msg_id, now + *timer_secs as u64);
                        count += 1;
                    }
                }
            }
            // Remove applied entries from pending
            for msg_id in pending.keys() {
                if let Some(msg) = messages.get(msg_id) {
                    if msg.sent_at <= cutoff {
                        self.pending.lock().unwrap().remove(msg_id);
                    }
                }
            }
            Ok(count)
        }

        async fn get_expired_disappearing_messages(
            &self,
            now: u64,
        ) -> std::result::Result<Vec<ExpiredMessage>, String> {
            let disappear_map = self.disappear_at.lock().unwrap();
            let messages = self.messages.lock().unwrap();
            let mut expired = Vec::new();

            for (msg_id, &da) in disappear_map.iter() {
                if da <= now {
                    if let Some(msg) = messages.get(msg_id) {
                        expired.push(ExpiredMessage {
                            id: msg.id,
                            msg_id: [msg.id as u8; 16],
                            file_path: msg.file_path.clone(),
                        });
                    }
                }
            }
            Ok(expired)
        }

        async fn overwrite_message_content(
            &self,
            msg_id: MessageId,
            zeroed: &[u8],
        ) -> std::result::Result<(), String> {
            if self.fail_overwrite { return Err("injected overwrite failure".into()); }
            if let Some(msg) = self.messages.lock().unwrap().get_mut(&msg_id) {
                msg.content = zeroed.to_vec();
            }
            Ok(())
        }

        async fn delete_message(&self, msg_id: MessageId) -> std::result::Result<(), String> {
            self.messages.lock().unwrap().remove(&msg_id);
            self.disappear_at.lock().unwrap().remove(&msg_id);
            self.pending.lock().unwrap().remove(&msg_id);
            Ok(())
        }

        async fn purge_expired_volatile_keys(&self, now: u64) -> std::result::Result<u32, String> {
            let mut keys = self.volatile_keys.lock().unwrap();
            let before = keys.len();
            keys.retain(|_, &mut expires_at| expires_at > now);
            Ok((before - keys.len()) as u32)
        }

        async fn wal_checkpoint(&self) -> std::result::Result<(), String> {
            *self.wal_checkpointed.lock().unwrap() = true;
            Ok(())
        }

        async fn search_messages_excluding_disappearing(
            &self,
            query: &str,
            _now: u64,
        ) -> std::result::Result<Vec<Message>, String> {
            let messages = self.messages.lock().unwrap();
            let disappear_map = self.disappear_at.lock().unwrap();
            let results: Vec<Message> = messages
                .values()
                .filter(|m| {
                    !disappear_map.contains_key(&m.id)
                        && String::from_utf8_lossy(&m.content).contains(query)
                })
                .map(|m| Message {
                    id: m.id,
                    contact_id: 1,
                    msg_id: [0; 16],
                    direction: Direction::Sent,
                    content_type: 0x01,
                    flags: 0,
                    content: m.content.clone(),
                    timestamp: m.sent_at,
                    status: MessageStatus::Sent,
                    ratchet_index: None,
                })
                .collect();
            Ok(results)
        }

        async fn get_messages_for_backup(
            &self,
            _now: u64,
        ) -> std::result::Result<Vec<Message>, String> {
            let messages = self.messages.lock().unwrap();
            let disappear_map = self.disappear_at.lock().unwrap();
            let results: Vec<Message> = messages
                .values()
                .filter(|m| !disappear_map.contains_key(&m.id))
                .map(|m| Message {
                    id: m.id,
                    contact_id: 1,
                    msg_id: [0; 16],
                    direction: Direction::Sent,
                    content_type: 0x01,
                    flags: 0,
                    content: m.content.clone(),
                    timestamp: m.sent_at,
                    status: MessageStatus::Sent,
                    ratchet_index: None,
                })
                .collect();
            Ok(results)
        }
    }

    // -----------------------------------------------------------------------
    // S12 §2.1: DisappearTimer tests
    // -----------------------------------------------------------------------

    #[test]
    fn timer_presets_all_values() {
        assert_eq!(DisappearTimer::Off.to_secs(), None);
        assert_eq!(DisappearTimer::Seconds30.to_secs(), Some(30));
        assert_eq!(DisappearTimer::Custom(999).to_secs(), Some(999));
    }

    #[test]
    fn timer_roundtrip_from_secs() {
        for secs in [0, 30, 300, 3600, 86400, 604800, 2592000, 42] {
            let timer = DisappearTimer::from_secs(secs);
            if secs == 0 {
                assert_eq!(timer.to_secs(), None);
            } else {
                assert_eq!(timer.to_secs(), Some(secs));
            }
        }
    }

    // -----------------------------------------------------------------------
    // S12 §2.2: Timer set/handle lifecycle
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn set_and_get_timer() {
        let storage = MockDisappearingStorage::new();
        let manager = DisappearingMessageManager::new(storage);

        // Initially no timer
        assert_eq!(manager.get_timer(1).await.unwrap(), None);

        // Set timer
        manager
            .set_timer(1, Some(3600), 1_000, &OUR_IK)
            .await
            .unwrap();
        assert_eq!(manager.get_timer(1).await.unwrap(), Some(3600));

        // Turn off timer (later set_at)
        manager.set_timer(1, None, 2_000, &OUR_IK).await.unwrap();
        assert_eq!(manager.get_timer(1).await.unwrap(), None);
    }

    #[tokio::test]
    async fn run_once_purges_expired_volatile_keys() {
        // S12 §7/§4.3: run_once purges persisted volatile keys whose expires_at
        // has passed, leaving live ones. now_ms is a large value, so a small
        // expires_at is expired and a far-future one survives.
        use super::cleanup::DisappearingCleanupTask;
        let manager = std::sync::Arc::new(DisappearingMessageManager::new(
            MockDisappearingStorage::new(),
        ));
        manager.storage().add_volatile_key(1, 1_000); // long-expired
        manager.storage().add_volatile_key(2, 9_999_999_999_999); // far future
        assert_eq!(manager.storage().volatile_key_count(), 2);

        let task = DisappearingCleanupTask::with_default_interval(manager.clone(), super::VolatileKeyCache::new());
        task.run_once().await.unwrap();

        assert_eq!(
            manager.storage().volatile_key_count(),
            1,
            "expired volatile key purged, live one kept"
        );
    }

    const THEIR_IK: [u8; 32] = [0x22; 32];

    #[tokio::test]
    async fn row10_cleanup_evicts_all_expired_keys_before_a_storage_failure() {
        let mut storage = MockDisappearingStorage::new();
        storage.fail_overwrite = true;
        let cache = super::VolatileKeyCache::new();
        let reader = cache.clone();
        let mut blobs = Vec::new();
        for id in [1, 2] {
            let blob = super::seal_content(&cache, &[id as u8; 16], b"secret").unwrap();
            storage.add_message(id, &blob, None, 1);
            storage.set_message_disappear_at(id, 1).await.unwrap();
            storage.add_volatile_key(id, 1);
            blobs.push((id, blob));
        }
        assert!(delete_expired_messages(&storage, &cache).await.is_err());
        assert_eq!(storage.volatile_key_count(), 0);
        for (id, blob) in blobs {
            assert!(storage.message_exists(id));
            assert!(matches!(super::open_sealed_content(&reader, &[id as u8; 16], &blob).unwrap(), super::Opened::Expired));
        }
    }
    const OUR_IK: [u8; 32] = [0x11; 32];

    #[tokio::test]
    async fn handle_timer_change_from_contact() {
        let storage = MockDisappearingStorage::new();
        let manager = DisappearingMessageManager::new(storage);

        // Contact sets timer to 5 minutes
        manager
            .handle_timer_change(1, 300, 1_000, &THEIR_IK)
            .await
            .unwrap();
        assert_eq!(manager.get_timer(1).await.unwrap(), Some(300));

        // Contact disables timer (later set_at → wins)
        manager
            .handle_timer_change(1, 0, 2_000, &THEIR_IK)
            .await
            .unwrap();
        assert_eq!(manager.get_timer(1).await.unwrap(), None);
    }

    // S12 §2.2: a change that was superseded before it arrived MUST be
    // ignored. This is the convergence bug the merge exists to fix — the old
    // code blindly overwrote, so a late-arriving stale change clobbered a
    // newer setting and the two sides never agreed.
    #[tokio::test]
    async fn stale_timer_change_does_not_clobber_newer_setting() {
        let manager = DisappearingMessageManager::new(MockDisappearingStorage::new());

        // We set 7 days at t=5000.
        manager
            .set_timer(1, Some(604_800), 5_000, &OUR_IK)
            .await
            .unwrap();
        assert_eq!(manager.get_timer(1).await.unwrap(), Some(604_800));

        // A contact's 30s change from t=1000 arrives late — superseded.
        manager
            .handle_timer_change(1, 30, 1_000, &THEIR_IK)
            .await
            .unwrap();
        assert_eq!(
            manager.get_timer(1).await.unwrap(),
            Some(604_800),
            "stale change must not clobber the newer setting"
        );

        // A genuinely newer change from the contact does apply.
        manager
            .handle_timer_change(1, 30, 9_000, &THEIR_IK)
            .await
            .unwrap();
        assert_eq!(manager.get_timer(1).await.unwrap(), Some(30));
    }

    // S12 §2.2: "off" is a timestamped setting, not a deleted row — an older
    // timer must not resurrect after a newer "off".
    #[tokio::test]
    async fn off_setting_carries_set_at_and_is_not_resurrected() {
        let manager = DisappearingMessageManager::new(MockDisappearingStorage::new());

        manager
            .handle_timer_change(1, 300, 1_000, &THEIR_IK)
            .await
            .unwrap();
        // We turn it off at t=2000.
        manager.set_timer(1, None, 2_000, &OUR_IK).await.unwrap();
        assert_eq!(manager.get_timer(1).await.unwrap(), None);

        // A stale 5-minute change from t=1500 must NOT bring the timer back.
        manager
            .handle_timer_change(1, 300, 1_500, &THEIR_IK)
            .await
            .unwrap();
        assert_eq!(
            manager.get_timer(1).await.unwrap(),
            None,
            "an older timer must not resurrect after a newer off"
        );
    }

    // S12 §2.2: both sides converge on the same value regardless of the order
    // the two changes are applied — the whole point of the merge.
    #[tokio::test]
    async fn both_sides_converge_regardless_of_order() {
        // Side A applies its own change first, then theirs.
        let a = DisappearingMessageManager::new(MockDisappearingStorage::new());
        a.set_timer(1, Some(3_600), 100, &OUR_IK).await.unwrap();
        a.handle_timer_change(1, 30, 200, &THEIR_IK).await.unwrap();

        // Side B receives them in the opposite order.
        let b = DisappearingMessageManager::new(MockDisappearingStorage::new());
        b.handle_timer_change(1, 30, 200, &THEIR_IK).await.unwrap();
        b.set_timer(1, Some(3_600), 100, &OUR_IK).await.unwrap();

        assert_eq!(
            a.get_timer(1).await.unwrap(),
            b.get_timer(1).await.unwrap(),
            "both sides must converge on the same timer"
        );
        assert_eq!(a.get_timer(1).await.unwrap(), Some(30));
    }

    // -----------------------------------------------------------------------
    // S12 §3.1: Sender-side scheduling (ACK-triggered)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn sender_side_schedule_and_ack() {
        let storage = MockDisappearingStorage::new();
        let manager = DisappearingMessageManager::new(storage);

        // Schedule a sent message (pending until ACK)
        manager.schedule_sent(1, 3600).await.unwrap();

        // No disappear_at yet
        assert!(manager.storage().get_disappear_at(1).is_none());

        // ACK received — timer starts
        manager.on_ack_received(1).await.unwrap();

        // disappear_at should now be set
        let da = manager.storage().get_disappear_at(1);
        assert!(da.is_some());
        let da = da.unwrap();
        assert!(da > najwa_crypto::prelude::now() - 5); // within 5s of expected
    }

    #[tokio::test]
    async fn ack_for_non_disappearing_message_is_noop() {
        let storage = MockDisappearingStorage::new();
        let manager = DisappearingMessageManager::new(storage);

        // ACK for a message that wasn't scheduled for disappearance
        manager.on_ack_received(999).await.unwrap();
        // No disappear_at set
        assert!(manager.storage().get_disappear_at(999).is_none());
    }

    // -----------------------------------------------------------------------
    // S12 §3.2: Recipient-side scheduling
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn recipient_side_schedule() {
        let storage = MockDisappearingStorage::new();
        let manager = DisappearingMessageManager::new(storage);

        // Schedule received message to disappear in 30s
        manager.schedule_received(1, 30).await.unwrap();

        let da = manager.storage().get_disappear_at(1);
        assert!(da.is_some());
    }

    // -----------------------------------------------------------------------
    // S12 §3.1: 24h fallback for unacked messages
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn fallback_timer_for_old_unacked_messages() {
        let storage = MockDisappearingStorage::new();
        // Add a message that was "sent" 25 hours ago. Timestamps in this module
        // are MILLISECONDS (now_ms / disappear_at / the fallback cutoff), so use
        // the ms clock — 25h = 90_000_000 ms.
        let sent_at = najwa_crypto::prelude::now_ms() as u64 - 90_000_000; // 25h ago (ms)
        storage.add_message(1, b"old message", None, sent_at);

        let manager = DisappearingMessageManager::new(storage);

        // Schedule sent (pending)
        manager.schedule_sent(1, 3600).await.unwrap();

        // Apply fallback — should trigger because sent_at < cutoff (now - 24h)
        let count = manager.apply_fallback_timers().await.unwrap();
        assert_eq!(count, 1);

        // disappear_at should now be set
        assert!(manager.storage().get_disappear_at(1).is_some());
    }

    #[tokio::test]
    async fn fallback_timer_does_not_trigger_for_recent_messages() {
        let storage = MockDisappearingStorage::new();
        // Message sent just now (milliseconds — matches the fallback cutoff unit).
        let sent_at = najwa_crypto::prelude::now_ms() as u64;
        storage.add_message(1, b"recent message", None, sent_at);

        let manager = DisappearingMessageManager::new(storage);

        manager.schedule_sent(1, 3600).await.unwrap();

        // Apply fallback — should NOT trigger
        let count = manager.apply_fallback_timers().await.unwrap();
        assert_eq!(count, 0);
        assert!(manager.storage().get_disappear_at(1).is_none());
    }

    // -----------------------------------------------------------------------
    // S12 §5.1: Secure deletion + WAL checkpoint
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn delete_expired_messages_removes_and_checkpoints() {
        let storage = MockDisappearingStorage::new();
        storage.add_message(1, b"secret content", None, 1000);
        storage.add_message(2, b"keep this", None, 1000);

        // msg 1 expired, msg 2 not
        storage.set_message_disappear_at(1, 1).await.unwrap(); // expired long ago
        storage.set_message_disappear_at(2, u64::MAX).await.unwrap(); // far future

        let count = delete_expired_messages(&storage, &super::VolatileKeyCache::new()).await.unwrap();
        assert_eq!(count, 1);

        // msg 1 deleted, msg 2 still exists
        assert!(!storage.message_exists(1));
        assert!(storage.message_exists(2));

        // WAL checkpointed
        assert!(storage.was_wal_checkpointed());
    }

    #[tokio::test]
    async fn delete_expired_no_messages_skips_checkpoint() {
        let storage = MockDisappearingStorage::new();
        let count = delete_expired_messages(&storage, &super::VolatileKeyCache::new()).await.unwrap();
        assert_eq!(count, 0);
        assert!(!storage.was_wal_checkpointed());
    }

    // -----------------------------------------------------------------------
    // S12 §9.1, §9.2: Search & backup exclusion
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn search_excludes_disappearing_messages() {
        let storage = MockDisappearingStorage::new();
        storage.add_message(1, b"hello world", None, 1000);
        storage.add_message(2, b"hello secret", None, 1000);

        // Mark msg 2 as disappearing
        storage.set_message_disappear_at(2, u64::MAX).await.unwrap();

        let results = storage
            .search_messages_excluding_disappearing("hello", najwa_crypto::prelude::now())
            .await
            .unwrap();

        // Only msg 1 should appear (msg 2 is disappearing)
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, 1);
    }

    #[tokio::test]
    async fn backup_excludes_disappearing_messages() {
        let storage = MockDisappearingStorage::new();
        storage.add_message(1, b"normal", None, 1000);
        storage.add_message(2, b"disappearing", None, 1000);

        // Mark msg 2 as disappearing
        storage.set_message_disappear_at(2, u64::MAX).await.unwrap();

        let results = storage
            .get_messages_for_backup(najwa_crypto::prelude::now())
            .await
            .unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, 1);
    }

    // -----------------------------------------------------------------------
    // S12 §3, §5: Full timer lifecycle test
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn full_timer_lifecycle() {
        let storage = MockDisappearingStorage::new();

        // Add message
        storage.add_message(1, b"ephemeral", None, 1000);

        let manager = DisappearingMessageManager::new(storage);

        // 1. Set conversation timer
        manager
            .set_timer(42, Some(30), 1_000, &OUR_IK)
            .await
            .unwrap();
        assert_eq!(manager.get_timer(42).await.unwrap(), Some(30));

        // 2. Schedule sent message
        manager.schedule_sent(1, 30).await.unwrap();

        // 3. ACK received — timer starts
        manager.on_ack_received(1).await.unwrap();
        assert!(manager.storage().get_disappear_at(1).is_some());

        // 4. Force expire by setting disappear_at to past
        manager
            .storage()
            .set_message_disappear_at(1, 1)
            .await
            .unwrap();

        // 5. Delete expired
        let count = delete_expired_messages(manager.storage(), &super::VolatileKeyCache::new()).await.unwrap();
        assert_eq!(count, 1);
        assert!(!manager.storage().message_exists(1));
    }
}
