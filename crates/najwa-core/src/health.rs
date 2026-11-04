//! Mailbox health tracking (S08 §9.3), plus threshold-based disabling helpers.
//!
//! Tracks per-mailbox success/failure rates and automatically disables
//! mailboxes that exceed a consecutive failure threshold.

use crate::error::Result;
use crate::multipath::DEFAULT_FAILURE_THRESHOLD;
use crate::storage::CoreStorage;
use crate::types::*;
use najwa_crypto::time::now;

/// Tracks mailbox health (S08 §9.3) and offers threshold-based disabling.
pub struct MailboxHealthTracker<'a, S: CoreStorage> {
    storage: &'a S,
    /// Consecutive failure threshold before auto-disable.
    failure_threshold: u32,
}

impl<'a, S: CoreStorage> MailboxHealthTracker<'a, S> {
    /// Create a new health tracker with the default failure threshold.
    pub fn new(storage: &'a S) -> Self {
        Self {
            storage,
            failure_threshold: DEFAULT_FAILURE_THRESHOLD,
        }
    }

    /// Create a new health tracker with a custom failure threshold.
    pub fn with_threshold(storage: &'a S, threshold: u32) -> Self {
        Self {
            storage,
            failure_threshold: threshold,
        }
    }

    /// Record a successful delivery to a mailbox (S08 §9.3).
    pub async fn record_success(&self, mailbox_id: MailboxId) -> Result<()> {
        self.storage
            .record_mailbox_success(mailbox_id, now())
            .await
            .map_err(crate::error::MessagingError::StorageError)
    }

    /// Record a failed delivery to a mailbox (S08 §9.3).
    pub async fn record_failure(&self, mailbox_id: MailboxId) -> Result<()> {
        self.storage
            .record_mailbox_failure(mailbox_id, now())
            .await
            .map_err(crate::error::MessagingError::StorageError)
    }

    /// Get mailboxes sorted by health — fewest failures first,
    /// then most recent success first.
    pub async fn ranked_mailboxes(&self) -> Result<Vec<MailboxHealth>> {
        let mut mailboxes = self
            .storage
            .list_mailbox_health()
            .await
            .map_err(crate::error::MessagingError::StorageError)?;

        mailboxes.sort_by(|a, b| {
            a.consecutive_failures
                .cmp(&b.consecutive_failures)
                .then_with(|| {
                    // Most recent success first (descending)
                    b.last_success
                        .unwrap_or(0)
                        .cmp(&a.last_success.unwrap_or(0))
                })
        });

        Ok(mailboxes)
    }

    /// Check all mailboxes and disable any that exceed the failure
    /// threshold. Returns the IDs of newly disabled mailboxes.
    pub async fn check_and_disable(&self) -> Result<Vec<MailboxId>> {
        let mailboxes = self
            .storage
            .list_mailbox_health()
            .await
            .map_err(crate::error::MessagingError::StorageError)?;

        let mut disabled = Vec::new();
        for mb in mailboxes {
            if mb.consecutive_failures >= self.failure_threshold && mb.enabled {
                tracing::warn!(
                    mailbox_id = mb.mailbox_id,
                    failures = mb.consecutive_failures,
                    threshold = self.failure_threshold,
                    "disabling mailbox due to excessive failures"
                );
                self.storage
                    .disable_mailbox(mb.mailbox_id)
                    .await
                    .map_err(crate::error::MessagingError::StorageError)?;
                disabled.push(mb.mailbox_id);
            }
        }
        Ok(disabled)
    }

    /// AUD-17: Detect server misbehavior — auto-disable mailboxes with 50%+ failure
    /// rate. Checks total_failures / (total_successes + total_failures).
    /// Returns IDs of newly disabled mailboxes.
    pub async fn detect_misbehavior(&self) -> Result<Vec<MailboxId>> {
        const MISBEHAVIOR_THRESHOLD_PERCENT: u64 = 50;
        const MIN_OPERATIONS_FOR_CHECK: u64 = 20;

        let mailboxes = self
            .storage
            .list_mailbox_health()
            .await
            .map_err(crate::error::MessagingError::StorageError)?;

        let mut disabled = Vec::new();
        for mb in mailboxes {
            if !mb.enabled {
                continue;
            }
            let total = mb.total_successes + mb.total_failures;
            if total < MIN_OPERATIONS_FOR_CHECK {
                continue;
            }
            let failure_pct = mb.total_failures * 100 / total;
            if failure_pct >= MISBEHAVIOR_THRESHOLD_PERCENT {
                tracing::warn!(
                    mailbox_id = mb.mailbox_id,
                    onion = %mb.onion_address,
                    failure_pct,
                    total,
                    "server misbehavior detected — auto-disabling (AUD-17)"
                );
                self.storage
                    .disable_mailbox(mb.mailbox_id)
                    .await
                    .map_err(crate::error::MessagingError::StorageError)?;
                disabled.push(mb.mailbox_id);
            }
        }
        Ok(disabled)
    }

    /// Re-enable a previously disabled mailbox (manual recovery).
    pub async fn re_enable(&self, mailbox_id: MailboxId) -> Result<()> {
        self.storage
            .enable_mailbox(mailbox_id)
            .await
            .map_err(crate::error::MessagingError::StorageError)
    }

    /// Process a delivery report, recording successes and failures
    /// for each mailbox in the report. Returns any newly disabled
    /// mailbox IDs.
    pub async fn process_report(&self, report: &DeliveryReport) -> Result<Vec<MailboxId>> {
        for result in &report.results {
            if result.success {
                self.record_success(result.mailbox_id).await?;
            } else {
                self.record_failure(result.mailbox_id).await?;
            }
        }
        self.check_and_disable().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::CoreStorage;
    use async_trait::async_trait;
    use najwa_crypto::keys::x25519::X25519KeyPair;
    use najwa_protocol::mailbox::types::MailboxConfig;
    use najwa_protocol::ratchet::state::RatchetState;
    use std::collections::HashMap;
    use std::sync::Mutex;

    // Minimal mock that only implements the health-tracking methods.
    struct HealthMockStorage {
        health: Mutex<HashMap<MailboxId, MailboxHealth>>,
    }

    impl HealthMockStorage {
        fn new() -> Self {
            Self {
                health: Mutex::new(HashMap::new()),
            }
        }

        fn add_mailbox(&self, id: MailboxId, onion: &str) {
            self.health.lock().unwrap().insert(
                id,
                MailboxHealth {
                    mailbox_id: id,
                    onion_address: onion.into(),
                    consecutive_failures: 0,
                    total_successes: 0,
                    total_failures: 0,
                    last_success: None,
                    last_failure: None,
                    enabled: true,
                },
            );
        }
    }

    #[async_trait]
    impl CoreStorage for HealthMockStorage {
        async fn get_contact(&self, _: ContactId) -> std::result::Result<Option<Contact>, String> {
            Ok(None)
        }
        async fn get_contact_by_pseudonym(
            &self,
            _: &[u8; 32],
        ) -> std::result::Result<Option<Contact>, String> {
            Ok(None)
        }
        async fn list_contacts(&self) -> std::result::Result<Vec<Contact>, String> {
            Ok(vec![])
        }
        async fn update_contact(&self, _: &Contact) -> std::result::Result<(), String> {
            Ok(())
        }
        async fn get_contact_capabilities(
            &self,
            _: ContactId,
        ) -> std::result::Result<Vec<ContactCapability>, String> {
            Ok(vec![])
        }
        async fn get_ratchet_state(
            &self,
            _: ContactId,
        ) -> std::result::Result<Option<RatchetState>, String> {
            Ok(None)
        }
        async fn save_ratchet_state(
            &self,
            _: ContactId,
            _: &RatchetState,
        ) -> std::result::Result<(), String> {
            Ok(())
        }
        async fn delete_ratchet_state(&self, _: ContactId) -> std::result::Result<(), String> {
            Ok(())
        }
        async fn get_ratchet_state_by_dh_pub(
            &self,
            _: &[u8; 32],
        ) -> std::result::Result<Option<(ContactId, RatchetState)>, String> {
            Ok(None)
        }
        async fn get_session_ad(
            &self,
            _: ContactId,
        ) -> std::result::Result<Option<Vec<u8>>, String> {
            Ok(None)
        }
        async fn save_session_ad(&self, _: ContactId, _: &[u8]) -> std::result::Result<(), String> {
            Ok(())
        }
        async fn delete_session_ad(&self, _: ContactId) -> std::result::Result<(), String> {
            Ok(())
        }
        async fn save_message(&self, _: &Message) -> std::result::Result<MessageId, String> {
            Ok(1)
        }
        async fn get_message_by_msg_id(
            &self,
            _: &[u8; 16],
        ) -> std::result::Result<Option<Message>, String> {
            Ok(None)
        }
        async fn update_message_status(
            &self,
            _: MessageId,
            _: MessageStatus,
        ) -> std::result::Result<(), String> {
            Ok(())
        }
        async fn get_pending_messages(&self) -> std::result::Result<Vec<Message>, String> {
            Ok(vec![])
        }
        async fn update_message_blob(
            &self,
            _: MessageId,
            _: &[u8],
        ) -> std::result::Result<(), String> {
            Ok(())
        }
        async fn clear_message_blob(&self, _: MessageId) -> std::result::Result<(), String> {
            Ok(())
        }
        async fn increment_retry_count(&self, _: MessageId) -> std::result::Result<(), String> {
            Ok(())
        }
        async fn get_message_blob(
            &self,
            _: MessageId,
        ) -> std::result::Result<Option<Vec<u8>>, String> {
            Ok(None)
        }
        async fn check_msg_id_seen(&self, _: &[u8; 16]) -> std::result::Result<bool, String> {
            Ok(false)
        }
        async fn mark_msg_id_seen(
            &self,
            _: ContactId,
            _: &[u8; 16],
        ) -> std::result::Result<(), String> {
            Ok(())
        }
        async fn list_mailboxes(&self) -> std::result::Result<Vec<MailboxConfig>, String> {
            Ok(vec![])
        }
        async fn list_mailboxes_with_ids(
            &self,
        ) -> std::result::Result<Vec<(MailboxId, MailboxConfig)>, String> {
            Ok(vec![])
        }
        async fn list_deposit_capabilities_for_mailbox(
            &self,
            _: MailboxId,
        ) -> std::result::Result<Vec<([u8; 32], [u8; 32])>, String> {
            Ok(vec![])
        }
        async fn get_spk_keypair(
            &self,
            _: &[u8; 4],
        ) -> std::result::Result<Option<X25519KeyPair>, String> {
            Ok(None)
        }
        async fn get_opk_keypair(
            &self,
            _: &[u8; 4],
        ) -> std::result::Result<Option<X25519KeyPair>, String> {
            Ok(None)
        }
        async fn mark_opk_used(&self, _: &[u8; 4]) -> std::result::Result<(), String> {
            Ok(())
        }

        // -- Health tracking --

        async fn list_mailbox_health(&self) -> std::result::Result<Vec<MailboxHealth>, String> {
            Ok(self.health.lock().unwrap().values().cloned().collect())
        }

        async fn get_mailbox_health(
            &self,
            mailbox_id: MailboxId,
        ) -> std::result::Result<Option<MailboxHealth>, String> {
            Ok(self.health.lock().unwrap().get(&mailbox_id).cloned())
        }

        async fn record_mailbox_success(
            &self,
            mailbox_id: MailboxId,
            timestamp: u64,
        ) -> std::result::Result<(), String> {
            if let Some(h) = self.health.lock().unwrap().get_mut(&mailbox_id) {
                h.consecutive_failures = 0;
                h.total_successes += 1;
                h.last_success = Some(timestamp);
            }
            Ok(())
        }

        async fn record_mailbox_failure(
            &self,
            mailbox_id: MailboxId,
            timestamp: u64,
        ) -> std::result::Result<(), String> {
            if let Some(h) = self.health.lock().unwrap().get_mut(&mailbox_id) {
                h.consecutive_failures += 1;
                h.total_failures += 1;
                h.last_failure = Some(timestamp);
            }
            Ok(())
        }

        async fn disable_mailbox(&self, mailbox_id: MailboxId) -> std::result::Result<(), String> {
            if let Some(h) = self.health.lock().unwrap().get_mut(&mailbox_id) {
                h.enabled = false;
            }
            Ok(())
        }

        async fn enable_mailbox(&self, mailbox_id: MailboxId) -> std::result::Result<(), String> {
            if let Some(h) = self.health.lock().unwrap().get_mut(&mailbox_id) {
                h.enabled = true;
                h.consecutive_failures = 0;
            }
            Ok(())
        }
        async fn save_contact_capability(
            &self,
            _contact_id: ContactId,
            _mailbox_id: MailboxId,
            _deposit_cap: &[u8; 32],
            _fetch_cap: Option<&[u8; 32]>,
            _their_dep: Option<&[u8; 32]>,
        ) -> std::result::Result<(), String> {
            Ok(())
        }
        async fn revoke_contact_capability(
            &self,
            _contact_id: ContactId,
            _mailbox_id: MailboxId,
        ) -> std::result::Result<(), String> {
            Ok(())
        }
        async fn delete_contact(&self, _contact_id: ContactId) -> std::result::Result<(), String> {
            Ok(())
        }
        async fn save_volatile_key(
            &self,
            _msg_id: &[u8; 16],
            _encrypted_key: &[u8],
            _expires_at: Option<u64>,
        ) -> std::result::Result<(), String> {
            Ok(())
        }
        async fn get_volatile_key(
            &self,
            _msg_id: &[u8; 16],
        ) -> std::result::Result<Option<Vec<u8>>, String> {
            Ok(None)
        }
        async fn cleanup_expired_volatile_keys(&self) -> std::result::Result<u32, String> {
            Ok(0)
        }
        async fn set_conversation_timer(
            &self,
            _contact_id: ContactId,
            _timer_secs: Option<u32>,
        ) -> std::result::Result<(), String> {
            Ok(())
        }
        async fn get_conversation_timer(
            &self,
            _contact_id: ContactId,
        ) -> std::result::Result<Option<u32>, String> {
            Ok(None)
        }
        async fn set_conversation_timer_setting(
            &self,
            _contact_id: ContactId,
            _timer_secs: Option<u32>,
            _set_at: u64,
            _setter_ik: &[u8; 32],
        ) -> std::result::Result<(), String> {
            Ok(())
        }
        async fn get_conversation_timer_setting(
            &self,
            _contact_id: ContactId,
        ) -> std::result::Result<Option<(Option<u32>, u64, [u8; 32])>, String> {
            Ok(None)
        }
        async fn get_expired_disappearing_messages(
            &self,
        ) -> std::result::Result<Vec<Message>, String> {
            Ok(vec![])
        }
        async fn overwrite_message_content(
            &self,
            _id: MessageId,
            _zeros: &[u8],
        ) -> std::result::Result<(), String> {
            Ok(())
        }
        async fn save_identity_history(
            &self,
            _contact_id: ContactId,
            _old_ik: &[u8; 32],
            _new_ik: &[u8; 32],
            _reason: Option<&str>,
        ) -> std::result::Result<(), String> {
            Ok(())
        }
        async fn save_skipped_key(
            &self,
            _contact_id: ContactId,
            _dh_pub: &[u8; 32],
            _msg_num: u32,
            _key: &[u8; 32],
        ) -> std::result::Result<(), String> {
            Ok(())
        }
        async fn get_skipped_key(
            &self,
            _contact_id: ContactId,
            _dh_pub: &[u8; 32],
            _msg_num: u32,
        ) -> std::result::Result<Option<[u8; 32]>, String> {
            Ok(None)
        }
        async fn delete_skipped_key(
            &self,
            _contact_id: ContactId,
            _dh_pub: &[u8; 32],
            _msg_num: u32,
        ) -> std::result::Result<(), String> {
            Ok(())
        }
        async fn cleanup_old_msg_ids(
            &self,
            _older_than_secs: u64,
        ) -> std::result::Result<u32, String> {
            Ok(0)
        }
        async fn cleanup_expired_skipped_keys(&self) -> std::result::Result<u32, String> {
            Ok(0)
        }
        async fn count_available_opks(
            &self,
            _mailbox_id: Option<MailboxId>,
        ) -> std::result::Result<u32, String> {
            Ok(100)
        }
        async fn save_pending_introduction(
            &self,
            _intro: &najwa_storage::types::NewPendingIntroduction,
        ) -> std::result::Result<i64, String> {
            Ok(0)
        }
        async fn get_pending_introduction(
            &self,
            _id: i64,
        ) -> std::result::Result<Option<najwa_storage::types::PendingIntroduction>, String>
        {
            Ok(None)
        }
        async fn list_pending_introductions(
            &self,
        ) -> std::result::Result<Vec<najwa_storage::types::PendingIntroduction>, String> {
            Ok(vec![])
        }
        async fn list_introductions_for_contact(
            &self,
            _introducer_contact_id: ContactId,
        ) -> std::result::Result<Vec<najwa_storage::types::PendingIntroduction>, String> {
            Ok(vec![])
        }
        async fn update_introduction_status(
            &self,
            _id: i64,
            _status: najwa_storage::types::IntroductionStatus,
        ) -> std::result::Result<(), String> {
            Ok(())
        }
        async fn count_pending_introductions(&self) -> std::result::Result<u32, String> {
            Ok(0)
        }
        async fn get_contact_by_ik(
            &self,
            _ik_pub: &[u8; 32],
        ) -> std::result::Result<Option<Contact>, String> {
            Ok(None)
        }
    }

    // S08 §9.3: Record success resets consecutive failures
    #[tokio::test]
    async fn record_success_resets_failures() {
        let storage = HealthMockStorage::new();
        storage.add_mailbox(1, "mb1.onion");

        // Simulate some failures first
        storage.record_mailbox_failure(1, 100).await.unwrap();
        storage.record_mailbox_failure(1, 200).await.unwrap();
        let h = storage.get_mailbox_health(1).await.unwrap().unwrap();
        assert_eq!(h.consecutive_failures, 2);

        // Now record success
        let tracker = MailboxHealthTracker::new(&storage);
        tracker.record_success(1).await.unwrap();
        let h = storage.get_mailbox_health(1).await.unwrap().unwrap();
        assert_eq!(h.consecutive_failures, 0);
        assert_eq!(h.total_successes, 1);
    }

    // S08 §9.3: Record failure increments consecutive count
    #[tokio::test]
    async fn record_failure_increments() {
        let storage = HealthMockStorage::new();
        storage.add_mailbox(1, "mb1.onion");

        let tracker = MailboxHealthTracker::new(&storage);
        tracker.record_failure(1).await.unwrap();
        tracker.record_failure(1).await.unwrap();
        tracker.record_failure(1).await.unwrap();

        let h = storage.get_mailbox_health(1).await.unwrap().unwrap();
        assert_eq!(h.consecutive_failures, 3);
        assert_eq!(h.total_failures, 3);
    }

    // Auto-disable after threshold
    #[tokio::test]
    async fn auto_disable_after_threshold() {
        let storage = HealthMockStorage::new();
        storage.add_mailbox(1, "mb1.onion");
        storage.add_mailbox(2, "mb2.onion");

        let tracker = MailboxHealthTracker::with_threshold(&storage, 3);

        // 3 failures on mailbox 1
        for i in 0..3 {
            tracker.record_failure(1).await.unwrap();
            let _ = i;
        }
        // 2 failures on mailbox 2 (below threshold)
        tracker.record_failure(2).await.unwrap();
        tracker.record_failure(2).await.unwrap();

        let disabled = tracker.check_and_disable().await.unwrap();
        assert_eq!(disabled.len(), 1);
        assert!(disabled.contains(&1));

        let h1 = storage.get_mailbox_health(1).await.unwrap().unwrap();
        assert!(!h1.enabled);
        let h2 = storage.get_mailbox_health(2).await.unwrap().unwrap();
        assert!(h2.enabled);
    }

    // Already disabled mailboxes not re-reported
    #[tokio::test]
    async fn already_disabled_not_re_reported() {
        let storage = HealthMockStorage::new();
        storage.add_mailbox(1, "mb1.onion");

        let tracker = MailboxHealthTracker::with_threshold(&storage, 2);
        tracker.record_failure(1).await.unwrap();
        tracker.record_failure(1).await.unwrap();

        let disabled = tracker.check_and_disable().await.unwrap();
        assert_eq!(disabled.len(), 1);

        // Second check should not re-report
        let disabled2 = tracker.check_and_disable().await.unwrap();
        assert!(disabled2.is_empty());
    }

    // Re-enable resets failures and sets enabled
    #[tokio::test]
    async fn re_enable_resets() {
        let storage = HealthMockStorage::new();
        storage.add_mailbox(1, "mb1.onion");

        let tracker = MailboxHealthTracker::with_threshold(&storage, 2);
        tracker.record_failure(1).await.unwrap();
        tracker.record_failure(1).await.unwrap();
        tracker.check_and_disable().await.unwrap();

        let h = storage.get_mailbox_health(1).await.unwrap().unwrap();
        assert!(!h.enabled);

        tracker.re_enable(1).await.unwrap();
        let h = storage.get_mailbox_health(1).await.unwrap().unwrap();
        assert!(h.enabled);
        assert_eq!(h.consecutive_failures, 0);
    }

    // Ranked mailboxes sorted by health
    #[tokio::test]
    async fn ranked_by_health() {
        let storage = HealthMockStorage::new();
        storage.add_mailbox(1, "bad.onion");
        storage.add_mailbox(2, "good.onion");
        storage.add_mailbox(3, "ok.onion");

        // mb1: 5 failures, mb2: 0 failures (success), mb3: 2 failures
        let tracker = MailboxHealthTracker::new(&storage);
        for _ in 0..5 {
            tracker.record_failure(1).await.unwrap();
        }
        tracker.record_success(2).await.unwrap();
        tracker.record_failure(3).await.unwrap();
        tracker.record_failure(3).await.unwrap();

        let ranked = tracker.ranked_mailboxes().await.unwrap();
        assert_eq!(ranked[0].mailbox_id, 2); // 0 failures
        assert_eq!(ranked[1].mailbox_id, 3); // 2 failures
        assert_eq!(ranked[2].mailbox_id, 1); // 5 failures
    }

    // process_report records and auto-disables
    #[tokio::test]
    async fn process_report_integration() {
        let storage = HealthMockStorage::new();
        storage.add_mailbox(1, "mb1.onion");
        storage.add_mailbox(2, "mb2.onion");

        let tracker = MailboxHealthTracker::with_threshold(&storage, 2);

        // First report: mb1 fails, mb2 succeeds
        let mut report = DeliveryReport::new();
        report.record_failure(1, "err".into());
        report.record_success(2, Some("id".into()));
        let disabled = tracker.process_report(&report).await.unwrap();
        assert!(disabled.is_empty());

        // Second report: mb1 fails again (threshold=2)
        let mut report2 = DeliveryReport::new();
        report2.record_failure(1, "err2".into());
        report2.record_success(2, Some("id2".into()));
        let disabled2 = tracker.process_report(&report2).await.unwrap();
        assert_eq!(disabled2, vec![1]);
    }
}
