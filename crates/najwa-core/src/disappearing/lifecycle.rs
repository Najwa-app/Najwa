//! Disappearing message timer lifecycle (S12 §3, §8).
//!
//! Manages the full lifecycle:
//! - Setting/changing timers per conversation
//! - Handling timer change control messages from contacts
//! - Sender-side scheduling (ACK-triggered + 24h fallback)
//! - Recipient-side scheduling (display/decryption-triggered)

use najwa_crypto::prelude::now_ms;

use super::config::{timer_setting_wins, TimerSetting};
use super::error::{DisappearError, Result};
use super::storage::DisappearingStorage;
use crate::types::MessageId;

/// 24-hour fallback constant (in milliseconds).
pub const FALLBACK_TIMEOUT_MS: u64 = 86_400_000;

/// Manages disappearing message timers (S12 §8).
pub struct DisappearingMessageManager<S: DisappearingStorage> {
    storage: S,
}

impl<S: DisappearingStorage> DisappearingMessageManager<S> {
    /// Create a new manager with the given storage backend.
    pub fn new(storage: S) -> Self {
        Self { storage }
    }

    /// Get a reference to the storage backend.
    pub fn storage(&self) -> &S {
        &self.storage
    }

    /// Set or change the disappearing timer for a conversation locally (S12 §2.2).
    ///
    /// Merges against the stored setting exactly as a received change would, so
    /// a local change that loses to a newer remote one does not silently win.
    ///
    /// `set_at` is the caller's clock reading (normally `now()`); the caller
    /// MUST put the **same** value on the wire in the `TimerChange` control
    /// message (§2.3). Two different values would have the two sides merging
    /// different records, which is precisely the divergence the merge exists
    /// to prevent — so it is a parameter here rather than stamped internally.
    pub async fn set_timer(
        &self,
        contact_id: u64,
        timer_secs: Option<u32>,
        set_at: u64,
        our_ik_pub: &[u8; 32],
    ) -> Result<()> {
        self.merge_timer(contact_id, timer_secs, set_at, our_ik_pub)
            .await
    }

    /// Get the current timer for a conversation.
    pub async fn get_timer(&self, contact_id: u64) -> Result<Option<u32>> {
        self.storage
            .get_conversation_timer(contact_id)
            .await
            .map_err(DisappearError::StorageError)
    }

    /// Handle a `TimerChange` control message from a contact (S12 §2.2/§2.3).
    ///
    /// `their_set_at` is the wire `set_at` and `their_ik_pub` the sender's
    /// identity key — both are merge inputs, not decoration: without them the
    /// two sides cannot converge on the same setting.
    pub async fn handle_timer_change(
        &self,
        contact_id: u64,
        duration_secs: u32,
        their_set_at: u64,
        their_ik_pub: &[u8; 32],
    ) -> Result<()> {
        // S12 §2.2: a set_at past the S07 §7.1 future bound is ignored.
        if super::config::set_at_too_far_ahead(their_set_at, najwa_crypto::time::now()) {
            return Ok(());
        }
        let timer = (duration_secs > 0).then_some(duration_secs);
        self.merge_timer(contact_id, timer, their_set_at, their_ik_pub)
            .await
    }

    /// S12 §2.2 merge-then-persist. Persists only when the incoming setting
    /// supersedes the stored one.
    async fn merge_timer(
        &self,
        contact_id: u64,
        timer_secs: Option<u32>,
        set_at: u64,
        setter_ik: &[u8; 32],
    ) -> Result<()> {
        if timer_secs.is_some_and(super::timer_below_minimum) {
            return Err(DisappearError::InvalidTimer(
                "disappearing timers must be at least 30 seconds".into(),
            ));
        }
        let timer_secs = timer_secs.filter(|secs| *secs != 0);
        let incoming = TimerSetting {
            timer_secs,
            set_at,
            setter_ik: *setter_ik,
        };
        let current = self
            .storage
            .get_conversation_timer_setting(contact_id)
            .await
            .map_err(DisappearError::StorageError)?
            .map(|(timer_secs, set_at, setter_ik)| TimerSetting {
                timer_secs,
                set_at,
                setter_ik,
            });

        if timer_setting_wins(current.as_ref(), &incoming) {
            self.storage
                .set_conversation_timer_setting(contact_id, timer_secs, set_at, setter_ik)
                .await
                .map_err(DisappearError::StorageError)?;
        }
        Ok(())
    }

    /// Schedule disappearance for a SENT message (S12 §3.1).
    ///
    /// Timer starts when ACK received, or 24h fallback.
    /// Records a pending timer — `disappear_at` is set later on ACK.
    pub async fn schedule_sent(&self, msg_id: MessageId, timer_secs: u32) -> Result<()> {
        self.storage
            .set_message_disappear_pending(msg_id, timer_secs)
            .await
            .map_err(DisappearError::StorageError)
    }

    /// Called when delivery ACK received — start the sender-side timer (S12 §3.1).
    pub async fn on_ack_received(&self, msg_id: MessageId) -> Result<()> {
        if let Some(timer_secs) = self
            .storage
            .get_message_disappear_pending(msg_id)
            .await
            .map_err(DisappearError::StorageError)?
        {
            let disappear_at = now_ms() as u64 + timer_secs as u64 * 1000;
            self.storage
                .set_message_disappear_at(msg_id, disappear_at)
                .await
                .map_err(DisappearError::StorageError)?;
        }
        Ok(())
    }

    /// Apply 24h fallback timers for unacked sent messages (S12 §3.1, §6).
    ///
    /// For messages that were sent more than 24h ago without receiving an ACK,
    /// start the timer anyway.
    pub async fn apply_fallback_timers(&self) -> Result<u32> {
        let cutoff = now_ms() as u64 - FALLBACK_TIMEOUT_MS;
        self.storage
            .apply_fallback_disappear_timers(cutoff)
            .await
            .map_err(DisappearError::StorageError)
    }

    /// Schedule disappearance for a RECEIVED message (S12 §3.2).
    ///
    /// Timer starts on display (read_at set) or decryption.
    pub async fn schedule_received(&self, msg_id: MessageId, timer_secs: u32) -> Result<()> {
        let disappear_at = now_ms() as u64 + timer_secs as u64 * 1000;
        self.storage
            .set_message_disappear_at(msg_id, disappear_at)
            .await
            .map_err(DisappearError::StorageError)
    }
}
