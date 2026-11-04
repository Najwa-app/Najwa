//! Contact blocking and session reset (S08 §7.1, §7.2).

use najwa_protocol::mailbox::client::MailboxClient;
use najwa_protocol::message::control::ControlMessage;

use crate::error::{MessagingError, Result};
use crate::service::MessagingService;
use crate::storage::CoreStorage;
use crate::types::ContactId;

impl<S: CoreStorage, M: MailboxClient> MessagingService<S, M> {
    /// Local contact controls serialize with receive, send and repair. No peer
    /// connection or mailbox request is needed to apply the user's choice.
    pub async fn manage_local_contact(
        &self,
        contact_id: ContactId,
        action: &str,
        name: &str,
    ) -> Result<()> {
        // S08 §7.1: Delete first seals a RevocationNotice into the outbox (no
        // network); the delete below moves it out of the contact row. Without
        // a session or a route nothing is sent. The local delete happens anyway.
        let notice = if action == "delete" {
            self.send_control_impl(contact_id, &ControlMessage::RevocationNotice, false, false)
                .await
                .inspect_err(|error| tracing::debug!(%error, contact_id, "no revocation notice"))
                .ok()
        } else {
            None
        };
        let _state = self.state_gate.lock().await;
        let db = self.storage.prekey_database().ok_or_else(|| {
            MessagingError::StorageError("local contact controls require persistent storage".into())
        })?;
        let contact = db
            .get_contact(contact_id as i64)
            .map_err(|e| MessagingError::StorageError(e.to_string()))?
            .ok_or(MessagingError::ContactNotFound)?;
        let result = match action {
            "block" => db.set_contact_blocked(contact.id, true),
            "unblock" => db.set_contact_blocked(contact.id, false),
            "rename" => db.rename_contact(contact.id, name),
            "delete" => {
                let ids = db
                    .contact_message_ids(contact.id)
                    .map_err(|e| MessagingError::StorageError(e.to_string()))?;
                let routes = match notice {
                    Some(_) => self.storage.get_contact_capabilities(contact_id).await.ok()
                        .and_then(|caps| crate::pipeline::encode_revocation_routes(&caps)),
                    None => None,
                };
                match notice.zip(routes) {
                    Some((frame, routes)) => db.delete_contact_with_revocation(contact.id, frame, &routes),
                    None => db.delete_contact(contact.id),
                }
                .map_err(|e| MessagingError::StorageError(e.to_string()))?;
                for id in ids {
                    self.volatile_cache.remove_key(&id);
                }
                self.unregister_pseudonym(contact.pseudonym)?;
                self.inbound_limiter.clear(contact_id);
                if let Ok(mut states) = self.repair_states.lock() {
                    states.remove(&contact_id);
                }
                if let Ok(mut states) = self.last_gap_repair.lock() {
                    states.remove(&contact_id);
                }
                Ok(())
            }
            _ => {
                return Err(MessagingError::InternalError(
                    "invalid contact action".into(),
                ))
            }
        };
        result.map_err(|e| MessagingError::StorageError(e.to_string()))
    }

    /// Block a contact (S08 §7.1).
    ///
    /// Blocked contacts:
    /// - Cannot receive messages from us
    /// - Their incoming messages are silently discarded
    /// - No read receipts or delivery ACKs are sent
    /// - Their ratchet session is preserved (not deleted)
    pub async fn block_contact(&self, contact_id: ContactId) -> Result<()> {
        let _state = self.state_gate.lock().await;
        let mut contact = self
            .storage
            .get_contact(contact_id)
            .await
            .map_err(MessagingError::StorageError)?
            .ok_or(MessagingError::ContactNotFound)?;

        contact.blocked = true;
        self.storage
            .update_contact(&contact)
            .await
            .map_err(MessagingError::StorageError)?;

        tracing::info!(contact_id, "contact blocked");
        Ok(())
    }

    /// Unblock a contact (S08 §7.1).
    pub async fn unblock_contact(&self, contact_id: ContactId) -> Result<()> {
        let _state = self.state_gate.lock().await;
        let mut contact = self
            .storage
            .get_contact(contact_id)
            .await
            .map_err(MessagingError::StorageError)?
            .ok_or(MessagingError::ContactNotFound)?;

        contact.blocked = false;
        self.storage
            .update_contact(&contact)
            .await
            .map_err(MessagingError::StorageError)?;

        tracing::info!(contact_id, "contact unblocked");
        Ok(())
    }

    /// Initiate a session reset with a contact (S08 §7.2).
    ///
    /// 1. Sends a SessionReset control message to the contact
    /// 2. Deletes the local ratchet state and session AD
    /// 3. The next message will trigger a new X3DH handshake
    pub async fn reset_session(&self, contact_id: ContactId) -> Result<()> {
        // Send SessionReset control message (best-effort)
        let _ = self
            .send_control_message(contact_id, &ControlMessage::SessionReset)
            .await;

        let _state = self.state_gate.lock().await;
        // Delete local session state
        self.storage
            .delete_ratchet_state(contact_id)
            .await
            .map_err(MessagingError::StorageError)?;
        self.storage
            .delete_session_ad(contact_id)
            .await
            .map_err(MessagingError::StorageError)?;

        tracing::info!(contact_id, "session reset initiated");
        Ok(())
    }
}
