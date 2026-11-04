//! Contact introduction operations (S05 §11).
//!
//! Provides send, accept, and reject logic for mutual introductions.
//!
//! NOTE: The Android FFI layer (`najwa-ffi/src/lib.rs`) reimplements these
//! operations directly for performance (avoids async overhead). These methods
//! are intended for non-FFI platforms (iOS, desktop) that use MessagingService
//! directly. The `accept_introduction` here only marks status — actual contact
//! creation is handled by the platform layer.

use najwa_protocol::contact::introduction::IntroductionPayload;
use najwa_protocol::mailbox::client::MailboxClient;
use najwa_protocol::message::control::ControlMessage;
use najwa_storage::types::IntroductionStatus;

use crate::error::{MessagingError, Result};
use crate::service::MessagingService;
use crate::storage::CoreStorage;
use crate::types::ContactId;

impl<S: CoreStorage, M: MailboxClient> MessagingService<S, M> {
    /// Send a mutual contact introduction (S05 §11).
    ///
    /// The introducer (us) introduces `contact_a` to `contact_b`.
    /// Two `IntroductionPayload`s are created and sent:
    /// - To contact_a: contains contact_b's info
    /// - To contact_b: contains contact_a's info
    pub async fn send_introduction(
        &self,
        contact_a_id: ContactId,
        contact_b_id: ContactId,
        anonymous: bool,
    ) -> Result<()> {
        // Load both contacts
        let contact_a = self
            .storage
            .get_contact(contact_a_id)
            .await
            .map_err(MessagingError::StorageError)?
            .ok_or(MessagingError::ContactNotFound)?;

        let contact_b = self
            .storage
            .get_contact(contact_b_id)
            .await
            .map_err(MessagingError::StorageError)?
            .ok_or(MessagingError::ContactNotFound)?;

        if contact_a.blocked || contact_b.blocked {
            return Err(MessagingError::ContactBlocked);
        }

        // Get mailbox info for both contacts from capabilities
        let caps_a = self
            .storage
            .get_contact_capabilities(contact_a_id)
            .await
            .map_err(MessagingError::StorageError)?;
        let caps_b = self
            .storage
            .get_contact_capabilities(contact_b_id)
            .await
            .map_err(MessagingError::StorageError)?;

        // Build MailboxInfo arrays for each contact
        let mailboxes_a: Vec<najwa_protocol::contact::introduction::IntroductionMailbox> = caps_a
            .iter()
            .filter_map(|cap| {
                cap.their_deposit_capability
                    .zip(cap.their_envelope_secret)
                    .map(|(dep, secret)| {
                        najwa_protocol::contact::introduction::IntroductionMailbox {
                            onion_address: cap.mailbox_onion.clone(),
                            deposit_capability: dep,
                            envelope_secret: secret,
                        }
                    })
            })
            .collect();

        let mailboxes_b: Vec<najwa_protocol::contact::introduction::IntroductionMailbox> = caps_b
            .iter()
            .filter_map(|cap| {
                cap.their_deposit_capability
                    .zip(cap.their_envelope_secret)
                    .map(|(dep, secret)| {
                        najwa_protocol::contact::introduction::IntroductionMailbox {
                            onion_address: cap.mailbox_onion.clone(),
                            deposit_capability: dep,
                            envelope_secret: secret,
                        }
                    })
            })
            .collect();

        if mailboxes_a.is_empty() || mailboxes_b.is_empty() {
            return Err(MessagingError::InternalError(
                "introduction target lacks deposit credentials".into(),
            ));
        }

        let name_a = contact_a.display_name.as_deref().unwrap_or("Unknown");
        let name_b = contact_b.display_name.as_deref().unwrap_or("Unknown");

        let validity_days = 7u32;

        // Create payloads — ALWAYS attributed (S05 §11). An introduction is
        // signed with our real identity key and the receiver verifies it against
        // our known IK; the former unauthenticated "anonymous" mode (ephemeral
        // introducer key) is removed — the receiver rejects it as
        // `IntroducerMismatch`, so creating one would only produce a message the
        // recipient discards.
        if anonymous {
            tracing::warn!(
                "anonymous introduction requested but is not supported (S05 §11); sending attributed"
            );
        }
        let payload_for_a = IntroductionPayload::create(
            &self.identity_key,
            &contact_b.their_ik_pub,
            name_b,
            &mailboxes_b,
            validity_days,
        )
        .map_err(|e| MessagingError::SerializationError(e.to_string()))?;
        let payload_for_b = IntroductionPayload::create(
            &self.identity_key,
            &contact_a.their_ik_pub,
            name_a,
            &mailboxes_a,
            validity_days,
        )
        .map_err(|e| MessagingError::SerializationError(e.to_string()))?;

        // Send to contact_a (about contact_b)
        self.send_control_message(contact_a_id, &ControlMessage::Introduction(payload_for_a))
            .await?;

        // Send to contact_b (about contact_a)
        self.send_control_message(contact_b_id, &ControlMessage::Introduction(payload_for_b))
            .await?;

        tracing::info!(
            contact_a_id,
            contact_b_id,
            anonymous,
            "sent mutual introduction"
        );

        Ok(())
    }

    /// Accept a pending introduction — create a new contact from the payload.
    ///
    /// Returns the new contact's ID.
    pub async fn accept_introduction(&self, introduction_id: i64) -> Result<ContactId> {
        let pending = self
            .storage
            .get_pending_introduction(introduction_id)
            .await
            .map_err(MessagingError::StorageError)?
            .ok_or(MessagingError::InternalError(
                "introduction not found".into(),
            ))?;

        if pending.status != IntroductionStatus::Pending {
            return Err(MessagingError::InternalError(
                "introduction already resolved".into(),
            ));
        }

        // Reconstruct and verify the payload
        let payload = IntroductionPayload::from_bytes(&pending.payload_blob).map_err(|e| {
            MessagingError::InternalError(format!("invalid introduction payload: {e}"))
        })?;

        // Check expiration
        let now = najwa_crypto::time::now();
        if now > payload.expires_at {
            self.storage
                .update_introduction_status(introduction_id, IntroductionStatus::Expired)
                .await
                .map_err(MessagingError::StorageError)?;
            return Err(MessagingError::InternalError("introduction expired".into()));
        }

        // Verify signature — S05 §11: ALWAYS enforced. Introductions are
        // attributed; the payload is verified against the introducer's known IK.
        // (The former `is_anonymous` skip that accepted introductions without any
        // identity verification is removed — the receiver rejects an IK mismatch
        // as `IntroducerMismatch` before this point.)
        let introducer = self
            .storage
            .get_contact(pending.introducer_contact_id as u64)
            .await
            .map_err(MessagingError::StorageError)?
            .ok_or(MessagingError::ContactNotFound)?;

        let introducer_pub =
            najwa_crypto::keys::ed25519::Ed25519Public::from_bytes(&introducer.their_ik_pub)
                .map_err(|e| {
                    MessagingError::InternalError(format!("invalid introducer key: {e}"))
                })?;

        payload.verify(&introducer_pub).map_err(|e| {
            MessagingError::InternalError(format!("introduction signature invalid: {e}"))
        })?;

        // Check if already a contact
        if let Some(_existing) = self
            .storage
            .get_contact_by_ik(&payload.introduced_ik_pub)
            .await
            .map_err(MessagingError::StorageError)?
        {
            self.storage
                .update_introduction_status(introduction_id, IntroductionStatus::Accepted)
                .await
                .map_err(MessagingError::StorageError)?;
            return Err(MessagingError::InternalError("already a contact".into()));
        }

        // Mark introduction as accepted.
        // Contact creation (pseudonym derivation, create_contact, mailbox cap setup)
        // is handled by the FFI layer which has direct SqliteStorage access.
        self.storage
            .update_introduction_status(introduction_id, IntroductionStatus::Accepted)
            .await
            .map_err(MessagingError::StorageError)?;

        tracing::info!(
            introduction_id,
            introduced_name = %payload.introduced_display_name,
            "introduction accepted — FFI layer will create contact"
        );

        Ok(0)
    }

    /// Reject a pending introduction.
    pub async fn reject_introduction(&self, introduction_id: i64) -> Result<()> {
        let pending = self
            .storage
            .get_pending_introduction(introduction_id)
            .await
            .map_err(MessagingError::StorageError)?
            .ok_or(MessagingError::InternalError(
                "introduction not found".into(),
            ))?;

        if pending.status != IntroductionStatus::Pending {
            return Err(MessagingError::InternalError(
                "introduction already resolved".into(),
            ));
        }

        self.storage
            .update_introduction_status(introduction_id, IntroductionStatus::Rejected)
            .await
            .map_err(MessagingError::StorageError)?;

        tracing::info!(introduction_id, "introduction rejected");
        Ok(())
    }
}
