//! S07 top-level delivery confirmations. These carry no Payload wrapper.

use najwa_protocol::mailbox::client::MailboxClient;
use najwa_protocol::message::ack::{to_padded_plaintext, CumulativeAck, ReadReceiptContent};
use najwa_protocol::message::types::{fixed_overhead, pad_to_bucket};
use najwa_protocol::message::{
    MessageHeader, MessageType, WireMessage, WirePrefixMeta, WIRE_VERSION,
};
use najwa_protocol::ratchet::encrypt::ratchet_encrypt;

use crate::cover::AbsorptionPriority;
use crate::error::{MessagingError, Result};
use crate::service::MessagingService;
use crate::storage::CoreStorage;
use crate::types::{ContactId, DeliveryStrategy, Direction};

impl<S: CoreStorage, M: MailboxClient> MessagingService<S, M> {
    pub async fn send_cumulative_ack(
        &self,
        contact_id: ContactId,
        ack: &CumulativeAck,
    ) -> Result<()> {
        self.send_confirmation(
            contact_id,
            MessageType::CumulativeAck,
            &ack.to_bytes()?,
            AbsorptionPriority::Ack,
            true,
            None,
        )
        .await
    }

    /// Called when an opted-in received message is displayed.
    pub async fn send_read_receipt(&self, contact_id: ContactId, msg_id: [u8; 16]) -> Result<()> {
        let msg = self
            .storage
            .get_message_by_msg_id(&msg_id)
            .await
            .map_err(MessagingError::StorageError)?;
        let Some(msg) = msg else {
            return Ok(());
        };
        if msg.contact_id != contact_id
            || !matches!(msg.direction, Direction::Received)
            || msg.flags & 4 == 0
        {
            return Ok(());
        }
        let receipt = ReadReceiptContent {
            msg_id,
            timestamp: self.message_time(),
        };
        self.send_confirmation(
            contact_id,
            MessageType::ReadReceipt,
            &receipt.to_bytes(),
            AbsorptionPriority::ReadReceipt,
            true,
            None,
        )
        .await
    }

    /// Convert saved display events to encrypted retryable frames without any
    /// network wait. Consuming the intent and advancing the ratchet are atomic.
    pub async fn enqueue_read_receipts(&self) -> Result<()> {
        for intent in self.storage.pending_read_receipts().await.map_err(MessagingError::StorageError)? {
            let receipt = ReadReceiptContent { msg_id: intent.msg_id, timestamp: intent.timestamp };
            if let Err(error) = self.send_confirmation(
                intent.contact_id as ContactId, MessageType::ReadReceipt, &receipt.to_bytes(),
                AbsorptionPriority::ReadReceipt, false, Some(intent.msg_id),
            ).await {
                tracing::debug!(%error, "read receipt preparation deferred");
            }
        }
        Ok(())
    }

    async fn send_confirmation(
        &self,
        contact_id: ContactId,
        kind: MessageType,
        body: &[u8],
        priority: AbsorptionPriority,
        dispatch: bool,
        receipt: Option<[u8; 16]>,
    ) -> Result<()> {
        let state_guard = self.state_gate.lock().await;
        let contact = self
            .storage
            .get_contact(contact_id)
            .await
            .map_err(MessagingError::StorageError)?
            .ok_or(MessagingError::ContactNotFound)?;
        if contact.blocked {
            return Err(MessagingError::ContactBlocked);
        }
        // A confirmation can only refer to an established, authenticated session.
        let mut state = self
            .storage
            .get_ratchet_state(contact_id)
            .await
            .map_err(MessagingError::StorageError)?
            .ok_or(MessagingError::NoMatchingSession)?;
        let ad = self
            .storage
            .get_session_ad(contact_id)
            .await
            .map_err(MessagingError::StorageError)?
            .ok_or(MessagingError::NoMatchingSession)?;
        let overhead = fixed_overhead(kind, false);
        let bucket = pad_to_bucket(body.len() + 2, overhead).ok_or_else(|| {
            MessagingError::SerializationError("confirmation exceeds largest bucket".into())
        })?;
        let plaintext = to_padded_plaintext(body, bucket - overhead)?;
        let (header, encrypted_payload) = ratchet_encrypt(
            &mut state,
            &plaintext,
            &ad,
            &WirePrefixMeta {
                version: WIRE_VERSION,
                message_type: kind.as_byte(),
                x3dh_header: None,
            },
        )?;
        let wire = WireMessage {
            version: WIRE_VERSION,
            message_type: kind,
            header: MessageHeader::Ratchet(header),
            x3dh_header: None,
            encrypted_payload,
        };
        let caps = self
            .storage
            .get_contact_capabilities(contact_id)
            .await
            .map_err(MessagingError::StorageError)?;
        if caps.is_empty() {
            return Err(MessagingError::NoMailboxCapability);
        }
        let ranges = if kind == MessageType::CumulativeAck {
            CumulativeAck::from_bytes(body)?
                .ranges
                .into_iter()
                .map(|r| (r.sender_dh_pub, r.start_n, r.end_n))
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        let MessageHeader::Ratchet(header) = &wire.header;
        let bytes = wire.to_bytes();
        let input = crate::pipeline::Outgoing {
            contact_id,
            state: &state,
            ad: None,
            message: None,
            existing_message_id: None,
            wire: &bytes,
            dh_pub: header.dh_pub.to_bytes(),
            n: header.n,
            requires_ack: false,
            disappearing: None,
            repair: None,
            logical_id: None,
            acknowledging: &ranges,
        };
        let (id, mid) = match receipt {
            Some(msg_id) => self.storage.commit_read_receipt(&input, msg_id).await,
            None => self.storage.commit_outgoing(&input).await,
        }.map_err(MessagingError::StorageError)?;
        let frame = crate::pipeline::queued_frame(id, mid, &input);
        drop(state_guard);
        if !dispatch { return Ok(()); }
        self.dispatch_frame(&frame, DeliveryStrategy::Primary, Some(priority))
            .await
    }
}
