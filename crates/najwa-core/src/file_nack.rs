//! S11 §4.1: missing-part requests (`FileChunkNack`, control subtype `0x3C`).
//!
//! A receiver whose file has metadata but lacks parts asks for them once the
//! file has been quiet for a while. The sender re-sends them from its own
//! stored outgoing copy through the ordinary outbox.

use najwa_protocol::mailbox::client::MailboxClient;
use najwa_protocol::message::control::ControlMessage;
use najwa_protocol::message::file_transfer::{
    FileMetadata, NACK_MAX_ATTEMPTS, NACK_MAX_INDICES, NACK_MIN_INTERVAL_SECS,
};

use crate::error::{MessagingError, Result};
use crate::service::MessagingService;
use crate::storage::CoreStorage;
use crate::types::*;

impl<S: CoreStorage, M: MailboxClient> MessagingService<S, M> {
    /// Receiver side. For each received file quiet for
    /// `NACK_MIN_INTERVAL_SECS << attempts`, queue a `FileChunkNack` for its
    /// first missing parts. A file that is complete, unreadable or out of
    /// attempts is no longer watched; an incomplete one is then failed.
    /// Only queues frames; the outbox delivers them.
    pub async fn enqueue_file_nacks(&self, now: u64) -> Result<()> {
        let due = self
            .storage
            .file_nacks_due(now, NACK_MIN_INTERVAL_SECS, NACK_MAX_ATTEMPTS)
            .await
            .map_err(MessagingError::StorageError)?;
        for file in due {
            let missing: Vec<u32> = FileMetadata::from_bytes(&file.metadata)
                .map(|meta| {
                    (0..meta.chunk_count)
                        .filter(|i| file.stored.binary_search(i).is_err())
                        .take(NACK_MAX_INDICES)
                        .collect()
                })
                .unwrap_or_default();
            let attempts = if missing.is_empty() || file.attempts >= NACK_MAX_ATTEMPTS {
                NACK_MAX_ATTEMPTS + 1
            } else {
                let nack = ControlMessage::FileChunkNack {
                    session_id: file.metadata[..16].try_into().expect("parsed metadata"),
                    missing_indices: missing,
                };
                if let Err(error) = self
                    .send_control_impl(file.contact_id as ContactId, &nack, false, false)
                    .await
                {
                    tracing::debug!(%error, "file part request deferred");
                    continue;
                }
                file.attempts + 1
            };
            self.storage
                .record_file_nack(file.metadata_id, attempts, now)
                .await
                .map_err(MessagingError::StorageError)?;
        }
        Ok(())
    }

    /// Sender side, from durable inbound work. Re-sends each listed part this
    /// contact's file still has, preserving its logical identity, at most once
    /// per file and contact per `NACK_MIN_INTERVAL_SECS`. Unknown files,
    /// indices and parts of other contacts' files find no stored copy and are
    /// ignored. The cursor is 1 + the indices handled; nonzero means admitted.
    pub(crate) async fn answer_file_nack(
        &self,
        work: &najwa_storage::messaging::InboundWork,
        session: [u8; 16],
        indices: &[u32],
    ) -> Result<()> {
        let cid = work.contact_id as ContactId;
        let mut cursor = work.cursor;
        for (i, &index) in indices.iter().enumerate().skip((cursor - 1).max(0) as usize) {
            let Some(part) = self
                .storage
                .outgoing_file_part(cid, &session, index)
                .await
                .map_err(MessagingError::StorageError)?
            else {
                continue;
            };
            if cursor == 0 {
                if !crate::service::admit(
                    &self.answered_file_nacks,
                    (cid, session),
                    najwa_crypto::time::now(),
                    NACK_MIN_INTERVAL_SECS,
                ) {
                    return Ok(());
                }
                cursor = 1;
                self.storage
                    .advance_inbound_work(work.id, Some(cursor))
                    .await
                    .map_err(MessagingError::StorageError)?;
            }
            let msg = &part.message;
            let content = MessageContent::Raw {
                content_type: 0x11,
                bytes: msg.content.clone(),
                reply_to: None,
            };
            let original = Some((msg.id, msg.timestamp as u64, part.logical_seq));
            match self
                .send_content_impl(cid, content, msg.flags as u8, original, false)
                .await
            {
                Ok(_) => {}
                // Resume from the cursor once outbound tokens refill (S08 §8.1).
                Err(error @ MessagingError::RateLimitExceeded { .. }) => return Err(error),
                // Best effort: the receiver asks again after its next quiet period.
                Err(error) => tracing::debug!(%error, index, "file part not re-sent"),
            }
            cursor = i as i64 + 2;
            self.storage
                .advance_inbound_work(work.id, Some(cursor))
                .await
                .map_err(MessagingError::StorageError)?;
        }
        Ok(())
    }
}
