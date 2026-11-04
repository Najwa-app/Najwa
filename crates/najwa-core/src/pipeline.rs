//! Atomic messaging boundaries and durable delivery work.
use crate::{
    cover::AbsorptionPriority,
    error::{MessagingError, Result},
    service::MessagingService,
    storage::CoreStorage,
    types::*,
};
use najwa_protocol::{mailbox::client::MailboxClient, ratchet::state::RatchetState};
use najwa_storage::messaging::{ChainRange, OutgoingFrame, ReceiveEffect, ReceivedFrame};

pub struct Incoming<'a> {
    pub contact_id: ContactId,
    pub state: &'a RatchetState,
    pub ad: Option<&'a [u8]>,
    pub opk_id: Option<[u8; 4]>,
    pub ephemeral_cap_id: Option<i64>,
    pub message: Option<&'a Message>,
    pub transport_id: &'a [u8; 16],
    pub logical_id: Option<&'a [u8; 16]>,
    pub disappearing: Option<(u32, u64)>,
    pub header_id: &'a [u8; 16],
    pub frame: &'a ReceivedFrame,
    pub effects: &'a [ReceiveEffect],
}

pub struct Outgoing<'a> {
    pub existing_message_id: Option<MessageId>,
    pub contact_id: ContactId,
    pub state: &'a RatchetState,
    pub ad: Option<&'a [u8]>,
    pub message: Option<&'a Message>,
    pub wire: &'a [u8],
    pub dh_pub: [u8; 32],
    pub n: u32,
    pub requires_ack: bool,
    pub disappearing: Option<(u32, u64)>,
    pub repair: Option<&'a najwa_protocol::message::gap_repair::RepairedItem>,
    pub logical_id: Option<[u8; 16]>,
    pub acknowledging: &'a [ChainRange],
}

/// Exclusive ownership of one durable frame; unrelated frames may park at
/// the scheduler together. Cancellation releases the claim synchronously.
struct FrameClaim<'a> {
    claims: &'a std::sync::Mutex<std::collections::HashSet<i64>>,
    id: i64,
}
impl<'a> FrameClaim<'a> {
    fn acquire(
        claims: &'a std::sync::Mutex<std::collections::HashSet<i64>>,
        id: i64,
    ) -> Option<Self> {
        if claims.lock().unwrap().insert(id) {
            Some(Self { claims, id })
        } else {
            None
        }
    }
}
impl Drop for FrameClaim<'_> {
    fn drop(&mut self) {
        self.claims.lock().unwrap().remove(&self.id);
    }
}

impl<S: CoreStorage, M: MailboxClient> MessagingService<S, M> {
    /// Called only after the frame and advanced ratchet are durable. The dispatch
    /// lock prevents a foreground attempt and a retry from racing each other.
    pub(crate) async fn dispatch_frame(
        &self,
        frame: &OutgoingFrame,
        strategy: DeliveryStrategy,
        priority: Option<AbsorptionPriority>,
    ) -> Result<()> {
        let Some(_dispatch) = FrameClaim::acquire(&self.dispatch_gate, frame.id) else {
            return Ok(());
        };
        self.dispatch_frame_locked(frame, strategy, priority).await
    }

    async fn dispatch_frame_locked(
        &self,
        frame: &OutgoingFrame,
        strategy: DeliveryStrategy,
        priority: Option<AbsorptionPriority>,
    ) -> Result<()> {
        let cid = frame.contact_id as ContactId;
        let contact = self
            .storage
            .get_contact(cid)
            .await
            .map_err(MessagingError::StorageError)?
            .ok_or(MessagingError::ContactNotFound)?;
        if contact.blocked {
            return Err(MessagingError::ContactBlocked);
        }
        if !self
            .storage
            .outgoing_frame_live(frame.id)
            .await
            .map_err(MessagingError::StorageError)?
        {
            return Ok(());
        }
        let caps = self
            .storage
            .get_contact_capabilities(cid)
            .await
            .map_err(MessagingError::StorageError)?;
        if caps.is_empty() {
            return Err(MessagingError::NoMailboxCapability);
        }
        let result = self
            .deposit_with_strategy(&caps, &frame.wire, strategy, priority, frame.id)
            .await;
        use rand::Rng;
        let ceiling = if result.is_ok() {
            (5u64.saturating_mul(1u64 << frame.attempts.min(10))).min(3600)
        } else {
            transport_retry_delay(frame.attempts.saturating_add(1))
        };
        let next = najwa_crypto::time::now() + rand::thread_rng().gen_range(1..=ceiling);
        self.storage
            .finish_outgoing(frame.id, result.is_ok(), next)
            .await
            .map_err(MessagingError::StorageError)?;
        result
    }

    /// Recover both Pending (crash before deposit) and Failed sends. Controls
    /// retain exactly the same inner frame until their chain position is ACKed.
    pub async fn retry_outgoing(&self) -> Result<()> {
        use futures_util::{stream, StreamExt};
        let ids = self
            .storage
            .outgoing_frame_ids()
            .await
            .map_err(MessagingError::StorageError)?;
        stream::iter(ids)
        .map(|id| async move {
            if let Ok(Some(frame))=self.storage.outgoing_frame(id).await {self.retry_queued_frame(frame).await;}
        })
        .buffer_unordered(32)
        .collect::<Vec<_>>()
        .await;
        self.deliver_revocations().await
    }

    /// S08 §7.1: deposit the RevocationNotices of deleted contacts. Each lives
    /// outside the contact row until its first deposit (the peer never ACKs
    /// it). Negated ids keep the claims and preflight apart from outbox frames.
    async fn deliver_revocations(&self) -> Result<()> {
        let Some(db) = self.storage.prekey_database() else {
            return Ok(());
        };
        let storage = |e: najwa_storage::error::StorageError| MessagingError::StorageError(e.to_string());
        for frame in db.revocation_frames().map_err(storage)? {
            let Some(_claim) = FrameClaim::acquire(&self.dispatch_gate, -frame.id) else {
                continue;
            };
            let Ok(_capacity) = self.background_delivery.try_acquire() else {
                break;
            };
            let caps = decode_revocation_routes(&frame.targets);
            let result = self
                .deposit_with_strategy(&caps, &frame.wire, DeliveryStrategy::Adaptive, Some(AbsorptionPriority::Control), -frame.id)
                .await;
            let next = najwa_crypto::time::now() + transport_retry_delay(frame.attempts.saturating_add(1));
            db.finish_revocation(frame.id, result.is_ok(), next).map_err(storage)?;
        }
        Ok(())
    }

    /// Admit newly queued work while older requests wait on the network or cover.
    /// The foreground retry API retains its finite-snapshot behavior. Desktop
    /// delivery uses this bounded driver so an old snapshot cannot freeze new sends.
    pub async fn drive_outgoing(&self) -> Result<()> {
        use futures_util::{stream::FuturesUnordered, StreamExt};
        use std::{collections::HashSet, time::Duration};
        use tokio::time::{sleep_until, Instant};
        let mut pending = FuturesUnordered::new();
        let mut active = HashSet::new();
        let mut next_scan = Instant::now();
        loop {
            if pending.len() < 32 && Instant::now() >= next_scan {
                next_scan = Instant::now() + Duration::from_secs(1);
                let frames = self
                    .storage
                    .outgoing_frame_batch()
                    .await
                    .map_err(MessagingError::StorageError)?;
                for frame in frames {
                    if frame.next_attempt > najwa_crypto::time::now()
                        || !active.insert(frame.id)
                    {
                        continue;
                    }
                    pending.push(self.retry_queued_frame(frame));
                    if pending.len() == 32 {
                        break;
                    }
                }
            }
            if pending.is_empty() {
                return self.deliver_revocations().await;
            }
            tokio::select! {
                Some(id) = pending.next() => { active.remove(&id); }
                _ = sleep_until(next_scan), if pending.len() < 32 => {}
            }
        }
    }

    async fn retry_queued_frame(&self, frame: OutgoingFrame) -> i64 {
        // The default Tor pool has eight request slots. A large outbox must
        // not queue dozens of background requests ahead of a foreground send.
        // Busy frames remain durable for the next scan; do not await admission
        // here, because receive polling also invokes the finite retry API.
        let Ok(_capacity) = self.background_delivery.try_acquire() else {
            return frame.id;
        };
        let priority = if frame.message_id.is_some() {
            AbsorptionPriority::RealMessage
        } else {
            use najwa_protocol::message::{MessageType, WireMessage};
            match WireMessage::from_bytes(&frame.wire).map(|w| w.message_type) {
                Ok(MessageType::Initial) => AbsorptionPriority::SessionRepairInit,
                Ok(MessageType::CumulativeAck) => AbsorptionPriority::Ack,
                Ok(MessageType::ReadReceipt) => AbsorptionPriority::ReadReceipt,
                _ => AbsorptionPriority::Control,
            }
        };
        if let Err(error) = self.retry_frame(&frame, priority).await {
            tracing::debug!(%error, frame_id=frame.id, "outbox attempt deferred");
        }
        frame.id
    }

    pub(crate) async fn retry_frame(
        &self,
        snapshot: &OutgoingFrame,
        priority: AbsorptionPriority,
    ) -> Result<()> {
        let Some(_dispatch) = FrameClaim::acquire(&self.dispatch_gate, snapshot.id) else {
            return Ok(());
        };
        // A foreground send (or a different retry pass) may have completed
        // since this batch was read. Revalidate under the per-frame claim.
        let current = self
            .storage
            .outgoing_frame(snapshot.id)
            .await
            .map_err(MessagingError::StorageError)?;
        let Some(frame) = current.filter(|frame| {
            frame.attempts == snapshot.attempts && frame.next_attempt <= najwa_crypto::time::now()
        }) else {
            return Ok(());
        };
        self.dispatch_frame_locked(&frame, DeliveryStrategy::Adaptive, Some(priority))
            .await
    }

    pub(crate) async fn flush_ack_intents(&self) -> Result<()> {
        for cid in self
            .storage
            .pending_ack_contacts()
            .await
            .map_err(MessagingError::StorageError)?
        {
            let ranges = self
                .storage
                .pending_ack_ranges(cid)
                .await
                .map_err(MessagingError::StorageError)?;
            if !ranges.is_empty() {
                let ack = najwa_protocol::message::ack::CumulativeAck {
                    ranges: ranges
                        .into_iter()
                        .map(|(sender_dh_pub, start_n, end_n)| {
                            najwa_protocol::message::ack::AckRange {
                                sender_dh_pub,
                                start_n,
                                end_n,
                            }
                        })
                        .collect(),
                };
                if let Err(error) = self.send_cumulative_ack(cid, &ack).await {
                    tracing::debug!(%error, cid, "ACK remains queued");
                }
            }
        }
        Ok(())
    }
}

pub(crate) fn queued_frame(
    id: i64,
    message_id: Option<MessageId>,
    input: &Outgoing<'_>,
) -> OutgoingFrame {
    OutgoingFrame {
        id,
        message_id,
        contact_id: input.contact_id as i64,
        wire: input.wire.to_vec(),
        dh_pub: input.dh_pub,
        n: input.n,
        requires_ack: input.requires_ack,
        attempts: 0,
        next_attempt: 0,
        deposited_at: None,
    }
}

/// A deleted contact's deposit routes, kept with its RevocationNotice (S08 §7.1).
/// `None` when no route can carry it.
pub(crate) fn encode_revocation_routes(caps: &[ContactCapability]) -> Option<Vec<u8>> {
    let routes: Vec<(&str, [u8; 32], [u8; 32])> = caps
        .iter()
        .filter_map(|c| Some((c.mailbox_onion.as_str(), c.their_deposit_capability?, c.their_envelope_secret?)))
        .collect();
    (!routes.is_empty()).then(|| serde_json::to_vec(&routes).ok()).flatten()
}

fn decode_revocation_routes(bytes: &[u8]) -> Vec<ContactCapability> {
    serde_json::from_slice::<Vec<(String, [u8; 32], [u8; 32])>>(bytes)
        .unwrap_or_default()
        .into_iter()
        .map(|(onion, deposit, secret)| ContactCapability {
            contact_id: 0,
            mailbox_id: 0,
            mailbox_onion: onion,
            mailbox_fetch_cap: [0; 32],
            mailbox_deposit_cap: [0; 32],
            their_deposit_capability: Some(deposit),
            their_envelope_secret: Some(secret),
        })
        .collect()
}

pub(crate) fn mailbox_health_failure(error: &najwa_protocol::mailbox::error::MailboxError) -> bool {
    use najwa_protocol::mailbox::error::MailboxError;
    matches!(
        error,
        MailboxError::TransportError(_) | MailboxError::ServerError(500..=599)
    )
}

/// Temporary failures back off without ever disabling a route or losing work.
pub(crate) fn transport_retry_delay(failures: u32) -> u64 {
    (5u64 << failures.saturating_sub(1).min(6)).min(300)
}
