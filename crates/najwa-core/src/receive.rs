//! Message receiving and processing logic (S08 §6).

use najwa_crypto::time::{now, now_ms};
use najwa_protocol::mailbox::client::MailboxClient;
use najwa_protocol::message::control::ControlMessage;
use najwa_protocol::message::envelope::{cap_hint, envelope_decrypt, CAP_HINT_SIZE};
use najwa_protocol::message::gap_repair::{
    EpochGap, GapRange, GapRepairUnavailable, RepairedItem, GAP_DETECT_SECS, GAP_REPAIR_MAX_EPOCHS,
    GAP_REPAIR_MAX_RANGE, GAP_REPAIR_MAX_RANGES_PER_EPOCH,
};
use najwa_protocol::message::timestamp::validate_timestamp;
use najwa_protocol::message::types::{
    ContentType, MessageHeader, MessageType, Payload, WireMessage,
};
use rand::seq::SliceRandom;

use crate::error::{MessagingError, Result};
use crate::service::{
    MessagingService, QuarantinedFrame, RepairPhase, RepairState, EPOCH_QUARANTINE_MAX,
    MAX_REPAIR_RETRIES, REPAIR_GRACE_SECS,
};
use crate::session::deserialize_x3dh_header;
use crate::storage::CoreStorage;
use crate::types::*;
use najwa_protocol::ratchet::state::RatchetState;

/// Reason code carried in `SessionRepairInit` — S06 §3.7.1.
const REPAIR_REASON_MISSED_EPOCH: u8 = 0x01;
const REPAIR_REASON_TOO_MANY_SKIPPED: u8 = 0x02;

#[cfg(test)]
mod deactivation_pacing_tests {
    use super::*;
    use crate::cover::{AbsorptionPriority, PendingPayload, PendingQueues, SlotSource};
    use najwa_protocol::mailbox::{
        client::Transport, http::HttpMailboxClient, types::MailboxConfig,
    };
    use najwa_transport::{
        circuit::{CircuitHandle, CircuitIsolation},
        error::TransportError,
        http::HttpResponse,
    };
    use std::sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    };

    struct FailingTransport(AtomicUsize);
    #[async_trait::async_trait]
    impl Transport for FailingTransport {
        async fn get_circuit(
            &self,
            isolation: CircuitIsolation,
        ) -> std::result::Result<CircuitHandle, TransportError> {
            Ok(CircuitHandle::new(isolation))
        }
        async fn post(
            &self,
            _: &CircuitHandle,
            url: &str,
            _: &[u8],
            _: &str,
        ) -> std::result::Result<HttpResponse, TransportError> {
            assert!(url.ends_with("/v1/capability/deactivate"));
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(HttpResponse {
                status: 503,
                headers: Default::default(),
                body: vec![],
            })
        }
        async fn get(
            &self,
            _: &CircuitHandle,
            _: &str,
        ) -> std::result::Result<HttpResponse, TransportError> {
            unreachable!()
        }
    }
    #[tokio::test]
    async fn deactivation_waits_for_control_slot_and_uses_one_attempt() {
        let transport = Arc::new(FailingTransport(AtomicUsize::new(0)));
        let mut service = MessagingService::new(
            najwa_crypto::keys::ed25519::Ed25519KeyPair::from_seed(&[7; 32]),
            najwa_storage::database::SqliteStorage::open_in_memory(&[8; 32]).unwrap(),
            HttpMailboxClient::new(transport.clone()),
        );
        let queues = Arc::new(PendingQueues::new());
        service.set_slot_source(Arc::new(SlotSource::new(
            queues.clone(),
            Arc::new(AtomicBool::new(true)),
        )));
        let mailbox = MailboxConfig::new("a".repeat(56), [1; 32], [2; 32]);
        let future = service.deactivate_ephemeral_handshake_cap(&mailbox, 1);
        tokio::pin!(future);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), &mut future)
                .await
                .is_err()
        );
        assert_eq!(transport.0.load(Ordering::SeqCst), 0);
        let item = queues.pop_highest(&mailbox.onion_address).unwrap();
        assert_eq!(item.priority, AbsorptionPriority::Control);
        let PendingPayload::Slot(grant) = item.payload else {
            panic!("expected control-slot waiter")
        };
        let (permit, _, _) = crate::cover::SlotPermit::tracked();
        grant.send(permit).unwrap();
        future.await;
        assert_eq!(transport.0.load(Ordering::SeqCst), 1);
    }
}

/// The ratchet-state commit a decrypted message needs, carried from the
/// decrypt/accept step to the atomic commit at the end of `process_message_impl`
/// (S06 §3.11 I3). `Normal` advances an existing session; `Initial` (re)establishes
/// one and therefore also commits the session AD + OPK consumption.
enum PendingCommit {
    Normal {
        cid: ContactId,
        state: RatchetState,
    },
    Initial {
        cid: ContactId,
        state: RatchetState,
        ad: Vec<u8>,
        opk_id: Option<[u8; 4]>,
    },
}

fn authenticated_header_id(header: &najwa_protocol::ratchet::header::RatchetHeader) -> [u8; 16] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(header.dh_pub.to_bytes());
    h.update(header.n.to_be_bytes());
    h.finalize()[..16].try_into().expect("SHA256 prefix")
}

fn verify_identity_rotation(body: &[u8; 200], known: &[u8; 32]) -> Result<[u8; 32]> {
    use najwa_crypto::keys::ed25519::{Ed25519Public, Ed25519Signature};
    let invalid = || MessagingError::SerializationError("invalid identity rotation".into());
    if &body[..32] != known {
        return Err(invalid());
    }
    let new_ik: [u8; 32] = body[32..64].try_into().unwrap();
    let old = Ed25519Public::from_bytes(known).map_err(|_| invalid())?;
    let new = Ed25519Public::from_bytes(&new_ik).map_err(|_| invalid())?;
    let old_sig =
        Ed25519Signature::from_bytes(body[72..136].try_into().unwrap()).map_err(|_| invalid())?;
    let new_sig =
        Ed25519Signature::from_bytes(body[136..200].try_into().unwrap()).map_err(|_| invalid())?;
    old.verify(&body[..72], &old_sig).map_err(|_| invalid())?;
    new.verify(&body[..72], &new_sig).map_err(|_| invalid())?;
    Ok(new_ik)
}

/// S11 §4.4: true for a `FileMetadata` (`0x10`) or `FileChunk` (`0x11`) body
/// that fails its S11 §2.2.1 layout. `Payload::from_bytes` already checks the
/// text types; file bodies are checked here, before they are stored.
fn malformed_file_body(content_type: u8, content: &[u8]) -> bool {
    use najwa_protocol::message::file_transfer::{FileChunkWire, FileMetadata};
    match content_type {
        0x10 => FileMetadata::from_bytes(content).is_err(),
        0x11 => FileChunkWire::from_bytes(content).is_err(),
        _ => false,
    }
}

/// Build a bounded §8.5 request from aged skipped ratchet keys. `logical_seq`
/// is deliberately absent: S07 §4 forbids using it as a delivery cursor.
fn gap_repair_request_for_state(state: &RatchetState, now_secs: u64) -> Option<ControlMessage> {
    let mut missing: Vec<([u8; 32], u32)> = state
        .skipped
        .iter()
        .filter_map(|(&(dh_pub, n), skipped)| {
            (now_secs.saturating_sub(skipped.created_at) >= GAP_DETECT_SECS).then_some((dh_pub, n))
        })
        .collect();
    missing.sort_unstable();

    let mut epochs: Vec<EpochGap> = Vec::new();
    let mut total = 0usize;
    for (dh_pub, n) in missing {
        if total == GAP_REPAIR_MAX_RANGE {
            break;
        }
        let epoch_index = match epochs.iter().position(|epoch| epoch.dh_pub == dh_pub) {
            Some(index) => index,
            None if epochs.len() < GAP_REPAIR_MAX_EPOCHS => {
                epochs.push(EpochGap {
                    dh_pub,
                    ranges: Vec::new(),
                });
                epochs.len() - 1
            }
            None => continue,
        };
        let ranges = &mut epochs[epoch_index].ranges;
        if let Some(last) = ranges.last_mut() {
            if last.end_n.checked_add(1) == Some(n) {
                last.end_n = n;
                total += 1;
                continue;
            }
        }
        if ranges.len() == GAP_REPAIR_MAX_RANGES_PER_EPOCH {
            continue;
        }
        ranges.push(GapRange {
            start_n: n,
            end_n: n,
        });
        total += 1;
    }
    epochs.retain(|epoch| !epoch.ranges.is_empty());
    (!epochs.is_empty()).then_some(ControlMessage::GapRepairRequest { epochs })
}

fn collapse_unavailable_ranges(mut missing: Vec<([u8; 32], u32)>) -> Vec<GapRepairUnavailable> {
    missing.sort_unstable();
    let mut ranges: Vec<GapRepairUnavailable> = Vec::new();
    for (dh_pub, n) in missing {
        if let Some(last) = ranges.last_mut() {
            if last.dh_pub == dh_pub && last.end_n.checked_add(1) == Some(n) {
                last.end_n = n;
                continue;
            }
        }
        ranges.push(GapRepairUnavailable {
            dh_pub,
            start_n: n,
            end_n: n,
        });
    }
    ranges
}

fn mailbox_poll_due(health: &crate::types::MailboxHealth, current: u64) -> bool {
    health.enabled
        && (health.consecutive_failures == 0
            || health.last_failure.is_none_or(|last| {
                // A clock correction must not trap a route behind a future timestamp.
                last > current
                    || current - last
                        >= crate::pipeline::transport_retry_delay(health.consecutive_failures)
            }))
}

#[cfg(test)]
mod automatic_retry_tests {
    use super::*;

    #[test]
    fn polling_resumes_at_the_deadline_and_never_overrides_explicit_disable() {
        let mut health = crate::types::MailboxHealth {
            mailbox_id: 1,
            onion_address: "a".repeat(56),
            consecutive_failures: 1,
            total_successes: 0,
            total_failures: 1,
            last_success: None,
            last_failure: Some(100),
            enabled: true,
        };
        for (failures, delay) in [
            (1, 5),
            (2, 10),
            (3, 20),
            (6, 160),
            (7, 300),
            (u32::MAX, 300),
        ] {
            health.consecutive_failures = failures;
            assert!(!mailbox_poll_due(&health, 100 + delay - 1));
            assert!(mailbox_poll_due(&health, 100 + delay));
        }
        assert!(mailbox_poll_due(&health, 99));
        health.enabled = false;
        assert!(!mailbox_poll_due(&health, 1000));
        health.enabled = true;
        health.consecutive_failures = 0;
        assert!(mailbox_poll_due(&health, 100));
    }
}

impl<S: CoreStorage, M: MailboxClient> MessagingService<S, M> {
    /// Poll all mailboxes for new messages and process them (S08 §6.1).
    ///
    /// Drains released, unacknowledged blobs. Durable completion is the only
    /// cursor; transient storage failures and rate limits leave server copies.
    ///
    /// Returns a list of successfully received and decrypted messages.
    pub async fn poll_messages(&self) -> Result<Vec<ReceivedMessage>> {
        let _poll = self.poll_gate.lock().await;
        if let Err(error) = self.maintain_prekeys().await {
            tracing::warn!(%error, "prekey maintenance failed; will retry next poll");
            self.require_prekey_recovery_complete()?;
        }
        // On the first poll after startup, reload any quarantine frames persisted
        // before a crash/restart so their grace windows resume (S08 §6.3).
        self.reload_quarantine_once().await;

        let queues = self
            .storage
            .list_mailboxes_with_ids()
            .await
            .map_err(MessagingError::StorageError)?;
        // S08 §6.1.1: read only this poll's selection from each mailbox's pool
        // of real and dummy queues, so its operator cannot count contacts. A
        // dummy queue has no envelope secret: its cover blobs are discarded
        // and acknowledged below like any blob that is not ours.
        let mut by_mailbox: Vec<(MailboxId, Vec<najwa_protocol::mailbox::types::MailboxConfig>)> =
            Vec::new();
        for (mailbox_id, queue) in queues {
            match by_mailbox.iter_mut().find(|(id, _)| *id == mailbox_id) {
                Some((_, real)) => real.push(queue),
                None => by_mailbox.push((mailbox_id, vec![queue])),
            }
        }
        let mut mailboxes = Vec::new();
        for (mailbox_id, real) in by_mailbox {
            let onion = real[0].onion_address.clone();
            let selected = self.fetch_plan.select(&onion, real, |cap| {
                crate::fetch_plan::fetch_only_queue(&onion, cap)
            });
            mailboxes.extend(selected.into_iter().map(|queue| (mailbox_id, queue)));
        }

        // S08 §9.2: visit mailboxes in a randomized order. They are stored in a
        // stable priority order, so a fixed visit order lets an observer
        // correlating fetches across servers rank a user's mailboxes and always
        // identify the primary by position. Shuffling is the cheap half of §9.2;
        // the remaining half — pacing the fan-out to one mailbox per cover poll
        // cycle instead of draining all of them back to back — is still open and
        // is a receive-latency change, not a reordering.
        mailboxes.shuffle(&mut rand::thread_rng());

        let mut received = Vec::new();

        // Per-fetch blob count (§6.1.1). The server returns the oldest released,
        // un-acknowledged blobs first; we drain across iterations.
        use crate::fetch_plan::FETCH_COUNT;
        // Bound the per-poll drain so a poison message (always-failing,
        // never-acked) cannot spin forever; it is retried next poll.
        const MAX_DRAIN_ITERS: usize = 64;
        // Responsive polling commits ACK intents with received frames, then
        // flushes cumulative ranges at the end of the batch. A slow ACK circuit
        // must not block storing every subsequent file part. Direct processing,
        // Timing privacy and stores without durable intents retain eager ACKs.
        let defer_acks = self.storage.durable_ack_intents()
            && self.slot_source.as_ref().is_some_and(|slots| slots.bypass());

        for (mailbox_id, mailbox) in &mailboxes {
            if let Some(health) = self
                .storage
                .get_mailbox_health(*mailbox_id)
                .await
                .map_err(MessagingError::StorageError)?
            {
                if !mailbox_poll_due(&health, najwa_crypto::time::now()) {
                    continue;
                }
            }
            let ephemeral = self
                .storage
                .get_ephemeral_handshake_capability(*mailbox_id, &mailbox.fetch_capability)
                .await
                .map_err(MessagingError::StorageError)?;

            // A successfully committed Initial consumes the slot locally even
            // when the deactivation POST was interrupted. Retry using the FETCH
            // capability (the server endpoint is deliberately keyed on fetch),
            // and never process a second depositor while that retry is pending.
            if let Some(cap) = ephemeral.filter(|cap| cap.accepted) {
                self.deactivate_ephemeral_handshake_cap(mailbox, cap.id)
                    .await;
                continue;
            }
            let mut ephemeral_consumed = false;
            // S07 §3.2: inbound blobs deposited to this mailbox are enveloped
            // under the (deposit_capability, envelope_secret) pair WE advertised for
            // it. Build the cap_hint → (deposit_cap, envelope_secret) map from the
            // queue's own pair so we can strip the envelope. `mailboxes` includes
            // the shared mailbox queue plus every registered per-contact queue for
            // that onion (S05 §8 step 10). The secret keys decryption; the deposit
            // cap supplies the routing cap_hint returned with each blob.
            let mut cap_map =
                std::collections::HashMap::<[u8; CAP_HINT_SIZE], ([u8; 32], [u8; 32])>::new();
            if mailbox.envelope_secret != [0u8; 32] {
                cap_map.insert(
                    cap_hint(&mailbox.deposit_capability),
                    (mailbox.deposit_capability, mailbox.envelope_secret),
                );
            }

            // D13/R6: there is NO `since_id` release-cursor. The randomised
            // batched-release `release_at` made a timestamp cursor lossy — a blob
            // released *after* the cursor passed it was skipped forever, a
            // guaranteed desync. Instead, `acknowledge` is the only cursor:
            // fetch all released-unacked blobs, process them, and acknowledge
            // (which deletes them server-side) so the next fetch returns the next
            // batch. Loop until the mailbox is drained. Redelivery (e.g. if an
            // acknowledge is lost) is absorbed by transport dedup, so this is
            // safe at-least-once.
            let mut iters = 0;
            loop {
                iters += 1;
                if iters > MAX_DRAIN_ITERS {
                    break;
                }

                let batch = match self
                    .mailbox_client
                    .fetch(mailbox, &mailbox.fetch_capability, None, FETCH_COUNT)
                    .await
                {
                    Ok(msgs) => {
                        if let Err(error) = crate::health::MailboxHealthTracker::new(&self.storage)
                            .record_success(*mailbox_id)
                            .await
                        {
                            tracing::warn!(%error,"mailbox health write deferred");
                        }
                        msgs
                    }
                    Err(e) => {
                        if crate::pipeline::mailbox_health_failure(&e) {
                            let health = crate::health::MailboxHealthTracker::new(&self.storage);
                            if let Err(error) = health.record_failure(*mailbox_id).await {
                                tracing::warn!(%error,"mailbox health write deferred");
                            }
                        }
                        tracing::warn!(
                            mailbox = %mailbox.onion_address,
                            error = %e,
                            "failed to fetch messages from mailbox"
                        );
                        break;
                    }
                };
                if batch.is_empty() {
                    break;
                }
                let batch_len = batch.len();

                // Collect the ids to acknowledge (delete). A blob is acked once
                // it reaches a terminal outcome: delivered, control-handled,
                // durably quarantined (D8), an undecryptable cover/spam blob,
                // or a terminal processing error. Transient storage failures
                // and rate limits are retried on a later poll.
                let mut ack_ids: Vec<String> = Vec::with_capacity(batch_len);
                let mut deferred = false;

                for envelope in &batch {
                    if ephemeral_consumed {
                        // Multiple deposits are allowed before success, but the
                        // first valid Initial wins. Remaining blobs in a page are
                        // discarded without another X3DH attempt.
                        ack_ids.push(envelope.id.clone());
                        continue;
                    }
                    // Envelope-decrypt before processing (S07 §3.2). A queue with
                    // no envelope secret has an empty map, so every blob fails
                    // here: an unwrapped blob is never parsed.
                    let inner_blob = match self.envelope_decrypt_blob(&envelope.blob, &cap_map) {
                        Ok(inner) => inner,
                        Err(_) => {
                            // Not addressed to us (cover traffic or spam) —
                            // terminal discard; ack so we stop re-fetching it.
                            tracing::debug!("envelope decryption failed, discarding blob");
                            ack_ids.push(envelope.id.clone());
                            continue;
                        }
                    };

                    let is_initial = WireMessage::from_bytes(&inner_blob)
                        .map(|wire| matches!(wire.message_type, MessageType::Initial))
                        .unwrap_or(false);
                    let processed = if defer_acks {
                        self.process_message_impl(&inner_blob, false, ephemeral.map(|cap| cap.id), true).await
                    } else {
                        self.process_message(&inner_blob, ephemeral.map(|cap| cap.id)).await
                    };
                    match processed {
                        Ok(Some(msg)) => {
                            received.push(msg);
                            ack_ids.push(envelope.id.clone());
                            if is_initial {
                                if let Some(cap) = ephemeral {
                                    ephemeral_consumed = true;
                                    self.deactivate_ephemeral_handshake_cap(mailbox, cap.id)
                                        .await;
                                }
                            }
                        }
                        Ok(None) => {
                            // Control message handled, or quarantined for
                            // epoch-reorder retry (D8 — persisted locally). Terminal
                            // for the server copy.
                            ack_ids.push(envelope.id.clone());
                            if is_initial {
                                if let Some(cap) = ephemeral {
                                    ephemeral_consumed = true;
                                    self.deactivate_ephemeral_handshake_cap(mailbox, cap.id)
                                        .await;
                                }
                            }
                        }
                        Err(MessagingError::RateLimitExceeded { .. }) => {
                            deferred = true;
                        }
                        Err(MessagingError::StorageError(e)) => {
                            deferred = true;
                            // Transient — do NOT ack; retry on the next poll.
                            tracing::warn!(error = %e, "transient storage error processing message; will retry");
                        }
                        Err(
                            e @ (MessagingError::DuplicateMessage
                            | MessagingError::KeepLocalSession),
                        ) => {
                            // Expected terminal drops: a replay/multi-path duplicate,
                            // or the S08 §4.3 crossing-Initial tiebreak. Ack (drop);
                            // not a failure, so log at debug.
                            tracing::debug!(reason = %e, "dropping message (expected)");
                            ack_ids.push(envelope.id.clone());
                        }
                        Err(e) => {
                            // Terminal processing failure (malformed, no session,
                            // bad decrypt, repair initiated). Ack to avoid a
                            // poison-message loop; dedup absorbs any duplicate.
                            tracing::warn!(error = %e, "failed to process message");
                            ack_ids.push(envelope.id.clone());
                        }
                    }
                }

                if !ack_ids.is_empty() {
                    if let Err(e) = self
                        .mailbox_client
                        .acknowledge(mailbox, &mailbox.fetch_capability, &ack_ids)
                        .await
                    {
                        // If the ack is lost the blobs remain and will be
                        // re-fetched next poll (dedup absorbs duplicates). Break
                        // to avoid re-processing the same batch this cycle.
                        tracing::warn!(error = %e, "failed to acknowledge messages");
                        break;
                    }
                }

                // A short page means the mailbox is drained for now.
                if deferred || batch_len < FETCH_COUNT as usize {
                    break;
                }
            }
        }

        // D8: now that this cycle's fresh frames have advanced sessions, retry
        // any epoch-reorder-quarantined frames. Recovered messages join the
        // batch; frames whose gap hasn't closed stay buffered (or escalate to
        // repair once REPAIR_GRACE_SECS elapses).
        received.extend(self.retry_quarantine().await);

        // Polling is also the §8.5 repair timer, so a gap becomes actionable
        // after the reorder window even when no later message arrives.
        self.request_aged_gap_repairs().await;
        // Once receives have committed, background failures must not hide their
        // UI delivery. Durable work/ACK/outbox entries remain for the next poll.
        for result in [
            self.drain_inbound_work().await,
            self.flush_ack_intents().await,
            self.retry_outgoing().await,
        ] {
            if let Err(error) = result {
                tracing::warn!(%error,"durable messaging work deferred");
            }
        }

        Ok(received)
    }

    /// Attempt to envelope-decrypt a blob using known deposit capabilities.
    ///
    /// Tries the cap_hint from the blob's associated capability first (O(1)),
    /// then falls back to trial decryption with all known caps.
    fn envelope_decrypt_blob(
        &self,
        blob: &[u8],
        cap_map: &std::collections::HashMap<[u8; CAP_HINT_SIZE], ([u8; 32], [u8; 32])>,
    ) -> Result<Vec<u8>> {
        // Trial decryption with all known (deposit_cap, envelope_secret) pairs (D3).
        for (dep_cap, env_secret) in cap_map.values() {
            if let Ok(inner) = envelope_decrypt(env_secret, dep_cap, blob) {
                return Ok(inner);
            }
        }
        Err(MessagingError::SerializationError(
            "envelope decryption failed for all known capabilities".into(),
        ))
    }

    /// Process a single raw message blob (S08 §6.2, §6.3).
    ///
    /// Returns `Some(ReceivedMessage)` for user-visible messages,
    /// `None` for internally-handled control messages (including a frame that
    /// was quarantined for epoch-reorder tolerance, D8).
    pub(crate) async fn process_message(
        &self,
        raw: &[u8],
        ephemeral_handshake_cap_id: Option<i64>,
    ) -> Result<Option<ReceivedMessage>> {
        self.process_message_impl(raw, false, ephemeral_handshake_cap_id, false)
            .await
    }

    async fn deactivate_ephemeral_handshake_cap(
        &self,
        mailbox: &najwa_protocol::mailbox::types::MailboxConfig,
        capability_id: i64,
    ) {
        // S05 §5.2 step 4 GOTCHA: /deactivate is keyed by FETCH capability.
        self.prekey_control_slot(mailbox).await;
        match self.mailbox_client.deactivate_once(mailbox).await {
            Ok(()) => {
                if let Err(error) = self
                    .storage
                    .mark_ephemeral_handshake_cap_deactivated(capability_id)
                    .await
                {
                    tracing::warn!(
                        capability_id,
                        %error,
                        "server deactivated ephemeral cap but local stamp failed"
                    );
                }
            }
            Err(error) => {
                // The valid Initial remains committed and the row remains
                // `accepted_at != NULL`; the next poll retries deactivation and
                // does not process another deposit. This degrades through a
                // transient network failure without reopening the one-shot slot.
                tracing::warn!(
                    capability_id,
                    %error,
                    "ephemeral capability deactivation failed; will retry"
                );
            }
        }
    }

    /// Buffer a frame that hit `MissedEpochBoundary` for later retry (D8).
    /// Returns `true` if it was quarantined, `false` if the buffer is full (in
    /// which case the caller escalates to session repair immediately).
    pub(crate) async fn try_quarantine(&self, raw: &[u8]) -> Result<bool> {
        let blob_hash = najwa_crypto::hash::sha256(raw);
        let quarantined_at = najwa_crypto::time::now();
        {
            let q = self
                .epoch_quarantine
                .lock()
                .map_err(|_| MessagingError::InternalError("quarantine lock poisoned".into()))?;
            if q.iter().any(|f| f.blob_hash == blob_hash) {
                return Ok(true);
            }
            if q.len() >= EPOCH_QUARANTINE_MAX {
                return Ok(false);
            }
        }
        self.storage
            .save_quarantined_frame(&blob_hash, raw, quarantined_at)
            .await
            .map_err(MessagingError::StorageError)?;
        let mut q = self
            .epoch_quarantine
            .lock()
            .map_err(|_| MessagingError::InternalError("quarantine lock poisoned".into()))?;
        if !q.iter().any(|f| f.blob_hash == blob_hash) {
            q.push(QuarantinedFrame {
                blob_hash,
                blob: raw.to_vec(),
                quarantined_at,
            });
        }
        Ok(true)
    }

    /// Reload every quarantine frame persisted before a crash/restart into the
    /// in-memory buffer, exactly once per process (S08 §6.3 crash recovery).
    /// Their original `quarantined_at` is preserved so grace windows resume where
    /// they left off rather than restarting.
    pub(crate) async fn reload_quarantine_once(&self) {
        use std::sync::atomic::Ordering;
        if self.quarantine_loaded.swap(true, Ordering::SeqCst) {
            return; // already reloaded this process
        }
        let persisted = match self.storage.load_quarantined_frames().await {
            Ok(f) => f,
            Err(_) => {
                self.quarantine_loaded.store(false, Ordering::SeqCst); // retry next poll
                return;
            }
        };
        if persisted.is_empty() {
            return;
        }
        if let Ok(mut q) = self.epoch_quarantine.lock() {
            for (blob, quarantined_at) in persisted {
                if q.len() >= EPOCH_QUARANTINE_MAX {
                    break;
                }
                let blob_hash = najwa_crypto::hash::sha256(&blob);
                if q.iter().any(|f| f.blob_hash == blob_hash) {
                    continue;
                }
                q.push(QuarantinedFrame {
                    blob_hash,
                    blob,
                    quarantined_at,
                });
            }
        }
    }

    /// Retry every quarantined frame (D8). Called at the end of a poll cycle,
    /// after fresh frames may have advanced the session and closed the epoch
    /// gap. A frame that now decrypts is delivered; one that still misses its
    /// epoch is re-buffered until `REPAIR_GRACE_SECS` elapses, after which it
    /// escalates to graceful session repair. Returns any recovered messages.
    pub(crate) async fn retry_quarantine(&self) -> Vec<ReceivedMessage> {
        // Take the current buffer; surviving frames are pushed back below.
        let frames: Vec<QuarantinedFrame> = match self.epoch_quarantine.lock() {
            Ok(mut g) => std::mem::take(&mut *g),
            Err(_) => return Vec::new(),
        };
        if frames.is_empty() {
            return Vec::new();
        }

        let now = najwa_crypto::time::now();
        let mut recovered = Vec::new();
        let mut survivors = Vec::new();

        for frame in frames {
            match self.process_message_impl(&frame.blob, true, None, false).await {
                // Gap closed → delivered (or recovered control message). Drop the
                // durable copy: it has served its purpose.
                Ok(maybe_msg) => {
                    if let Some(msg) = maybe_msg {
                        recovered.push(msg);
                    }
                    let _ = self
                        .storage
                        .delete_quarantined_frame(&frame.blob_hash)
                        .await;
                }
                Err(MessagingError::RatchetError(
                    najwa_protocol::ratchet::error::RatchetError::MissedEpochBoundary,
                )) => {
                    // Still missing the linking epoch.
                    if now.saturating_sub(frame.quarantined_at) >= REPAIR_GRACE_SECS {
                        // Grace expired → genuine miss, not a reorder. Repair.
                        if let Ok(wire) = WireMessage::from_bytes(&frame.blob) {
                            let MessageHeader::Ratchet(rh) = &wire.header;
                            let dh_pub = rh.dh_pub.to_bytes();
                            let epoch_link = rh.epoch_link;
                            self.on_ratchet_failure(
                                &dh_pub,
                                REPAIR_REASON_MISSED_EPOCH,
                                dh_pub,
                                epoch_link,
                            )
                            .await;
                        }
                        // repair initiated → drop the durable copy too
                        let _ = self
                            .storage
                            .delete_quarantined_frame(&frame.blob_hash)
                            .await;
                    } else {
                        survivors.push(frame); // keep buffered + persisted, retry next cycle
                    }
                }
                Err(MessagingError::NoMatchingSession) => {
                    // S05 §8.2: batched release can surface a Standard from a
                    // newly-created sender session before its Initial. Keep the
                    // raw frame for the same bounded repair grace and retry it
                    // after the Initial installs the session. With no authenticated
                    // contact identity yet there is no safe repair peer to signal;
                    // expiry therefore discards the orphan instead of guessing.
                    if now.saturating_sub(frame.quarantined_at) >= REPAIR_GRACE_SECS {
                        let _ = self
                            .storage
                            .delete_quarantined_frame(&frame.blob_hash)
                            .await;
                    } else {
                        survivors.push(frame);
                    }
                }
                Err(MessagingError::StorageError(_) | MessagingError::RateLimitExceeded { .. }) => {
                    survivors.push(frame);
                }
                // Permanent failure → drop the durable copy so it can't wedge.
                Err(_) => {
                    let _ = self
                        .storage
                        .delete_quarantined_frame(&frame.blob_hash)
                        .await;
                }
            }
        }

        if !survivors.is_empty() {
            if let Ok(mut g) = self.epoch_quarantine.lock() {
                // Prepend survivors so newly-quarantined frames from this cycle
                // (added after we took the buffer) are preserved too.
                survivors.append(&mut *g);
                *g = survivors;
            }
        }

        recovered
    }

    /// Inner processing. `is_retry` is true when re-feeding a quarantined frame
    /// (D8): a fresh `MissedEpochBoundary` is buffered, but on retry the error
    /// is propagated so [`retry_quarantine`] can apply the grace/repair policy.
    async fn process_message_impl(
        &self,
        raw: &[u8],
        is_retry: bool,
        ephemeral_handshake_cap_id: Option<i64>,
        defer_acks: bool,
    ) -> Result<Option<ReceivedMessage>> {
        // 1. Parse wire message
        if let Some(&value) = raw.first() {
            if value != najwa_protocol::message::WIRE_VERSION {
                tracing::warn!(offset = 0, value, "unknown wire version");
                return Ok(None);
            }
        }
        let wire = WireMessage::from_bytes(raw)?;
        let state_guard = self.state_gate.lock().await;
        let MessageHeader::Ratchet(frame_header) = &wire.header;
        let header_id = authenticated_header_id(frame_header);
        if self
            .storage
            .check_msg_id_seen(&header_id)
            .await
            .map_err(MessagingError::StorageError)?
        {
            self.storage
                .repeat_ack(&header_id)
                .await
                .map_err(MessagingError::StorageError)?;
            drop(state_guard);
            if !defer_acks { self.flush_ack_intents().await?; }
            return Ok(None);
        }

        // 2. Route by message type. `pending` carries the advanced-but-unsaved
        // ratchet state for the Normal path, to be committed atomically with the
        // message + dedup below (I3). Initials also carry their candidate AD and
        // OPK consumption into that same transaction.
        let (contact, plaintext, pending) = match wire.message_type {
            MessageType::Initial => {
                // New session: the X3DH header now travels cleartext in the wire
                // prefix (S07 §2) and is bound into the AAD — NOT inside
                // encrypted_payload (which is just nonce||ct||tag).
                let x3dh_bytes = wire.x3dh_header.as_deref().ok_or_else(|| {
                    MessagingError::SerializationError("initial message missing X3DH header".into())
                })?;
                let (x3dh_header, _) = deserialize_x3dh_header(x3dh_bytes)?;

                let MessageHeader::Ratchet(ratchet_header) = &wire.header;
                let wire_prefix = wire.wire_prefix().ok_or_else(|| {
                    MessagingError::SerializationError("initial message has no wire prefix".into())
                })?;

                let accepted = self
                    .accept_session(
                        &x3dh_header,
                        ratchet_header,
                        &wire.encrypted_payload,
                        &wire_prefix,
                        ephemeral_handshake_cap_id.is_some(),
                    )
                    .await?;
                let cid = accepted.contact.id;
                (
                    accepted.contact,
                    accepted.plaintext,
                    PendingCommit::Initial {
                        cid,
                        state: accepted.state,
                        ad: accepted.ad,
                        opk_id: accepted.opk_id,
                    },
                )
            }
            MessageType::Normal => {
                // Existing session: decrypt with existing ratchet
                let MessageHeader::Ratchet(ratchet_header) = &wire.header;
                let wire_prefix = wire.wire_prefix().ok_or_else(|| {
                    MessagingError::SerializationError("normal message has no wire prefix".into())
                })?;

                match self
                    .decrypt_with_existing_session(
                        ratchet_header,
                        &wire.encrypted_payload,
                        &wire_prefix,
                    )
                    .await
                {
                    Ok((c, pt, cid, state)) => (c, pt, PendingCommit::Normal { cid, state }),
                    Err(MessagingError::RatchetError(
                        najwa_protocol::ratchet::error::RatchetError::TooManySkipped {
                            limit,
                            requested,
                        },
                    )) => {
                        // S08 §6.2: graceful repair instead of a bidirectional reset.
                        // Old ratchet state is preserved; a SessionRepairInit is sent,
                        // retried up to MAX_REPAIR_RETRIES, then falls back to the
                        // local-only session teardown as a last resort.
                        tracing::warn!(
                            limit,
                            requested,
                            "MAX_SKIP exceeded — initiating graceful session repair (RFC-18 Layer 2)"
                        );
                        let dh_pub = ratchet_header.dh_pub.to_bytes();
                        let epoch_link = ratchet_header.epoch_link;
                        drop(state_guard);
                        self.on_ratchet_failure(
                            &dh_pub,
                            REPAIR_REASON_TOO_MANY_SKIPPED,
                            dh_pub,
                            epoch_link,
                        )
                        .await;
                        return Err(MessagingError::InternalError(format!(
                            "session repair initiated: MAX_SKIP exceeded (limit={limit}, requested={requested})"
                        )));
                    }
                    Err(MessagingError::RatchetError(
                        najwa_protocol::ratchet::error::RatchetError::MissedEpochBoundary,
                    )) => {
                        // D8 (S06 §3.7.1): an epoch-link mismatch is usually a
                        // *reorder*, not a real loss — the server holds each blob
                        // a randomised time and multi-path copies traverse
                        // different mailboxes, so a later epoch can be released
                        // before the epoch that links it. Quarantine the frame
                        // and retry once intervening frames have advanced the
                        // session, instead of tearing the session down on every
                        // reorder. Only escalate to repair after REPAIR_GRACE_SECS
                        // (handled by retry_quarantine) or when the buffer is full.
                        if is_retry {
                            // Re-fed by retry_quarantine: surface the error so the
                            // caller applies the grace/repair policy.
                            return Err(MessagingError::RatchetError(
                                najwa_protocol::ratchet::error::RatchetError::MissedEpochBoundary,
                            ));
                        }
                        if self.try_quarantine(raw).await? {
                            tracing::debug!(
                                "MissedEpochBoundary — quarantined for epoch-reorder tolerance (D8)"
                            );
                            return Ok(None);
                        }
                        // Quarantine full → escalate to graceful repair now.
                        tracing::warn!(
                            "MissedEpochBoundary, quarantine full — initiating graceful session repair"
                        );
                        let dh_pub = ratchet_header.dh_pub.to_bytes();
                        let epoch_link = ratchet_header.epoch_link;
                        drop(state_guard);
                        self.on_ratchet_failure(
                            &dh_pub,
                            REPAIR_REASON_MISSED_EPOCH,
                            dh_pub,
                            epoch_link,
                        )
                        .await;
                        return Err(MessagingError::InternalError(
                            "session repair initiated: missed epoch boundary".into(),
                        ));
                    }
                    Err(MessagingError::NoMatchingSession) => {
                        // S05 §8.2 reordering tolerance: a Standard for the new
                        // session may be released before its Initial. It is safe
                        // to hold only the encrypted frame; no contact or ratchet
                        // state is created until a valid reciprocal Initial arrives.
                        if is_retry {
                            return Err(MessagingError::NoMatchingSession);
                        }
                        if self.try_quarantine(raw).await? {
                            tracing::debug!(
                                "Standard without session — quarantined pending its Initial"
                            );
                            return Ok(None);
                        }
                        return Err(MessagingError::NoMatchingSession);
                    }
                    Err(e) => return Err(e),
                }
            }
            MessageType::ReadReceipt | MessageType::CumulativeAck | MessageType::Unknown(_) => {
                use najwa_protocol::message::ack::{
                    from_padded_plaintext, CumulativeAck, ReadReceiptContent,
                };
                let prefix = wire.wire_prefix().expect("ratchet prefix");
                let (contact, plaintext, cid, state) = self
                    .decrypt_with_existing_session(frame_header, &wire.encrypted_payload, &prefix)
                    .await?;
                if let MessageType::Unknown(value) = wire.message_type {
                    tracing::warn!(offset = 1, value, "unknown wire type");
                    self.storage
                        .commit_received(cid, &state, None, &header_id, None, None)
                        .await
                        .map_err(MessagingError::StorageError)?;
                    return Ok(None);
                }
                let body = from_padded_plaintext(&plaintext)?;
                let effect = match wire.message_type {
                    MessageType::ReadReceipt => {
                        let receipt = ReadReceiptContent::from_bytes(body)?;
                        DeliveryConfirmation::ReadReceipt {
                            msg_id: receipt.msg_id,
                            timestamp: receipt.timestamp,
                        }
                    }
                    MessageType::CumulativeAck => {
                        let ack = CumulativeAck::from_bytes(body)?;
                        DeliveryConfirmation::Ack(
                            ack.ranges
                                .into_iter()
                                .map(|r| (r.sender_dh_pub, r.start_n, r.end_n))
                                .collect(),
                        )
                    }
                    _ => unreachable!(),
                };
                if contact.blocked {
                    self.storage
                        .commit_received(cid, &state, None, &header_id, None, None)
                        .await
                        .map_err(MessagingError::StorageError)?;
                } else {
                    self.storage
                        .commit_confirmation(cid, &state, &header_id, &effect)
                        .await
                        .map_err(MessagingError::StorageError)?;
                    self.end_repair(cid);
                }
                // No immediate ACK-of-ACK exchange. A confirmation has no UI message.
                return Ok(None);
            }
        };

        // 3. Parse the payload directly from the decrypted zero-padded bytes:
        //    `Payload::from_bytes` reads the authoritative `content_length` and
        //    verifies the trailing `0x00` padding (S07 §5.2/§5.3) — no separate
        //    length-prefix unpad step.
        let payload = match Payload::from_bytes(&plaintext) {
            Ok(payload) => payload,
            Err(najwa_protocol::message::MessageError::UnknownContentType(value)) => {
                return self
                    .discard_unknown(&pending, &header_id, 32, value, ephemeral_handshake_cap_id)
                    .await;
            }
            Err(error) => return Err(error.into()),
        };

        // 4. Validate timestamp (§7.1). A future-dated message (> now +
        //    MAX_FUTURE_SKEW_SECS) is never legitimate and has no carve-out —
        //    reject it (the poll loop then acks + drops the blob). A past-window
        //    failure is NOT rejected here: re-sent / gap-repair content
        //    legitimately carries its ORIGINAL (possibly > 90-day-old) timestamp
        //    for logical_msg_id stability, and at-most-once is enforced by
        //    logical dedup, not this window (§7.1 re-send carve-out).
        let now_ts = self.message_time();
        if validate_timestamp(payload.timestamp, now_ts).is_err() {
            if payload.timestamp > now_ts {
                tracing::warn!(
                    timestamp = payload.timestamp,
                    now = now_ts,
                    "message timestamp too far in the future — rejecting (§7.1)"
                );
                return Err(MessagingError::TimestampOutOfRange);
            }
            tracing::warn!(
                timestamp = payload.timestamp,
                "message timestamp past the 90-day window; deferring to logical dedup (§7.1 carve-out)"
            );
        }

        // 5. Deduplication check (S08 §9.4). The dedup *mark* is applied as part
        // of the atomic commit below (step 9), not here — so it can never persist
        // without the ratchet advance + message (I3).
        let seen = self
            .storage
            .check_msg_id_seen(&payload.msg_id)
            .await
            .map_err(MessagingError::StorageError)?;
        if seen {
            tracing::debug!(msg_id = ?payload.msg_id, "duplicate message, skipping");
            return Err(MessagingError::DuplicateMessage);
        }

        // 6. Pseudonym verification — BEFORE any commit. A mismatched/forged
        // frame must not advance our ratchet, so reject before committing (the
        // deferred ratchet advance is then simply discarded).
        if payload.sender_pseudonym != contact.their_pseudonym {
            return Err(MessagingError::PseudonymMismatch);
        }

        self.inbound_limiter.check(contact.id)?;

        // 7. Handle by content type and decide whether the message is stored.
        if payload.content_type == ContentType::ReciprocalHandshake {
            if let Some(&version) = payload.content.first() {
                if version != najwa_protocol::contact::types::HANDSHAKE_VERSION {
                    return self
                        .discard_unknown(
                            &pending,
                            &header_id,
                            66,
                            version,
                            ephemeral_handshake_cap_id,
                        )
                        .await;
                }
            }
        }
        let is_control = payload.content_type == ContentType::Control;
        let is_reciprocal = payload.content_type == ContentType::ReciprocalHandshake;
        if is_reciprocal && !matches!(&pending, PendingCommit::Initial { .. }) {
            return Err(MessagingError::SerializationError(
                "reciprocal handshake is only valid in an Initial".into(),
            ));
        }
        // ReciprocalHandshake is contact-establishment metadata, not a user
        // message. Its session/dedup commit still happens below, but it is not
        // surfaced in the conversation.
        // S11 §4.4: a file body that fails its §2.2.1 layout commits (ratchet,
        // dedup, ACK) like any frame but is never stored as a message row.
        let mut store = !contact.blocked
            && !is_reciprocal
            && !malformed_file_body(payload.content_type as u8, &payload.content);
        let mut effects = Vec::new();
        let mut control_message = None;
        let mut ack_required = !contact.blocked;
        if is_control && !contact.blocked {
            // Parse and handle control message
            let control = match ControlMessage::from_bytes(&payload.content) {
                Ok(control) => control,
                Err(najwa_protocol::message::MessageError::UnknownControlSubtype(value)) => {
                    return self
                        .discard_unknown(
                            &pending,
                            &header_id,
                            66,
                            value,
                            ephemeral_handshake_cap_id,
                        )
                        .await;
                }
                Err(najwa_protocol::message::MessageError::UnknownNestedVersion {
                    offset,
                    value,
                }) => {
                    return self
                        .discard_unknown(
                            &pending,
                            &header_id,
                            66 + offset,
                            value,
                            ephemeral_handshake_cap_id,
                        )
                        .await;
                }
                Err(error) => return Err(error.into()),
            };
            effects = self.prepare_control_effects(&contact, &control).await?;
            if matches!(
                control,
                ControlMessage::RevocationNotice | ControlMessage::SessionReset
            ) {
                ack_required = false;
                store = false;
            }
            if matches!(
                control,
                ControlMessage::GapRepairRequest { .. }
                    | ControlMessage::GapRepairBundle { .. }
                    | ControlMessage::GapRepairUnavailable(_)
                    | ControlMessage::ReSendRequest { .. }
                    | ControlMessage::FileChunkNack { .. }
            ) {
                store = false;
            }
            control_message = Some(control.clone());

            // These control messages are handled but NOT stored as messages.
            if matches!(
                control,
                ControlMessage::TypingIndicator | ControlMessage::Introduction(..)
            ) {
                store = false;
            }
        }

        // 7b. S07 §6.2 / S08 §9.4: endpoint-invariant logical dedup for user
        // content. A session-repair / gap-repair re-send carries a fresh
        // transport msg_id but the SAME logical_msg_id; if we already delivered
        // it, do not surface it again — but still commit the ratchet advance so
        // we stay in sync with the sender's re-encrypted session.
        let logical_msg_id: Option<[u8; 16]> = (!is_control && !is_reciprocal).then(|| {
            let my_ik = self.identity_key.public().to_bytes();
            najwa_protocol::message::id::generate_logical_msg_id(
                &my_ik,
                &contact.their_ik_pub,
                payload.timestamp,
                payload.logical_seq,
                payload.content_type as u8,
                &payload.content,
            )
        });
        if let Some(l) = &logical_msg_id {
            if self
                .storage
                .check_logical_msg_id_seen(contact.id, l)
                .await
                .map_err(MessagingError::StorageError)?
            {
                tracing::debug!(
                    contact_id = contact.id,
                    "logical duplicate (re-send) — absorbing without re-surfacing"
                );
                store = false;
            }
        }

        // 8. Build the message to store, if any.
        //
        // S12 §4.1: for a timer-enabled conversation, seal the LOCAL at-rest copy
        // under a fresh per-message ephemeral key held only in the volatile cache.
        // The received wire copy is not retained — only this stored copy exists —
        // so zeroising the key on expiry is the primary deletion defence (§5.1).
        let disappear_timer = if store {
            self.storage
                .get_conversation_timer(contact.id)
                .await
                .map_err(MessagingError::StorageError)?
        } else {
            None
        };
        let stored_message = if store {
            let content = match disappear_timer {
                Some(_) => crate::disappearing::seal_content(
                    &self.volatile_cache,
                    &payload.msg_id,
                    &payload.content,
                )
                .map_err(|e| MessagingError::InternalError(e.to_string()))?,
                None => payload.content.clone(),
            };
            Some(Message {
                id: 0,
                contact_id: contact.id,
                msg_id: payload.msg_id,
                direction: Direction::Received,
                content_type: payload.content_type as u8,
                flags: payload.flags,
                content,
                timestamp: payload.timestamp,
                status: MessageStatus::Delivered,
                ratchet_index: None,
            })
        } else {
            None
        };

        // S12 §3.2: decrypt-triggered without receipts; otherwise display may
        // shorten the never-read fallback, but must never extend it.
        let disappearing = disappear_timer.map(|secs| {
            let disappear_at_ms = crate::disappearing::config::recipient_deadline(
                now_ms().max(0) as u64,
                secs,
                payload.flags,
            );
            (secs, disappear_at_ms)
        });

        // 9. Atomic commit (I3): persist the (advanced or newly-established)
        // ratchet state, the message (if any), the dedup marks, and the
        // disappearing marker in ONE transaction. Runs AFTER the dedup CHECK above
        // (step 5), so a replayed Initial/repair is dropped before this overwrite —
        // the anti-clobber property the old pre-decrypt guard used to provide. For
        // the Initial path this also commits the session AD + OPK consumption
        // atomically (S08 §4.3).
        let (cid, state, ad, opk_id) = match &pending {
            PendingCommit::Normal { cid, state } => (*cid, state, None, None),
            PendingCommit::Initial {
                cid,
                state,
                ad,
                opk_id,
            } => (*cid, state, Some(ad.as_slice()), *opk_id),
        };
        let frame = najwa_storage::messaging::ReceivedFrame {
            contact_id: cid as i64,
            dh_pub: frame_header.dh_pub.to_bytes(),
            n: frame_header.n,
            ack_required,
        };
        self.storage
            .commit_incoming(&crate::pipeline::Incoming {
                contact_id: cid,
                state,
                ad,
                opk_id,
                ephemeral_cap_id: ad.and(ephemeral_handshake_cap_id),
                message: stored_message.as_ref(),
                transport_id: &payload.msg_id,
                logical_id: logical_msg_id.as_ref(),
                disappearing,
                header_id: &header_id,
                frame: &frame,
                effects: &effects,
            })
            .await
            .map_err(MessagingError::StorageError)?;
        drop(state_guard);
        self.end_repair(cid);
        if let Some(ControlMessage::SessionRepairInit {
            reason,
            failed_dh_pub,
            failed_epoch_link,
        }) = &control_message
        {
            self.on_session_repair_init(cid, *reason, failed_dh_pub, failed_epoch_link);
        }
        if let Err(error) = self.drain_inbound_work().await {
            tracing::warn!(%error,"inbound work deferred");
        }

        // ACK exactly the authenticated frame that reached durable completion.
        // This includes controls and logical duplicates, independently of UI flags.
        if ack_required && !defer_acks {
            let mut ranges = match self.storage.pending_ack_ranges(contact.id).await {
                Ok(ranges) => ranges,
                Err(error) => {
                    tracing::warn!(%error,"ACK lookup deferred after receive commit");
                    Vec::new()
                }
            };
            // Test stores without durable intents still ACK this completed frame.
            if ranges.is_empty() {
                ranges.push((
                    frame_header.dh_pub.to_bytes(),
                    frame_header.n,
                    frame_header.n,
                ));
            }
            let ack = najwa_protocol::message::ack::CumulativeAck {
                ranges: ranges
                    .into_iter()
                    .map(
                        |(sender_dh_pub, start_n, end_n)| najwa_protocol::message::ack::AckRange {
                            sender_dh_pub,
                            start_n,
                            end_n,
                        },
                    )
                    .collect(),
            };
            if let Err(error) = self.send_cumulative_ack(contact.id, &ack).await {
                tracing::warn!(%error, "failed to send delivery ACK");
            }
        }

        // 10. Blocked contact, or a handled-but-not-stored control message →
        // nothing to surface to the app (the ratchet + dedup are committed).
        if contact.blocked {
            tracing::debug!(
                contact_id = contact.id,
                "message from blocked contact, discarding"
            );
            return Ok(None);
        }
        if stored_message.is_none() {
            return Ok(None);
        }

        Ok(Some(ReceivedMessage {
            contact_id: contact.id,
            msg_id: payload.msg_id,
            content_type: payload.content_type as u8,
            content: payload.content,
            timestamp: payload.timestamp,
            is_control,
        }))
    }

    /// Scan durable ratchet states for gaps whose reorder grace period elapsed.
    async fn request_aged_gap_repairs(&self) {
        let contacts = match self.storage.list_contacts().await {
            Ok(contacts) => contacts,
            Err(e) => {
                tracing::warn!(error = %e, "failed to list contacts for gap repair");
                return;
            }
        };
        let now_secs = now();
        for contact in contacts {
            let state = match self.storage.get_ratchet_state(contact.id).await {
                Ok(Some(state)) => state,
                Ok(None) => continue,
                Err(e) => {
                    tracing::warn!(contact_id = contact.id, error = %e, "failed to load ratchet for gap repair");
                    continue;
                }
            };
            let Some(request) = gap_repair_request_for_state(&state, now_secs) else {
                continue;
            };
            if !self.gap_repair_allowed(contact.id, now_secs) {
                continue;
            }
            if let Err(e) = self.send_control_message(contact.id, &request).await {
                tracing::warn!(contact_id = contact.id, error = %e, "failed to send gap-repair request");
                self.rollback_gap_repair(contact.id);
            }
        }
    }

    /// Answer a bounded ratchet-addressed request from durable outbound history.
    async fn handle_gap_repair_request(
        &self,
        contact_id: ContactId,
        epochs: &[EpochGap],
    ) -> Result<()> {
        use najwa_protocol::message::types::MAX_CONTENT_SIZE;

        let mut bundles: Vec<Vec<RepairedItem>> = Vec::new();
        let mut current = Vec::new();
        let mut current_size = 2usize; // subtype + item_count
        let mut missing = Vec::new();

        for epoch in epochs {
            for range in &epoch.ranges {
                for n in range.start_n..=range.end_n {
                    match self
                        .storage
                        .get_outbound_repair_entry(contact_id, &epoch.dh_pub, n)
                        .await
                    {
                        Ok(Some((mut item, sealed))) => {
                            if sealed {
                                match crate::disappearing::open_sealed_content(
                                    &self.volatile_cache,
                                    &item.original_msg_id,
                                    &item.original_content,
                                ) {
                                    Ok(crate::disappearing::Opened::Plaintext(plain)) => {
                                        item.original_content = plain
                                    }
                                    _ => {
                                        missing.push((epoch.dh_pub, n));
                                        continue;
                                    }
                                }
                            }
                            let item_size = 70usize.saturating_add(item.original_content.len());
                            if item_size.saturating_add(2) > MAX_CONTENT_SIZE {
                                // §8.5 defines no fragmentation for a single item.
                                missing.push((epoch.dh_pub, n));
                                continue;
                            }
                            if current.len() == u8::MAX as usize
                                || current_size.saturating_add(item_size) > MAX_CONTENT_SIZE
                            {
                                bundles.push(std::mem::take(&mut current));
                                current_size = 2;
                            }
                            current_size += item_size;
                            current.push(item);
                        }
                        Ok(None) => missing.push((epoch.dh_pub, n)),
                        Err(e) => return Err(MessagingError::StorageError(e)),
                    }
                }
            }
        }
        if !current.is_empty() {
            bundles.push(current);
        }

        for items in bundles {
            self.send_control_message(contact_id, &ControlMessage::GapRepairBundle { items })
                .await?;
        }
        for unavailable in collapse_unavailable_ranges(missing) {
            self.send_control_message(
                contact_id,
                &ControlMessage::GapRepairUnavailable(unavailable),
            )
            .await?;
        }
        Ok(())
    }

    /// S07 §10: authenticate first, then co-commit progress and header dedup.
    async fn discard_unknown(
        &self,
        pending: &PendingCommit,
        header_id: &[u8; 16],
        offset: usize,
        value: u8,
        ephemeral_cap_id: Option<i64>,
    ) -> Result<Option<ReceivedMessage>> {
        tracing::warn!(offset, value, "unknown authenticated message byte");
        match pending {
            PendingCommit::Normal { cid, state } => {
                self.storage
                    .commit_received(*cid, state, None, header_id, None, None)
                    .await
                    .map_err(MessagingError::StorageError)?;
            }
            PendingCommit::Initial {
                cid,
                state,
                ad,
                opk_id,
            } => {
                self.storage
                    .commit_initial_received(
                        *cid,
                        state,
                        ad,
                        *opk_id,
                        None,
                        header_id,
                        None,
                        None,
                        ephemeral_cap_id,
                    )
                    .await
                    .map_err(MessagingError::StorageError)?;
            }
        }
        Ok(None)
    }

    /// Prepare local effects without mutating storage. They are applied in the
    /// same transaction as the authenticated frame and advanced receive state.
    async fn prepare_control_effects(
        &self,
        contact: &Contact,
        control: &ControlMessage,
    ) -> Result<Vec<najwa_storage::messaging::ReceiveEffect>> {
        use najwa_storage::messaging::ReceiveEffect as E;
        let cid = contact.id;
        let mut effects = Vec::new();
        match control {
            ControlMessage::ReSendRequest { .. }
            | ControlMessage::GapRepairRequest { .. }
            | ControlMessage::FileChunkNack { .. } => effects.push(E::Work(control.to_bytes())),
            ControlMessage::SessionReset => effects.push(E::Reset),
            ControlMessage::RevocationNotice => effects.push(E::Revoke),
            ControlMessage::MailboxUpdate { mailboxes } => {
                effects.push(crate::bridge::mailbox_update_effect(cid, mailboxes)?)
            }
            ControlMessage::IdentityRotation { body } => effects.push(E::Identity {
                old: contact.their_ik_pub,
                new: verify_identity_rotation(body, &contact.their_ik_pub)?,
            }),
            ControlMessage::DisappearTimer {
                duration_secs,
                set_at,
            } => {
                // S12 §2.2: a below-minimum timer or a set_at past the S07 §7.1
                // future bound is ignored; the frame is still committed and ACKed.
                if !crate::disappearing::timer_below_minimum(*duration_secs)
                    && !crate::disappearing::config::set_at_too_far_ahead(
                        *set_at,
                        self.message_time(),
                    )
                {
                    let incoming = crate::disappearing::TimerSetting {
                        timer_secs: (*duration_secs > 0).then_some(*duration_secs),
                        set_at: *set_at,
                        setter_ik: contact.their_ik_pub,
                    };
                    let current = self
                        .storage
                        .get_conversation_timer_setting(cid)
                        .await
                        .map_err(MessagingError::StorageError)?
                        .map(
                            |(timer_secs, set_at, setter_ik)| crate::disappearing::TimerSetting {
                                timer_secs,
                                set_at,
                                setter_ik,
                            },
                        );
                    if crate::disappearing::timer_setting_wins(current.as_ref(), &incoming) {
                        effects.push(E::Timer {
                            secs: incoming.timer_secs,
                            set_at: incoming.set_at,
                            setter: incoming.setter_ik,
                        });
                    }
                }
            }
            ControlMessage::GapRepairUnavailable(unavailable) => {
                if unavailable.start_n <= unavailable.end_n
                    && (unavailable.end_n as u64 - unavailable.start_n as u64)
                        < GAP_REPAIR_MAX_RANGE as u64
                {
                    effects.push(E::ForgetSkipped((
                        unavailable.dh_pub,
                        unavailable.start_n,
                        unavailable.end_n,
                    )));
                }
            }
            ControlMessage::GapRepairBundle { items } => {
                let mut transport_ids = std::collections::HashSet::new();
                let mut logical_ids = std::collections::HashSet::new();
                for item in items {
                    let kind = ContentType::try_from(item.original_content_type)?;
                    if matches!(
                        kind,
                        ContentType::Control | ContentType::ReciprocalHandshake
                    ) || item.original_logical_seq == 0
                    {
                        return Err(MessagingError::SerializationError(
                            "invalid repaired content".into(),
                        ));
                    }
                    let payload = Payload {
                        sender_pseudonym: contact.their_pseudonym,
                        content_type: kind,
                        flags: item.original_flags,
                        timestamp: item.original_timestamp,
                        msg_id: item.original_msg_id,
                        logical_seq: item.original_logical_seq,
                        content: item.original_content.clone(),
                    };
                    Payload::from_bytes(&payload.to_bytes())?;
                    if validate_timestamp(payload.timestamp, self.message_time()).is_err()
                        && payload.timestamp > self.message_time()
                    {
                        return Err(MessagingError::TimestampOutOfRange);
                    }
                    use sha2::{Digest, Sha256};
                    let mut hash = Sha256::new();
                    hash.update([item.original_content_type]);
                    hash.update(&item.original_content);
                    let hash: [u8; 32] = hash.finalize().into();
                    if najwa_protocol::message::id::generate_msg_id(
                        &item.original_dh_pub,
                        item.original_n,
                        &hash,
                        &contact.their_pseudonym,
                    ) != item.original_msg_id
                    {
                        return Err(MessagingError::SerializationError(
                            "repaired message ID mismatch".into(),
                        ));
                    }
                    let logical = najwa_protocol::message::id::generate_logical_msg_id(
                        &self.identity_key.public().to_bytes(),
                        &contact.their_ik_pub,
                        item.original_timestamp,
                        item.original_logical_seq,
                        item.original_content_type,
                        &item.original_content,
                    );
                    effects.push(E::ForgetSkipped((
                        item.original_dh_pub,
                        item.original_n,
                        item.original_n,
                    )));
                    effects.push(E::RepairedPosition {
                        dh_pub: item.original_dh_pub,
                        n: item.original_n,
                    });
                    if !transport_ids.insert(item.original_msg_id)
                        || !logical_ids.insert(logical)
                        || self
                            .storage
                            .check_msg_id_seen(&item.original_msg_id)
                            .await
                            .map_err(MessagingError::StorageError)?
                        || self
                            .storage
                            .check_logical_msg_id_seen(cid, &logical)
                            .await
                            .map_err(MessagingError::StorageError)?
                        || malformed_file_body(item.original_content_type, &item.original_content)
                    {
                        continue;
                    }
                    let msg = Message {
                        id: 0,
                        contact_id: cid,
                        msg_id: item.original_msg_id,
                        direction: Direction::Received,
                        content_type: item.original_content_type,
                        flags: item.original_flags,
                        content: item.original_content.clone(),
                        timestamp: item.original_timestamp,
                        status: MessageStatus::Delivered,
                        ratchet_index: Some(item.original_n),
                    };
                    effects.push(self.received_message_effect(msg, Some(logical)).await?);
                }
            }
            ControlMessage::Introduction(intro) => {
                if contact.their_ik_pub != intro.introducer_ik_pub {
                    return Err(MessagingError::IntroducerMismatch);
                }
                if self
                    .storage
                    .get_contact_by_ik(&intro.introduced_ik_pub)
                    .await
                    .map_err(MessagingError::StorageError)?
                    .is_none()
                {
                    // S05 §11.4 steps 4–5: expiry and the introducer's signature.
                    let introducer =
                        najwa_crypto::keys::ed25519::Ed25519Public::from_bytes(&contact.their_ik_pub)
                            .map_err(|e| MessagingError::InvalidIntroduction(e.to_string()))?;
                    intro
                        .verify(&introducer)
                        .map_err(|e| MessagingError::InvalidIntroduction(e.to_string()))?;
                    effects.push(E::Introduction(
                        najwa_storage::types::NewPendingIntroduction {
                            introducer_contact_id: cid as i64,
                            introduced_ik_pub: intro.introduced_ik_pub,
                            introduced_display_name: intro.introduced_display_name.clone(),
                            introducer_ik_pub: intro.introducer_ik_pub,
                            payload_blob: intro.to_bytes(),
                            is_anonymous: false,
                            created_at: intro.timestamp as i64,
                            expires_at: intro.expires_at as i64,
                        },
                    ));
                    let text = format!(
                        "{} introduced you to {}",
                        contact.display_name.as_deref().unwrap_or("Someone"),
                        intro.introduced_display_name
                    );
                    let msg = Message {
                        id: 0,
                        contact_id: cid,
                        msg_id: najwa_crypto::random::random_bytes(),
                        direction: Direction::Received,
                        content_type: 1,
                        flags: 0,
                        content: text.into_bytes(),
                        timestamp: self.message_time(),
                        status: MessageStatus::Delivered,
                        ratchet_index: None,
                    };
                    effects.push(self.received_message_effect(msg, None).await?);
                }
            }
            ControlMessage::SessionRepairInit { .. }
            | ControlMessage::TypingIndicator
            | ControlMessage::RotationAnnouncementRequest => {}
        }
        Ok(effects)
    }

    async fn received_message_effect(
        &self,
        mut msg: Message,
        logical_id: Option<[u8; 16]>,
    ) -> Result<najwa_storage::messaging::ReceiveEffect> {
        let timer = self
            .storage
            .get_conversation_timer(msg.contact_id)
            .await
            .map_err(MessagingError::StorageError)?;
        if timer.is_some() {
            msg.content =
                crate::disappearing::seal_content(&self.volatile_cache, &msg.msg_id, &msg.content)
                    .map_err(|e| MessagingError::InternalError(e.to_string()))?;
        }
        let disappearing = timer.map(|secs| {
            (
                secs,
                crate::disappearing::config::recipient_deadline(
                    now_ms().max(0) as u64,
                    secs,
                    msg.flags,
                ),
            )
        });
        Ok(najwa_storage::messaging::ReceiveEffect::Message {
            message: Box::new(crate::bridge::core_to_new_message(&msg)),
            logical_id,
            disappearing,
        })
    }

    /// Replayable network work is durable before the mailbox copy is removed.
    pub(crate) async fn drain_inbound_work(&self) -> Result<()> {
        let Ok(_work) = self.work_gate.try_lock() else {
            return Ok(());
        };
        for work in self
            .storage
            .inbound_work()
            .await
            .map_err(MessagingError::StorageError)?
        {
            let cid = work.contact_id as ContactId;
            if self
                .storage
                .get_contact(cid)
                .await
                .map_err(MessagingError::StorageError)?
                .is_none_or(|c| c.blocked)
            {
                continue;
            }
            let control = ControlMessage::from_bytes(&work.body)?;
            let result = match control {
                // S08 §6.5: one answered request per contact per
                // GAP_REPAIR_MIN_INTERVAL_SECS; the rest are dropped unanswered.
                // Cursor 1 marks an admitted request, so a retry after a
                // failure is not refused.
                ControlMessage::GapRepairRequest { epochs } => {
                    if work.cursor > 0
                        || crate::service::admit(
                            &self.answered_gap_repairs,
                            cid,
                            najwa_crypto::time::now(),
                            crate::service::GAP_REPAIR_MIN_INTERVAL_SECS,
                        )
                    {
                        self.storage
                            .advance_inbound_work(work.id, Some(1))
                            .await
                            .map_err(MessagingError::StorageError)?;
                        self.handle_gap_repair_request(cid, &epochs).await
                    } else {
                        Ok(())
                    }
                }
                ControlMessage::ReSendRequest { mode, body } => {
                    self.resend_history(&work, mode, &body).await
                }
                ControlMessage::FileChunkNack {
                    session_id,
                    missing_indices,
                } => {
                    self.answer_file_nack(&work, session_id, &missing_indices)
                        .await
                }
                _ => Ok(()),
            };
            match result {
                Ok(()) => self
                    .storage
                    .advance_inbound_work(work.id, None)
                    .await
                    .map_err(MessagingError::StorageError)?,
                Err(error) => {
                    tracing::warn!(%error,work_id=work.id,"inbound request remains queued")
                }
            }
        }
        Ok(())
    }

    async fn resend_history(
        &self,
        work: &najwa_storage::messaging::InboundWork,
        mode: u8,
        body: &[u8],
    ) -> Result<()> {
        let (anchor, from, to) = match (mode, body.len()) {
            (1, 24) => (
                Some(body[..16].try_into().unwrap()),
                u64::from_be_bytes(body[16..24].try_into().unwrap()),
                self.message_time(),
            ),
            (2, 16) => (
                None,
                u64::from_be_bytes(body[..8].try_into().unwrap()),
                u64::from_be_bytes(body[8..16].try_into().unwrap()),
            ),
            _ => {
                return Err(MessagingError::SerializationError(
                    "invalid resend request".into(),
                ))
            }
        };
        let mut cursor = work.cursor;
        loop {
            let page = self
                .storage
                .outbound_history(work.contact_id as u64, anchor, from, to, cursor)
                .await
                .map_err(MessagingError::StorageError)?;
            if page.is_empty() {
                break;
            }
            for history in page {
                let msg = &history.message;
                let content = if msg.disappear_timer.is_some() {
                    match crate::disappearing::open_sealed_content(
                        &self.volatile_cache,
                        &msg.msg_id,
                        &msg.content,
                    )
                    .map_err(|e| MessagingError::InternalError(e.to_string()))?
                    {
                        crate::disappearing::Opened::Plaintext(bytes) => Some(bytes),
                        crate::disappearing::Opened::Expired => None,
                    }
                } else {
                    Some(msg.content.clone())
                };
                if let Some(bytes) = content {
                    let content_type = match msg.content_type {
                        najwa_storage::types::ContentType::Text => 1,
                        najwa_storage::types::ContentType::TextReply => 2,
                        najwa_storage::types::ContentType::Binary => 3,
                        najwa_storage::types::ContentType::FileMetadata => 0x10,
                        najwa_storage::types::ContentType::FileChunk => 0x11,
                        _ => {
                            cursor = msg.id;
                            self.storage
                                .advance_inbound_work(work.id, Some(cursor))
                                .await
                                .map_err(MessagingError::StorageError)?;
                            continue;
                        }
                    };
                    self.send_content(
                        work.contact_id as u64,
                        MessageContent::Raw {
                            content_type,
                            bytes,
                            reply_to: None,
                        },
                        msg.flags as u8,
                        Some((msg.id, msg.timestamp as u64, history.logical_seq)),
                    )
                    .await?;
                }
                cursor = msg.id;
                self.storage
                    .advance_inbound_work(work.id, Some(cursor))
                    .await
                    .map_err(MessagingError::StorageError)?;
            }
        }
        Ok(())
    }

    /// Graceful repair entry point (S08 §6.2).
    ///
    /// Called when `ratchet_decrypt` returns `MissedEpochBoundary` or
    /// `TooManySkipped`. Preserves the old ratchet state, records repair
    /// state in-memory, sends a fresh `SessionRepairInit` control message,
    /// and retries up to `MAX_REPAIR_RETRIES` times before tearing down the
    /// local session only (no `SessionReset` is sent).
    ///
    /// This function is best-effort: it logs and swallows errors so the
    /// surrounding `process_message` caller can return a clean error to the
    /// polling loop without cascading failure.
    async fn on_ratchet_failure(
        &self,
        failing_dh_pub: &[u8; 32],
        reason: u8,
        failed_dh_pub: [u8; 32],
        failed_epoch_link: [u8; 32],
    ) {
        // Resolve the contact whose session the header names: `DHr` equals the
        // failing `dh_pub` (same epoch) or a non-zero `epoch_link` (next epoch).
        // The ratchet state row still exists (we have NOT deleted it) so the
        // lookup is cheap. If it cannot be resolved, there is nothing to repair.
        let mut found = self.storage.get_ratchet_state_by_dh_pub(failing_dh_pub).await;
        if matches!(found, Ok(None)) && failed_epoch_link != [0u8; 32] {
            found = self.storage.get_ratchet_state_by_dh_pub(&failed_epoch_link).await;
        }
        let contact_id = match found {
            Ok(Some((cid, _))) => cid,
            Ok(None) => {
                tracing::debug!(
                    "on_ratchet_failure: no ratchet state for failing dh_pub, dropping"
                );
                return;
            }
            Err(e) => {
                tracing::warn!("on_ratchet_failure: storage lookup failed: {}", e);
                return;
            }
        };

        // Bump the retry counter under the lock, then release before
        // awaiting the send (Mutex is not held across await).
        let (retry_count, should_fallback) = {
            let mut guard = match self.repair_states.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            let entry = guard.entry(contact_id).or_insert_with(|| RepairState {
                phase: RepairPhase::InProgress,
                retry_count: 0,
                last_attempt_unix: 0,
                reason,
            });
            entry.retry_count = entry.retry_count.saturating_add(1);
            entry.last_attempt_unix = najwa_crypto::time::now();
            entry.reason = reason;
            let rc = entry.retry_count;
            let fallback = rc > MAX_REPAIR_RETRIES;
            if fallback {
                entry.phase = RepairPhase::Failed;
            } else {
                entry.phase = RepairPhase::InProgress;
            }
            (rc, fallback)
        };

        if should_fallback {
            // Retry budget exhausted (§3.7.1) → LOCAL-ONLY directional teardown.
            //
            // We MUST NOT emit `SessionReset (0x30)` here. That signal is the
            // user-initiated *bidirectional* reset (S08 §7.2) — sending it would
            // tell the peer to delete their still-working direction too, which
            // is exactly the bilateral desync session repair exists to avoid
            // (§3.7.1: "Reusing the same wire signal for a directional teardown
            // would tell the peer to also delete their working-direction state,
            // defeating the whole point"). The teardown is a purely client-side
            // recovery primitive with NO on-wire signature: we drop our local
            // session state so the next inbound frame that fails to validate
            // re-establishes a fresh X3DH session, and the peer converges
            // naturally when its own next message fails to decrypt on our side.
            //
            // ponytail: single-slot storage tears down BOTH directions locally;
            // full §3.7.1 fidelity preserves the working direction via a second
            // ratchet slot per contact (the dual-slot follow-up). The critical
            // fix here is that we no longer corrupt the PEER's state.
            tracing::error!(
                contact_id,
                retry_count,
                "session repair exhausted MAX_REPAIR_RETRIES — local-only directional teardown (no SessionReset per §3.7.1)"
            );
            if let Err(e) = self.storage.delete_ratchet_state(contact_id).await {
                tracing::error!("repair teardown: delete_ratchet_state failed: {}", e);
            }
            if let Err(e) = self.storage.delete_session_ad(contact_id).await {
                tracing::error!("repair teardown: delete_session_ad failed: {}", e);
            }
            return;
        }

        tracing::info!(
            contact_id,
            retry_count,
            reason,
            "sending SessionRepairInit (RFC-18 Layer 2)"
        );

        // send_control_message constructs and commits a fresh Initial candidate
        // under the state guard. A failed fetch/validation leaves the old state.
        let repair = ControlMessage::SessionRepairInit {
            reason,
            failed_dh_pub,
            failed_epoch_link,
        };
        if let Err(e) = self.send_control_message(contact_id, &repair).await {
            tracing::warn!(
                contact_id,
                "SessionRepairInit send failed (will retry on next failure): {}",
                e
            );
        }
    }

    /// Handle an incoming `SessionRepairInit` control message.
    ///
    /// The fresh X3DH session carrying this control message is already
    /// installed by `accept_session` when the wrapping `Initial` wire
    /// message is processed — see `process_message` above. This handler
    /// therefore only clears any outstanding repair state we were tracking
    /// for this contact and logs the repair event for diagnostics.
    fn on_session_repair_init(
        &self,
        contact_id: ContactId,
        reason: u8,
        failed_dh_pub: &[u8; 32],
        _failed_epoch_link: &[u8; 32],
    ) {
        tracing::info!(
            contact_id,
            reason,
            peer_failed_dh = ?&failed_dh_pub[..4],
            "received SessionRepairInit — fresh session installed, clearing repair state"
        );
        if let Ok(mut guard) = self.repair_states.lock() {
            guard.remove(&contact_id);
        }
    }
}

#[cfg(test)]
mod gap_repair_tests {
    use super::*;
    use najwa_crypto::keys::x25519::X25519KeyPair;
    use najwa_protocol::ratchet::init::init_bob;
    use najwa_protocol::ratchet::state::SkippedKey;

    fn state() -> RatchetState {
        let mut rng = rand::thread_rng();
        init_bob(&[0x42; 32], X25519KeyPair::generate(&mut rng))
    }

    #[test]
    fn gap_detection_uses_ratchet_numbers_not_logical_seq() {
        let now_secs = 50_000;
        let mut state = state();

        // A discontinuity in logical_seq is deliberately invisible to this
        // detector: §4 makes logical_seq an opaque uniqueness input, not a
        // delivery cursor. That property is guaranteed by the SIGNATURE —
        // `gap_repair_request_for_state` takes no logical_seq input at all, so
        // it cannot observe one. No assertion can demonstrate that more
        // strongly than the type does, and a loop feeding discarded seq values
        // to an unchanged empty state would only look like it did.
        assert!(gap_repair_request_for_state(&state, now_secs).is_none());

        // An aged hole in the authenticated ratchet numbering does fire and is
        // collapsed into an inclusive range for the corresponding DH epoch.
        for n in [3u32, 4] {
            state.skipped.insert(
                ([0xAA; 32], n),
                SkippedKey {
                    message_key: [n as u8; 32],
                    created_at: now_secs - GAP_DETECT_SECS,
                },
            );
        }
        match gap_repair_request_for_state(&state, now_secs).unwrap() {
            ControlMessage::GapRepairRequest { epochs } => {
                assert_eq!(
                    epochs,
                    vec![EpochGap {
                        dh_pub: [0xAA; 32],
                        ranges: vec![GapRange {
                            start_n: 3,
                            end_n: 4,
                        }],
                    }]
                );
            }
            other => panic!("expected GapRepairRequest, got {other:?}"),
        }
    }

    #[test]
    fn fresh_ratchet_gap_waits_for_reorder_window() {
        let now_secs = 50_000;
        let mut state = state();
        state.skipped.insert(
            ([0xBB; 32], 7),
            SkippedKey {
                message_key: [7; 32],
                created_at: now_secs - GAP_DETECT_SECS + 1,
            },
        );
        assert!(gap_repair_request_for_state(&state, now_secs).is_none());
    }
}
