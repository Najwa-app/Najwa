//! Message sending logic (S08 §5).

use std::time::Duration;

use najwa_crypto::time::now_ms;
use najwa_protocol::mailbox::client::MailboxClient;
use najwa_protocol::message::control::ControlMessage;
use najwa_protocol::message::envelope::envelope_encrypt;
use najwa_protocol::message::gap_repair::RepairedItem;
use najwa_protocol::message::id::generate_msg_id;
use najwa_protocol::message::padding::pad_payload;
use najwa_protocol::message::types::{
    ContentType, MessageHeader, MessageType, Payload, WireMessage, WIRE_VERSION,
};
use najwa_protocol::message::WirePrefixMeta;
use najwa_protocol::ratchet::encrypt::ratchet_encrypt;
use rand::seq::SliceRandom;
use rand::Rng;

use crate::cover::AbsorptionPriority;
use crate::error::{MessagingError, Result};
use crate::multipath::{is_epoch_transition_message, STAGGER_DELAY_MAX_MS, STAGGER_DELAY_MIN_MS};
use crate::service::MessagingService;
use crate::storage::CoreStorage;
use crate::types::*;

/// S07 §5.1.1 fixed per-message overhead for the 1:1 deposited blob:
/// `ENVELOPE_OVERHEAD(40) + wire_prefix + AEAD nonce(24)+tag(16)`. The padded
/// plaintext targets `bucket − fixed_overhead` so the DEPOSITED blob lands
/// exactly on a §5.1 bucket. `x3dh_len` = the cleartext X3DH header length
/// (101/105) for an `Initial` message, `None` for `Normal` → 160 / 263 / 267.
fn deposit_fixed_overhead(x3dh_len: Option<usize>) -> usize {
    const ENVELOPE_OVERHEAD: usize = 40; // S07 §3.1 (nonce 24 + tag 16)
    const AEAD_OVERHEAD: usize = 40; // S07 §2.3 (nonce 24 + tag 16)
    const BASE_WIRE_PREFIX: usize = 80; // version1+type1+reserved2+paylen4+ratchet_header72
    let wire_prefix = match x3dh_len {
        Some(x) => BASE_WIRE_PREFIX + 2 + x, // + x3dh_header_len(2) + x3dh_header(x)
        None => BASE_WIRE_PREFIX,
    };
    ENVELOPE_OVERHEAD + wire_prefix + AEAD_OVERHEAD
}

/// Absorption tier for a control message (S10 §6.1).
///
/// Keyed off the wire subtype rather than the enum variant so the mapping is
/// checked against the message-type registry, not against Rust naming.
fn control_absorption_priority(control: &ControlMessage) -> Option<AbsorptionPriority> {
    absorption_priority_for_subtype(control.subtype())
}

/// The subtype → tier mapping itself. Split out from
/// [`control_absorption_priority`] so the unpaced 0x45-0x48 arm below can be
/// asserted over the whole subtype range without building a `ControlMessage`
/// for each one.
fn absorption_priority_for_subtype(subtype: u8) -> Option<AbsorptionPriority> {
    match subtype {
        // 0x45-0x48 are unassigned control subtypes: no `ControlMessage`
        // variant produces them and the receiver rejects them. They map to no
        // tier (deposit without slot pacing), because a multi-recipient fan-out
        // paced one slot per recipient would block for K slots and make its
        // timing window grow with the recipient count.
        0x45..=0x48 => None,
        0x31 => Some(AbsorptionPriority::SessionRepairInit),
        // 0x34 is an unassigned control subtype (no `ControlMessage` variant
        // produces it); it maps to the `GroupKeyDistribution` tier.
        0x34 => Some(AbsorptionPriority::GroupKeyDistribution),
        0x00 => Some(AbsorptionPriority::Ack),
        0x02 => Some(AbsorptionPriority::TypingIndicator),
        _ => Some(AbsorptionPriority::Control),
    }
}

/// Select target mailboxes from `caps` according to `strategy`
/// (S08 §9.1). This is the canonical multi-path target selection, paired
/// with the per-target deposit-envelope encryption (S07 §3.1) in `try_deposit_one`.
///
/// A free function rather than a method: it reads nothing from the service, and
/// keeping it free means the §9.2 ordering property below can be tested with
/// plain values instead of a whole `MessagingService`.
///
/// S08 §9.1/§9.2: multi-mailbox delivery order is **randomized**. `caps` is
/// stored in a stable priority order, so depositing in that order makes the
/// sequence itself a fingerprint — an observer correlating across mailboxes
/// sees the same "first hop" every time and can rank a user's mailboxes, and
/// for Adaptive can tell the primary from the backup by position alone.
/// Which mailboxes are chosen stays priority-driven; only the order is
/// shuffled, so reliability ranking is preserved and linkability is not.
fn select_delivery_targets<'a>(
    caps: &'a [ContactCapability],
    strategy: DeliveryStrategy,
) -> Vec<&'a ContactCapability> {
    let mut targets: Vec<&'a ContactCapability> = match strategy {
        DeliveryStrategy::Primary => caps.iter().take(1).collect(),
        DeliveryStrategy::Paranoid => caps.iter().collect(),
        DeliveryStrategy::Adaptive => {
            let mut targets: Vec<&ContactCapability> = Vec::new();
            if let Some(primary) = caps.first() {
                targets.push(primary);
            }
            if caps.len() > 1 {
                let idx = rand::thread_rng().gen_range(1..caps.len());
                targets.push(&caps[idx]);
            }
            targets
        }
    };
    targets.shuffle(&mut rand::thread_rng());
    targets
}

impl<S: CoreStorage, M: MailboxClient> MessagingService<S, M> {
    /// Send a text message to a contact (S08 §5).
    ///
    /// 1. Build payload with sender pseudonym, timestamp, msg_id
    /// 2. Pad to bucket size
    /// 3. Get/create ratchet session (X3DH if first message)
    /// 4. Encrypt with Double Ratchet
    /// 5. Build WireMessage and deposit to contact's mailbox
    pub async fn send_message(
        &self,
        contact_id: ContactId,
        content: MessageContent,
    ) -> Result<SentMessage> {
        self.send_message_with_flags(contact_id, content, 0).await
    }

    /// Send user content with the S07 UI and receipt-request flags.
    pub async fn send_message_with_flags(
        &self,
        contact_id: ContactId,
        content: MessageContent,
        requested_flags: u8,
    ) -> Result<SentMessage> {
        self.send_content(contact_id, content, requested_flags, None)
            .await
    }

    pub(crate) async fn send_content(
        &self,
        contact_id: ContactId,
        content: MessageContent,
        requested_flags: u8,
        original: Option<(MessageId, u64, u32)>,
    ) -> Result<SentMessage> {
        self.send_content_impl(contact_id, content, requested_flags, original, true)
            .await
    }

    /// Commit user content to the durable outbox without network work. The
    /// session must already exist; synchronization performs slot-paced delivery.
    pub async fn enqueue_message(
        &self,
        contact_id: ContactId,
        content: MessageContent,
    ) -> Result<SentMessage> {
        self.send_content_impl(contact_id, content, 0, None, false)
            .await
    }

    /// The desktop reader requests receipts while retaining offline enqueueing.
    pub async fn enqueue_message_with_flags(
        &self, contact_id: ContactId, content: MessageContent, requested_flags: u8,
    ) -> Result<SentMessage> {
        self.send_content_impl(contact_id, content, requested_flags, None, false).await
    }

    pub(crate) async fn send_content_impl(
        &self,
        contact_id: ContactId,
        content: MessageContent,
        requested_flags: u8,
        original: Option<(MessageId, u64, u32)>,
        dispatch: bool,
    ) -> Result<SentMessage> {
        let state_guard = self.state_gate.lock().await;
        najwa_protocol::message::validate_flags(requested_flags)?;
        // 1. Load contact
        let contact = self
            .storage
            .get_contact(contact_id)
            .await
            .map_err(MessagingError::StorageError)?
            .ok_or(MessagingError::ContactNotFound)?;

        if contact.blocked {
            return Err(MessagingError::ContactBlocked);
        }

        if !dispatch
            && self
                .storage
                .get_ratchet_state(contact.id)
                .await
                .map_err(MessagingError::StorageError)?
                .is_none()
        {
            return Err(MessagingError::NoMatchingSession);
        }

        if !dispatch
            && self
                .storage
                .timer_change_pending(contact.id)
                .await
                .map_err(MessagingError::StorageError)?
        {
            return Err(MessagingError::StorageError(
                "timer change awaiting peer acknowledgement".into(),
            ));
        }

        // S08 §8: outbound token-bucket gate (10 msg/s, burst 20). Applies to
        // user content only — ACKs/gap-repair go through `send_control_message`
        // and are intentionally not throttled.
        self.outbound_limiter.check()?;

        // Load/create the ratchet session first so msg_id can be derived from the
        // actual outgoing ratchet header (S07 §6.1) rather than a wall-clock second.
        let (mut session, ad_or_combined, is_initial) =
            self.get_or_create_session(&contact).await?;

        // 2. Build payload
        let timestamp = original.map(|v| v.1).unwrap_or_else(|| self.message_time());
        let content_bytes = content.to_bytes();
        // content_hash = SHA256(content_type_byte || content_bytes) (S07 §6.1)
        let content_hash = {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update([content.content_type_byte()]);
            h.update(&content_bytes);
            let res = h.finalize();
            let mut out = [0u8; 32];
            out.copy_from_slice(&res);
            out
        };
        // Peek the outgoing ratchet header (dh_pub, message number) before
        // ratchet_encrypt advances the chain, so two byte-identical messages sent
        // in the same second get distinct IDs instead of colliding and having the
        // second silently dropped as a transport duplicate.
        let original_dh_pub = session.dhs.public().to_bytes();
        let original_n = session.ns;
        let msg_id = generate_msg_id(
            &original_dh_pub,
            original_n,
            &content_hash,
            &contact.our_pseudonym,
        );

        // S07 §4: stamp the per-contact monotonic uniqueness component. The
        // receiver treats it as opaque; repair is keyed by ratchet (dh_pub, n).
        let logical_seq = match original {
            Some((_, _, seq)) => seq,
            None => self
                .storage
                .next_outbound_seq(contact.id)
                .await
                .map_err(MessagingError::StorageError)?,
        };

        let disappear_timer = self
            .storage
            .get_conversation_timer(contact.id)
            .await
            .map_err(MessagingError::StorageError)?;
        // Browser attachments are prepared durably outside disappearing-key
        // storage. Refuse the race with a newly enabled timer under state_gate.
        if !dispatch
            && disappear_timer.is_some()
            && matches!(content.content_type_byte(), 0x10 | 0x11)
        {
            return Err(MessagingError::InternalError(
                "attachments require the conversation timer off".into(),
            ));
        }
        let flags = requested_flags
            | if original.is_none() && disappear_timer.is_some() {
                najwa_protocol::message::payload_flags::EPHEMERAL
            } else {
                0
            };
        let payload = Payload {
            sender_pseudonym: contact.our_pseudonym,
            content_type: ContentType::try_from(content.content_type_byte())
                .map_err(MessagingError::MessageError)?,
            flags,
            timestamp,
            msg_id,
            logical_seq,

            content: content_bytes,
        };
        let repair_item = RepairedItem {
            original_dh_pub,
            original_n,
            original_msg_id: msg_id,
            original_timestamp: timestamp,
            original_logical_seq: logical_seq,
            original_content_type: payload.content_type as u8,
            original_flags: payload.flags,
            original_content: payload.content.clone(),
        };

        // 3. Pad payload so the DEPOSITED blob lands on a §5.1 bucket (§5.1.1).
        // `is_initial` decides the fixed overhead (Initial carries the cleartext
        // X3DH header = ad_or_combined minus the trailing 64-byte AD).
        let x3dh_len = is_initial.then(|| ad_or_combined.len() - 64);
        let payload_bytes = payload.to_bytes();
        // Validate content framing (including UTF-8/reply length) before
        // consuming a sending-chain position or persisting a malformed frame.
        Payload::from_bytes(&payload_bytes)?;
        let padded = pad_payload(&payload_bytes, deposit_fixed_overhead(x3dh_len))?;

        // S08 §9.1 — if this is one of the first
        // `EPOCH_REDUNDANCY_WINDOW` messages of a new sending epoch, route
        // it via `Adaptive` (primary + one backup) to reduce the probability
        // of a lost epoch-boundary triggering a full repair cycle. `ns` is
        // still the index of the message about to be sent at this point —
        // `ratchet_encrypt` below will increment it.
        let epoch_transition = is_epoch_transition_message(&session);

        // Split AD from X3DH header if this is an initial message.
        // For initial: combined = x3dh_header_bytes || ad(64)
        // For existing: ad_or_combined = ad(64)
        let (x3dh_prefix, ad) = if is_initial {
            let ad_start = ad_or_combined.len() - 64;
            let x3dh_bytes = &ad_or_combined[..ad_start];
            let ad_bytes = &ad_or_combined[ad_start..];
            (Some(x3dh_bytes.to_vec()), ad_bytes.to_vec())
        } else {
            (None, ad_or_combined)
        };

        let message_type = if is_initial {
            MessageType::Initial
        } else {
            MessageType::Normal
        };

        // 5. Encrypt with Double Ratchet. The X3DH header (Initial only) travels
        //    cleartext in the wire prefix and is bound into the AEAD AAD (S07 §2.3),
        //    NOT prepended to the ciphertext. `encrypted_payload = nonce||ct||tag`.
        let meta = WirePrefixMeta {
            version: WIRE_VERSION,
            message_type: message_type.as_byte(),
            x3dh_header: x3dh_prefix.as_deref(),
        };
        let (ratchet_header, encrypted_payload) =
            ratchet_encrypt(&mut session, &padded, &ad, &meta)?;
        // NB: the advanced `session` is NOT persisted here — it is committed
        // atomically with the message row + retry blob via `commit_outgoing` below
        // (S03 §6.1 I2: never advance the sending chain without a retryable row).

        // 6. Build WireMessage (S07 §2 layout).
        let wire = WireMessage {
            version: WIRE_VERSION,
            message_type,
            header: MessageHeader::Ratchet(ratchet_header),
            x3dh_header: x3dh_prefix,
            encrypted_payload,
        };

        let wire_bytes = wire.to_bytes();

        // 8. Load mailbox capabilities. Envelope encryption (S07 §3.1)
        // happens inside `deposit_with_strategy`, once per target mailbox,
        // because each target has its own `envelope_secret` (the outer key)
        // and deposit capability (the cap_hint AAD).
        let caps = self
            .storage
            .get_contact_capabilities(contact.id)
            .await
            .map_err(MessagingError::StorageError)?;
        if caps.is_empty() {
            return Err(MessagingError::NoMailboxCapability);
        }

        // 9. Store message as Pending with wire blob BEFORE deposit attempt.
        //
        // S12 §4.1: in a timer-enabled conversation, seal the LOCAL at-rest copy
        // of the content under a fresh per-message ephemeral key held only in the
        // volatile cache. `wire_bytes` (the ratchet-encrypted copy already built
        // for deposit) is untouched — only the stored copy is sealed, so expiry
        // can zeroise the key as the primary deletion defence (§5.1).
        let stored_content = match disappear_timer.filter(|_| original.is_none()) {
            Some(_) => crate::disappearing::seal_content(
                &self.volatile_cache,
                &msg_id,
                &content.to_bytes(),
            )
            .map_err(|e| MessagingError::InternalError(e.to_string()))?,
            None => content.to_bytes(),
        };
        let msg = Message {
            id: 0, // DB will assign
            contact_id: contact.id,
            msg_id,
            direction: Direction::Sent,
            content_type: content.content_type_byte(),
            flags,
            content: stored_content,
            timestamp,
            status: MessageStatus::Pending,
            ratchet_index: Some(session.ns.saturating_sub(1)),
        };
        // S12 §3.1: the sender-side timer starts on the delivery ACK. At send we
        // set only the no-ACK FALLBACK deadline (sent_at + SENDER_FALLBACK_SECS +
        // timer); the ACK handler (`start_sender_disappear_on_ack`) moves it
        // earlier to ack_at + timer when delivery is confirmed. So the sender's
        // own copy never vanishes before delivery, yet still expires if no ACK
        // ever arrives (and its ephemeral key is zeroised on expiry). Passed into
        // commit_outgoing so the sealed row is stored-and-marked in ONE transaction.
        let disappearing = disappear_timer.map(|secs| {
            let disappear_at_ms =
                now_ms() as u64 + (crate::disappearing::SENDER_FALLBACK_SECS + secs as u64) * 1000;
            (secs, disappear_at_ms)
        });

        // S03 §6.1 (I2): commit the advanced ratchet state, the message row, the
        // retry wire blob, AND the disappearing marker in ONE durable transaction
        // BEFORE the deposit.
        let logical_id = najwa_protocol::message::id::generate_logical_msg_id(
            &self.identity_key.public().to_bytes(),
            &contact.their_ik_pub,
            timestamp,
            logical_seq,
            payload.content_type as u8,
            &payload.content,
        );
        let input = crate::pipeline::Outgoing {
            contact_id: contact.id,
            state: &session,
            ad: is_initial.then_some(ad.as_slice()),
            message: original.is_none().then_some(&msg),
            existing_message_id: original.map(|v| v.0),
            wire: &wire_bytes,
            dh_pub: original_dh_pub,
            n: original_n,
            requires_ack: false,
            disappearing,
            repair: original.is_none().then_some(&repair_item),
            logical_id: Some(logical_id),
            acknowledging: &[],
        };
        let (frame_id, stored_id) = self
            .storage
            .commit_outgoing(&input)
            .await
            .map_err(MessagingError::StorageError)?;
        let db_id = stored_id.expect("outgoing user message has a row");
        let frame = crate::pipeline::queued_frame(frame_id, stored_id, &input);
        drop(state_guard);
        if !dispatch {
            return Ok(SentMessage { id: db_id, msg_id });
        }
        let strategy = if epoch_transition {
            DeliveryStrategy::Adaptive
        } else {
            DeliveryStrategy::Primary
        };
        if let Err(error) = self
            .dispatch_frame(&frame, strategy, Some(AbsorptionPriority::RealMessage))
            .await
        {
            tracing::warn!(%error, contact_id, "message remains in durable outbox");
        }

        Ok(SentMessage { id: db_id, msg_id })
    }

    /// Send a control message to a contact (S08 §5.1).
    pub async fn send_control_message(
        &self,
        contact_id: ContactId,
        control: &ControlMessage,
    ) -> Result<()> {
        self.send_control_impl(contact_id, control, true, false)
            .await
            .map(drop)
    }

    /// Local timer and peer notification commit atomically; delivery uses the outbox.
    pub async fn enqueue_timer_change(
        &self,
        contact_id: ContactId,
        secs: Option<u32>,
    ) -> Result<()> {
        if secs.is_some_and(|s| s < crate::disappearing::MIN_TIMER_SECS) {
            return Err(MessagingError::StorageError(
                "invalid disappearing timer".into(),
            ));
        }
        let control = ControlMessage::DisappearTimer {
            duration_secs: secs.unwrap_or(0),
            set_at: 0,
        };
        self.send_control_impl(contact_id, &control, false, true)
            .await
            .map(drop)
    }

    /// Returns the durable outbox frame id. Without `dispatch` it only queues,
    /// and only on an existing session.
    pub(crate) async fn send_control_impl(
        &self,
        contact_id: ContactId,
        requested: &ControlMessage,
        dispatch: bool,
        local_timer: bool,
    ) -> Result<i64> {
        let state_guard = self.state_gate.lock().await;
        let control = if local_timer {
            if self
                .storage
                .timer_change_pending(contact_id)
                .await
                .map_err(MessagingError::StorageError)?
            {
                return Err(MessagingError::StorageError(
                    "timer change awaiting peer acknowledgement".into(),
                ));
            }
            let previous = self
                .storage
                .get_conversation_timer_setting(contact_id)
                .await
                .map_err(MessagingError::StorageError)?;
            let next = match previous {
                Some((_, time, _)) => time.checked_add(1).ok_or_else(|| {
                    MessagingError::StorageError("timer timestamp exhausted".into())
                })?,
                None => 0,
            };
            let ControlMessage::DisappearTimer { duration_secs, .. } = requested else {
                unreachable!()
            };
            // Same clock as Payload timestamps, so the peer's S07 §7.1 future
            // bound on set_at (S12 §2.2) holds even if the system clock is fast.
            ControlMessage::DisappearTimer {
                duration_secs: *duration_secs,
                set_at: self.message_time().max(next),
            }
        } else {
            requested.clone()
        };
        let control = &control;
        let contact = self
            .storage
            .get_contact(contact_id)
            .await
            .map_err(MessagingError::StorageError)?
            .ok_or(MessagingError::ContactNotFound)?;

        // Deleting a blocked contact still tells them (S08 §7.1).
        if contact.blocked && !matches!(control, ControlMessage::RevocationNotice) {
            return Err(MessagingError::ContactBlocked);
        }

        if !dispatch
            && self
                .storage
                .get_ratchet_state(contact.id)
                .await
                .map_err(MessagingError::StorageError)?
                .is_none()
        {
            return Err(MessagingError::NoMatchingSession);
        }

        // Load session first so msg_id derives from the outgoing ratchet header (S07 §6.1).
        let (mut session, ad_or_combined, is_initial) =
            if matches!(control, ControlMessage::SessionRepairInit { .. }) {
                self.create_session_candidate(&contact).await?
            } else {
                self.get_or_create_session(&contact).await?
            };

        // Build a Control-type payload
        let timestamp = self.message_time();
        let control_bytes = control.to_bytes();
        // content_hash = SHA256(content_type_byte || content) (S07 §6.1)
        let content_hash = {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update([ContentType::Control as u8]);
            h.update(&control_bytes);
            let res = h.finalize();
            let mut out = [0u8; 32];
            out.copy_from_slice(&res);
            out
        };
        let msg_id = generate_msg_id(
            &session.dhs.public().to_bytes(),
            session.ns,
            &content_hash,
            &contact.our_pseudonym,
        );

        let payload = Payload {
            sender_pseudonym: contact.our_pseudonym,
            content_type: ContentType::Control,
            flags: 0x00,
            timestamp,
            msg_id,
            // Control messages don't participate in gap repair.
            logical_seq: 0,
            content: control_bytes,
        };

        // Pad so the DEPOSITED blob lands on a §5.1 bucket (§5.1.1); Initial
        // control frames (e.g. session-repair carrying a fresh X3DH) pay the
        // larger fixed overhead.
        let x3dh_len = is_initial.then(|| ad_or_combined.len() - 64);
        let payload_bytes = payload.to_bytes();
        let padded = pad_payload(&payload_bytes, deposit_fixed_overhead(x3dh_len))?;

        let (x3dh_prefix, ad) = if is_initial {
            let ad_start = ad_or_combined.len() - 64;
            (
                Some(ad_or_combined[..ad_start].to_vec()),
                ad_or_combined[ad_start..].to_vec(),
            )
        } else {
            (None, ad_or_combined)
        };

        let message_type = if is_initial {
            MessageType::Initial
        } else {
            MessageType::Normal
        };

        let meta = WirePrefixMeta {
            version: WIRE_VERSION,
            message_type: message_type.as_byte(),
            x3dh_header: x3dh_prefix.as_deref(),
        };
        let (ratchet_header, encrypted_payload) =
            ratchet_encrypt(&mut session, &padded, &ad, &meta)?;

        let wire = WireMessage {
            version: WIRE_VERSION,
            message_type,
            header: MessageHeader::Ratchet(ratchet_header),
            x3dh_header: x3dh_prefix,
            encrypted_payload,
        };

        let wire_bytes = wire.to_bytes();

        // Load mailbox capabilities. Per-target envelope encryption (S07 §3)
        // happens inside `deposit_with_strategy`.
        let caps = self
            .storage
            .get_contact_capabilities(contact.id)
            .await
            .map_err(MessagingError::StorageError)?;
        if caps.is_empty() {
            return Err(MessagingError::NoMailboxCapability);
        }

        // S08 §9.1 — SessionRepairInit is routed via Paranoid
        // (every mailbox, maximum delivery probability). All other control
        // messages use the default Primary path.
        let strategy = match control {
            ControlMessage::SessionRepairInit { .. } => DeliveryStrategy::Paranoid,
            _ => DeliveryStrategy::Primary,
        };

        let MessageHeader::Ratchet(header) = &wire.header;
        let input = crate::pipeline::Outgoing {
            contact_id: contact.id,
            state: &session,
            ad: is_initial.then_some(ad.as_slice()),
            message: None,
            existing_message_id: None,
            wire: &wire_bytes,
            dh_pub: header.dh_pub.to_bytes(),
            n: header.n,
            requires_ack: true,
            disappearing: None,
            repair: None,
            logical_id: None,
            acknowledging: &[],
        };
        let (id, mid) = if local_timer {
            let ControlMessage::DisappearTimer {
                duration_secs,
                set_at,
            } = control
            else {
                unreachable!()
            };
            self.storage
                .commit_outgoing_timer(
                    &input,
                    (
                        (*duration_secs > 0).then_some(*duration_secs),
                        *set_at,
                        self.identity_key.public().to_bytes(),
                    ),
                )
                .await
        } else {
            self.storage.commit_outgoing(&input).await
        }
        .map_err(MessagingError::StorageError)?;
        let frame = crate::pipeline::queued_frame(id, mid, &input);
        drop(state_guard);
        if !dispatch {
            return Ok(id);
        }
        // Success here means durable acceptance. A failed deposit remains queued.
        if let Err(error) = self
            .dispatch_frame(&frame, strategy, control_absorption_priority(control))
            .await
        {
            tracing::warn!(%error,contact_id,"control remains in durable outbox");
        }

        tracing::debug!(
            contact_id = contact.id,
            control_subtype = control.subtype(),
            ?strategy,
            "control message sent"
        );

        Ok(id)
    }

    /// Deposit a raw `WireMessage` blob via the given delivery strategy
    /// (S08 §9.1, §9.2). Each selected mailbox gets
    /// its own S07 §3.1 envelope: the outer AEAD key is derived from that
    /// mailbox's `their_envelope_secret`, and its `their_deposit_capability`
    /// supplies the cap_hint AAD, so each envelope is mailbox-specific.
    ///
    /// Returns `Ok` on at least one successful deposit, or
    /// `AllMailboxesFailed` when every target fails.
    ///
    /// Sends are staggered with a random delay between
    /// `STAGGER_DELAY_MIN_MS` and `STAGGER_DELAY_MAX_MS` (S08 §9.1).
    ///
    /// A negative `frame_id` is a `revocation_frames` row (S08 §7.1): its
    /// contact is already deleted, so the contact and outbox checks are skipped.
    pub(crate) async fn deposit_with_strategy(
        &self,
        caps: &[ContactCapability],
        wire_bytes: &[u8],
        strategy: DeliveryStrategy,
        priority: Option<AbsorptionPriority>,
        frame_id: i64,
    ) -> Result<()> {
        let targets = select_delivery_targets(caps, strategy);
        if targets.is_empty() {
            return Err(MessagingError::NoMailboxCapability);
        }

        let mut success = 0usize;
        let mut failures = 0usize;

        for (i, cap) in targets.iter().enumerate() {
            if i > 0 {
                let delay_ms =
                    rand::thread_rng().gen_range(STAGGER_DELAY_MIN_MS..=STAGGER_DELAY_MAX_MS);
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            }

            if self
                .try_deposit_one(cap, wire_bytes, priority, frame_id)
                .await
            {
                success += 1;
            } else {
                failures += 1;
            }
        }

        // S08 §10.1.1: same-blob deposit-failure retry across up to
        // DEPOSIT_RETRIES=2 ALTERNATIVE mailboxes (each re-enveloped with a fresh
        // nonce) when every selected target failed. One success is enough; there
        // is deliberately NO timeout-driven retry for user content.
        if success == 0 {
            const DEPOSIT_RETRIES: usize = 2;
            let tried: std::collections::HashSet<&str> =
                targets.iter().map(|c| c.mailbox_onion.as_str()).collect();
            let mut retries = 0usize;
            // Same §9.2 reasoning as target selection: walking `caps` in stored
            // order would always fall back to the same alternative, so a failing
            // primary would deterministically reveal the next mailbox down the
            // user's list.
            let mut fallbacks: Vec<&ContactCapability> = caps.iter().collect();
            fallbacks.shuffle(&mut rand::thread_rng());
            for cap in fallbacks {
                if retries >= DEPOSIT_RETRIES {
                    break;
                }
                if tried.contains(cap.mailbox_onion.as_str()) {
                    continue;
                }
                retries += 1;
                let delay_ms =
                    rand::thread_rng().gen_range(STAGGER_DELAY_MIN_MS..=STAGGER_DELAY_MAX_MS);
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                if self
                    .try_deposit_one(cap, wire_bytes, priority, frame_id)
                    .await
                {
                    success += 1;
                    break;
                } else {
                    failures += 1;
                }
            }
        }

        if success == 0 {
            Err(MessagingError::AllMailboxesFailed(failures))
        } else {
            Ok(())
        }
    }

    /// Deposit the wire blob to a single mailbox, keyed by that mailbox's own
    /// S07 §3.1 envelope (the outer AEAD key is derived from its
    /// `envelope_secret`; its deposit capability supplies the cap_hint AAD, so
    /// the same inner ciphertext is re-enveloped per destination with a fresh
    /// nonce). Returns `true` on a
    /// successful deposit, `false` on any failure (missing caps, envelope
    /// error, or a mailbox error) — the caller counts and, on total failure,
    /// retries alternative mailboxes.
    async fn try_deposit_one(
        &self,
        cap: &ContactCapability,
        wire_bytes: &[u8],
        priority: Option<AbsorptionPriority>,
        frame_id: i64,
    ) -> bool {
        let dep_cap = match cap.their_deposit_capability {
            Some(dc) => dc,
            None => return false,
        };
        // S07 §3.1: key the envelope from their envelope_secret (server-unknown),
        // not the deposit cap. Skip the target if we don't have it yet.
        let env_secret = match cap.their_envelope_secret {
            Some(s) => s,
            None => {
                tracing::warn!(
                    mailbox = %cap.mailbox_onion,
                    "no envelope_secret for target; skipping (D3)"
                );
                return false;
            }
        };
        let envelope_bytes = match envelope_encrypt(&env_secret, &dep_cap, wire_bytes) {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::warn!(mailbox = %cap.mailbox_onion, error = %e, "envelope_encrypt failed");
                return false;
            }
        };

        let mailbox = cap.mailbox_config();
        let mut pow = None;
        loop {
            let permit = if let (Some(slots), Some(priority)) = (&self.slot_source, priority) {
                Some(slots.await_slot(&cap.mailbox_onion, priority, None).await)
            } else {
                None
            };
            // Keep the grant unconsumed until all local preflight checks pass.
            // Returning or cancellation drops it and causes replacement cover.
            if frame_id >= 0 {
                match self.storage.get_contact(cap.contact_id).await {
                    Ok(Some(contact)) if !contact.blocked => {}
                    _ => return false,
                }
                if !matches!(self.storage.outgoing_frame_live(frame_id).await, Ok(true)) {
                    return false;
                }
            }
            if let Some(permit) = permit {
                if !permit.begin() {
                    continue;
                }
            }
            // Read the live mode immediately before each attempt: changing back
            // to Timing privacy must also affect already queued attachments.
            let result = match self.responsive_file_isolation(cap, frame_id).await {
                Some(isolation) => self.mailbox_client.deposit_file_once(
                    &mailbox, &dep_cap, &envelope_bytes, pow.as_ref(), isolation,
                ).await,
                None => self.mailbox_client.deposit_once(
                    &mailbox, &dep_cap, &envelope_bytes, pow.as_ref(),
                ).await,
            };
            match result {
                Ok(receipt) if receipt.accepted => {
                    if let Err(error) = self
                        .storage
                        .record_remote_mailbox(&cap.mailbox_onion, true)
                        .await
                    {
                        tracing::warn!(%error, "mailbox health write failed");
                    }
                    return true;
                }
                // PoW retries also consume a NEW slot. Challenge work occurs
                // outside that slot so it cannot delay the granted deposit.
                Err(najwa_protocol::mailbox::error::MailboxError::RateLimited) if pow.is_none() => {
                    match self
                        .mailbox_client
                        .prepare_deposit_pow(&mailbox, &dep_cap, &envelope_bytes)
                        .await
                    {
                        Ok(solution) => pow = Some(solution),
                        Err(_) => return false,
                    }
                }
                Ok(_) => return false,
                Err(error) => {
                    if crate::pipeline::mailbox_health_failure(&error) {
                        if let Err(error) = self
                            .storage
                            .record_remote_mailbox(&cap.mailbox_onion, false)
                            .await
                        {
                            tracing::warn!(%error, "mailbox health write failed");
                        }
                    }
                    tracing::warn!(mailbox = %cap.mailbox_onion, %error, "deposit failure");
                    return false;
                }
            }
        }
    }

    pub(crate) async fn responsive_file_isolation(&self, cap: &ContactCapability, frame_id: i64) -> Option<[u8; 32]> {
        if !self.slot_source.as_ref().is_some_and(|slots| slots.bypass()) {
            return None;
        }
        let session = self.storage.outgoing_file_session(frame_id).await.ok()??;
        use sha2::{Digest, Sha256};
        let mut hash = Sha256::new();
        hash.update(b"najwa-responsive-file-circuit-v1\0");
        hash.update(cap.contact_id.to_be_bytes());
        hash.update(session);
        hash.update(cap.their_deposit_capability?);
        hash.update(cap.their_envelope_secret?);
        hash.update(cap.mailbox_onion.as_bytes());
        Some(hash.finalize().into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caps(n: usize) -> Vec<ContactCapability> {
        (0..n)
            .map(|i| ContactCapability {
                contact_id: 1,
                mailbox_id: i as i64,
                mailbox_onion: format!("mb{i}"),
                mailbox_fetch_cap: [0xAA; 32],
                mailbox_deposit_cap: [0xBB; 32],
                their_deposit_capability: Some([0xCC; 32]),
                their_envelope_secret: Some([0xEE; 32]),
            })
            .collect()
    }

    fn onions(targets: &[&ContactCapability]) -> Vec<String> {
        targets.iter().map(|c| c.mailbox_onion.clone()).collect()
    }

    // S08 §9.2: Paranoid must reach EVERY mailbox, in a randomized order.
    // Selection and ordering are separate properties, so assert both — a shuffle
    // that dropped or duplicated a target would still look random.
    #[test]
    fn paranoid_covers_every_mailbox_in_varying_order() {
        let caps = caps(4);
        let mut first_seen = std::collections::HashSet::new();
        for _ in 0..200 {
            let targets = select_delivery_targets(&caps, DeliveryStrategy::Paranoid);
            let mut got = onions(&targets);
            first_seen.insert(got[0].clone());
            got.sort();
            assert_eq!(got, vec!["mb0", "mb1", "mb2", "mb3"]);
        }
        // 200 draws over 4 mailboxes: seeing only one distinct first hop means
        // the order is fixed. (Chance of a false failure ≈ 4·(1/4)^200.)
        assert!(
            first_seen.len() > 1,
            "Paranoid deposit order is deterministic — the first hop is always {:?}",
            first_seen
        );
    }

    // §9.2 for Adaptive: still exactly two mailboxes, the priority-0 primary
    // always among them, but the primary must not always be deposited FIRST or
    // its position alone identifies it.
    #[test]
    fn adaptive_keeps_primary_but_not_always_first() {
        let caps = caps(4);
        let mut primary_first = 0usize;
        for _ in 0..200 {
            let targets = select_delivery_targets(&caps, DeliveryStrategy::Adaptive);
            let got = onions(&targets);
            assert_eq!(got.len(), 2);
            assert!(got.contains(&"mb0".to_string()), "primary must be selected");
            assert_ne!(got[0], got[1], "must be two distinct mailboxes");
            if got[0] == "mb0" {
                primary_first += 1;
            }
        }
        assert!(
            primary_first > 0 && primary_first < 200,
            "primary position is fixed ({primary_first}/200 first)"
        );
    }

    // The unassigned subtypes 0x45-0x48 map to no tier, so they are never
    // slot-paced. Pinned as a test because "everything should ride slots" is the
    // natural thing for a reader to assume.
    #[test]
    fn group_fanout_subtypes_are_not_slot_paced() {
        for subtype in 0x45u8..=0x48 {
            assert!(
                absorption_priority_for_subtype(subtype).is_none(),
                "subtype {subtype:#04x} must not be slot-paced (S09 §6.3/§6.4)"
            );
        }
        // Non-fan-out control traffic still is.
        assert_eq!(
            absorption_priority_for_subtype(0x00),
            Some(AbsorptionPriority::Ack)
        );
        assert_eq!(
            absorption_priority_for_subtype(0x31),
            Some(AbsorptionPriority::SessionRepairInit)
        );
        assert_eq!(
            absorption_priority_for_subtype(0x20),
            Some(AbsorptionPriority::Control)
        );
    }

    // Primary strategy is a single deposit: shuffling must not change the count
    // or reach a second mailbox.
    #[test]
    fn primary_selects_exactly_the_first_capability() {
        let caps = caps(4);
        for _ in 0..20 {
            let targets = select_delivery_targets(&caps, DeliveryStrategy::Primary);
            assert_eq!(onions(&targets), vec!["mb0"]);
        }
        assert!(select_delivery_targets(&[], DeliveryStrategy::Paranoid).is_empty());
    }
}
