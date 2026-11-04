//! Storage trait for the core messaging service (S08 §3).

use async_trait::async_trait;
use najwa_crypto::keys::x25519::X25519KeyPair;
use najwa_protocol::mailbox::types::MailboxConfig;
use najwa_protocol::ratchet::state::RatchetState;

use crate::types::*;

/// Local lifecycle metadata for a registered type-1 receive queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EphemeralHandshakeCapability {
    pub id: i64,
    /// Once set, no later deposit may consume/create another contact even if
    /// the network deactivation request needs a retry.
    pub accepted: bool,
}

/// Trait abstracting all storage operations needed by the messaging service.
///
/// Implementations live in `najwa-storage`; this trait decouples
/// the core service from concrete storage details.
#[async_trait]
pub trait CoreStorage: Send + Sync {
    /// SQL-backed prekey maintenance. Custom storage implementations manage their
    /// own lifecycle; the production adapter exposes its encrypted database.
    fn prekey_database(&self) -> Option<&najwa_storage::database::SqliteStorage> { None }
    /// Signing key from the authenticated contact mailbox entry, never from a fetch response.
    async fn get_contact_mailbox_signing_key(
        &self, _contact_id: ContactId, _onion: &str,
    ) -> std::result::Result<Option<[u8; 32]>, String> { Ok(None) }

    /// Durable implementations must override these atomic boundaries. Unsupported
    /// stores fail before any state mutation; test doubles explicitly opt in.
    async fn commit_incoming(
        &self,
        _input: &crate::pipeline::Incoming<'_>,
    ) -> std::result::Result<Option<MessageId>, String> {
        Err("atomic incoming transaction is not implemented".into())
    }
    async fn commit_outgoing(
        &self,
        _input: &crate::pipeline::Outgoing<'_>,
    ) -> std::result::Result<(i64, Option<MessageId>), String> {
        Err("atomic outbox transaction is not implemented".into())
    }
    async fn pending_read_receipts(&self) -> std::result::Result<Vec<najwa_storage::read_receipts::ReadReceiptIntent>, String> {
        Ok(Vec::new())
    }
    async fn commit_read_receipt(
        &self,
        _input: &crate::pipeline::Outgoing<'_>,
        _msg_id: [u8; 16],
    ) -> std::result::Result<(i64, Option<MessageId>), String> {
        Err("atomic read receipt transaction is not implemented".into())
    }
    /// Save a local timer change together with its exact encrypted control frame.
    /// Unsupported stores fail closed without changing either state.
    async fn commit_outgoing_timer(
        &self,
        _input: &crate::pipeline::Outgoing<'_>,
        _timer: (Option<u32>, u64, [u8; 32]),
    ) -> std::result::Result<(i64, Option<MessageId>), String> {
        Err("atomic timer outbox transaction is not implemented".into())
    }
    async fn timer_change_pending(&self, _contact_id: ContactId) -> std::result::Result<bool, String> { Ok(false) }
    async fn outgoing_frames(
        &self,
    ) -> std::result::Result<Vec<najwa_storage::messaging::OutgoingFrame>, String> {
        Ok(Vec::new())
    }
    async fn outgoing_frame_ids(&self)->std::result::Result<Vec<i64>,String> {
        Ok(self.outgoing_frames().await?.into_iter().filter(|f|f.next_attempt<=najwa_crypto::time::now()).map(|f|f.id).collect())
    }
    async fn outgoing_frame(&self,id:i64)->std::result::Result<Option<najwa_storage::messaging::OutgoingFrame>,String> {
        Ok(self.outgoing_frames().await?.into_iter().find(|f|f.id==id))
    }
    async fn outgoing_frame_batch(&self)->std::result::Result<Vec<najwa_storage::messaging::OutgoingFrame>,String> {
        Ok(self.outgoing_frames().await?.into_iter().filter(|f|f.next_attempt<=najwa_crypto::time::now()).take(64).collect())
    }
    async fn outgoing_frame_live(&self, _id: i64) -> std::result::Result<bool, String> {
        Err("outbox lookup is not implemented".into())
    }
    /// File session only, without loading the attachment body. A missing lookup
    /// keeps the conservative one-shot circuit policy.
    async fn outgoing_file_session(&self, _id: i64) -> std::result::Result<Option<[u8; 16]>, String> {
        Ok(None)
    }
    async fn finish_outgoing(
        &self,
        _id: i64,
        _success: bool,
        _next: u64,
    ) -> std::result::Result<(), String> {
        Err("outbox completion is not implemented".into())
    }
    async fn received_frame(
        &self,
        _id: &[u8; 16],
    ) -> std::result::Result<Option<najwa_storage::messaging::ReceivedFrame>, String> {
        Ok(None)
    }
    async fn repeat_ack(&self, _id: &[u8; 16]) -> std::result::Result<(), String> {
        Ok(())
    }
    async fn pending_ack_contacts(&self) -> std::result::Result<Vec<ContactId>, String> {
        Ok(Vec::new())
    }
    /// True only when every incoming ACK intent is committed with its frame.
    fn durable_ack_intents(&self) -> bool { false }
    async fn pending_ack_ranges(
        &self,
        _cid: ContactId,
    ) -> std::result::Result<Vec<najwa_storage::messaging::ChainRange>, String> {
        Ok(Vec::new())
    }
    async fn inbound_work(
        &self,
    ) -> std::result::Result<Vec<najwa_storage::messaging::InboundWork>, String> {
        Ok(Vec::new())
    }
    async fn advance_inbound_work(
        &self,
        _id: i64,
        _cursor: Option<i64>,
    ) -> std::result::Result<(), String> {
        Err("inbound work is not implemented".into())
    }
    async fn outbound_history(
        &self,
        _cid: ContactId,
        _anchor: Option<[u8; 16]>,
        _from: u64,
        _to: u64,
        _cursor: i64,
    ) -> std::result::Result<Vec<najwa_storage::messaging::HistoryMessage>, String> {
        Err("history scan is not implemented".into())
    }
    /// S11 §4.1: the stored sent part `index` of file `session` to `cid`.
    /// Without it a `FileChunkNack` is ignored.
    async fn outgoing_file_part(
        &self,
        _cid: ContactId,
        _session: &[u8; 16],
        _index: u32,
    ) -> std::result::Result<Option<najwa_storage::messaging::HistoryMessage>, String> {
        Ok(None)
    }
    /// S11 §4.1: received files whose quiet period has elapsed (see
    /// `SqliteStorage::file_nacks_due`). Without it no `FileChunkNack` is sent.
    async fn file_nacks_due(
        &self,
        _now: u64,
        _interval: u64,
        _max_attempts: u32,
    ) -> std::result::Result<Vec<najwa_storage::transfers::FileNackDue>, String> {
        Ok(Vec::new())
    }
    async fn record_file_nack(
        &self,
        _metadata_id: MessageId,
        _attempts: u32,
        _now: u64,
    ) -> std::result::Result<(), String> {
        Ok(())
    }
    async fn remote_mailbox_enabled(&self, _onion: &str) -> std::result::Result<bool, String> {
        Ok(true)
    }
    async fn record_remote_mailbox(
        &self,
        _onion: &str,
        _success: bool,
    ) -> std::result::Result<(), String> {
        Ok(())
    }

    /// Atomically consume a typed confirmation with its delivery effects.
    /// SQL storage overrides this; the sequential default is for in-memory tests.
    async fn commit_confirmation(
        &self,
        contact_id: ContactId,
        state: &RatchetState,
        header_id: &[u8; 16],
        effect: &DeliveryConfirmation,
    ) -> std::result::Result<(), String> {
        match effect {
            DeliveryConfirmation::Ack(ranges) => {
                for id in self.acknowledged_message_ids(contact_id, ranges).await? {
                    if let Some(msg) = self.get_message_by_msg_id(&id).await? {
                        if msg.contact_id == contact_id
                            && matches!(msg.direction, Direction::Sent)
                            && !matches!(msg.status, MessageStatus::Read | MessageStatus::Delivered)
                        {
                            self.update_message_status(msg.id, MessageStatus::Delivered)
                                .await?;
                            self.start_sender_disappear_on_ack(&id).await?;
                        }
                    }
                }
            }
            DeliveryConfirmation::ReadReceipt { msg_id, .. } => {
                if let Some(msg) = self.get_message_by_msg_id(msg_id).await? {
                    if msg.contact_id == contact_id
                        && matches!(msg.direction, Direction::Sent)
                        && msg.flags & 0x04 != 0
                        && msg.status != MessageStatus::Read
                    {
                        if msg.status != MessageStatus::Delivered {
                            self.start_sender_disappear_on_ack(msg_id).await?;
                        }
                        self.update_message_status(msg.id, MessageStatus::Read)
                            .await?;
                    }
                }
            }
        }
        self.commit_received(contact_id, state, None, header_id, None, None)
            .await?;
        Ok(())
    }

    /// Resolve ACK ranges using persisted outbound chain positions, not message IDs
    /// or arrival order. Backends without this index must fail without consuming it.
    async fn acknowledged_message_ids(
        &self,
        _contact_id: ContactId,
        _ranges: &[([u8; 32], u32, u32)],
    ) -> std::result::Result<Vec<[u8; 16]>, String> {
        Err("ACK position lookup is not implemented".into())
    }

    async fn update_remote_mailboxes(
        &self,
        _contact_id: ContactId,
        _entries: &[najwa_protocol::contact::mailbox_key::MailboxEntry],
    ) -> std::result::Result<(), String> {
        Err("mailbox update persistence is not implemented".into())
    }
    // -- Contact operations --

    /// Get a contact by ID.
    async fn get_contact(&self, id: ContactId) -> std::result::Result<Option<Contact>, String>;

    /// Get a contact by their pseudonym.
    async fn get_contact_by_pseudonym(
        &self,
        pseudonym: &[u8; 32],
    ) -> std::result::Result<Option<Contact>, String>;

    /// List all contacts.
    async fn list_contacts(&self) -> std::result::Result<Vec<Contact>, String>;

    /// Update a contact record (e.g., blocked flag).
    async fn update_contact(&self, contact: &Contact) -> std::result::Result<(), String>;

    /// Persist a fully-validated reciprocal handshake as a new contact (S05
    /// §8.2), including the peer's mailbox coordinates. Callers MUST validate
    /// and identity-bind the payload before invoking this method; the default is
    /// deliberately unsupported so a storage backend cannot silently create a
    /// contact without implementing the corresponding persistence.
    async fn create_reciprocal_contact(
        &self,
        _payload: &najwa_protocol::contact::HandshakePayload,
        _our_pseudonym: &[u8; 32],
        _their_pseudonym: &[u8; 32],
    ) -> std::result::Result<Contact, String> {
        Err("reciprocal contact persistence is not implemented".into())
    }

    /// Atomically increment and return this contact's outbound sequence counter
    /// (Phase 3 / D4), stamped into the message's `logical_seq`. The first
    /// message to a contact returns 1. The default returns 0 (mocks); only the
    /// real storage maintains the counter.
    async fn next_outbound_seq(&self, _contact_id: ContactId) -> std::result::Result<u32, String> {
        Ok(0)
    }

    /// Persist a complete S07 §8.5 repair source keyed by `(contact, dh_pub, n)`.
    async fn buffer_outbound_repair(
        &self,
        _contact_id: ContactId,
        _item: &najwa_protocol::message::gap_repair::RepairedItem,
    ) -> std::result::Result<(), String> {
        Ok(())
    }

    /// Look up a repair source by its exact ratchet address.
    async fn get_outbound_repair(
        &self,
        _contact_id: ContactId,
        _dh_pub: &[u8; 32],
        _message_number: u32,
    ) -> std::result::Result<Option<najwa_protocol::message::gap_repair::RepairedItem>, String>
    {
        Ok(None)
    }

    /// Read repair content with its at-rest encoding flag. A true flag requires
    /// the sender's live ephemeral message key before retransmission.
    async fn get_outbound_repair_entry(
        &self,
        contact_id: ContactId,
        dh_pub: &[u8; 32],
        message_number: u32,
    ) -> std::result::Result<
        Option<(najwa_protocol::message::gap_repair::RepairedItem, bool)>,
        String,
    > {
        self.get_outbound_repair(contact_id, dh_pub, message_number)
            .await
            .map(|item| item.map(|item| (item, false)))
    }

    /// Get mailbox capabilities for a contact.
    async fn get_contact_capabilities(
        &self,
        contact_id: ContactId,
    ) -> std::result::Result<Vec<ContactCapability>, String>;

    // -- Ratchet state --

    /// Get the ratchet state for a contact.
    async fn get_ratchet_state(
        &self,
        contact_id: ContactId,
    ) -> std::result::Result<Option<RatchetState>, String>;

    /// Save (create or update) the ratchet state for a contact.
    async fn save_ratchet_state(
        &self,
        contact_id: ContactId,
        state: &RatchetState,
    ) -> std::result::Result<(), String>;

    /// Delete the ratchet state for a contact (session reset, S08 §7.2).
    async fn delete_ratchet_state(&self, contact_id: ContactId) -> std::result::Result<(), String>;

    /// Look up a ratchet state by the remote DH public key (S08 §4.4 fast path).
    async fn get_ratchet_state_by_dh_pub(
        &self,
        dh_pub: &[u8; 32],
    ) -> std::result::Result<Option<(ContactId, RatchetState)>, String>;

    /// Atomically commit a received message (S06 §3.11 I3): advance the ratchet
    /// session (including its skipped keys), insert the message (when stored),
    /// and mark transport dedup — all in ONE transaction. Either all succeed or
    /// none, so a crash mid-receive cannot leave the ratchet advanced without
    /// the message durably stored and deduped (which would lose the message on
    /// re-fetch). `message` is `None` for control messages handled but not
    /// stored; the ratchet + dedup still commit. Returns the new message row id
    /// when a message was stored.
    ///
    /// The default implementation is sequential (non-atomic) — adequate for the
    /// in-memory mocks used in tests. `SqliteStorage` overrides it with a real
    /// SQLite transaction.
    async fn commit_received(
        &self,
        contact_id: ContactId,
        ratchet_state: &RatchetState,
        message: Option<&Message>,
        transport_msg_id: &[u8; 16],
        logical_msg_id: Option<&[u8; 16]>,
        disappearing: Option<(u32, u64)>,
    ) -> std::result::Result<Option<MessageId>, String> {
        self.save_ratchet_state(contact_id, ratchet_state).await?;
        let id = match message {
            Some(m) => Some(self.save_message(m).await?),
            None => None,
        };
        self.mark_msg_id_seen(contact_id, transport_msg_id).await?;
        // S08 §9.4: mark the endpoint-invariant logical id in the SAME commit so
        // a session-repair / gap-repair re-send of this content is deduped.
        if let Some(l) = logical_msg_id {
            self.mark_logical_msg_id_seen(contact_id, l).await?;
        }
        // S12 §4.1: co-commit the disappearing marker with the stored message.
        if let (Some((secs, at)), Some(mid)) = (disappearing, id) {
            self.set_message_disappearing(mid, secs, at).await?;
        }
        Ok(id)
    }

    /// S08 §4.3 / S06 §3.11 (I3): atomically ESTABLISH a session from an Initial /
    /// SessionRepairInit — persist the responder ratchet state, session AD, OPK
    /// consumption, the stored message, and the transport + logical dedup marks in
    /// ONE transaction. `INSERT OR REPLACE` on the ratchet row makes this both
    /// create a fresh session and overwrite an existing one (repair re-establish /
    /// crossing-Initial adopt); the dedup marks gate a replayed Initial from
    /// clobbering an advanced session. Returns the new message row id when stored.
    ///
    /// The default impl is sequential (non-atomic) — adequate for the in-memory
    /// mocks; `SqliteStorage` overrides it with a real transaction.
    /// Atomically store a repaired user message and mark both its original
    /// transport ID and endpoint-invariant logical ID as seen. Returns `None`
    /// when either ID was already present.
    async fn commit_repaired_received(
        &self,
        contact_id: ContactId,
        message: &Message,
        transport_msg_id: &[u8; 16],
        logical_msg_id: &[u8; 16],
    ) -> std::result::Result<Option<MessageId>, String> {
        if self.check_msg_id_seen(transport_msg_id).await?
            || self
                .check_logical_msg_id_seen(contact_id, logical_msg_id)
                .await?
        {
            return Ok(None);
        }
        let id = self.save_message(message).await?;
        self.mark_msg_id_seen(contact_id, transport_msg_id).await?;
        self.mark_logical_msg_id_seen(contact_id, logical_msg_id)
            .await?;
        Ok(Some(id))
    }

    #[allow(clippy::too_many_arguments)]
    async fn commit_initial_received(
        &self,
        contact_id: ContactId,
        ratchet_state: &RatchetState,
        session_ad: &[u8],
        opk_id: Option<[u8; 4]>,
        message: Option<&Message>,
        transport_msg_id: &[u8; 16],
        logical_msg_id: Option<&[u8; 16]>,
        disappearing: Option<(u32, u64)>,
        ephemeral_handshake_cap_id: Option<i64>,
    ) -> std::result::Result<Option<MessageId>, String> {
        self.save_ratchet_state(contact_id, ratchet_state).await?;
        self.save_session_ad(contact_id, session_ad).await?;
        if let Some(id) = opk_id {
            // Lenient: an already-consumed id is non-fatal (session still stands).
            let _ = self.mark_opk_used(&id).await;
        }
        let id = match message {
            Some(m) => Some(self.save_message(m).await?),
            None => None,
        };
        self.mark_msg_id_seen(contact_id, transport_msg_id).await?;
        if let Some(l) = logical_msg_id {
            self.mark_logical_msg_id_seen(contact_id, l).await?;
        }
        if let (Some((secs, at)), Some(mid)) = (disappearing, id) {
            self.set_message_disappearing(mid, secs, at).await?;
        }
        if let Some(capability_id) = ephemeral_handshake_cap_id {
            self.mark_ephemeral_handshake_cap_accepted(capability_id)
                .await?;
        }
        Ok(id)
    }

    /// S03 §6.1 (I2) persist-before-send: durably commit the advanced sending
    /// ratchet state AND the outgoing message row (with its cached wire blob for
    /// byte-identical retry) in ONE transaction before the frame reaches
    /// transport — so a crash can never advance the sending chain without leaving
    /// a retryable message. Returns the new message row id.
    ///
    /// The default implementation is sequential (non-atomic) — adequate for the
    /// in-memory mocks. `SqliteStorage` overrides it with a real transaction that
    /// also syncs the WAL.
    async fn commit_sent(
        &self,
        contact_id: ContactId,
        ratchet_state: &RatchetState,
        message: &Message,
        wire_blob: &[u8],
        disappearing: Option<(u32, u64)>,
        repair_item: Option<&najwa_protocol::message::gap_repair::RepairedItem>,
    ) -> std::result::Result<MessageId, String> {
        self.save_ratchet_state(contact_id, ratchet_state).await?;
        let id = self.save_message(message).await?;
        self.update_message_blob(id, wire_blob).await?;
        // S12 §4.1: co-commit the disappearing marker with the stored message.
        if let Some((secs, at)) = disappearing {
            self.set_message_disappearing(id, secs, at).await?;
        }
        if let Some(item) = repair_item {
            self.buffer_outbound_repair(contact_id, item).await?;
        }
        Ok(id)
    }

    // -- Session associated data --

    /// Get the session AD (64 bytes: IK_initiator || IK_responder) for a contact.
    async fn get_session_ad(
        &self,
        contact_id: ContactId,
    ) -> std::result::Result<Option<Vec<u8>>, String>;

    /// Save the session AD for a contact.
    async fn save_session_ad(
        &self,
        contact_id: ContactId,
        ad: &[u8],
    ) -> std::result::Result<(), String>;

    /// Delete the session AD for a contact (session reset).
    async fn delete_session_ad(&self, contact_id: ContactId) -> std::result::Result<(), String>;

    // -- Message storage --

    /// Save a message and return its database ID.
    async fn save_message(&self, msg: &Message) -> std::result::Result<MessageId, String>;

    /// Look up a message by its 16-byte msg_id.
    async fn get_message_by_msg_id(
        &self,
        msg_id: &[u8; 16],
    ) -> std::result::Result<Option<Message>, String>;

    /// Update message delivery status.
    async fn update_message_status(
        &self,
        id: MessageId,
        status: MessageStatus,
    ) -> std::result::Result<(), String>;

    /// Get messages with Pending or Failed status (for retry).
    async fn get_pending_messages(&self) -> std::result::Result<Vec<Message>, String>;

    /// Store the encrypted wire blob on a message (for retry without re-encryption).
    async fn update_message_blob(
        &self,
        id: MessageId,
        blob: &[u8],
    ) -> std::result::Result<(), String>;

    /// Clear the encrypted wire blob after successful deposit (free storage).
    async fn clear_message_blob(&self, id: MessageId) -> std::result::Result<(), String>;

    /// Increment the retry counter and update last_retry_at.
    async fn increment_retry_count(&self, id: MessageId) -> std::result::Result<(), String>;

    /// Get the stored encrypted wire blob for a message (for retry).
    async fn get_message_blob(&self, id: MessageId)
        -> std::result::Result<Option<Vec<u8>>, String>;

    // -- Message deduplication (S08 §9.4) --

    /// Check if a transport msg_id has been seen before. The transport id is a
    /// globally-unique HKDF value, so the check is not contact-scoped.
    async fn check_msg_id_seen(&self, msg_id: &[u8; 16]) -> std::result::Result<bool, String>;

    /// Mark a transport msg_id as seen. `contact_id` scopes the row for
    /// FK-cascade cleanup (S03 §5.7 `msg_id_cache_transport`).
    async fn mark_msg_id_seen(
        &self,
        contact_id: ContactId,
        msg_id: &[u8; 16],
    ) -> std::result::Result<(), String>;

    /// Check whether a `(contact_id, logical_msg_id)` has already been seen —
    /// the endpoint-invariant logical dedup (S03 §5.7 / S07 §6.2 / S08 §9.4) that
    /// survives session-repair / gap-repair re-encryption (a re-sent message has
    /// a fresh transport `msg_id` but the same `logical_msg_id`). Default: never
    /// seen — mocks don't dedup logically; `SqliteStorage` overrides it.
    async fn check_logical_msg_id_seen(
        &self,
        _contact_id: ContactId,
        _logical_msg_id: &[u8; 16],
    ) -> std::result::Result<bool, String> {
        Ok(false)
    }

    /// Mark a `(contact_id, logical_msg_id)` as seen. Default: no-op.
    async fn mark_logical_msg_id_seen(
        &self,
        _contact_id: ContactId,
        _logical_msg_id: &[u8; 16],
    ) -> std::result::Result<(), String> {
        Ok(())
    }

    // -- Mailbox --

    /// List all configured mailboxes.
    async fn list_mailboxes(&self) -> std::result::Result<Vec<MailboxConfig>, String>;

    /// List all configured mailboxes with their storage IDs (for poll cursor tracking).
    async fn list_mailboxes_with_ids(
        &self,
    ) -> std::result::Result<Vec<(MailboxId, MailboxConfig)>, String>;

    // -- Deposit capability lookup (for envelope decryption, S07 §3.2) --

    /// List all `(deposit_capability, envelope_secret)` pairs associated with a
    /// mailbox (D3). Used to build the `cap_hint → (deposit_cap, envelope_secret)`
    /// map for envelope decryption: the secret keys the envelope, the cap routes.
    async fn list_deposit_capabilities_for_mailbox(
        &self,
        mailbox_id: MailboxId,
    ) -> std::result::Result<Vec<([u8; 32], [u8; 32])>, String>;

    /// Resolve whether a receive queue is a type-1 handshake capability.
    async fn get_ephemeral_handshake_capability(
        &self,
        _mailbox_id: MailboxId,
        _fetch_capability: &[u8; 32],
    ) -> std::result::Result<Option<EphemeralHandshakeCapability>, String> {
        Ok(None)
    }

    /// Sequential fallback for the Initial commit hook. SqliteStorage overrides
    /// `commit_initial_received` and co-commits this stamp transactionally.
    async fn mark_ephemeral_handshake_cap_accepted(
        &self,
        _capability_id: i64,
    ) -> std::result::Result<(), String> {
        Ok(())
    }

    /// Persist that the server accepted deactivation of the type-1 FETCH cap.
    async fn mark_ephemeral_handshake_cap_deactivated(
        &self,
        _capability_id: i64,
    ) -> std::result::Result<(), String> {
        Ok(())
    }

    // -- Prekey access (for session acceptance, S08 §4.3) --

    /// Get the SPK key pair by ID (for X3DH responder).
    async fn get_spk_keypair(
        &self,
        id: &[u8; 4],
    ) -> std::result::Result<Option<X25519KeyPair>, String>;

    /// Get an OPK key pair by ID (for X3DH responder).
    async fn get_opk_keypair(
        &self,
        id: &[u8; 4],
    ) -> std::result::Result<Option<X25519KeyPair>, String>;

    /// Mark an OPK as used after X3DH consumption.
    async fn mark_opk_used(&self, id: &[u8; 4]) -> std::result::Result<(), String>;

    // -- Mailbox health tracking (S08 §9.3) --

    /// Get health records for all mailboxes, sorted by health (best first).
    async fn list_mailbox_health(&self) -> std::result::Result<Vec<MailboxHealth>, String>;

    /// Get health record for a specific mailbox.
    async fn get_mailbox_health(
        &self,
        mailbox_id: MailboxId,
    ) -> std::result::Result<Option<MailboxHealth>, String>;

    /// Record a successful delivery to a mailbox (resets consecutive failures).
    async fn record_mailbox_success(
        &self,
        mailbox_id: MailboxId,
        timestamp: u64,
    ) -> std::result::Result<(), String>;

    /// Record a failed delivery to a mailbox (increments consecutive failures).
    async fn record_mailbox_failure(
        &self,
        mailbox_id: MailboxId,
        timestamp: u64,
    ) -> std::result::Result<(), String>;

    /// Disable a mailbox (set enabled = false).
    async fn disable_mailbox(&self, mailbox_id: MailboxId) -> std::result::Result<(), String>;

    /// Re-enable a mailbox (set enabled = true, reset consecutive failures).
    async fn enable_mailbox(&self, mailbox_id: MailboxId) -> std::result::Result<(), String>;

    // -- Contact mailbox capabilities (S05 §8, HIGH-09/12) --

    /// Save a per-contact mailbox capability.
    async fn save_contact_capability(
        &self,
        contact_id: ContactId,
        mailbox_id: MailboxId,
        deposit_cap: &[u8; 32],
        fetch_cap: Option<&[u8; 32]>,
        their_deposit_cap: Option<&[u8; 32]>,
    ) -> std::result::Result<(), String>;

    /// Revoke a contact's capability for a specific mailbox.
    async fn revoke_contact_capability(
        &self,
        contact_id: ContactId,
        mailbox_id: MailboxId,
    ) -> std::result::Result<(), String>;

    /// Delete a contact and all associated data.
    async fn delete_contact(&self, contact_id: ContactId) -> std::result::Result<(), String>;

    // -- Volatile keys (S03 §5.13, disappearing message key persistence) --

    /// Save an encrypted volatile key for a disappearing message.
    async fn save_volatile_key(
        &self,
        msg_id: &[u8; 16],
        encrypted_key: &[u8],
        expires_at: Option<u64>,
    ) -> std::result::Result<(), String>;

    /// Get an encrypted volatile key by message ID.
    async fn get_volatile_key(
        &self,
        msg_id: &[u8; 16],
    ) -> std::result::Result<Option<Vec<u8>>, String>;

    /// Delete expired volatile keys. Returns number deleted.
    async fn cleanup_expired_volatile_keys(&self) -> std::result::Result<u32, String>;

    // -- Disappearing messages (S12) --

    /// Set the disappearing message timer for a conversation.
    async fn set_conversation_timer(
        &self,
        contact_id: ContactId,
        timer_secs: Option<u32>,
    ) -> std::result::Result<(), String>;

    /// Get the disappearing message timer for a conversation.
    async fn get_conversation_timer(
        &self,
        contact_id: ContactId,
    ) -> std::result::Result<Option<u32>, String>;

    /// Persist the full S12 §2.2 timer setting (value + `set_at` + setter IK).
    async fn set_conversation_timer_setting(
        &self,
        contact_id: ContactId,
        timer_secs: Option<u32>,
        set_at: u64,
        setter_ik: &[u8; 32],
    ) -> std::result::Result<(), String>;

    /// Read the full S12 §2.2 timer setting: `(timer_secs, set_at, setter_ik)`.
    async fn get_conversation_timer_setting(
        &self,
        contact_id: ContactId,
    ) -> std::result::Result<Option<(Option<u32>, u64, [u8; 32])>, String>;

    /// Get messages whose disappear_at has passed.
    async fn get_expired_disappearing_messages(&self) -> std::result::Result<Vec<Message>, String>;

    /// Securely overwrite message content (for disappearing message deletion).
    async fn overwrite_message_content(
        &self,
        id: MessageId,
        zeros: &[u8],
    ) -> std::result::Result<(), String>;

    /// Mark a stored message as disappearing (S12 §4.1): record its
    /// `timer_secs` (the conversation timer) and the absolute `disappear_at_ms`
    /// (epoch milliseconds) at which it expires and its ephemeral key is
    /// zeroised. Called by the send/receive paths after they seal the content
    /// under a per-message ephemeral key. Default no-op for mocks;
    /// `SqliteStorage` writes the `disappear_timer` + `disappear_at` columns.
    async fn set_message_disappearing(
        &self,
        id: MessageId,
        timer_secs: u32,
        disappear_at_ms: u64,
    ) -> std::result::Result<(), String> {
        let _ = (id, timer_secs, disappear_at_ms);
        Ok(())
    }

    /// Sender-side ACK trigger (S12 §3.1): a delivery ACK for a sent
    /// disappearing message starts its timer now (moving `disappear_at` earlier
    /// than the send-time fallback deadline). Keyed by the 16-byte transport
    /// `msg_id`. Default no-op for mocks; `SqliteStorage` runs the UPDATE.
    async fn start_sender_disappear_on_ack(
        &self,
        msg_id: &[u8; 16],
    ) -> std::result::Result<(), String> {
        let _ = msg_id;
        Ok(())
    }

    // -- Identity history (S02 §18.1, contact identity rotation) --

    /// Save an identity rotation history entry for a CONTACT (S03 §5.14 —
    /// per-contact, FK CASCADE, so it is removed when the contact is deleted).
    async fn save_identity_history(
        &self,
        contact_id: ContactId,
        old_ik_pub: &[u8; 32],
        new_ik_pub: &[u8; 32],
        reason: Option<&str>,
    ) -> std::result::Result<(), String>;

    // -- Skipped keys (Double Ratchet out-of-order) --

    /// Save a skipped message key.
    async fn save_skipped_key(
        &self,
        contact_id: ContactId,
        dh_pub: &[u8; 32],
        msg_num: u32,
        message_key: &[u8; 32],
    ) -> std::result::Result<(), String>;

    /// Get a skipped message key.
    async fn get_skipped_key(
        &self,
        contact_id: ContactId,
        dh_pub: &[u8; 32],
        msg_num: u32,
    ) -> std::result::Result<Option<[u8; 32]>, String>;

    /// Delete a skipped key after use.
    async fn delete_skipped_key(
        &self,
        contact_id: ContactId,
        dh_pub: &[u8; 32],
        msg_num: u32,
    ) -> std::result::Result<(), String>;

    // -- Epoch-reorder quarantine (S08 §6.3) --

    /// Durably persist an epoch-reorder-quarantined frame so it survives a crash
    /// or restart during the up-to-`REPAIR_GRACE_SECS` grace window (S08 §6.3).
    /// Called BEFORE the server blob is acked, so the client — not the mailbox —
    /// owns the only durable copy. Keyed by `blob_hash` (idempotent upsert).
    /// Default no-op (mocks retry from their in-memory buffer); `SqliteStorage`
    /// persists it in the encrypted DB.
    async fn save_quarantined_frame(
        &self,
        _blob_hash: &[u8; 32],
        _blob: &[u8],
        _quarantined_at: u64,
    ) -> std::result::Result<(), String> {
        Ok(())
    }

    /// Load every persisted quarantined frame `(blob, quarantined_at)` — called
    /// once on startup so frames buffered before a restart are retried. Default
    /// empty (mocks).
    async fn load_quarantined_frames(&self) -> std::result::Result<Vec<(Vec<u8>, u64)>, String> {
        Ok(Vec::new())
    }

    /// Delete a persisted quarantined frame once it is recovered (gap closed) or
    /// its grace window expires (repair initiated). Default no-op (mocks).
    async fn delete_quarantined_frame(
        &self,
        _blob_hash: &[u8; 32],
    ) -> std::result::Result<(), String> {
        Ok(())
    }

    // -- Maintenance --

    /// Cleanup old message ID cache entries. Returns number deleted.
    async fn cleanup_old_msg_ids(&self, older_than_secs: u64) -> std::result::Result<u32, String>;

    /// Cleanup expired skipped keys. Returns number deleted.
    async fn cleanup_expired_skipped_keys(&self) -> std::result::Result<u32, String>;

    /// Count available one-time prekeys (for replenishment check).
    async fn count_available_opks(
        &self,
        mailbox_id: Option<MailboxId>,
    ) -> std::result::Result<u32, String>;

    // -- Pending introductions (S05 §11) --

    /// Save a received introduction for user approval.
    async fn save_pending_introduction(
        &self,
        intro: &najwa_storage::types::NewPendingIntroduction,
    ) -> std::result::Result<i64, String>;

    /// Get a pending introduction by ID.
    async fn get_pending_introduction(
        &self,
        id: i64,
    ) -> std::result::Result<Option<najwa_storage::types::PendingIntroduction>, String>;

    /// List all pending introductions (status = 0).
    async fn list_pending_introductions(
        &self,
    ) -> std::result::Result<Vec<najwa_storage::types::PendingIntroduction>, String>;

    /// List introductions from a specific introducer (all statuses).
    async fn list_introductions_for_contact(
        &self,
        introducer_contact_id: ContactId,
    ) -> std::result::Result<Vec<najwa_storage::types::PendingIntroduction>, String>;

    /// Update introduction status (0=pending, 1=accepted, 2=rejected, 3=expired).
    async fn update_introduction_status(
        &self,
        id: i64,
        status: najwa_storage::types::IntroductionStatus,
    ) -> std::result::Result<(), String>;

    /// Count pending introductions.
    async fn count_pending_introductions(&self) -> std::result::Result<u32, String>;

    /// Get a contact by their identity public key (32 bytes).
    async fn get_contact_by_ik(
        &self,
        ik_pub: &[u8; 32],
    ) -> std::result::Result<Option<Contact>, String>;

    /// S03 §5.2 lookup (at most one row): a contact by
    /// `(their_ik_pub, their_device_pub)`. The default falls back to the IK-only
    /// lookup (single-device: device_pub == ik_pub); `SqliteStorage` overrides it
    /// with the exact `(ik, device)` query.
    async fn get_contact_by_ik_device(
        &self,
        ik_pub: &[u8; 32],
        _device_pub: &[u8; 32],
    ) -> std::result::Result<Option<Contact>, String> {
        self.get_contact_by_ik(ik_pub).await
    }
}
