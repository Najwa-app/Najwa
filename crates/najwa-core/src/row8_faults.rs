// SQLite-backed fault injection used by the row 8 regression tests.
struct Row8SqlStore {
    inner: najwa_storage::database::SqliteStorage,
    pause: std::sync::atomic::AtomicBool,
    reads: std::sync::atomic::AtomicUsize,
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
    fail_seen: std::sync::atomic::AtomicBool,
    fail_quarantine: std::sync::atomic::AtomicBool,
    fail_incoming: std::sync::atomic::AtomicBool,
    fail_maintenance: std::sync::atomic::AtomicBool,
}
impl Row8SqlStore {
    fn new(inner: najwa_storage::database::SqliteStorage) -> Self {
        Self {
            inner,
            pause: false.into(),
            reads: 0.into(),
            entered: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
            fail_seen: false.into(),
            fail_quarantine: false.into(),
            fail_incoming: false.into(),
            fail_maintenance: false.into(),
        }
    }
}
#[async_trait]
impl CoreStorage for Row8SqlStore {
    async fn commit_incoming(
        &self,
        _input: &crate::pipeline::Incoming<'_>,
    ) -> std::result::Result<Option<MessageId>, String> {
        if self.fail_incoming.load(std::sync::atomic::Ordering::SeqCst) {
            return Err("injected storage failure".into());
        }
        CoreStorage::commit_incoming(&self.inner, _input).await
    }
    async fn commit_outgoing(
        &self,
        _input: &crate::pipeline::Outgoing<'_>,
    ) -> std::result::Result<(i64, Option<MessageId>), String> {
        CoreStorage::commit_outgoing(&self.inner, _input).await
    }
    async fn outgoing_frames(
        &self,
    ) -> std::result::Result<Vec<najwa_storage::messaging::OutgoingFrame>, String> {
        if self
            .fail_maintenance
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err("injected queue read failure".into());
        }
        CoreStorage::outgoing_frames(&self.inner).await
    }
    async fn outgoing_frame_live(&self, _id: i64) -> std::result::Result<bool, String> {
        CoreStorage::outgoing_frame_live(&self.inner, _id).await
    }
    async fn finish_outgoing(
        &self,
        _id: i64,
        _success: bool,
        _next: u64,
    ) -> std::result::Result<(), String> {
        CoreStorage::finish_outgoing(&self.inner, _id, _success, _next).await
    }
    async fn received_frame(
        &self,
        _id: &[u8; 16],
    ) -> std::result::Result<Option<najwa_storage::messaging::ReceivedFrame>, String> {
        CoreStorage::received_frame(&self.inner, _id).await
    }
    async fn repeat_ack(&self, _id: &[u8; 16]) -> std::result::Result<(), String> {
        CoreStorage::repeat_ack(&self.inner, _id).await
    }
    async fn pending_ack_contacts(&self) -> std::result::Result<Vec<ContactId>, String> {
        CoreStorage::pending_ack_contacts(&self.inner).await
    }
    async fn pending_ack_ranges(
        &self,
        _cid: ContactId,
    ) -> std::result::Result<Vec<najwa_storage::messaging::ChainRange>, String> {
        if self
            .fail_maintenance
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err("injected queue read failure".into());
        }
        CoreStorage::pending_ack_ranges(&self.inner, _cid).await
    }
    async fn inbound_work(
        &self,
    ) -> std::result::Result<Vec<najwa_storage::messaging::InboundWork>, String> {
        if self
            .fail_maintenance
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err("injected queue read failure".into());
        }
        CoreStorage::inbound_work(&self.inner).await
    }
    async fn advance_inbound_work(
        &self,
        _id: i64,
        _cursor: Option<i64>,
    ) -> std::result::Result<(), String> {
        CoreStorage::advance_inbound_work(&self.inner, _id, _cursor).await
    }
    async fn outbound_history(
        &self,
        _cid: ContactId,
        _anchor: Option<[u8; 16]>,
        _from: u64,
        _to: u64,
        _cursor: i64,
    ) -> std::result::Result<Vec<najwa_storage::messaging::HistoryMessage>, String> {
        CoreStorage::outbound_history(&self.inner, _cid, _anchor, _from, _to, _cursor).await
    }
    async fn remote_mailbox_enabled(&self, _onion: &str) -> std::result::Result<bool, String> {
        CoreStorage::remote_mailbox_enabled(&self.inner, _onion).await
    }
    async fn record_remote_mailbox(
        &self,
        _onion: &str,
        _success: bool,
    ) -> std::result::Result<(), String> {
        CoreStorage::record_remote_mailbox(&self.inner, _onion, _success).await
    }
    async fn commit_confirmation(
        &self,
        contact_id: ContactId,
        state: &RatchetState,
        header_id: &[u8; 16],
        effect: &DeliveryConfirmation,
    ) -> std::result::Result<(), String> {
        CoreStorage::commit_confirmation(&self.inner, contact_id, state, header_id, effect).await
    }
    async fn acknowledged_message_ids(
        &self,
        _contact_id: ContactId,
        _ranges: &[([u8; 32], u32, u32)],
    ) -> std::result::Result<Vec<[u8; 16]>, String> {
        CoreStorage::acknowledged_message_ids(&self.inner, _contact_id, _ranges).await
    }
    async fn update_remote_mailboxes(
        &self,
        _contact_id: ContactId,
        _entries: &[najwa_protocol::contact::mailbox_key::MailboxEntry],
    ) -> std::result::Result<(), String> {
        CoreStorage::update_remote_mailboxes(&self.inner, _contact_id, _entries).await
    }
    async fn get_contact(&self, id: ContactId) -> std::result::Result<Option<Contact>, String> {
        CoreStorage::get_contact(&self.inner, id).await
    }
    async fn get_contact_by_pseudonym(
        &self,
        pseudonym: &[u8; 32],
    ) -> std::result::Result<Option<Contact>, String> {
        CoreStorage::get_contact_by_pseudonym(&self.inner, pseudonym).await
    }
    async fn list_contacts(&self) -> std::result::Result<Vec<Contact>, String> {
        CoreStorage::list_contacts(&self.inner).await
    }
    async fn update_contact(&self, contact: &Contact) -> std::result::Result<(), String> {
        CoreStorage::update_contact(&self.inner, contact).await
    }
    async fn create_reciprocal_contact(
        &self,
        _payload: &najwa_protocol::contact::HandshakePayload,
        _our_pseudonym: &[u8; 32],
        _their_pseudonym: &[u8; 32],
    ) -> std::result::Result<Contact, String> {
        CoreStorage::create_reciprocal_contact(
            &self.inner,
            _payload,
            _our_pseudonym,
            _their_pseudonym,
        )
        .await
    }
    async fn next_outbound_seq(&self, _contact_id: ContactId) -> std::result::Result<u32, String> {
        CoreStorage::next_outbound_seq(&self.inner, _contact_id).await
    }
    async fn buffer_outbound_repair(
        &self,
        _contact_id: ContactId,
        _item: &najwa_protocol::message::gap_repair::RepairedItem,
    ) -> std::result::Result<(), String> {
        CoreStorage::buffer_outbound_repair(&self.inner, _contact_id, _item).await
    }
    async fn get_outbound_repair(
        &self,
        _contact_id: ContactId,
        _dh_pub: &[u8; 32],
        _message_number: u32,
    ) -> std::result::Result<Option<najwa_protocol::message::gap_repair::RepairedItem>, String>
    {
        CoreStorage::get_outbound_repair(&self.inner, _contact_id, _dh_pub, _message_number).await
    }
    async fn get_outbound_repair_entry(
        &self,
        contact_id: ContactId,
        dh_pub: &[u8; 32],
        message_number: u32,
    ) -> std::result::Result<
        Option<(najwa_protocol::message::gap_repair::RepairedItem, bool)>,
        String,
    > {
        CoreStorage::get_outbound_repair_entry(&self.inner, contact_id, dh_pub, message_number)
            .await
    }
    async fn get_contact_capabilities(
        &self,
        contact_id: ContactId,
    ) -> std::result::Result<Vec<ContactCapability>, String> {
        CoreStorage::get_contact_capabilities(&self.inner, contact_id).await
    }
    async fn get_ratchet_state(
        &self,
        contact_id: ContactId,
    ) -> std::result::Result<Option<RatchetState>, String> {
        let state = CoreStorage::get_ratchet_state(&self.inner, contact_id).await;
        if self.pause.load(std::sync::atomic::Ordering::SeqCst)
            && self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0
        {
            self.entered.notify_one();
            self.release.notified().await;
        }
        state
    }
    async fn save_ratchet_state(
        &self,
        contact_id: ContactId,
        state: &RatchetState,
    ) -> std::result::Result<(), String> {
        CoreStorage::save_ratchet_state(&self.inner, contact_id, state).await
    }
    async fn delete_ratchet_state(&self, contact_id: ContactId) -> std::result::Result<(), String> {
        CoreStorage::delete_ratchet_state(&self.inner, contact_id).await
    }
    async fn get_ratchet_state_by_dh_pub(
        &self,
        dh_pub: &[u8; 32],
    ) -> std::result::Result<Option<(ContactId, RatchetState)>, String> {
        CoreStorage::get_ratchet_state_by_dh_pub(&self.inner, dh_pub).await
    }
    async fn commit_received(
        &self,
        contact_id: ContactId,
        ratchet_state: &RatchetState,
        message: Option<&Message>,
        transport_msg_id: &[u8; 16],
        logical_msg_id: Option<&[u8; 16]>,
        disappearing: Option<(u32, u64)>,
    ) -> std::result::Result<Option<MessageId>, String> {
        CoreStorage::commit_received(
            &self.inner,
            contact_id,
            ratchet_state,
            message,
            transport_msg_id,
            logical_msg_id,
            disappearing,
        )
        .await
    }
    async fn commit_repaired_received(
        &self,
        contact_id: ContactId,
        message: &Message,
        transport_msg_id: &[u8; 16],
        logical_msg_id: &[u8; 16],
    ) -> std::result::Result<Option<MessageId>, String> {
        CoreStorage::commit_repaired_received(
            &self.inner,
            contact_id,
            message,
            transport_msg_id,
            logical_msg_id,
        )
        .await
    }
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
        CoreStorage::commit_initial_received(
            &self.inner,
            contact_id,
            ratchet_state,
            session_ad,
            opk_id,
            message,
            transport_msg_id,
            logical_msg_id,
            disappearing,
            ephemeral_handshake_cap_id,
        )
        .await
    }
    async fn commit_sent(
        &self,
        contact_id: ContactId,
        ratchet_state: &RatchetState,
        message: &Message,
        wire_blob: &[u8],
        disappearing: Option<(u32, u64)>,
        repair_item: Option<&najwa_protocol::message::gap_repair::RepairedItem>,
    ) -> std::result::Result<MessageId, String> {
        CoreStorage::commit_sent(
            &self.inner,
            contact_id,
            ratchet_state,
            message,
            wire_blob,
            disappearing,
            repair_item,
        )
        .await
    }
    async fn get_session_ad(
        &self,
        contact_id: ContactId,
    ) -> std::result::Result<Option<Vec<u8>>, String> {
        CoreStorage::get_session_ad(&self.inner, contact_id).await
    }
    async fn save_session_ad(
        &self,
        contact_id: ContactId,
        ad: &[u8],
    ) -> std::result::Result<(), String> {
        CoreStorage::save_session_ad(&self.inner, contact_id, ad).await
    }
    async fn delete_session_ad(&self, contact_id: ContactId) -> std::result::Result<(), String> {
        CoreStorage::delete_session_ad(&self.inner, contact_id).await
    }
    async fn save_message(&self, msg: &Message) -> std::result::Result<MessageId, String> {
        CoreStorage::save_message(&self.inner, msg).await
    }
    async fn get_message_by_msg_id(
        &self,
        msg_id: &[u8; 16],
    ) -> std::result::Result<Option<Message>, String> {
        CoreStorage::get_message_by_msg_id(&self.inner, msg_id).await
    }
    async fn update_message_status(
        &self,
        id: MessageId,
        status: MessageStatus,
    ) -> std::result::Result<(), String> {
        CoreStorage::update_message_status(&self.inner, id, status).await
    }
    async fn get_pending_messages(&self) -> std::result::Result<Vec<Message>, String> {
        CoreStorage::get_pending_messages(&self.inner).await
    }
    async fn update_message_blob(
        &self,
        id: MessageId,
        blob: &[u8],
    ) -> std::result::Result<(), String> {
        CoreStorage::update_message_blob(&self.inner, id, blob).await
    }
    async fn clear_message_blob(&self, id: MessageId) -> std::result::Result<(), String> {
        CoreStorage::clear_message_blob(&self.inner, id).await
    }
    async fn increment_retry_count(&self, id: MessageId) -> std::result::Result<(), String> {
        CoreStorage::increment_retry_count(&self.inner, id).await
    }
    async fn get_message_blob(
        &self,
        id: MessageId,
    ) -> std::result::Result<Option<Vec<u8>>, String> {
        CoreStorage::get_message_blob(&self.inner, id).await
    }
    async fn check_msg_id_seen(&self, msg_id: &[u8; 16]) -> std::result::Result<bool, String> {
        if self.fail_seen.load(std::sync::atomic::Ordering::SeqCst) {
            return Err("injected storage failure".into());
        }
        CoreStorage::check_msg_id_seen(&self.inner, msg_id).await
    }
    async fn mark_msg_id_seen(
        &self,
        contact_id: ContactId,
        msg_id: &[u8; 16],
    ) -> std::result::Result<(), String> {
        CoreStorage::mark_msg_id_seen(&self.inner, contact_id, msg_id).await
    }
    async fn check_logical_msg_id_seen(
        &self,
        _contact_id: ContactId,
        _logical_msg_id: &[u8; 16],
    ) -> std::result::Result<bool, String> {
        CoreStorage::check_logical_msg_id_seen(&self.inner, _contact_id, _logical_msg_id).await
    }
    async fn mark_logical_msg_id_seen(
        &self,
        _contact_id: ContactId,
        _logical_msg_id: &[u8; 16],
    ) -> std::result::Result<(), String> {
        CoreStorage::mark_logical_msg_id_seen(&self.inner, _contact_id, _logical_msg_id).await
    }
    async fn list_mailboxes(&self) -> std::result::Result<Vec<MailboxConfig>, String> {
        CoreStorage::list_mailboxes(&self.inner).await
    }
    async fn list_mailboxes_with_ids(
        &self,
    ) -> std::result::Result<Vec<(MailboxId, MailboxConfig)>, String> {
        CoreStorage::list_mailboxes_with_ids(&self.inner).await
    }
    async fn list_deposit_capabilities_for_mailbox(
        &self,
        mailbox_id: MailboxId,
    ) -> std::result::Result<Vec<([u8; 32], [u8; 32])>, String> {
        CoreStorage::list_deposit_capabilities_for_mailbox(&self.inner, mailbox_id).await
    }
    async fn get_ephemeral_handshake_capability(
        &self,
        _mailbox_id: MailboxId,
        _fetch_capability: &[u8; 32],
    ) -> std::result::Result<Option<EphemeralHandshakeCapability>, String> {
        CoreStorage::get_ephemeral_handshake_capability(&self.inner, _mailbox_id, _fetch_capability)
            .await
    }
    async fn mark_ephemeral_handshake_cap_accepted(
        &self,
        _capability_id: i64,
    ) -> std::result::Result<(), String> {
        CoreStorage::mark_ephemeral_handshake_cap_accepted(&self.inner, _capability_id).await
    }
    async fn mark_ephemeral_handshake_cap_deactivated(
        &self,
        _capability_id: i64,
    ) -> std::result::Result<(), String> {
        CoreStorage::mark_ephemeral_handshake_cap_deactivated(&self.inner, _capability_id).await
    }
    async fn get_spk_keypair(
        &self,
        id: &[u8; 4],
    ) -> std::result::Result<Option<X25519KeyPair>, String> {
        CoreStorage::get_spk_keypair(&self.inner, id).await
    }
    async fn get_opk_keypair(
        &self,
        id: &[u8; 4],
    ) -> std::result::Result<Option<X25519KeyPair>, String> {
        CoreStorage::get_opk_keypair(&self.inner, id).await
    }
    async fn mark_opk_used(&self, id: &[u8; 4]) -> std::result::Result<(), String> {
        CoreStorage::mark_opk_used(&self.inner, id).await
    }
    async fn list_mailbox_health(&self) -> std::result::Result<Vec<MailboxHealth>, String> {
        CoreStorage::list_mailbox_health(&self.inner).await
    }
    async fn get_mailbox_health(
        &self,
        mailbox_id: MailboxId,
    ) -> std::result::Result<Option<MailboxHealth>, String> {
        CoreStorage::get_mailbox_health(&self.inner, mailbox_id).await
    }
    async fn record_mailbox_success(
        &self,
        mailbox_id: MailboxId,
        timestamp: u64,
    ) -> std::result::Result<(), String> {
        CoreStorage::record_mailbox_success(&self.inner, mailbox_id, timestamp).await
    }
    async fn record_mailbox_failure(
        &self,
        mailbox_id: MailboxId,
        timestamp: u64,
    ) -> std::result::Result<(), String> {
        CoreStorage::record_mailbox_failure(&self.inner, mailbox_id, timestamp).await
    }
    async fn disable_mailbox(&self, mailbox_id: MailboxId) -> std::result::Result<(), String> {
        CoreStorage::disable_mailbox(&self.inner, mailbox_id).await
    }
    async fn enable_mailbox(&self, mailbox_id: MailboxId) -> std::result::Result<(), String> {
        CoreStorage::enable_mailbox(&self.inner, mailbox_id).await
    }
    async fn save_contact_capability(
        &self,
        contact_id: ContactId,
        mailbox_id: MailboxId,
        deposit_cap: &[u8; 32],
        fetch_cap: Option<&[u8; 32]>,
        their_deposit_cap: Option<&[u8; 32]>,
    ) -> std::result::Result<(), String> {
        CoreStorage::save_contact_capability(
            &self.inner,
            contact_id,
            mailbox_id,
            deposit_cap,
            fetch_cap,
            their_deposit_cap,
        )
        .await
    }
    async fn revoke_contact_capability(
        &self,
        contact_id: ContactId,
        mailbox_id: MailboxId,
    ) -> std::result::Result<(), String> {
        CoreStorage::revoke_contact_capability(&self.inner, contact_id, mailbox_id).await
    }
    async fn delete_contact(&self, contact_id: ContactId) -> std::result::Result<(), String> {
        CoreStorage::delete_contact(&self.inner, contact_id).await
    }
    async fn save_volatile_key(
        &self,
        msg_id: &[u8; 16],
        encrypted_key: &[u8],
        expires_at: Option<u64>,
    ) -> std::result::Result<(), String> {
        CoreStorage::save_volatile_key(&self.inner, msg_id, encrypted_key, expires_at).await
    }
    async fn get_volatile_key(
        &self,
        msg_id: &[u8; 16],
    ) -> std::result::Result<Option<Vec<u8>>, String> {
        CoreStorage::get_volatile_key(&self.inner, msg_id).await
    }
    async fn cleanup_expired_volatile_keys(&self) -> std::result::Result<u32, String> {
        CoreStorage::cleanup_expired_volatile_keys(&self.inner).await
    }
    async fn set_conversation_timer(
        &self,
        contact_id: ContactId,
        timer_secs: Option<u32>,
    ) -> std::result::Result<(), String> {
        CoreStorage::set_conversation_timer(&self.inner, contact_id, timer_secs).await
    }
    async fn get_conversation_timer(
        &self,
        contact_id: ContactId,
    ) -> std::result::Result<Option<u32>, String> {
        CoreStorage::get_conversation_timer(&self.inner, contact_id).await
    }
    async fn set_conversation_timer_setting(
        &self,
        contact_id: ContactId,
        timer_secs: Option<u32>,
        set_at: u64,
        setter_ik: &[u8; 32],
    ) -> std::result::Result<(), String> {
        CoreStorage::set_conversation_timer_setting(
            &self.inner,
            contact_id,
            timer_secs,
            set_at,
            setter_ik,
        )
        .await
    }
    async fn get_conversation_timer_setting(
        &self,
        contact_id: ContactId,
    ) -> std::result::Result<Option<(Option<u32>, u64, [u8; 32])>, String> {
        CoreStorage::get_conversation_timer_setting(&self.inner, contact_id).await
    }
    async fn get_expired_disappearing_messages(&self) -> std::result::Result<Vec<Message>, String> {
        CoreStorage::get_expired_disappearing_messages(&self.inner).await
    }
    async fn overwrite_message_content(
        &self,
        id: MessageId,
        zeros: &[u8],
    ) -> std::result::Result<(), String> {
        CoreStorage::overwrite_message_content(&self.inner, id, zeros).await
    }
    async fn set_message_disappearing(
        &self,
        id: MessageId,
        timer_secs: u32,
        disappear_at_ms: u64,
    ) -> std::result::Result<(), String> {
        CoreStorage::set_message_disappearing(&self.inner, id, timer_secs, disappear_at_ms).await
    }
    async fn start_sender_disappear_on_ack(
        &self,
        msg_id: &[u8; 16],
    ) -> std::result::Result<(), String> {
        CoreStorage::start_sender_disappear_on_ack(&self.inner, msg_id).await
    }
    async fn save_identity_history(
        &self,
        contact_id: ContactId,
        old_ik_pub: &[u8; 32],
        new_ik_pub: &[u8; 32],
        reason: Option<&str>,
    ) -> std::result::Result<(), String> {
        CoreStorage::save_identity_history(&self.inner, contact_id, old_ik_pub, new_ik_pub, reason)
            .await
    }
    async fn save_skipped_key(
        &self,
        contact_id: ContactId,
        dh_pub: &[u8; 32],
        msg_num: u32,
        message_key: &[u8; 32],
    ) -> std::result::Result<(), String> {
        CoreStorage::save_skipped_key(&self.inner, contact_id, dh_pub, msg_num, message_key).await
    }
    async fn get_skipped_key(
        &self,
        contact_id: ContactId,
        dh_pub: &[u8; 32],
        msg_num: u32,
    ) -> std::result::Result<Option<[u8; 32]>, String> {
        CoreStorage::get_skipped_key(&self.inner, contact_id, dh_pub, msg_num).await
    }
    async fn delete_skipped_key(
        &self,
        contact_id: ContactId,
        dh_pub: &[u8; 32],
        msg_num: u32,
    ) -> std::result::Result<(), String> {
        CoreStorage::delete_skipped_key(&self.inner, contact_id, dh_pub, msg_num).await
    }
    async fn save_quarantined_frame(
        &self,
        _blob_hash: &[u8; 32],
        _blob: &[u8],
        _quarantined_at: u64,
    ) -> std::result::Result<(), String> {
        if self
            .fail_quarantine
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err("injected storage failure".into());
        }
        CoreStorage::save_quarantined_frame(&self.inner, _blob_hash, _blob, _quarantined_at).await
    }
    async fn load_quarantined_frames(&self) -> std::result::Result<Vec<(Vec<u8>, u64)>, String> {
        CoreStorage::load_quarantined_frames(&self.inner).await
    }
    async fn delete_quarantined_frame(
        &self,
        _blob_hash: &[u8; 32],
    ) -> std::result::Result<(), String> {
        CoreStorage::delete_quarantined_frame(&self.inner, _blob_hash).await
    }
    async fn cleanup_old_msg_ids(&self, older_than_secs: u64) -> std::result::Result<u32, String> {
        CoreStorage::cleanup_old_msg_ids(&self.inner, older_than_secs).await
    }
    async fn cleanup_expired_skipped_keys(&self) -> std::result::Result<u32, String> {
        CoreStorage::cleanup_expired_skipped_keys(&self.inner).await
    }
    async fn count_available_opks(
        &self,
        mailbox_id: Option<MailboxId>,
    ) -> std::result::Result<u32, String> {
        CoreStorage::count_available_opks(&self.inner, mailbox_id).await
    }
    async fn save_pending_introduction(
        &self,
        intro: &najwa_storage::types::NewPendingIntroduction,
    ) -> std::result::Result<i64, String> {
        CoreStorage::save_pending_introduction(&self.inner, intro).await
    }
    async fn get_pending_introduction(
        &self,
        id: i64,
    ) -> std::result::Result<Option<najwa_storage::types::PendingIntroduction>, String> {
        CoreStorage::get_pending_introduction(&self.inner, id).await
    }
    async fn list_pending_introductions(
        &self,
    ) -> std::result::Result<Vec<najwa_storage::types::PendingIntroduction>, String> {
        CoreStorage::list_pending_introductions(&self.inner).await
    }
    async fn list_introductions_for_contact(
        &self,
        introducer_contact_id: ContactId,
    ) -> std::result::Result<Vec<najwa_storage::types::PendingIntroduction>, String> {
        CoreStorage::list_introductions_for_contact(&self.inner, introducer_contact_id).await
    }
    async fn update_introduction_status(
        &self,
        id: i64,
        status: najwa_storage::types::IntroductionStatus,
    ) -> std::result::Result<(), String> {
        CoreStorage::update_introduction_status(&self.inner, id, status).await
    }
    async fn count_pending_introductions(&self) -> std::result::Result<u32, String> {
        CoreStorage::count_pending_introductions(&self.inner).await
    }
    async fn get_contact_by_ik(
        &self,
        ik_pub: &[u8; 32],
    ) -> std::result::Result<Option<Contact>, String> {
        CoreStorage::get_contact_by_ik(&self.inner, ik_pub).await
    }
    async fn get_contact_by_ik_device(
        &self,
        ik_pub: &[u8; 32],
        _device_pub: &[u8; 32],
    ) -> std::result::Result<Option<Contact>, String> {
        CoreStorage::get_contact_by_ik_device(&self.inner, ik_pub, _device_pub).await
    }
}
struct Row8Mailbox {
    inner: MockMailbox,
    deposit_status: std::sync::atomic::AtomicU16,
    fetch_status: std::sync::atomic::AtomicU16,
    fetch_calls: std::sync::atomic::AtomicUsize,
    pause_deposit: std::sync::atomic::AtomicBool,
    deposit_entered: tokio::sync::Notify,
    deposit_release: tokio::sync::Notify,
    pause_bulk: std::sync::atomic::AtomicBool,
    bulk_entered: std::sync::atomic::AtomicUsize,
    request_slots: tokio::sync::Semaphore,
}
impl Row8Mailbox {
    fn new() -> Self {
        Self {
            inner: MockMailbox::new(),
            deposit_status: 0.into(),
            fetch_status: 0.into(),
            fetch_calls: 0.into(),
            pause_deposit: false.into(),
            deposit_entered: tokio::sync::Notify::new(),
            deposit_release: tokio::sync::Notify::new(),
            pause_bulk: false.into(),
            bulk_entered: 0.into(),
            request_slots: tokio::sync::Semaphore::new(8),
        }
    }
}
#[async_trait]
impl MailboxClient for Row8Mailbox {
    async fn register_capability(
        &self,
        _mailbox: &MailboxConfig,
        _settings: &CapabilitySettings,
        _pow: Option<&PowSolution>,
    ) -> najwa_protocol::mailbox::error::Result<()> {
        MailboxClient::register_capability(&self.inner, _mailbox, _settings, _pow).await
    }
    async fn get_challenge(
        &self,
        _mailbox: &MailboxConfig,
        _hint: &[u8; 8],
    ) -> najwa_protocol::mailbox::error::Result<PowChallenge> {
        MailboxClient::get_challenge(&self.inner, _mailbox, _hint).await
    }
    async fn deposit(
        &self,
        mailbox: &MailboxConfig,
        _deposit_cap: &[u8; 32],
        blob: &[u8],
        _pow: Option<&PowSolution>,
    ) -> najwa_protocol::mailbox::error::Result<DepositResult> {
        let _request = self.request_slots.acquire().await.unwrap();
        if blob.len() > 32_768 && self.pause_bulk.load(std::sync::atomic::Ordering::SeqCst) {
            self.bulk_entered.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.deposit_release.notified().await;
        }
        if self
            .pause_deposit
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            self.deposit_entered.notify_one();
            self.deposit_release.notified().await;
        }
        let code = self
            .deposit_status
            .load(std::sync::atomic::Ordering::SeqCst);
        if code != 0 {
            return Err(MailboxError::ServerError(code));
        }
        MailboxClient::deposit(&self.inner, mailbox, _deposit_cap, blob, _pow).await
    }
    async fn fetch(
        &self,
        _mailbox: &MailboxConfig,
        _fetch_cap: &[u8; 32],
        _since_id: Option<&str>,
        _limit: u32,
    ) -> najwa_protocol::mailbox::error::Result<Vec<MailboxMessage>> {
        self.fetch_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let code = self.fetch_status.load(std::sync::atomic::Ordering::SeqCst);
        if code != 0 {
            return Err(MailboxError::ServerError(code));
        }
        MailboxClient::fetch(&self.inner, _mailbox, _fetch_cap, _since_id, _limit).await
    }
    async fn upload_prekey_bundle(
        &self,
        _mailbox: &MailboxConfig,
        _deposit_cap: &[u8; 32],
        _bundle: &PrekeyBundle,
    ) -> najwa_protocol::mailbox::error::Result<()> {
        MailboxClient::upload_prekey_bundle(&self.inner, _mailbox, _deposit_cap, _bundle).await
    }
    async fn fetch_prekey_bundle(
        &self,
        _mailbox: &MailboxConfig,
        _deposit_cap: &[u8; 32],
        _contact_pseudonym: &[u8; 32],
    ) -> najwa_protocol::mailbox::error::Result<PrekeyBundle> {
        MailboxClient::fetch_prekey_bundle(&self.inner, _mailbox, _deposit_cap, _contact_pseudonym)
            .await
    }
    async fn get_status(
        &self,
        _mailbox: &MailboxConfig,
        _fetch_cap: &[u8; 32],
    ) -> najwa_protocol::mailbox::error::Result<CapabilityStatus> {
        MailboxClient::get_status(&self.inner, _mailbox, _fetch_cap).await
    }
    async fn deactivate_capability(
        &self,
        _mailbox: &MailboxConfig,
        fetch_cap: &[u8; 32],
    ) -> najwa_protocol::mailbox::error::Result<()> {
        MailboxClient::deactivate_capability(&self.inner, _mailbox, fetch_cap).await
    }
    async fn acknowledge(
        &self,
        _mailbox: &MailboxConfig,
        _fetch_cap: &[u8; 32],
        message_ids: &[String],
    ) -> najwa_protocol::mailbox::error::Result<()> {
        MailboxClient::acknowledge(&self.inner, _mailbox, _fetch_cap, message_ids).await
    }
}
