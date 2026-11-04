//! Messaging service for Najwa (S08, S10, S11, S12).
//!
//! Provides:
//! - `MessagingService` orchestration (S08 §2)
//! - Session management over X3DH and the Double Ratchet, with repair (S08 §4, §6.5)
//! - Send pipeline: padding, encryption, durable outbox (S08 §5)
//! - Receive pipeline: fetch, decryption, single-transaction commit (S08 §6)
//! - Delivery ACKs and read receipts (S08 §6.6)
//! - Contact blocking and session reset (S08 §7)
//! - Outbound rate limiting (S08 §8)
//! - Multi-mailbox delivery, mailbox health and deduplication (S08 §9)
//! - Background sync and retry (S08 §10)
//! - Cover-traffic scheduling and slot absorption (S10)
//! - File transfer: chunking, reassembly, sanitization (S11)
//! - Disappearing messages: timers, secure deletion, cleanup (S12)

pub mod blocking;
pub mod bridge;
pub mod confirmation;
pub mod contact_rate_limit;
pub mod cover;
pub mod dedup;
pub mod disappearing;
pub mod error;
pub mod fetch_plan;
mod file_nack;
pub mod filetransfer;
pub mod health;
pub mod introduction;
pub mod multipath;
pub mod najwa_core;
pub mod pipeline;
mod prekeys;
pub mod rate_limit;
pub mod receive;
pub mod send;
pub mod service;
pub mod session;
pub mod storage;
pub mod sync;
pub mod types;

/// Convenience re-exports for common types.
pub mod prelude {
    pub use crate::cover::{CoverLevel, CoverTrafficConfig, CoverTrafficScheduler};
    pub use crate::dedup::MsgIdCache;
    pub use crate::disappearing::{
        DisappearTimer, DisappearingCleanupTask, DisappearingMessageManager, DisappearingStorage,
    };
    pub use crate::error::{MessagingError, Result};
    pub use crate::filetransfer::{FileTransferManager, FileTransferSession};
    pub use crate::health::MailboxHealthTracker;
    pub use crate::najwa_core::{NajwaCore, NajwaCoreHooks, PollResult, SendResult};
    pub use crate::rate_limit::{InboundRateLimiter, OutboundRateLimiter};
    pub use crate::service::MessagingService;
    pub use crate::session::{deserialize_x3dh_header, serialize_x3dh_header};
    pub use crate::storage::CoreStorage;
    pub use crate::sync::{BackgroundSync, DEFAULT_POLL_INTERVAL_SECS};
    pub use crate::types::*;
}

#[cfg(test)]
mod tests {
    include!("row3_storage_tests.rs");
    include!("row4_transport_tests.rs");
    include!("row5_contact_tests.rs");
    include!("row6_key_agreement_tests.rs");
    include!("row7_message_tests.rs");
    include!("row8_messaging_tests.rs");
    include!("row10_disappearing_tests.rs");
    include!("row11_file_nack_tests.rs");
    include!("fetch_plan_tests.rs");

    const BOB_IK_SEED: [u8; 32] = [0x02; 32];
    const ALICE_IK_SEED: [u8; 32] = [
        0x9D, 0x61, 0xB1, 0x9D, 0xEF, 0xFD, 0x5A, 0x60, 0xBA, 0x84, 0x4A, 0xF4, 0x92, 0xEC, 0x2C,
        0xC4, 0x44, 0x49, 0xC5, 0x69, 0x7B, 0x32, 0x69, 0x19, 0x70, 0x3B, 0xAC, 0x03, 0x1C, 0xAE,
        0x7F, 0x60,
    ];
    const SPK_SEED_E2E: [u8; 32] = [0x10; 32];
    const OPK_SEED_E2E: [u8; 32] = [0x20; 32];
    const SPK_ID_E2E: u32 = 1;
    const OPK_ID_E2E: u32 = 7;
    const MAILBOX_ONION_E2E: &str = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz";

    /// Deterministic bob bundle for the row-8 receive-path E2E: SPK/OPK from
    /// fixed seeds, SPK signed by the per-mailbox derived signing key.
    fn bob_bundle_for_e2e(bob_ik: &Ed25519KeyPair) -> najwa_protocol::mailbox::types::PrekeyBundle {
        use najwa_crypto::keys::X25519KeyPair;
        use najwa_protocol::mailbox::types::OneTimePrekey;
        // The wire PrekeyBundle carries no mailbox_ik_pub, so the SPK signature
        // is verified against identity_key — sign with bob's real IK.
        let spk_pub = X25519KeyPair::from_seed(SPK_SEED_E2E).public().to_bytes();
        let signature = bob_ik.sign(&najwa_protocol::x3dh::types::spk_signature_message(
            &spk_pub,
            &SPK_ID_E2E.to_be_bytes(),
            0,
        ));
        najwa_protocol::mailbox::types::PrekeyBundle {
            identity_key: bob_ik.public().to_bytes(),
            signed_prekey: spk_pub,
            signed_prekey_id: SPK_ID_E2E,
            signed_prekey_signature: signature.to_bytes().to_vec(),
            signed_prekey_timestamp: 0,
            one_time_prekeys: vec![OneTimePrekey {
                id: OPK_ID_E2E,
                key: X25519KeyPair::from_seed(OPK_SEED_E2E).public().to_bytes(),
            }],
            manifest: Some(najwa_protocol::x3dh::types::build_wire_manifest(
                bob_ik,
                &SPK_ID_E2E.to_be_bytes(),
                &[OPK_ID_E2E],
                0,
            )),
        }
    }

    use std::collections::HashMap;
    use std::sync::Mutex;

    use async_trait::async_trait;
    use najwa_crypto::keys::ed25519::Ed25519KeyPair;
    use najwa_crypto::keys::x25519::X25519KeyPair;
    use najwa_protocol::mailbox::client::MailboxClient;
    use najwa_protocol::mailbox::error::MailboxError;
    use najwa_protocol::mailbox::types::*;
    use najwa_protocol::ratchet::state::RatchetState;

    use crate::error::MessagingError;
    use crate::service::MessagingService;
    use crate::storage::{CoreStorage, EphemeralHandshakeCapability};
    use crate::types::*;

    // -----------------------------------------------------------------------
    // Mock Storage
    // -----------------------------------------------------------------------

    type EphemeralCapKey = (MailboxId, [u8; 32]);
    type TimerSettingTuple = (Option<u32>, u64, [u8; 32]);
    type OutboundPosition = (ContactId, [u8; 32], u32, [u8; 16]);
    use std::sync::Arc;
    #[derive(Clone)]
    struct MockStorage {
        outbox: Arc<Mutex<Vec<najwa_storage::messaging::OutgoingFrame>>>,
        work: Arc<Mutex<Vec<najwa_storage::messaging::InboundWork>>>,
        contacts: Arc<Mutex<HashMap<ContactId, Contact>>>,
        capabilities: Arc<Mutex<HashMap<ContactId, Vec<ContactCapability>>>>,
        ratchet_states: Arc<Mutex<HashMap<ContactId, Vec<u8>>>>,
        session_ads: Arc<Mutex<HashMap<ContactId, Vec<u8>>>>,
        messages: Arc<Mutex<Vec<Message>>>,
        outbound_positions: Arc<Mutex<Vec<OutboundPosition>>>,
        next_msg_id: Arc<Mutex<i64>>,
        seen_ids: Arc<Mutex<Vec<[u8; 16]>>>,
        mailboxes: Arc<Mutex<Vec<MailboxConfig>>>,
        ephemeral_caps: Arc<Mutex<HashMap<EphemeralCapKey, (i64, bool)>>>,
        spk_keys: Arc<Mutex<HashMap<[u8; 4], Vec<u8>>>>,
        opk_keys: Arc<Mutex<HashMap<[u8; 4], Vec<u8>>>>,
        /// Per-conversation disappearing timer setting (S12 §2.2):
        /// `(timer_secs, set_at, setter_ik)`; outer `None` = never set.
        conversation_timer: Arc<Mutex<Option<TimerSettingTuple>>>,
    }

    impl MockStorage {
        fn new() -> Self {
            Self {
                outbox: Arc::new(Mutex::new(Vec::new())),
                work: Arc::new(Mutex::new(Vec::new())),
                contacts: Arc::new(Mutex::new(HashMap::new())),
                capabilities: Arc::new(Mutex::new(HashMap::new())),
                ratchet_states: Arc::new(Mutex::new(HashMap::new())),
                session_ads: Arc::new(Mutex::new(HashMap::new())),
                messages: Arc::new(Mutex::new(Vec::new())),
                outbound_positions: Arc::new(Mutex::new(Vec::new())),
                next_msg_id: Arc::new(Mutex::new(1)),
                seen_ids: Arc::new(Mutex::new(Vec::new())),
                mailboxes: Arc::new(Mutex::new(Vec::new())),
                ephemeral_caps: Arc::new(Mutex::new(HashMap::new())),
                spk_keys: Arc::new(Mutex::new(HashMap::new())),
                opk_keys: Arc::new(Mutex::new(HashMap::new())),
                conversation_timer: Arc::new(Mutex::new(None)),
            }
        }

        fn add_contact(&self, contact: Contact) {
            self.contacts.lock().unwrap().insert(contact.id, contact);
        }

        fn add_capability(&self, cap: ContactCapability) {
            self.capabilities
                .lock()
                .unwrap()
                .entry(cap.contact_id)
                .or_default()
                .push(cap);
        }

        fn add_mailbox(&self, config: MailboxConfig) {
            self.mailboxes.lock().unwrap().push(config);
        }

        fn add_ephemeral_capability(
            &self,
            mailbox_id: MailboxId,
            fetch_capability: [u8; 32],
            capability_id: i64,
        ) {
            self.ephemeral_caps
                .lock()
                .unwrap()
                .insert((mailbox_id, fetch_capability), (capability_id, false));
        }

        fn add_spk(&self, id: [u8; 4], kp: &X25519KeyPair) {
            let bytes = kp.private().to_bytes();
            self.spk_keys.lock().unwrap().insert(id, bytes.to_vec());
        }

        fn add_opk(&self, id: [u8; 4], kp: &X25519KeyPair) {
            let bytes = kp.private().to_bytes();
            self.opk_keys.lock().unwrap().insert(id, bytes.to_vec());
        }
    }

    #[async_trait]
    impl CoreStorage for MockStorage {
        async fn commit_outgoing(
            &self,
            i: &crate::pipeline::Outgoing<'_>,
        ) -> std::result::Result<(i64, Option<MessageId>), String> {
            if let Some(ad) = i.ad {
                self.save_session_ad(i.contact_id, ad).await?;
            }
            let mid = if let Some(msg) = i.message {
                Some(
                    self.commit_sent(i.contact_id, i.state, msg, i.wire, i.disappearing, i.repair)
                        .await?,
                )
            } else {
                self.save_ratchet_state(i.contact_id, i.state).await?;
                i.existing_message_id
            };
            let mut q = self.outbox.lock().unwrap();
            let id = q.iter().map(|f| f.id).max().unwrap_or(0) + 1;
            q.push(crate::pipeline::queued_frame(id, mid, i));
            Ok((id, mid))
        }
        async fn outgoing_frame_live(&self, id: i64) -> std::result::Result<bool, String> {
            Ok(self.outbox.lock().unwrap().iter().any(|f| f.id == id))
        }
        async fn outgoing_frames(
            &self,
        ) -> std::result::Result<Vec<najwa_storage::messaging::OutgoingFrame>, String> {
            Ok(self.outbox.lock().unwrap().clone())
        }
        async fn finish_outgoing(
            &self,
            id: i64,
            success: bool,
            next: u64,
        ) -> std::result::Result<(), String> {
            let mid = {
                let mut q = self.outbox.lock().unwrap();
                let Some(frame) = q.iter_mut().find(|f| f.id == id) else {
                    return Ok(());
                };
                frame.attempts += 1;
                frame.next_attempt = next;
                let mid = frame.message_id;
                let done = (success && !frame.requires_ack)
                    || (!frame.requires_ack && frame.attempts >= 5);
                if done {
                    q.retain(|f| f.id != id);
                }
                mid
            };
            if let Some(mid) = mid {
                self.update_message_status(
                    mid,
                    if success {
                        MessageStatus::Sent
                    } else {
                        MessageStatus::Failed
                    },
                )
                .await?;
            }
            Ok(())
        }
        async fn commit_incoming(
            &self,
            i: &crate::pipeline::Incoming<'_>,
        ) -> std::result::Result<Option<MessageId>, String> {
            let id = if let Some(ad) = i.ad {
                self.commit_initial_received(
                    i.contact_id,
                    i.state,
                    ad,
                    i.opk_id,
                    i.message,
                    i.transport_id,
                    i.logical_id,
                    i.disappearing,
                    i.ephemeral_cap_id,
                )
                .await?
            } else {
                self.commit_received(
                    i.contact_id,
                    i.state,
                    i.message,
                    i.transport_id,
                    i.logical_id,
                    i.disappearing,
                )
                .await?
            };
            self.mark_msg_id_seen(i.contact_id, i.header_id).await?;
            use najwa_storage::messaging::ReceiveEffect as E;
            for effect in i.effects {
                match effect {
                    E::Timer {
                        secs,
                        set_at,
                        setter,
                    } => {
                        self.set_conversation_timer_setting(i.contact_id, *secs, *set_at, setter)
                            .await?
                    }
                    E::Identity { old, new } => {
                        let mut c = self.get_contact(i.contact_id).await?.unwrap();
                        c.their_ik_pub = *new;
                        self.update_contact(&c).await?;
                        self.save_identity_history(i.contact_id, old, new, Some("rotation"))
                            .await?;
                    }
                    E::Reset | E::Revoke => {
                        self.delete_ratchet_state(i.contact_id).await?;
                        self.delete_session_ad(i.contact_id).await?;
                        if matches!(effect, E::Revoke) {
                            self.delete_contact(i.contact_id).await?;
                        }
                    }
                    E::Introduction(intro) => {
                        self.save_pending_introduction(intro).await?;
                    }
                    E::Message {
                        message,
                        logical_id,
                        disappearing,
                    } => {
                        let kind = match message.content_type {
                            najwa_storage::types::ContentType::Text => 1,
                            najwa_storage::types::ContentType::TextReply => 2,
                            najwa_storage::types::ContentType::Control => 0x20,
                            _ => 3,
                        };
                        let msg = Message {
                            id: 0,
                            contact_id: i.contact_id,
                            msg_id: message.msg_id,
                            direction: Direction::Received,
                            content_type: kind,
                            flags: message.flags as u8,
                            content: message.content.clone(),
                            timestamp: message.timestamp as u64,
                            status: MessageStatus::Delivered,
                            ratchet_index: None,
                        };
                        if let Some(logical) = logical_id {
                            self.commit_repaired_received(i.contact_id, &msg, &msg.msg_id, logical)
                                .await?;
                        } else {
                            self.save_message(&msg).await?;
                        }
                        if let Some((secs, at)) = disappearing {
                            if let Some(saved) = self.get_message_by_msg_id(&msg.msg_id).await? {
                                self.set_message_disappearing(saved.id, *secs, *at).await?;
                            }
                        }
                    }
                    E::ForgetSkipped((dh, start, end)) => {
                        for n in *start..=*end {
                            self.delete_skipped_key(i.contact_id, dh, n).await?;
                        }
                    }
                    E::RepairedPosition { dh_pub, n } => {
                        let mut bytes = dh_pub.to_vec();
                        bytes.extend_from_slice(&n.to_be_bytes());
                        let header = najwa_crypto::hash::sha256(&bytes)[..16].try_into().unwrap();
                        self.mark_msg_id_seen(i.contact_id, &header).await?;
                    }
                    E::Confirmation(effect) => {
                        self.commit_confirmation(i.contact_id, i.state, i.header_id, effect)
                            .await?
                    }
                    E::Settings(_) => return Err("mock settings effects unsupported".into()),
                    E::Work(body) => {
                        let mut q = self.work.lock().unwrap();
                        let id = q.iter().map(|w| w.id).max().unwrap_or(0) + 1;
                        q.push(najwa_storage::messaging::InboundWork {
                            id,
                            contact_id: i.contact_id as i64,
                            body: body.clone(),
                            cursor: 0,
                        });
                    }
                }
            }
            Ok(id)
        }
        async fn inbound_work(
            &self,
        ) -> std::result::Result<Vec<najwa_storage::messaging::InboundWork>, String> {
            Ok(self.work.lock().unwrap().clone())
        }
        async fn advance_inbound_work(
            &self,
            id: i64,
            cursor: Option<i64>,
        ) -> std::result::Result<(), String> {
            let mut q = self.work.lock().unwrap();
            if let Some(cursor) = cursor {
                if let Some(w) = q.iter_mut().find(|w| w.id == id) {
                    w.cursor = cursor;
                }
            } else {
                q.retain(|w| w.id != id);
            }
            Ok(())
        }
        async fn buffer_outbound_repair(
            &self,
            contact_id: ContactId,
            item: &najwa_protocol::message::gap_repair::RepairedItem,
        ) -> std::result::Result<(), String> {
            let state = self
                .get_ratchet_state(contact_id)
                .await?
                .ok_or("missing sending state")?;
            self.outbound_positions.lock().unwrap().push((
                contact_id,
                state.dhs.public().to_bytes(),
                state.ns.saturating_sub(1),
                item.original_msg_id,
            ));
            Ok(())
        }

        async fn acknowledged_message_ids(
            &self,
            contact_id: ContactId,
            ranges: &[([u8; 32], u32, u32)],
        ) -> std::result::Result<Vec<[u8; 16]>, String> {
            Ok(self
                .outbound_positions
                .lock()
                .unwrap()
                .iter()
                .filter(|(peer, dh, n, _)| {
                    *peer == contact_id
                        && ranges
                            .iter()
                            .any(|(key, start, end)| dh == key && n >= start && n <= end)
                })
                .map(|(_, _, _, id)| *id)
                .collect())
        }

        async fn get_contact(&self, id: ContactId) -> std::result::Result<Option<Contact>, String> {
            Ok(self.contacts.lock().unwrap().get(&id).cloned())
        }

        async fn get_contact_by_pseudonym(
            &self,
            pseudonym: &[u8; 32],
        ) -> std::result::Result<Option<Contact>, String> {
            Ok(self
                .contacts
                .lock()
                .unwrap()
                .values()
                .find(|c| &c.their_pseudonym == pseudonym)
                .cloned())
        }

        async fn list_contacts(&self) -> std::result::Result<Vec<Contact>, String> {
            Ok(self.contacts.lock().unwrap().values().cloned().collect())
        }

        async fn update_contact(&self, contact: &Contact) -> std::result::Result<(), String> {
            self.contacts
                .lock()
                .unwrap()
                .insert(contact.id, contact.clone());
            Ok(())
        }

        async fn create_reciprocal_contact(
            &self,
            payload: &najwa_protocol::contact::HandshakePayload,
            our_pseudonym: &[u8; 32],
            their_pseudonym: &[u8; 32],
        ) -> std::result::Result<Contact, String> {
            let entry = payload
                .mailbox_entries
                .first()
                .ok_or_else(|| "missing reciprocal mailbox".to_string())?;
            let mut contacts = self.contacts.lock().unwrap();
            if contacts.values().any(|c| c.their_ik_pub == payload.ik_pub) {
                return Err("contact identity already exists".into());
            }
            let id = contacts.keys().max().copied().unwrap_or(0) + 1;
            let contact = Contact {
                id,
                their_pseudonym: *their_pseudonym,
                our_pseudonym: *our_pseudonym,
                their_ik_pub: payload.ik_pub,
                display_name: (!payload.display_name.is_empty())
                    .then(|| payload.display_name.clone()),
                blocked: false,
                verified: false,
                avatar_hash: None,
                created_at: Some(najwa_crypto::time::now() as i64),
                last_message_at: None,
            };
            contacts.insert(id, contact.clone());
            drop(contacts);

            self.add_capability(ContactCapability {
                contact_id: id,
                mailbox_id: 1,
                mailbox_onion: String::from_utf8_lossy(&entry.onion_address)
                    .trim_end_matches('\0')
                    .to_string(),
                mailbox_fetch_cap: [0u8; 32],
                mailbox_deposit_cap: [0u8; 32],
                their_deposit_capability: Some(entry.deposit_capability),
                their_envelope_secret: Some(entry.envelope_secret),
            });
            Ok(contact)
        }

        async fn get_contact_capabilities(
            &self,
            contact_id: ContactId,
        ) -> std::result::Result<Vec<ContactCapability>, String> {
            Ok(self
                .capabilities
                .lock()
                .unwrap()
                .get(&contact_id)
                .cloned()
                .unwrap_or_default())
        }

        async fn get_ratchet_state(
            &self,
            contact_id: ContactId,
        ) -> std::result::Result<Option<RatchetState>, String> {
            let states = self.ratchet_states.lock().unwrap();
            if let Some(bytes) = states.get(&contact_id) {
                let state = najwa_protocol::ratchet::persist::deserialize_state(bytes)
                    .map_err(|e| e.to_string())?;
                Ok(Some(state))
            } else {
                Ok(None)
            }
        }

        async fn save_ratchet_state(
            &self,
            contact_id: ContactId,
            state: &RatchetState,
        ) -> std::result::Result<(), String> {
            let bytes = najwa_protocol::ratchet::persist::serialize_state(state)
                .map_err(|e| e.to_string())?;
            self.ratchet_states
                .lock()
                .unwrap()
                .insert(contact_id, bytes);
            Ok(())
        }

        async fn delete_ratchet_state(
            &self,
            contact_id: ContactId,
        ) -> std::result::Result<(), String> {
            self.ratchet_states.lock().unwrap().remove(&contact_id);
            Ok(())
        }

        async fn get_ratchet_state_by_dh_pub(
            &self,
            _dh_pub: &[u8; 32],
        ) -> std::result::Result<Option<(ContactId, RatchetState)>, String> {
            // Simple mock: no DH index, always returns None (forces slow path)
            Ok(None)
        }

        async fn get_session_ad(
            &self,
            contact_id: ContactId,
        ) -> std::result::Result<Option<Vec<u8>>, String> {
            Ok(self.session_ads.lock().unwrap().get(&contact_id).cloned())
        }

        async fn save_session_ad(
            &self,
            contact_id: ContactId,
            ad: &[u8],
        ) -> std::result::Result<(), String> {
            self.session_ads
                .lock()
                .unwrap()
                .insert(contact_id, ad.to_vec());
            Ok(())
        }

        async fn delete_session_ad(
            &self,
            contact_id: ContactId,
        ) -> std::result::Result<(), String> {
            self.session_ads.lock().unwrap().remove(&contact_id);
            Ok(())
        }

        async fn save_message(&self, msg: &Message) -> std::result::Result<MessageId, String> {
            let mut next = self.next_msg_id.lock().unwrap();
            let id = *next;
            *next += 1;
            let mut stored = msg.clone();
            stored.id = id;
            self.messages.lock().unwrap().push(stored);
            Ok(id)
        }

        async fn get_message_by_msg_id(
            &self,
            msg_id: &[u8; 16],
        ) -> std::result::Result<Option<Message>, String> {
            Ok(self
                .messages
                .lock()
                .unwrap()
                .iter()
                .find(|m| &m.msg_id == msg_id)
                .cloned())
        }

        async fn update_message_status(
            &self,
            id: MessageId,
            status: MessageStatus,
        ) -> std::result::Result<(), String> {
            if let Some(msg) = self
                .messages
                .lock()
                .unwrap()
                .iter_mut()
                .find(|m| m.id == id)
            {
                msg.status = status;
            }
            Ok(())
        }

        async fn get_pending_messages(&self) -> std::result::Result<Vec<Message>, String> {
            Ok(self
                .messages
                .lock()
                .unwrap()
                .iter()
                .filter(|m| m.status == MessageStatus::Pending || m.status == MessageStatus::Failed)
                .cloned()
                .collect())
        }

        async fn update_message_blob(
            &self,
            _id: MessageId,
            _blob: &[u8],
        ) -> std::result::Result<(), String> {
            Ok(())
        }

        async fn clear_message_blob(&self, _id: MessageId) -> std::result::Result<(), String> {
            Ok(())
        }

        async fn increment_retry_count(&self, _id: MessageId) -> std::result::Result<(), String> {
            Ok(())
        }

        async fn get_message_blob(
            &self,
            _id: MessageId,
        ) -> std::result::Result<Option<Vec<u8>>, String> {
            Ok(None)
        }

        async fn check_msg_id_seen(&self, msg_id: &[u8; 16]) -> std::result::Result<bool, String> {
            Ok(self.seen_ids.lock().unwrap().contains(msg_id))
        }

        async fn mark_msg_id_seen(
            &self,
            _contact_id: ContactId,
            msg_id: &[u8; 16],
        ) -> std::result::Result<(), String> {
            self.seen_ids.lock().unwrap().push(*msg_id);
            Ok(())
        }

        async fn list_mailboxes(&self) -> std::result::Result<Vec<MailboxConfig>, String> {
            Ok(self.mailboxes.lock().unwrap().clone())
        }

        async fn list_mailboxes_with_ids(
            &self,
        ) -> std::result::Result<Vec<(MailboxId, MailboxConfig)>, String> {
            Ok(self
                .mailboxes
                .lock()
                .unwrap()
                .iter()
                .enumerate()
                .map(|(i, m)| (i as i64, m.clone()))
                .collect())
        }

        async fn list_deposit_capabilities_for_mailbox(
            &self,
            _mailbox_id: MailboxId,
        ) -> std::result::Result<Vec<([u8; 32], [u8; 32])>, String> {
            // Collect (their_deposit_capability, their_envelope_secret) pairs.
            let caps = self.capabilities.lock().unwrap();
            let mut result = Vec::new();
            for cap_list in caps.values() {
                for cap in cap_list {
                    if let (Some(dep_cap), Some(secret)) =
                        (cap.their_deposit_capability, cap.their_envelope_secret)
                    {
                        result.push((dep_cap, secret));
                    }
                }
            }
            Ok(result)
        }

        async fn get_ephemeral_handshake_capability(
            &self,
            mailbox_id: MailboxId,
            fetch_capability: &[u8; 32],
        ) -> std::result::Result<Option<EphemeralHandshakeCapability>, String> {
            Ok(self
                .ephemeral_caps
                .lock()
                .unwrap()
                .get(&(mailbox_id, *fetch_capability))
                .map(|(id, accepted)| EphemeralHandshakeCapability {
                    id: *id,
                    accepted: *accepted,
                }))
        }

        async fn mark_ephemeral_handshake_cap_accepted(
            &self,
            capability_id: i64,
        ) -> std::result::Result<(), String> {
            let mut caps = self.ephemeral_caps.lock().unwrap();
            let (_, accepted) = caps
                .values_mut()
                .find(|(id, _)| *id == capability_id)
                .ok_or_else(|| "ephemeral capability not found".to_string())?;
            *accepted = true;
            Ok(())
        }

        async fn get_spk_keypair(
            &self,
            id: &[u8; 4],
        ) -> std::result::Result<Option<X25519KeyPair>, String> {
            Ok(self.spk_keys.lock().unwrap().get(id).map(|bytes| {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(bytes);
                X25519KeyPair::from_seed(arr)
            }))
        }

        async fn get_opk_keypair(
            &self,
            id: &[u8; 4],
        ) -> std::result::Result<Option<X25519KeyPair>, String> {
            Ok(self.opk_keys.lock().unwrap().get(id).map(|bytes| {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(bytes);
                X25519KeyPair::from_seed(arr)
            }))
        }

        async fn mark_opk_used(&self, id: &[u8; 4]) -> std::result::Result<(), String> {
            self.opk_keys.lock().unwrap().remove(id);
            Ok(())
        }

        async fn list_mailbox_health(&self) -> std::result::Result<Vec<MailboxHealth>, String> {
            Ok(vec![])
        }
        async fn get_mailbox_health(
            &self,
            _mailbox_id: MailboxId,
        ) -> std::result::Result<Option<MailboxHealth>, String> {
            Ok(None)
        }
        async fn record_mailbox_success(
            &self,
            _mailbox_id: MailboxId,
            _timestamp: u64,
        ) -> std::result::Result<(), String> {
            Ok(())
        }
        async fn record_mailbox_failure(
            &self,
            _mailbox_id: MailboxId,
            _timestamp: u64,
        ) -> std::result::Result<(), String> {
            Ok(())
        }
        async fn disable_mailbox(&self, _mailbox_id: MailboxId) -> std::result::Result<(), String> {
            Ok(())
        }
        async fn enable_mailbox(&self, _mailbox_id: MailboxId) -> std::result::Result<(), String> {
            Ok(())
        }
        // --- HIGH-12 expanded methods (stubs for test mock) ---
        async fn save_contact_capability(
            &self,
            _contact_id: ContactId,
            _mailbox_id: MailboxId,
            _deposit_cap: &[u8; 32],
            _fetch_cap: Option<&[u8; 32]>,
            _their_dep: Option<&[u8; 32]>,
        ) -> std::result::Result<(), String> {
            Ok(())
        }
        async fn revoke_contact_capability(
            &self,
            _contact_id: ContactId,
            _mailbox_id: MailboxId,
        ) -> std::result::Result<(), String> {
            Ok(())
        }
        async fn delete_contact(&self, _contact_id: ContactId) -> std::result::Result<(), String> {
            Ok(())
        }
        async fn save_volatile_key(
            &self,
            _msg_id: &[u8; 16],
            _encrypted_key: &[u8],
            _expires_at: Option<u64>,
        ) -> std::result::Result<(), String> {
            Ok(())
        }
        async fn get_volatile_key(
            &self,
            _msg_id: &[u8; 16],
        ) -> std::result::Result<Option<Vec<u8>>, String> {
            Ok(None)
        }
        async fn cleanup_expired_volatile_keys(&self) -> std::result::Result<u32, String> {
            Ok(0)
        }
        async fn set_conversation_timer(
            &self,
            _contact_id: ContactId,
            timer_secs: Option<u32>,
        ) -> std::result::Result<(), String> {
            *self.conversation_timer.lock().unwrap() =
                Some((timer_secs, najwa_crypto::prelude::now(), [0u8; 32]));
            Ok(())
        }
        async fn get_conversation_timer(
            &self,
            _contact_id: ContactId,
        ) -> std::result::Result<Option<u32>, String> {
            Ok(self
                .conversation_timer
                .lock()
                .unwrap()
                .and_then(|(t, _, _)| t))
        }
        async fn set_conversation_timer_setting(
            &self,
            _contact_id: ContactId,
            timer_secs: Option<u32>,
            set_at: u64,
            setter_ik: &[u8; 32],
        ) -> std::result::Result<(), String> {
            *self.conversation_timer.lock().unwrap() = Some((timer_secs, set_at, *setter_ik));
            Ok(())
        }
        async fn get_conversation_timer_setting(
            &self,
            _contact_id: ContactId,
        ) -> std::result::Result<Option<(Option<u32>, u64, [u8; 32])>, String> {
            Ok(*self.conversation_timer.lock().unwrap())
        }
        async fn get_expired_disappearing_messages(
            &self,
        ) -> std::result::Result<Vec<Message>, String> {
            Ok(vec![])
        }
        async fn overwrite_message_content(
            &self,
            _id: MessageId,
            _zeros: &[u8],
        ) -> std::result::Result<(), String> {
            Ok(())
        }
        async fn save_identity_history(
            &self,
            _contact_id: ContactId,
            _old_ik: &[u8; 32],
            _new_ik: &[u8; 32],
            _reason: Option<&str>,
        ) -> std::result::Result<(), String> {
            Ok(())
        }
        async fn save_skipped_key(
            &self,
            _contact_id: ContactId,
            _dh_pub: &[u8; 32],
            _msg_num: u32,
            _key: &[u8; 32],
        ) -> std::result::Result<(), String> {
            Ok(())
        }
        async fn get_skipped_key(
            &self,
            _contact_id: ContactId,
            _dh_pub: &[u8; 32],
            _msg_num: u32,
        ) -> std::result::Result<Option<[u8; 32]>, String> {
            Ok(None)
        }
        async fn delete_skipped_key(
            &self,
            _contact_id: ContactId,
            _dh_pub: &[u8; 32],
            _msg_num: u32,
        ) -> std::result::Result<(), String> {
            Ok(())
        }
        async fn cleanup_old_msg_ids(
            &self,
            _older_than_secs: u64,
        ) -> std::result::Result<u32, String> {
            Ok(0)
        }
        async fn cleanup_expired_skipped_keys(&self) -> std::result::Result<u32, String> {
            Ok(0)
        }
        async fn count_available_opks(
            &self,
            _mailbox_id: Option<MailboxId>,
        ) -> std::result::Result<u32, String> {
            Ok(100)
        }

        // -- Pending introductions (S05 §11) --
        async fn save_pending_introduction(
            &self,
            _intro: &najwa_storage::types::NewPendingIntroduction,
        ) -> std::result::Result<i64, String> {
            Ok(1)
        }
        async fn get_pending_introduction(
            &self,
            _id: i64,
        ) -> std::result::Result<Option<najwa_storage::types::PendingIntroduction>, String>
        {
            Ok(None)
        }
        async fn list_pending_introductions(
            &self,
        ) -> std::result::Result<Vec<najwa_storage::types::PendingIntroduction>, String> {
            Ok(vec![])
        }
        async fn list_introductions_for_contact(
            &self,
            _contact_id: ContactId,
        ) -> std::result::Result<Vec<najwa_storage::types::PendingIntroduction>, String> {
            Ok(vec![])
        }
        async fn update_introduction_status(
            &self,
            _id: i64,
            _status: najwa_storage::types::IntroductionStatus,
        ) -> std::result::Result<(), String> {
            Ok(())
        }
        async fn count_pending_introductions(&self) -> std::result::Result<u32, String> {
            Ok(0)
        }
        async fn get_contact_by_ik(
            &self,
            ik_pub: &[u8; 32],
        ) -> std::result::Result<Option<Contact>, String> {
            Ok(self
                .contacts
                .lock()
                .unwrap()
                .values()
                .find(|c| &c.their_ik_pub == ik_pub)
                .cloned())
        }
    }

    // -----------------------------------------------------------------------
    // Mock MailboxClient
    // -----------------------------------------------------------------------

    type DepositLog = Arc<Mutex<Vec<(String, Vec<u8>)>>>;
    type BundleSlot = Arc<Mutex<Option<PrekeyBundle>>>;

    #[derive(Clone)]
    struct MockMailbox {
        deposited: DepositLog,
        prekey_bundle: BundleSlot,
        /// Messages to return on next fetch() call (for E2E testing).
        fetched_messages: Arc<Mutex<Vec<MailboxMessage>>>,
        /// Message ids passed to acknowledge() (ack-as-cursor, D13).
        acked: Arc<Mutex<Vec<String>>>,
        deactivated_fetch_caps: Arc<Mutex<Vec<[u8; 32]>>>,
    }

    impl MockMailbox {
        fn new() -> Self {
            Self {
                deposited: Arc::new(Mutex::new(Vec::new())),
                prekey_bundle: Arc::new(Mutex::new(None)),
                fetched_messages: Arc::new(Mutex::new(Vec::new())),
                acked: Arc::new(Mutex::new(Vec::new())),
                deactivated_fetch_caps: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn set_prekey_bundle(&self, bundle: PrekeyBundle) {
            *self.prekey_bundle.lock().unwrap() = Some(bundle);
        }

        fn set_fetched(&self, msgs: Vec<MailboxMessage>) {
            *self.fetched_messages.lock().unwrap() = msgs;
        }

        fn last_deposit(&self) -> Vec<u8> {
            self.deposited
                .lock()
                .unwrap()
                .last()
                .expect("a deposit was made")
                .1
                .clone()
        }

        fn take_deposited(&self) -> Vec<(String, Vec<u8>)> {
            std::mem::take(&mut *self.deposited.lock().unwrap())
        }

        /// Inject messages that will be returned by the next fetch() call.
        fn inject_fetched(&self, msgs: Vec<MailboxMessage>) {
            *self.fetched_messages.lock().unwrap() = msgs;
        }

        /// Ids that have been acknowledged (D13 ack-as-cursor).
        fn acked_ids(&self) -> Vec<String> {
            self.acked.lock().unwrap().clone()
        }

        fn deactivated_fetch_caps(&self) -> Vec<[u8; 32]> {
            self.deactivated_fetch_caps.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl MailboxClient for MockMailbox {
        async fn register_capability(
            &self,
            _mailbox: &MailboxConfig,
            _settings: &CapabilitySettings,
            _pow: Option<&PowSolution>,
        ) -> najwa_protocol::mailbox::error::Result<()> {
            Ok(())
        }

        async fn get_challenge(
            &self,
            _mailbox: &MailboxConfig,
            _hint: &[u8; 8],
        ) -> najwa_protocol::mailbox::error::Result<PowChallenge> {
            Err(MailboxError::CapabilityNotFound)
        }

        async fn deposit(
            &self,
            mailbox: &MailboxConfig,
            _deposit_cap: &[u8; 32],
            blob: &[u8],
            _pow: Option<&PowSolution>,
        ) -> najwa_protocol::mailbox::error::Result<DepositResult> {
            self.deposited
                .lock()
                .unwrap()
                .push((mailbox.onion_address.clone(), blob.to_vec()));
            Ok(DepositResult {
                accepted: true,
                message_id: Some("mock-id".into()),
            })
        }

        async fn fetch(
            &self,
            _mailbox: &MailboxConfig,
            _fetch_cap: &[u8; 32],
            _since_id: Option<&str>,
            _limit: u32,
        ) -> najwa_protocol::mailbox::error::Result<Vec<MailboxMessage>> {
            Ok(std::mem::take(&mut *self.fetched_messages.lock().unwrap()))
        }

        async fn upload_prekey_bundle(
            &self,
            _mailbox: &MailboxConfig,
            _deposit_cap: &[u8; 32],
            _bundle: &PrekeyBundle,
        ) -> najwa_protocol::mailbox::error::Result<()> {
            Ok(())
        }

        async fn fetch_prekey_bundle(
            &self,
            _mailbox: &MailboxConfig,
            _deposit_cap: &[u8; 32],
            _contact_pseudonym: &[u8; 32],
        ) -> najwa_protocol::mailbox::error::Result<PrekeyBundle> {
            self.prekey_bundle
                .lock()
                .unwrap()
                .clone()
                .ok_or(MailboxError::CapabilityNotFound)
        }

        async fn get_status(
            &self,
            _mailbox: &MailboxConfig,
            _fetch_cap: &[u8; 32],
        ) -> najwa_protocol::mailbox::error::Result<CapabilityStatus> {
            Ok(CapabilityStatus {
                messages_stored: 0,
                quota_remaining: 1000,
                oldest_message_age: 0,
                prekey_count: 100,
                prekey_ids: (0..100).collect(),
            })
        }

        async fn deactivate_capability(
            &self,
            _mailbox: &MailboxConfig,
            fetch_cap: &[u8; 32],
        ) -> najwa_protocol::mailbox::error::Result<()> {
            self.deactivated_fetch_caps.lock().unwrap().push(*fetch_cap);
            Ok(())
        }

        async fn acknowledge(
            &self,
            _mailbox: &MailboxConfig,
            _fetch_cap: &[u8; 32],
            message_ids: &[String],
        ) -> najwa_protocol::mailbox::error::Result<()> {
            self.acked
                .lock()
                .unwrap()
                .extend(message_ids.iter().cloned());
            Ok(())
        }
    }

    // -----------------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------------

    fn test_mailbox_config() -> MailboxConfig {
        MailboxConfig::new("testmailbox".into(), [0xAA; 32], [0xBB; 32])
    }

    fn make_alice_bob_setup() -> (
        Ed25519KeyPair, // alice_ik
        Ed25519KeyPair, // bob_ik
        X25519KeyPair,  // bob_spk
        X25519KeyPair,  // bob_opk
        [u8; 4],        // spk_id
        [u8; 4],        // opk_id
    ) {
        let mut rng = rand::thread_rng();
        let alice_ik = Ed25519KeyPair::generate(&mut rng);
        let bob_ik = Ed25519KeyPair::generate(&mut rng);
        let bob_spk = X25519KeyPair::generate(&mut rng);
        let bob_opk = X25519KeyPair::generate(&mut rng);
        let spk_id = [0, 0, 0, 1];
        let opk_id = [0, 0, 0, 2];
        (alice_ik, bob_ik, bob_spk, bob_opk, spk_id, opk_id)
    }

    fn make_prekey_bundle(
        bob_ik: &Ed25519KeyPair,
        bob_spk: &X25519KeyPair,
        bob_opk: &X25519KeyPair,
        spk_id: [u8; 4],
        opk_id: [u8; 4],
    ) -> PrekeyBundle {
        let sig = bob_ik.sign(&najwa_protocol::x3dh::types::spk_signature_message(
            &bob_spk.public().to_bytes(),
            &spk_id,
            0,
        ));
        PrekeyBundle {
            identity_key: bob_ik.public().to_bytes(),
            signed_prekey: bob_spk.public().to_bytes(),
            signed_prekey_id: u32::from_be_bytes(spk_id),
            signed_prekey_signature: sig.to_bytes().to_vec(),
            signed_prekey_timestamp: 0,
            one_time_prekeys: vec![OneTimePrekey {
                id: u32::from_be_bytes(opk_id),
                key: bob_opk.public().to_bytes(),
            }],
            manifest: Some(najwa_protocol::x3dh::types::build_wire_manifest(
                bob_ik,
                &spk_id,
                &[u32::from_be_bytes(opk_id)],
                0,
            )),
        }
    }

    // -----------------------------------------------------------------------
    // Integration tests
    // -----------------------------------------------------------------------

    // S08 §2: MessagingService can be constructed
    #[test]
    fn service_construction() {
        let ik = Ed25519KeyPair::from_seed(&[0x01; 32]);
        let storage = MockStorage::new();
        let mailbox = MockMailbox::new();
        let _service = MessagingService::new(ik, storage, mailbox);
    }

    // S08 §6.5: gap-repair is rate-limited (≤1/contact/hour) and suppressed while
    // a session repair is already in flight for the contact.
    #[test]
    fn gap_repair_rate_limited_and_suppressed() {
        use crate::service::{RepairPhase, RepairState, GAP_REPAIR_MIN_INTERVAL_SECS};
        let ik = Ed25519KeyPair::from_seed(&[0x09; 32]);
        let svc = MessagingService::new(ik, MockStorage::new(), MockMailbox::new());
        let now = 1_000_000u64;

        // First allowed (recorded); repeats within the window are suppressed.
        assert!(svc.gap_repair_allowed(1, now));
        assert!(!svc.gap_repair_allowed(1, now + 100));
        assert!(!svc.gap_repair_allowed(1, now + GAP_REPAIR_MIN_INTERVAL_SECS - 1));
        // After the window it is allowed again; other contacts are independent.
        assert!(svc.gap_repair_allowed(1, now + GAP_REPAIR_MIN_INTERVAL_SECS));
        assert!(svc.gap_repair_allowed(2, now));

        // While a repair is in flight for a contact, suppress regardless of time.
        svc.repair_states.lock().unwrap().insert(
            3,
            RepairState {
                phase: RepairPhase::InProgress,
                retry_count: 0,
                last_attempt_unix: 0,
                reason: 0,
            },
        );
        assert!(!svc.gap_repair_allowed(3, now + 10 * GAP_REPAIR_MIN_INTERVAL_SECS));

        // A `Failed` repair (retries exhausted, torn down locally) must NOT
        // suppress gap-repair forever: it is stale and is GC'd on the next check.
        svc.repair_states.lock().unwrap().insert(
            4,
            RepairState {
                phase: RepairPhase::Failed,
                retry_count: 99,
                last_attempt_unix: 0,
                reason: 0,
            },
        );
        assert!(
            svc.gap_repair_allowed(4, now),
            "Failed phase must not suppress"
        );
        assert!(
            !svc.repair_states.lock().unwrap().contains_key(&4),
            "stale Failed entry must be GC'd"
        );

        // rollback_gap_repair undoes the rate-limit record when the request
        // failed to send, so the next gap can retry immediately.
        assert!(svc.gap_repair_allowed(5, now));
        assert!(
            !svc.gap_repair_allowed(5, now + 1),
            "recorded => suppressed"
        );
        svc.rollback_gap_repair(5);
        assert!(
            svc.gap_repair_allowed(5, now + 2),
            "rolled back => allowed again"
        );
    }

    // D8: the epoch-reorder quarantine is bounded by EPOCH_QUARANTINE_MAX and
    // drains safely (malformed frames are dropped without panic or leak).
    #[tokio::test]
    async fn d8_epoch_quarantine_is_bounded_and_drains() {
        use crate::service::EPOCH_QUARANTINE_MAX;
        let ik = Ed25519KeyPair::from_seed(&[0x07; 32]);
        let service = MessagingService::new(ik, MockStorage::new(), MockMailbox::new());

        // Fill to the bound — every insert up to the cap is accepted.
        for i in 0..EPOCH_QUARANTINE_MAX {
            assert!(service.try_quarantine(&[i as u8]).await.unwrap());
        }
        // Buffer full → the next frame is rejected, so the caller escalates to
        // session repair instead of growing the buffer without bound.
        assert!(!service.try_quarantine(b"reordered-frame").await.unwrap());

        // Retrying drains the buffer: these blobs are not valid WireMessages, so
        // each is a permanent failure and is dropped — no recovery, no panic,
        // and the buffer ends empty (no leak).
        let recovered = service.retry_quarantine().await;
        assert!(recovered.is_empty());
        assert!(service.epoch_quarantine.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn quarantine_survives_restart() {
        // S08 §6.3: a quarantined frame persisted to Bob's DEVICE must
        // survive a crash mid-grace-window and be reloaded on restart. Uses the
        // real SqliteStorage (bridge + migration 022 + keys.rs), not a mock.
        use najwa_storage::database::SqliteStorage;
        let ik = Ed25519KeyPair::from_seed(&[0x0D; 32]);
        let storage = SqliteStorage::open_in_memory(&[0x42; 32]).unwrap();
        let service = MessagingService::new(ik, storage, MockMailbox::new());

        let raw = b"epoch-orphan-frame";
        assert!(
            service.try_quarantine(raw).await.unwrap(),
            "frame should quarantine"
        );
        assert_eq!(service.epoch_quarantine.lock().unwrap().len(), 1);

        // Crash: lose the in-memory buffer and the one-shot reload flag, exactly as
        // a process restart would — the only durable copy now lives in the DB.
        service.epoch_quarantine.lock().unwrap().clear();
        service
            .quarantine_loaded
            .store(false, std::sync::atomic::Ordering::SeqCst);

        // Restart: reload from the device-local store.
        service.reload_quarantine_once().await;
        let q = service.epoch_quarantine.lock().unwrap();
        assert_eq!(
            q.len(),
            1,
            "frame must be reloaded from durable store after restart"
        );
        assert_eq!(q[0].blob, raw);
    }

    // S08 §5: send_message to unknown contact returns ContactNotFound
    #[tokio::test]
    async fn send_to_unknown_contact_fails() {
        let ik = Ed25519KeyPair::from_seed(&[0x01; 32]);
        let storage = MockStorage::new();
        let mailbox = MockMailbox::new();
        let service = MessagingService::new(ik, storage, mailbox);

        let result = service
            .send_message(999, MessageContent::Text("hello".into()))
            .await;
        assert!(matches!(result, Err(MessagingError::ContactNotFound)));
    }

    // S08 §7.1: send_message to blocked contact returns ContactBlocked
    #[tokio::test]
    async fn send_to_blocked_contact_fails() {
        let ik = Ed25519KeyPair::from_seed(&[0x01; 32]);
        let storage = MockStorage::new();
        storage.add_contact(Contact {
            id: 1,
            their_pseudonym: [0x11; 32],
            our_pseudonym: [0x22; 32],
            their_ik_pub: [0x33; 32],
            display_name: Some("Bob".into()),
            blocked: true,
            verified: false,
            avatar_hash: None,
            created_at: None,
            last_message_at: None,
        });
        let mailbox = MockMailbox::new();
        let service = MessagingService::new(ik, storage, mailbox);

        let result = service
            .send_message(1, MessageContent::Text("hello".into()))
            .await;
        assert!(matches!(result, Err(MessagingError::ContactBlocked)));
    }

    // S08 §4.2: send_message initiates X3DH and deposits to mailbox
    #[tokio::test]
    async fn send_message_initiates_session() {
        let (alice_ik, bob_ik, bob_spk, bob_opk, spk_id, opk_id) = make_alice_bob_setup();

        let storage = MockStorage::new();
        storage.add_contact(Contact {
            id: 1,
            their_pseudonym: [0x11; 32],
            our_pseudonym: [0x22; 32],
            their_ik_pub: bob_ik.public().to_bytes(),
            display_name: Some("Bob".into()),
            blocked: false,
            verified: false,
            avatar_hash: None,
            created_at: None,
            last_message_at: None,
        });
        storage.add_capability(ContactCapability {
            contact_id: 1,
            mailbox_id: 100,
            mailbox_onion: "bobmailbox".into(),
            mailbox_fetch_cap: [0xAA; 32],
            mailbox_deposit_cap: [0xBB; 32],
            their_deposit_capability: Some([0xCC; 32]),
            their_envelope_secret: Some([0xEE; 32]),
        });

        let mock_mailbox = MockMailbox::new();
        mock_mailbox.set_prekey_bundle(make_prekey_bundle(
            &bob_ik, &bob_spk, &bob_opk, spk_id, opk_id,
        ));

        let service = MessagingService::new(alice_ik, storage, mock_mailbox);

        let result = service
            .send_message(1, MessageContent::Text("Hello Bob!".into()))
            .await;
        assert!(result.is_ok());

        let sent = result.unwrap();
        assert_ne!(sent.msg_id, [0u8; 16]);
        assert_eq!(sent.id, 1);

        // Verify something was deposited
        let deposited = service.mailbox_client.take_deposited();
        assert_eq!(deposited.len(), 1);
        assert_eq!(deposited[0].0, "bobmailbox");
    }

    /// Alice-with-one-Bob-capability service, the fixture the S10 §6.2
    /// absorption tests share.
    fn service_ready_to_send() -> MessagingService<MockStorage, MockMailbox> {
        let (alice_ik, bob_ik, bob_spk, bob_opk, spk_id, opk_id) = make_alice_bob_setup();
        let storage = MockStorage::new();
        storage.add_contact(Contact {
            id: 1,
            their_pseudonym: [0x11; 32],
            our_pseudonym: [0x22; 32],
            their_ik_pub: bob_ik.public().to_bytes(),
            display_name: Some("Bob".into()),
            blocked: false,
            verified: false,
            avatar_hash: None,
            created_at: None,
            last_message_at: None,
        });
        storage.add_capability(ContactCapability {
            contact_id: 1,
            mailbox_id: 100,
            mailbox_onion: "bobmailbox".into(),
            mailbox_fetch_cap: [0xAA; 32],
            mailbox_deposit_cap: [0xBB; 32],
            their_deposit_capability: Some([0xCC; 32]),
            their_envelope_secret: Some([0xEE; 32]),
        });
        let mock_mailbox = MockMailbox::new();
        mock_mailbox.set_prekey_bundle(make_prekey_bundle(
            &bob_ik, &bob_spk, &bob_opk, spk_id, opk_id,
        ));
        MessagingService::new(alice_ik, storage, mock_mailbox)
    }

    // S10 §6.2: a send must not deposit at the moment the user presses send —
    // it waits for a scheduler slot. This is THE property the whole absorption
    // model exists for, and it is only real if the deposit is observably absent
    // before the grant and observably present after it.
    #[tokio::test]
    async fn send_waits_for_a_deposit_slot_then_lands() {
        use crate::cover::{AbsorptionPriority, PendingPayload, PendingQueues, SlotSource};
        use std::sync::atomic::AtomicBool;
        use std::sync::Arc;
        use std::time::Duration;

        let mut service = service_ready_to_send();
        let queues = Arc::new(PendingQueues::new());
        let running = Arc::new(AtomicBool::new(true));
        service.set_slot_source(Arc::new(SlotSource::new(
            Arc::clone(&queues),
            Arc::clone(&running),
        )));

        let fut = service.send_message(1, MessageContent::Text("Hello Bob!".into()));
        tokio::pin!(fut);

        // Parked: no slot has been granted, so nothing may reach the mailbox.
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut fut)
                .await
                .is_err(),
            "send completed without waiting for a deposit slot"
        );
        assert!(
            service.mailbox_client.take_deposited().is_empty(),
            "deposit happened before a slot was granted"
        );

        // The parked sender is queued under its DESTINATION onion at tier 1.
        assert_eq!(queues.nonempty_onions(), vec!["bobmailbox".to_string()]);
        let item = queues.pop_highest("bobmailbox").expect("a parked sender");
        assert_eq!(item.priority, AbsorptionPriority::RealMessage);
        match item.payload {
            PendingPayload::Slot(tx) => tx
                .send(crate::cover::SlotPermit::unpaced(
                    crate::cover::SlotGrant::Granted,
                ))
                .expect("sender still parked"),
            PendingPayload::Blob { .. } => panic!("send path must park, not hand over a blob"),
        }

        let sent = fut.await.expect("send completes once its slot is granted");
        assert_ne!(sent.msg_id, [0u8; 16]);
        let deposited = service.mailbox_client.take_deposited();
        assert_eq!(deposited.len(), 1);
        assert_eq!(deposited[0].0, "bobmailbox");
    }

    // S10 §6.2: delivery must never depend on the cover subsystem being
    // healthy. Both "no scheduler running" and "user chose fast mode" deposit
    // immediately — if either could park forever, a stopped scheduler would
    // silently stop the user's messages instead of only their unobservability.
    #[tokio::test]
    async fn send_never_parks_when_there_are_no_slots_to_wait_for() {
        use crate::cover::{PendingQueues, SlotSource};
        use std::sync::atomic::AtomicBool;
        use std::sync::Arc;
        use std::time::Duration;

        for (label, running_flag, bypass) in [
            ("scheduler stopped", false, false),
            ("fast mode", true, true),
        ] {
            let mut service = service_ready_to_send();
            let queues = Arc::new(PendingQueues::new());
            let source = Arc::new(SlotSource::new(
                Arc::clone(&queues),
                Arc::new(AtomicBool::new(running_flag)),
            ));
            source.set_bypass(bypass);
            service.set_slot_source(source);

            let sent = tokio::time::timeout(
                Duration::from_secs(5),
                service.send_message(1, MessageContent::Text("Hello Bob!".into())),
            )
            .await
            .unwrap_or_else(|_| panic!("{label}: send parked with no slot source to release it"))
            .expect("send succeeds");

            assert_ne!(sent.msg_id, [0u8; 16]);
            assert_eq!(
                service.mailbox_client.take_deposited().len(),
                1,
                "{label}: expected an immediate deposit"
            );
            assert!(queues.is_empty(), "{label}: nothing should have parked");
        }
    }

    // S08 §7.1: block and unblock contact
    #[tokio::test]
    async fn block_and_unblock_contact() {
        let ik = Ed25519KeyPair::from_seed(&[0x01; 32]);
        let storage = MockStorage::new();
        storage.add_contact(Contact {
            id: 1,
            their_pseudonym: [0x11; 32],
            our_pseudonym: [0x22; 32],
            their_ik_pub: [0x33; 32],
            display_name: Some("Bob".into()),
            blocked: false,
            verified: false,
            avatar_hash: None,
            created_at: None,
            last_message_at: None,
        });
        let mailbox = MockMailbox::new();
        let service = MessagingService::new(ik, storage, mailbox);

        // Block
        service.block_contact(1).await.unwrap();
        let contact = service.storage.get_contact(1).await.unwrap().unwrap();
        assert!(contact.blocked);

        // Unblock
        service.unblock_contact(1).await.unwrap();
        let contact = service.storage.get_contact(1).await.unwrap().unwrap();
        assert!(!contact.blocked);
    }

    // S08 §7.2: session reset clears ratchet state
    #[tokio::test]
    async fn session_reset_clears_state() {
        let (alice_ik, bob_ik, bob_spk, bob_opk, spk_id, opk_id) = make_alice_bob_setup();

        let storage = MockStorage::new();
        storage.add_contact(Contact {
            id: 1,
            their_pseudonym: [0x11; 32],
            our_pseudonym: [0x22; 32],
            their_ik_pub: bob_ik.public().to_bytes(),
            display_name: Some("Bob".into()),
            blocked: false,
            verified: false,
            avatar_hash: None,
            created_at: None,
            last_message_at: None,
        });
        storage.add_capability(ContactCapability {
            contact_id: 1,
            mailbox_id: 100,
            mailbox_onion: "bobmailbox".into(),
            mailbox_fetch_cap: [0xAA; 32],
            mailbox_deposit_cap: [0xBB; 32],
            their_deposit_capability: Some([0xCC; 32]),
            their_envelope_secret: Some([0xEE; 32]),
        });

        let mock_mailbox = MockMailbox::new();
        mock_mailbox.set_prekey_bundle(make_prekey_bundle(
            &bob_ik, &bob_spk, &bob_opk, spk_id, opk_id,
        ));

        let service = MessagingService::new(alice_ik, storage, mock_mailbox);

        // Send a message (creates session)
        service
            .send_message(1, MessageContent::Text("hi".into()))
            .await
            .unwrap();

        // Verify session exists
        assert!(service
            .storage
            .get_ratchet_state(1)
            .await
            .unwrap()
            .is_some());

        // Reset session
        service.reset_session(1).await.unwrap();

        // Verify session cleared
        assert!(service
            .storage
            .get_ratchet_state(1)
            .await
            .unwrap()
            .is_none());
        assert!(service.storage.get_session_ad(1).await.unwrap().is_none());
    }

    // S08 §9.4: message deduplication
    #[tokio::test]
    async fn dedup_rejects_seen_msg_id() {
        let storage = MockStorage::new();
        let test_id = [0xAA; 16];
        storage.mark_msg_id_seen(1, &test_id).await.unwrap();
        assert!(storage.check_msg_id_seen(&test_id).await.unwrap());
        assert!(!storage.check_msg_id_seen(&[0xBB; 16]).await.unwrap());
    }

    // S08 §5.2: message status tracking
    #[tokio::test]
    async fn message_status_lifecycle() {
        let storage = MockStorage::new();
        let msg = Message {
            id: 0,
            contact_id: 1,
            msg_id: [0x01; 16],
            direction: Direction::Sent,
            content_type: 0x01,
            flags: 0,
            content: b"hello".to_vec(),
            timestamp: 12345,
            status: MessageStatus::Sent,
            ratchet_index: Some(0),
        };
        let id = storage.save_message(&msg).await.unwrap();

        // Update to Delivered
        storage
            .update_message_status(id, MessageStatus::Delivered)
            .await
            .unwrap();
        let found = storage.get_message_by_msg_id(&[0x01; 16]).await.unwrap();
        assert_eq!(found.unwrap().status, MessageStatus::Delivered);

        // Update to Read
        storage
            .update_message_status(id, MessageStatus::Read)
            .await
            .unwrap();
        let found = storage.get_message_by_msg_id(&[0x01; 16]).await.unwrap();
        assert_eq!(found.unwrap().status, MessageStatus::Read);
    }

    // S08 §6.1: poll_messages with empty mailboxes returns empty
    #[tokio::test]
    async fn poll_empty_mailboxes() {
        let ik = Ed25519KeyPair::from_seed(&[0x01; 32]);
        let storage = MockStorage::new();
        storage.add_mailbox(test_mailbox_config());
        let mailbox = MockMailbox::new();
        let service = MessagingService::new(ik, storage, mailbox);

        let received = service.poll_messages().await.unwrap();
        assert!(received.is_empty());
    }

    // S08 §4.2: X3DH header roundtrip is tested in session.rs

    // S08 §8.1: outbound rate limiter integration
    #[test]
    fn outbound_rate_limiter_works() {
        let limiter = crate::rate_limit::OutboundRateLimiter::new(1.0, 2);
        assert!(limiter.check().is_ok());
        assert!(limiter.check().is_ok());
        // Third should fail
        let err = limiter.check().unwrap_err();
        assert!(matches!(err, MessagingError::RateLimitExceeded { .. }));
    }

    // S08 §8.2: inbound rate limiter per-contact isolation
    #[test]
    fn inbound_rate_limiter_per_contact() {
        let limiter = crate::rate_limit::InboundRateLimiter::new(2, 60);
        assert!(limiter.check(1).is_ok());
        assert!(limiter.check(1).is_ok());
        assert!(limiter.check(1).is_err());
        // Different contact is independent
        assert!(limiter.check(2).is_ok());
    }

    // S08 §5.1: send_control_message to unknown contact fails
    #[tokio::test]
    async fn send_control_to_unknown_fails() {
        let ik = Ed25519KeyPair::from_seed(&[0x01; 32]);
        let storage = MockStorage::new();
        let mailbox = MockMailbox::new();
        let service = MessagingService::new(ik, storage, mailbox);

        let ack = najwa_protocol::message::control::ControlMessage::TypingIndicator;
        let result = service.send_control_message(999, &ack).await;
        assert!(matches!(result, Err(MessagingError::ContactNotFound)));
    }

    // Storage trait: ratchet state save/load roundtrip
    #[tokio::test]
    async fn ratchet_state_storage_roundtrip() {
        let mut rng = rand::thread_rng();
        let spk = X25519KeyPair::generate(&mut rng);
        let state = najwa_protocol::ratchet::init::init_bob(&[0xAA; 32], spk);

        let storage = MockStorage::new();
        storage.save_ratchet_state(42, &state).await.unwrap();
        let loaded = storage.get_ratchet_state(42).await.unwrap().unwrap();
        assert_eq!(loaded.rk, state.rk);
        assert_eq!(loaded.ns, state.ns);
        assert_eq!(loaded.nr, state.nr);
    }

    // Session AD persistence
    #[tokio::test]
    async fn session_ad_persistence() {
        let storage = MockStorage::new();
        let ad = vec![0x11u8; 64];
        storage.save_session_ad(1, &ad).await.unwrap();
        let loaded = storage.get_session_ad(1).await.unwrap().unwrap();
        assert_eq!(loaded, ad);

        storage.delete_session_ad(1).await.unwrap();
        assert!(storage.get_session_ad(1).await.unwrap().is_none());
    }

    // -----------------------------------------------------------------------
    // §1.1 E2E Integration Test: Alice → send → Bob → receive roundtrip
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn e2e_alice_sends_bob_receives() {
        // --- Key setup (deterministic seeds for reproducibility) ---
        let alice_seed = [0x01u8; 32];
        let bob_seed = [0x02u8; 32];
        let alice_ik = Ed25519KeyPair::from_seed(&alice_seed);
        let bob_ik = Ed25519KeyPair::from_seed(&bob_seed);
        let mut rng = rand::thread_rng();
        let bob_spk = X25519KeyPair::generate(&mut rng);
        let bob_opk = X25519KeyPair::generate(&mut rng);
        let spk_id: [u8; 4] = [0, 0, 0, 1];
        let opk_id: [u8; 4] = [0, 0, 0, 2];

        // Capture public keys before consuming key pairs
        let alice_ik_pub = alice_ik.public().to_bytes();
        let bob_ik_pub = bob_ik.public().to_bytes();

        // Pseudonyms: Alice sees Bob with these, Bob sees Alice with swapped values
        let alice_pseudo_for_bob = [0xAA; 32]; // Alice's pseudonym as seen by Bob
        let bob_pseudo_for_alice = [0xBB; 32]; // Bob's pseudonym as seen by Alice

        // --- Alice's side ---
        let alice_storage = MockStorage::new();
        alice_storage.add_contact(Contact {
            id: 1,
            their_pseudonym: bob_pseudo_for_alice,
            our_pseudonym: alice_pseudo_for_bob,
            their_ik_pub: bob_ik_pub,
            display_name: Some("Bob".into()),
            blocked: false,
            verified: false,
            avatar_hash: None,
            created_at: None,
            last_message_at: None,
        });
        alice_storage.add_capability(ContactCapability {
            contact_id: 1,
            mailbox_id: 100,
            mailbox_onion: "bobmailbox.onion".into(),
            mailbox_fetch_cap: [0xF0; 32],
            mailbox_deposit_cap: [0xD0; 32],
            their_deposit_capability: Some([0xCC; 32]),
            // D3: shared with Bob's matching cap so Alice's envelope decrypts.
            their_envelope_secret: Some([0xEE; 32]),
        });

        let alice_mailbox = MockMailbox::new();
        alice_mailbox.set_prekey_bundle(make_prekey_bundle(
            &bob_ik, &bob_spk, &bob_opk, spk_id, opk_id,
        ));

        let alice_service = MessagingService::new(alice_ik, alice_storage, alice_mailbox);

        // Alice sends "Hello Bob!"
        let sent = alice_service
            .send_message(1, MessageContent::Text("Hello Bob!".into()))
            .await
            .unwrap();
        assert_ne!(sent.msg_id, [0u8; 16]);

        // Capture the wire bytes that Alice deposited
        let deposited = alice_service.mailbox_client.take_deposited();
        assert_eq!(deposited.len(), 1, "exactly one message deposited");
        let wire_bytes = &deposited[0].1;

        // --- Bob's side ---
        let bob_storage = MockStorage::new();
        // Bob knows Alice by her pseudonym
        bob_storage.add_contact(Contact {
            id: 1,
            their_pseudonym: alice_pseudo_for_bob,
            our_pseudonym: bob_pseudo_for_alice,
            their_ik_pub: alice_ik_pub,
            display_name: Some("Alice".into()),
            blocked: false,
            verified: false,
            avatar_hash: None,
            created_at: None,
            last_message_at: None,
        });
        // Bob needs his SPK and OPK in storage for X3DH responder
        bob_storage.add_spk(spk_id, &bob_spk);
        bob_storage.add_opk(opk_id, &bob_opk);
        // Bob needs a mailbox configured so poll_messages iterates over it. Its
        // (deposit_capability, envelope_secret) is the pair Bob HANDED Alice in his
        // handshake — the same pair Alice enveloped under ([0xCC;32]/[0xEE;32]).
        // Receive de-envelopes inbound blobs with this mailbox pair (S07 §3.2).
        let mut bob_mb = MailboxConfig::new("bobmailbox.onion".into(), [0xF0; 32], [0xCC; 32]);
        bob_mb.envelope_secret = [0xEE; 32];
        bob_storage.add_mailbox(bob_mb);
        // Bob needs the deposit capability that Alice used to envelope-encrypt.
        // Alice's their_deposit_capability = [0xCC; 32], so Bob must have this
        // in his cap list for envelope decryption (CRIT-01/02).
        bob_storage.add_capability(ContactCapability {
            contact_id: 1,
            mailbox_id: 100,
            mailbox_onion: "bobmailbox.onion".into(),
            mailbox_fetch_cap: [0xF0; 32],
            mailbox_deposit_cap: [0xD0; 32],
            their_deposit_capability: Some([0xCC; 32]),
            // D3: same secret Alice enveloped with, so Bob's cap_map decrypts it.
            their_envelope_secret: Some([0xEE; 32]),
        });

        let bob_mailbox = MockMailbox::new();
        // Recreate Bob's IK from seed (Ed25519KeyPair is not Clone)
        let bob_ik_for_service = Ed25519KeyPair::from_seed(&bob_seed);
        let bob_service = MessagingService::new(bob_ik_for_service, bob_storage, bob_mailbox);

        // S01 §3.2 regression: a peer can authenticate the outer envelope
        // while supplying a non-contributory ephemeral key. The REAL poll
        // path must reject it without panicking or consuming the OPK/session.
        let inner = najwa_protocol::message::envelope::envelope_decrypt(
            &[0xEE; 32],
            &[0xCC; 32],
            wire_bytes,
        )
        .unwrap();
        let mut malformed = najwa_protocol::message::WireMessage::from_bytes(&inner).unwrap();
        let (mut header, _) =
            crate::session::deserialize_x3dh_header(malformed.x3dh_header.as_ref().unwrap())
                .unwrap();
        header.ephemeral_key = najwa_crypto::keys::X25519Public::from_bytes([0; 32]);
        malformed.x3dh_header = Some(crate::session::serialize_x3dh_header(&header));
        let malformed_blob = najwa_protocol::message::envelope::envelope_encrypt(
            &[0xEE; 32],
            &[0xCC; 32],
            &malformed.to_bytes(),
        )
        .unwrap();
        bob_service
            .mailbox_client
            .inject_fetched(vec![MailboxMessage {
                id: "bad-initial".into(),
                size: malformed_blob.len() as u32,
                blob: malformed_blob,
                deposited_at: 12344,
                cap_hint: None,
            }]);
        assert!(bob_service.poll_messages().await.unwrap().is_empty());
        assert!(bob_service
            .storage
            .get_ratchet_state(1)
            .await
            .unwrap()
            .is_none());
        assert!(bob_service
            .storage
            .get_opk_keypair(&opk_id)
            .await
            .unwrap()
            .is_some());
        bob_service
            .mailbox_client
            .inject_fetched(vec![MailboxMessage {
                id: "msg-001".into(),
                blob: wire_bytes.clone(),
                deposited_at: 12345,
                size: wire_bytes.len() as u32,
                cap_hint: None,
            }]);

        // Bob polls and receives the message
        let received = bob_service.poll_messages().await.unwrap();
        assert_eq!(received.len(), 1, "Bob should receive exactly one message");

        let msg = &received[0];
        assert_eq!(msg.contact_id, 1, "message is from contact 1 (Alice)");
        // Verify the decrypted content is "Hello Bob!"
        assert_eq!(
            std::str::from_utf8(&msg.content).unwrap(),
            "Hello Bob!",
            "decrypted content matches"
        );
        assert_eq!(msg.msg_id, sent.msg_id, "msg_id matches what Alice sent");

        // D13: the processed message was acknowledged (ack-as-cursor) so the
        // server deletes it — there is no lossy since_id release-cursor.
        assert_eq!(
            bob_service.mailbox_client.acked_ids(),
            vec!["bad-initial".to_string(), "msg-001".to_string()],
            "delivered message must be acknowledged for server-side deletion"
        );

        // Verify Bob's ratchet state was saved (session established)
        assert!(
            bob_service
                .storage
                .get_ratchet_state(1)
                .await
                .unwrap()
                .is_some(),
            "Bob has a ratchet session with Alice"
        );

        // Verify the OPK was consumed
        assert!(
            bob_service
                .storage
                .get_opk_keypair(&opk_id)
                .await
                .unwrap()
                .is_none(),
            "OPK was consumed after X3DH"
        );
    }

    // S05 §8.2: one scan is sufficient. Bob (the scanner) sends his signed
    // reciprocal HandshakePayload as the first Initial; Alice creates Bob on
    // that Initial, and a Standard released before it is recovered from the
    // bounded quarantine rather than discarded as "no session".
    #[tokio::test]
    async fn reciprocal_initial_creates_contact_and_releases_early_standard() {
        use najwa_protocol::contact::create_reciprocal_payload;
        use najwa_protocol::message::types::ContentType;
        use najwa_protocol::pseudonym::derive_pairwise_pseudonyms;

        let alice_seed = [0x31; 32];
        let bob_seed = [0x42; 32];
        let alice_ik = Ed25519KeyPair::from_seed(&alice_seed);
        let bob_ik = Ed25519KeyPair::from_seed(&bob_seed);
        let mut rng = rand::thread_rng();
        let alice_spk = X25519KeyPair::generate(&mut rng);
        let alice_opk = X25519KeyPair::generate(&mut rng);
        let spk_id = [0, 0, 0, 7];
        let opk_id = [0, 0, 0, 8];

        let (bob_our_pseudo, alice_their_pseudo) =
            derive_pairwise_pseudonyms(&bob_ik, alice_ik.public()).unwrap();
        let bob_storage = MockStorage::new();
        bob_storage.add_contact(Contact {
            id: 1,
            their_pseudonym: alice_their_pseudo.0,
            our_pseudonym: bob_our_pseudo.0,
            their_ik_pub: alice_ik.public().to_bytes(),
            display_name: Some("Alice".into()),
            blocked: false,
            verified: false,
            avatar_hash: None,
            created_at: None,
            last_message_at: None,
        });
        bob_storage.add_capability(ContactCapability {
            contact_id: 1,
            mailbox_id: 1,
            mailbox_onion: "alice-mailbox".into(),
            mailbox_fetch_cap: [0xA0; 32],
            mailbox_deposit_cap: [0xA1; 32],
            their_deposit_capability: Some([0xA2; 32]),
            their_envelope_secret: Some([0xA3; 32]),
        });
        let bob_mailbox = MockMailbox::new();
        bob_mailbox.set_prekey_bundle(make_prekey_bundle(
            &alice_ik, &alice_spk, &alice_opk, spk_id, opk_id,
        ));
        let bob_service = MessagingService::new(bob_ik, bob_storage, bob_mailbox);

        let mut future_config = MailboxConfig::new("future-mailbox".into(), [0xC0; 32], [0xC1; 32]);
        future_config.envelope_secret = [0xC2; 32];
        let mut bob_config = MailboxConfig::new("bob-mailbox".into(), [0xB0; 32], [0xB1; 32]);
        bob_config.envelope_secret = [0xB2; 32];
        let bob_signer = Ed25519KeyPair::from_seed(&bob_seed);
        let mut reciprocal =
            create_reciprocal_payload(&bob_signer, &[future_config, bob_config], "Bob", 24)
                .unwrap();
        reciprocal.mailbox_entries[0].capability_type = 0x7F;
        let signable = reciprocal.signable_bytes();
        reciprocal.signature = bob_signer.sign(&signable).to_bytes();
        bob_service
            .send_message(
                1,
                MessageContent::Raw {
                    content_type: ContentType::ReciprocalHandshake as u8,
                    bytes: reciprocal.to_bytes(),
                    reply_to: None,
                },
            )
            .await
            .unwrap();
        bob_service
            .send_message(1, MessageContent::Text("arrived early".into()))
            .await
            .unwrap();
        let deposited = bob_service.mailbox_client.take_deposited();
        assert_eq!(deposited.len(), 2);

        // The same Initial on an ordinary queue creates nothing: existing
        // contacts can deposit there and must not be able to add contacts.
        {
            let storage = MockStorage::new();
            storage.add_spk(spk_id, &alice_spk);
            storage.add_opk(opk_id, &alice_opk);
            let mut config = MailboxConfig::new("alice-mailbox".into(), [0xA0; 32], [0xA2; 32]);
            config.envelope_secret = [0xA3; 32];
            storage.add_mailbox(config);
            let mailbox = MockMailbox::new();
            mailbox.inject_fetched(vec![MailboxMessage {
                id: "reciprocal-initial".into(),
                blob: deposited[0].1.clone(),
                deposited_at: 1,
                size: deposited[0].1.len() as u32,
                cap_hint: None,
            }]);
            let alice =
                MessagingService::new(Ed25519KeyPair::from_seed(&alice_seed), storage, mailbox);
            assert!(alice.poll_messages().await.unwrap().is_empty());
            assert!(alice.storage.list_contacts().await.unwrap().is_empty());
        }

        let alice_storage = MockStorage::new();
        alice_storage.add_spk(spk_id, &alice_spk);
        alice_storage.add_opk(opk_id, &alice_opk);
        let mut alice_config = MailboxConfig::new("alice-mailbox".into(), [0xA0; 32], [0xA2; 32]);
        alice_config.envelope_secret = [0xA3; 32];
        alice_storage.add_mailbox(alice_config);
        alice_storage.add_ephemeral_capability(0, [0xA0; 32], 700);
        let alice_mailbox = MockMailbox::new();
        alice_mailbox.inject_fetched(vec![
            MailboxMessage {
                id: "scraped-qr-garbage".into(),
                blob: vec![0xEE; 64],
                deposited_at: 0,
                size: 64,
                cap_hint: None,
            },
            MailboxMessage {
                id: "standard-before-initial".into(),
                blob: deposited[1].1.clone(),
                deposited_at: 2,
                size: deposited[1].1.len() as u32,
                cap_hint: None,
            },
            MailboxMessage {
                id: "reciprocal-initial".into(),
                blob: deposited[0].1.clone(),
                deposited_at: 1,
                size: deposited[0].1.len() as u32,
                cap_hint: None,
            },
        ]);
        let alice_service = MessagingService::new(
            Ed25519KeyPair::from_seed(&alice_seed),
            alice_storage,
            alice_mailbox,
        );

        let received = alice_service.poll_messages().await.unwrap();
        assert_eq!(received.len(), 1);
        assert_eq!(received[0].content, b"arrived early");
        let contacts = alice_service.storage.list_contacts().await.unwrap();
        assert_eq!(contacts.len(), 1);
        assert_eq!(
            contacts[0].their_ik_pub,
            Ed25519KeyPair::from_seed(&bob_seed).public().to_bytes()
        );
        assert_eq!(contacts[0].display_name.as_deref(), Some("Bob"));
        let caps = alice_service
            .storage
            .get_contact_capabilities(contacts[0].id)
            .await
            .unwrap();
        assert_eq!(caps[0].mailbox_onion, "bob-mailbox");
        assert_eq!(caps[0].their_deposit_capability, Some([0xB1; 32]));
        assert!(alice_service.epoch_quarantine.lock().unwrap().is_empty());
        assert_eq!(
            alice_service.mailbox_client.deactivated_fetch_caps(),
            vec![[0xA0; 32]],
            "first valid Initial deactivates by FETCH capability; garbage did not consume it"
        );
    }

    // S05 §8.2 fail-closed: successful X3DH/AEAD alone is insufficient. A
    // reciprocal payload with an invalid outer signature must not create even a
    // partial contact or install a session.
    #[tokio::test]
    async fn invalid_reciprocal_initial_does_not_create_contact() {
        use najwa_protocol::contact::create_reciprocal_payload;
        use najwa_protocol::message::types::ContentType;
        use najwa_protocol::pseudonym::derive_pairwise_pseudonyms;

        let alice_seed = [0x51; 32];
        let bob_seed = [0x62; 32];
        let alice_ik = Ed25519KeyPair::from_seed(&alice_seed);
        let bob_ik = Ed25519KeyPair::from_seed(&bob_seed);
        let mut rng = rand::thread_rng();
        let alice_spk = X25519KeyPair::generate(&mut rng);
        let alice_opk = X25519KeyPair::generate(&mut rng);
        let spk_id = [0, 0, 0, 9];
        let opk_id = [0, 0, 0, 10];
        let (bob_our_pseudo, alice_their_pseudo) =
            derive_pairwise_pseudonyms(&bob_ik, alice_ik.public()).unwrap();

        let bob_storage = MockStorage::new();
        bob_storage.add_contact(Contact {
            id: 1,
            their_pseudonym: alice_their_pseudo.0,
            our_pseudonym: bob_our_pseudo.0,
            their_ik_pub: alice_ik.public().to_bytes(),
            display_name: Some("Alice".into()),
            blocked: false,
            verified: false,
            avatar_hash: None,
            created_at: None,
            last_message_at: None,
        });
        bob_storage.add_capability(ContactCapability {
            contact_id: 1,
            mailbox_id: 1,
            mailbox_onion: "alice-mailbox".into(),
            mailbox_fetch_cap: [0xC0; 32],
            mailbox_deposit_cap: [0xC1; 32],
            their_deposit_capability: Some([0xC2; 32]),
            their_envelope_secret: Some([0xC3; 32]),
        });
        let bob_mailbox = MockMailbox::new();
        bob_mailbox.set_prekey_bundle(make_prekey_bundle(
            &alice_ik, &alice_spk, &alice_opk, spk_id, opk_id,
        ));
        let bob_service = MessagingService::new(bob_ik, bob_storage, bob_mailbox);
        let mut bob_config = MailboxConfig::new("bob-mailbox".into(), [0xD0; 32], [0xD1; 32]);
        bob_config.envelope_secret = [0xD2; 32];
        let mut reciprocal = create_reciprocal_payload(
            &Ed25519KeyPair::from_seed(&bob_seed),
            &[bob_config],
            "Bob",
            24,
        )
        .unwrap();
        reciprocal.signature[0] ^= 0x80;
        bob_service
            .send_message(
                1,
                MessageContent::Raw {
                    content_type: ContentType::ReciprocalHandshake as u8,
                    bytes: reciprocal.to_bytes(),
                    reply_to: None,
                },
            )
            .await
            .unwrap();
        let deposited = bob_service.mailbox_client.take_deposited();

        let alice_storage = MockStorage::new();
        alice_storage.add_spk(spk_id, &alice_spk);
        alice_storage.add_opk(opk_id, &alice_opk);
        let mut alice_config = MailboxConfig::new("alice-mailbox".into(), [0xC0; 32], [0xC2; 32]);
        alice_config.envelope_secret = [0xC3; 32];
        alice_storage.add_mailbox(alice_config);
        alice_storage.add_ephemeral_capability(0, [0xC0; 32], 701);
        let alice_mailbox = MockMailbox::new();
        alice_mailbox.inject_fetched(vec![MailboxMessage {
            id: "bad-reciprocal".into(),
            blob: deposited[0].1.clone(),
            deposited_at: 1,
            size: deposited[0].1.len() as u32,
            cap_hint: None,
        }]);
        let alice_service = MessagingService::new(
            Ed25519KeyPair::from_seed(&alice_seed),
            alice_storage,
            alice_mailbox,
        );

        assert!(alice_service.poll_messages().await.unwrap().is_empty());
        assert!(alice_service
            .storage
            .list_contacts()
            .await
            .unwrap()
            .is_empty());
        assert!(alice_service
            .storage
            .get_ratchet_state(1)
            .await
            .unwrap()
            .is_none());
        assert!(
            alice_service
                .mailbox_client
                .deactivated_fetch_caps()
                .is_empty(),
            "an Initial with invalid reciprocal content must not consume the slot"
        );
    }

    // S12 §4.1: the REAL send path seals a disappearing message's at-rest copy
    // under a per-message ephemeral key held in the service's volatile cache.
    // The stored content is ciphertext (never the plaintext) and round-trips to
    // plaintext only via the live key; with the timer off, content is verbatim.
    #[tokio::test]
    async fn e2e_disappearing_send_seals_at_rest() {
        use crate::disappearing::{open_sealed_content, Opened};

        let alice_seed = [0x11u8; 32];
        let bob_seed = [0x22u8; 32];
        let alice_ik = Ed25519KeyPair::from_seed(&alice_seed);
        let bob_ik = Ed25519KeyPair::from_seed(&bob_seed);
        let mut rng = rand::thread_rng();
        let bob_spk = X25519KeyPair::generate(&mut rng);
        let bob_opk = X25519KeyPair::generate(&mut rng);
        let spk_id: [u8; 4] = [0, 0, 0, 1];
        let opk_id: [u8; 4] = [0, 0, 0, 2];

        let alice_storage = MockStorage::new();
        alice_storage.add_contact(Contact {
            id: 1,
            their_pseudonym: [0xBB; 32],
            our_pseudonym: [0xAA; 32],
            their_ik_pub: bob_ik.public().to_bytes(),
            display_name: Some("Bob".into()),
            blocked: false,
            verified: false,
            avatar_hash: None,
            created_at: None,
            last_message_at: None,
        });
        alice_storage.add_capability(ContactCapability {
            contact_id: 1,
            mailbox_id: 100,
            mailbox_onion: "bobmailbox.onion".into(),
            mailbox_fetch_cap: [0xF0; 32],
            mailbox_deposit_cap: [0xD0; 32],
            their_deposit_capability: Some([0xCC; 32]),
            their_envelope_secret: Some([0xEE; 32]),
        });
        // Timer ON for this conversation.
        alice_storage
            .set_conversation_timer(1, Some(30))
            .await
            .unwrap();

        let alice_mailbox = MockMailbox::new();
        alice_mailbox.set_prekey_bundle(make_prekey_bundle(
            &bob_ik, &bob_spk, &bob_opk, spk_id, opk_id,
        ));
        let alice = MessagingService::new(alice_ik, alice_storage, alice_mailbox);

        // --- Disappearing send (timer on) ---
        let secret = "vanishing secret";
        let sent = alice
            .send_message(1, MessageContent::Text(secret.into()))
            .await
            .unwrap();
        let stored = alice
            .storage
            .get_message_by_msg_id(&sent.msg_id)
            .await
            .unwrap()
            .expect("sent message is stored");
        assert_ne!(
            stored.content,
            secret.as_bytes(),
            "disappearing content must be sealed at rest, not plaintext"
        );
        assert!(
            !stored
                .content
                .windows(secret.len())
                .any(|w| w == secret.as_bytes()),
            "plaintext must not appear anywhere in the sealed blob"
        );
        // Opens to plaintext only via the live ephemeral key.
        match open_sealed_content(alice.volatile_cache(), &sent.msg_id, &stored.content).unwrap() {
            Opened::Plaintext(p) => assert_eq!(p, secret.as_bytes()),
            Opened::Expired => panic!("key is live — content must open"),
        }
        // Zeroising the key (as expiry does) makes it irrecoverable.
        alice.volatile_cache().remove_key(&sent.msg_id);
        assert!(matches!(
            open_sealed_content(alice.volatile_cache(), &sent.msg_id, &stored.content).unwrap(),
            Opened::Expired
        ));

        // --- Control: timer off → content stored verbatim ---
        alice.storage.set_conversation_timer(1, None).await.unwrap();
        let sent2 = alice
            .send_message(1, MessageContent::Text(secret.into()))
            .await
            .unwrap();
        let stored2 = alice
            .storage
            .get_message_by_msg_id(&sent2.msg_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            stored2.content,
            secret.as_bytes(),
            "with no timer, content is stored verbatim (no sealing)"
        );
    }

    // -----------------------------------------------------------------------
    // Regression (S06 §3.5, S08 §9.1) — a lost DH-epoch-boundary message through
    // the FULL send/receive pipeline (a busy, file-
    // transfer-like flight where the first frame of a new sending epoch is lost).
    // This is the pipeline-level analogue of the ratchet unit test
    // `epoch_link_lost_boundary_recovered`: it proves that because every frame in
    // an epoch carries the same `epoch_link`, the receiver bridges the missing
    // boundary, DH-ratchets forward, and still decrypts the rest of the epoch —
    // with no session repair and no data loss. Nothing else exercises this end to
    // end through `MessagingService`.
    //
    // Two limits of the in-memory harness bound what this can assert (both worth
    // knowing for production readiness):
    //   * MockStorage does not persist skipped-message keys across messages
    //     (that lives in SqliteStorage), so this delivers the surviving frames in
    //     order — a *reordered* burst needs SqliteStorage. Skipped-key persistence
    //     itself is covered by `bridge_persists_and_reloads_skipped_keys`.
    //   * A real `MissedEpochBoundary` (a receiver that missed an ENTIRE epoch)
    //     is unreachable here: a "ghost" receiver can't advance the peer's epoch
    //     in a clone (each DH step draws a fresh random key). Such a frame names
    //     no session, so `decrypt_with_existing_session` reports it as
    //     `NoMatchingSession` and it is quarantined. The ratchet unit tests and
    //     `d8_epoch_quarantine_is_bounded_and_drains` cover it; repair after a
    //     desync is covered by `too_many_skipped_starts_repair_and_session_recovers`.
    // -----------------------------------------------------------------------

    // Envelope (D3) + pseudonym constants for the two-way harness.
    const DCB: [u8; 32] = [0xCB; 32]; // Bob's advertised deposit cap  (Alice → Bob)
    const ESB: [u8; 32] = [0xEB; 32]; // Bob's advertised envelope secret
    const DCA: [u8; 32] = [0xCA; 32]; // Alice's advertised deposit cap (Bob → Alice)
    const ESA: [u8; 32] = [0xEA; 32]; // Alice's advertised envelope secret
    const ALICE_PSEUDO: [u8; 32] = [0xA1; 32]; // Alice as seen by Bob
    const BOB_PSEUDO: [u8; 32] = [0xB1; 32]; // Bob as seen by Alice

    /// Wrap raw deposited blobs as fetchable `MailboxMessage`s with unique ids.
    fn as_fetched(deposited: Vec<(String, Vec<u8>)>, next_id: &mut u32) -> Vec<MailboxMessage> {
        deposited
            .into_iter()
            .map(|(_, blob)| {
                let id = format!("msg-{:05}", *next_id);
                *next_id += 1;
                let size = blob.len() as u32;
                MailboxMessage {
                    id,
                    blob,
                    deposited_at: 0,
                    size,
                    cap_hint: None,
                }
            })
            .collect()
    }

    fn contact_row(
        their_pseudo: [u8; 32],
        our_pseudo: [u8; 32],
        their_ik_pub: [u8; 32],
        name: &str,
    ) -> Contact {
        Contact {
            id: 1,
            their_pseudonym: their_pseudo,
            our_pseudonym: our_pseudo,
            their_ik_pub,
            display_name: Some(name.into()),
            blocked: false,
            verified: false,
            avatar_hash: None,
            created_at: None,
            last_message_at: None,
        }
    }

    /// Build a fully-wired Bob-side service (X3DH responder + reply-capable).
    /// The identical setup is used for the real Bob and the "ghost" Bob that
    /// drives Alice's sending epochs forward while the real Bob stays pinned.
    fn build_bob(
        bob_seed: &[u8; 32],
        spk_priv: [u8; 32],
        opk_priv: [u8; 32],
        spk_id: [u8; 4],
        opk_id: [u8; 4],
        alice_ik_pub: [u8; 32],
    ) -> MessagingService<MockStorage, MockMailbox> {
        let storage = MockStorage::new();
        storage.add_contact(contact_row(ALICE_PSEUDO, BOB_PSEUDO, alice_ik_pub, "Alice"));
        storage.add_spk(spk_id, &X25519KeyPair::from_seed(spk_priv));
        storage.add_opk(opk_id, &X25519KeyPair::from_seed(opk_priv));
        // Cap to deposit replies to Alice (enveloped under Alice's advertised pair).
        storage.add_capability(ContactCapability {
            contact_id: 1,
            mailbox_id: 200,
            mailbox_onion: "alice.onion".into(),
            mailbox_fetch_cap: [0xF1; 32],
            mailbox_deposit_cap: [0xD1; 32],
            their_deposit_capability: Some(DCA),
            their_envelope_secret: Some(ESA),
        });
        // Bob's own mailbox: inbound Alice→Bob blobs are enveloped under (DCB, ESB).
        let mut mb = MailboxConfig::new("bob.onion".into(), [0xFB; 32], DCB);
        mb.envelope_secret = ESB;
        storage.add_mailbox(mb);
        MessagingService::new(
            Ed25519KeyPair::from_seed(bob_seed),
            storage,
            MockMailbox::new(),
        )
    }

    /// Decrypt-and-collect the plaintext bodies from a poll result.
    fn bodies(msgs: &[crate::types::ReceivedMessage]) -> Vec<String> {
        msgs.iter()
            .map(|m| String::from_utf8(m.content.clone()).unwrap())
            .collect()
    }

    /// S08 §4.3: an Initial whose payload pseudonym names an existing contact but
    /// whose X3DH-header IK is a different key must not bind to that contact.
    #[tokio::test]
    async fn initial_with_known_pseudonym_but_foreign_ik_is_rejected() {
        let bob_seed = [0x12u8; 32];
        let bob_ik = Ed25519KeyPair::from_seed(&bob_seed);
        let alice_ik_pub = Ed25519KeyPair::from_seed(&[0x11u8; 32]).public().to_bytes();
        let mut rng = rand::thread_rng();
        let bob_spk = X25519KeyPair::generate(&mut rng);
        let bob_opk = X25519KeyPair::generate(&mut rng);
        let (spk_id, opk_id) = ([0, 0, 0, 1], [0, 0, 0, 2]);

        // Mallory holds Bob's deposit cap and envelope secret (as any contact or
        // invitee does) and has learned Alice's pseudonym, but signs with her own IK.
        let mallory_storage = MockStorage::new();
        mallory_storage.add_contact(contact_row(
            BOB_PSEUDO,
            ALICE_PSEUDO,
            bob_ik.public().to_bytes(),
            "Bob",
        ));
        mallory_storage.add_capability(ContactCapability {
            contact_id: 1,
            mailbox_id: 100,
            mailbox_onion: "bob.onion".into(),
            mailbox_fetch_cap: [0xF0; 32],
            mailbox_deposit_cap: [0xD0; 32],
            their_deposit_capability: Some(DCB),
            their_envelope_secret: Some(ESB),
        });
        let mallory_mailbox = MockMailbox::new();
        mallory_mailbox.set_prekey_bundle(make_prekey_bundle(
            &bob_ik, &bob_spk, &bob_opk, spk_id, opk_id,
        ));
        let mallory = MessagingService::new(
            Ed25519KeyPair::from_seed(&[0x66u8; 32]),
            mallory_storage,
            mallory_mailbox,
        );
        let bob = build_bob(
            &bob_seed,
            bob_spk.private().to_bytes(),
            bob_opk.private().to_bytes(),
            spk_id,
            opk_id,
            alice_ik_pub,
        );

        mallory
            .send_message(1, MessageContent::Text("impersonated".into()))
            .await
            .unwrap();
        let mut nid = 0u32;
        bob.mailbox_client
            .inject_fetched(as_fetched(mallory.mailbox_client.take_deposited(), &mut nid));
        let received = bob.poll_messages().await.unwrap_or_default();

        assert!(bodies(&received).is_empty());
        assert!(CoreStorage::get_ratchet_state(&bob.storage, 1)
            .await
            .unwrap()
            .is_none());
    }

    /// S07 §3.2: a receive queue without an envelope secret must not parse
    /// unwrapped blobs. A raw, otherwise valid Initial is discarded and acked.
    #[tokio::test]
    async fn queue_without_envelope_secret_discards_unwrapped_blobs() {
        let bob_seed = [0x12u8; 32];
        let bob_ik = Ed25519KeyPair::from_seed(&bob_seed);
        let alice_ik = Ed25519KeyPair::from_seed(&[0x11u8; 32]);
        let alice_ik_pub = alice_ik.public().to_bytes();
        let mut rng = rand::thread_rng();
        let bob_spk = X25519KeyPair::generate(&mut rng);
        let bob_opk = X25519KeyPair::generate(&mut rng);
        let (spk_id, opk_id) = ([0, 0, 0, 1], [0, 0, 0, 2]);

        let alice_storage = MockStorage::new();
        alice_storage.add_contact(contact_row(
            BOB_PSEUDO,
            ALICE_PSEUDO,
            bob_ik.public().to_bytes(),
            "Bob",
        ));
        alice_storage.add_capability(ContactCapability {
            contact_id: 1,
            mailbox_id: 100,
            mailbox_onion: "bob.onion".into(),
            mailbox_fetch_cap: [0xF0; 32],
            mailbox_deposit_cap: [0xD0; 32],
            their_deposit_capability: Some(DCB),
            their_envelope_secret: Some(ESB),
        });
        let alice_mailbox = MockMailbox::new();
        alice_mailbox.set_prekey_bundle(make_prekey_bundle(
            &bob_ik, &bob_spk, &bob_opk, spk_id, opk_id,
        ));
        let alice = MessagingService::new(alice_ik, alice_storage, alice_mailbox);
        alice
            .send_message(1, MessageContent::Text("unwrapped".into()))
            .await
            .unwrap();
        let (_, wrapped) = alice.mailbox_client.take_deposited().remove(0);
        let raw = najwa_protocol::message::envelope::envelope_decrypt(&ESB, &DCB, &wrapped).unwrap();

        // Bob's queue has no envelope secret; the server hands him the raw frame.
        let bob_storage = MockStorage::new();
        bob_storage.add_contact(contact_row(ALICE_PSEUDO, BOB_PSEUDO, alice_ik_pub, "Alice"));
        bob_storage.add_spk(spk_id, &X25519KeyPair::from_seed(bob_spk.private().to_bytes()));
        bob_storage.add_opk(opk_id, &X25519KeyPair::from_seed(bob_opk.private().to_bytes()));
        let mut mb = MailboxConfig::new("bob.onion".into(), [0xFB; 32], DCB);
        mb.envelope_secret = [0u8; 32];
        bob_storage.add_mailbox(mb);
        let bob = MessagingService::new(bob_ik, bob_storage, MockMailbox::new());
        let mut nid = 0u32;
        bob.mailbox_client
            .inject_fetched(as_fetched(vec![(String::new(), raw)], &mut nid));

        assert!(bodies(&bob.poll_messages().await.unwrap()).is_empty());
        assert_eq!(bob.mailbox_client.acked_ids(), vec!["msg-00000".to_string()]);
        assert!(CoreStorage::get_ratchet_state(&bob.storage, 1)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn lost_epoch_boundary_bridged_through_pipeline() {
        let alice_seed = [0x11u8; 32];
        let bob_seed = [0x12u8; 32];
        let alice_ik = Ed25519KeyPair::from_seed(&alice_seed);
        let bob_ik = Ed25519KeyPair::from_seed(&bob_seed);
        let alice_ik_pub = alice_ik.public().to_bytes();
        let bob_ik_pub = bob_ik.public().to_bytes();

        let mut rng = rand::thread_rng();
        let bob_spk = X25519KeyPair::generate(&mut rng);
        let bob_opk = X25519KeyPair::generate(&mut rng);
        let spk_priv = bob_spk.private().to_bytes();
        let opk_priv = bob_opk.private().to_bytes();
        let spk_id = [0, 0, 0, 1];
        let opk_id = [0, 0, 0, 2];

        // --- Alice (X3DH initiator) ---
        let alice_storage = MockStorage::new();
        alice_storage.add_contact(contact_row(BOB_PSEUDO, ALICE_PSEUDO, bob_ik_pub, "Bob"));
        alice_storage.add_capability(ContactCapability {
            contact_id: 1,
            mailbox_id: 100,
            mailbox_onion: "bob.onion".into(),
            mailbox_fetch_cap: [0xF0; 32],
            mailbox_deposit_cap: [0xD0; 32],
            their_deposit_capability: Some(DCB),
            their_envelope_secret: Some(ESB),
        });
        let mut alice_mb = MailboxConfig::new("alice.onion".into(), [0xFA; 32], DCA);
        alice_mb.envelope_secret = ESA;
        alice_storage.add_mailbox(alice_mb);
        let alice_mailbox = MockMailbox::new();
        alice_mailbox.set_prekey_bundle(make_prekey_bundle(
            &bob_ik, &bob_spk, &bob_opk, spk_id, opk_id,
        ));
        let alice = MessagingService::new(alice_ik, alice_storage, alice_mailbox);

        // --- Real Bob (X3DH responder, reply-capable) ---
        let bob = build_bob(&bob_seed, spk_priv, opk_priv, spk_id, opk_id, alice_ik_pub);

        let mut nid = 0u32;

        // Establish the session: Alice → Bob, epoch E0.
        alice
            .send_message(1, MessageContent::Text("a0".into()))
            .await
            .unwrap();
        let a0 = alice.mailbox_client.take_deposited();
        bob.mailbox_client.inject_fetched(as_fetched(a0, &mut nid));
        assert_eq!(bodies(&bob.poll_messages().await.unwrap()), ["a0"]);
        bob.mailbox_client.take_deposited(); // discard Bob's auto-ACK

        // Bob replies → Alice DH-ratchets into a NEW sending epoch E1. Alice's E1 is
        // negotiated against THIS Bob's fresh (random) DH key, so only this Bob can
        // read epoch E1 — which is exactly why a ghost/clone receiver cannot stand
        // in for Bob here; the epoch is bound to the real reply.
        bob.send_message(1, MessageContent::Text("b0".into()))
            .await
            .unwrap();
        let b0 = bob.mailbox_client.take_deposited();
        alice
            .mailbox_client
            .inject_fetched(as_fetched(b0, &mut nid));
        assert_eq!(bodies(&alice.poll_messages().await.unwrap()), ["b0"]);
        alice.mailbox_client.take_deposited(); // discard Alice's auto-ACK

        // Alice sends a 10-message burst IN epoch E1 (n = 0..9) — a file-transfer-
        // like flight. Every frame carries the SAME epoch_link = E0; that is the
        // epoch-link property (S06 §3.9) that makes losing any single boundary frame non-fatal.
        const BURST: usize = 10;
        for i in 0..BURST {
            alice
                .send_message(1, MessageContent::Text(format!("e1-{i}")))
                .await
                .unwrap();
        }
        let mut frames = alice.mailbox_client.take_deposited();
        assert_eq!(frames.len(), BURST);

        // The epoch BOUNDARY frame (n = 0) is LOST in transit — never delivered.
        // Deliver the other nine. Without the epoch link, losing the first frame of a
        // new sending epoch would desync that direction permanently (the receiver
        // could not derive the new chain). Every frame in the epoch carry
        // the same epoch_link = E0, so the first surviving frame (n = 1) still
        // bridges the gap: Bob DH-ratchets into E1 and decrypts all nine, the lost
        // boundary becoming a single skipped-key slot rather than a dead session.
        let _boundary_lost = frames.remove(0); // n = 0, dropped
        bob.mailbox_client
            .inject_fetched(as_fetched(frames, &mut nid));
        let got: std::collections::HashSet<String> = bodies(&bob.poll_messages().await.unwrap())
            .into_iter()
            .collect();
        let want: std::collections::HashSet<String> =
            (1..BURST).map(|i| format!("e1-{i}")).collect();
        assert_eq!(
            got, want,
            "a lost epoch-boundary frame must not desync the session — every later frame bridges via epoch_link"
        );
        assert!(
            bob.get_repair_state(1).is_none(),
            "a lost boundary frame is bridged inline; it must not trigger session repair"
        );
    }

    // S06 §3.7.1 / S08 §6.2: a desynchronised session repairs itself. The
    // sender's next MAX_SKIP + 1 frames are lost (for example expired on the
    // mailbox), so the following frame fails with TooManySkipped. Trial
    // decryption used to report that as NoMatchingSession: the frame was
    // quarantined and discarded, and so was every later frame of the session.
    // Now the receiver sends a SessionRepairInit, the repair window closes when
    // the peer answers in the new session, and traffic flows both ways again.
    // The receiver is SQLite-backed (the production adapter and its dhr index).
    #[tokio::test]
    async fn too_many_skipped_starts_repair_and_session_recovers() {
        use crate::service::RepairPhase;
        use najwa_protocol::message::envelope::envelope_decrypt;
        use najwa_protocol::message::{MessageHeader, MessageType, WireMessage, WirePrefixMeta};
        use najwa_protocol::ratchet::{encrypt::ratchet_encrypt, state::MAX_SKIP};

        let (sender, receiver) = row7_pair().await;
        let to_receiver = |blob: &[u8]| envelope_decrypt(&ESA, &DCA, blob).unwrap();
        let to_sender = |blob: &[u8]| envelope_decrypt(&ESB, &DCB, blob).unwrap();

        // Both directions work: the receiver's ACK gives the sender a receiving chain.
        sender.send_message(1, MessageContent::Text("hello".into())).await.unwrap();
        for (_, blob) in sender.mailbox_client.take_deposited() {
            receiver.process_message(&to_receiver(&blob), None).await.unwrap();
        }
        for (_, blob) in receiver.mailbox_client.take_deposited() {
            sender.process_message(&to_sender(&blob), None).await.unwrap();
        }

        // Desync: the sender's next MAX_SKIP + 1 frames never arrive.
        let mut state = sender.storage.get_ratchet_state(1).await.unwrap().unwrap();
        let meta = WirePrefixMeta { version: 1, message_type: 2, x3dh_header: None };
        for _ in 0..=MAX_SKIP {
            ratchet_encrypt(&mut state, b"lost", b"row7 AD", &meta).unwrap();
        }
        sender.storage.save_ratchet_state(1, &state).await.unwrap();
        sender.send_message(1, MessageContent::Text("after the gap".into())).await.unwrap();

        // The receiver repairs against the sender's prekey bundle (row7_pair keys).
        receiver.mailbox_client.set_prekey_bundle(make_prekey_bundle(
            &Ed25519KeyPair::from_seed(&[172; 32]),
            &X25519KeyPair::from_seed([176; 32]),
            &X25519KeyPair::from_seed([177; 32]),
            [1; 4],
            [2; 4],
        ));
        for (_, blob) in sender.mailbox_client.take_deposited() {
            assert!(receiver.process_message(&to_receiver(&blob), None).await.is_err());
        }
        assert_eq!(
            receiver.get_repair_state(1).map(|s| s.phase),
            Some(RepairPhase::InProgress)
        );
        let repair = receiver.mailbox_client.take_deposited();
        assert!(!repair.is_empty(), "TooManySkipped must send a SessionRepairInit");
        for (_, blob) in &repair {
            let wire = WireMessage::from_bytes(&to_sender(blob)).unwrap();
            assert!(matches!(wire.message_type, MessageType::Initial));
        }

        // The sender accepts the repair over its established session and ACKs it
        // in the new session; that answer ends the receiver's repair window.
        for (_, blob) in repair {
            sender.process_message(&to_sender(&blob), None).await.unwrap();
        }
        for (_, blob) in sender.mailbox_client.take_deposited() {
            receiver.process_message(&to_receiver(&blob), None).await.unwrap();
        }
        assert!(
            receiver.get_repair_state(1).is_none(),
            "a repair answered by the peer must clear the repair state"
        );

        // Traffic flows both ways in the repaired session.
        receiver.send_message(1, MessageContent::Text("r1".into())).await.unwrap();
        let mut got = Vec::new();
        for (_, blob) in receiver.mailbox_client.take_deposited() {
            let raw = to_sender(&blob);
            let MessageHeader::Ratchet(header) = &WireMessage::from_bytes(&raw).unwrap().header;
            // prev_DHs_pub survived the SQLite commits (S06 §3.10).
            assert_ne!(header.epoch_link, [0u8; 32]);
            got.extend(sender.process_message(&raw, None).await.unwrap());
        }
        assert_eq!(bodies(&got), ["r1"]);
        sender.send_message(1, MessageContent::Text("s1".into())).await.unwrap();
        let mut got = Vec::new();
        for (_, blob) in sender.mailbox_client.take_deposited() {
            got.extend(receiver.process_message(&to_receiver(&blob), None).await.unwrap());
        }
        assert_eq!(bodies(&got), ["s1"]);
    }

    // -----------------------------------------------------------------------
    // Row 8 — unified receive path, two-party in-process E2E (no network).
    //
    // Alice drives her REAL send path (X3DH bootstrap from bob's served
    // prekey bundle, envelope-sealed deposits); bob drives his REAL poll loop
    // (fetch → envelope-decrypt → process_message). Covers: Initial session
    // accept, Normal decrypt + dedup + commit, and the row-7 0x11
    // ReadReceipt arm (decrypt + durable ratchet advance, no UI message —
    // §8.1 coverage rule).
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn unified_receive_path_initial_normal_and_receipt() {
        use crate::storage::CoreStorage;
        use najwa_protocol::message::ack::{to_padded_plaintext, ReadReceiptContent};
        use najwa_protocol::message::types::{MessageType, WIRE_VERSION};

        let bob_ik = Ed25519KeyPair::from_seed(&BOB_IK_SEED);
        let alice_ik = Ed25519KeyPair::from_seed(&ALICE_IK_SEED);

        // Pairwise pseudonyms (row-5-verified derivation). Bob's pub is
        // bytewise lower → bob is the initiator.
        let (bob_pseudo, alice_pseudo) = {
            let (first, second) =
                najwa_protocol::pseudonym::derive_pairwise_pseudonyms(&bob_ik, alice_ik.public())
                    .unwrap();
            (first.as_bytes().to_vec(), second.as_bytes().to_vec())
        };

        let bob_mailbox_cfg = MailboxConfig {
            onion_address: MAILBOX_ONION_E2E.to_string(),
            fetch_capability: [0x11; 32],
            deposit_capability: [0x22; 32],
            envelope_secret: [0x33; 32],
            cover_deposit_capability: None,
            cover_fetch_capability: None,
            cover_envelope_secret: None,
        };

        // ---- Bob: storage preloaded with SPK/OPK seeds + contact + mailbox ----
        let bob_storage = MockStorage::new();
        bob_storage
            .spk_keys
            .lock()
            .unwrap()
            .insert(SPK_ID_E2E.to_be_bytes(), SPK_SEED_E2E.to_vec());
        bob_storage
            .opk_keys
            .lock()
            .unwrap()
            .insert(OPK_ID_E2E.to_be_bytes(), OPK_SEED_E2E.to_vec());
        bob_storage.add_mailbox(bob_mailbox_cfg.clone());
        bob_storage.add_contact(Contact {
            id: 1,
            their_pseudonym: alice_pseudo.clone().try_into().unwrap(),
            our_pseudonym: bob_pseudo.clone().try_into().unwrap(),
            their_ik_pub: alice_ik.public().to_bytes(),
            display_name: Some("Alice".into()),
            blocked: false,
            verified: true,
            avatar_hash: None,
            created_at: Some(1),
            last_message_at: None,
        });
        // The (deposit_cap, envelope_secret) pair alice seals with — bob's
        // envelope lookup must find it (S07 §3.2).
        bob_storage.add_capability(ContactCapability {
            contact_id: 1,
            mailbox_id: 1,
            mailbox_onion: MAILBOX_ONION_E2E.to_string(),
            mailbox_fetch_cap: [0x11; 32],
            mailbox_deposit_cap: [0x44; 32],
            their_deposit_capability: Some([0x44; 32]),
            their_envelope_secret: Some([0x55; 32]),
        });

        let bob_mailbox = MockMailbox::new();
        let bob_mailbox_handle = bob_mailbox.clone();
        let bob_storage_handle = bob_storage.clone();
        let bob = MessagingService::new(
            Ed25519KeyPair::from_seed(&BOB_IK_SEED),
            bob_storage,
            bob_mailbox,
        );

        // ---- Alice: her mock serves bob's prekey bundle ----
        let alice_storage = MockStorage::new();
        let alice_mailbox = MockMailbox::new();
        alice_mailbox.set_prekey_bundle(bob_bundle_for_e2e(&bob_ik));
        let alice_mailbox_handle = alice_mailbox.clone();
        alice_storage.add_contact(Contact {
            id: 1,
            their_pseudonym: bob_pseudo.clone().try_into().unwrap(),
            our_pseudonym: alice_pseudo.clone().try_into().unwrap(),
            their_ik_pub: bob_ik.public().to_bytes(),
            display_name: Some("Bob".into()),
            blocked: false,
            verified: true,
            avatar_hash: None,
            created_at: Some(1),
            last_message_at: None,
        });
        alice_storage.add_capability(ContactCapability {
            contact_id: 1,
            mailbox_id: 1,
            mailbox_onion: MAILBOX_ONION_E2E.to_string(),
            mailbox_fetch_cap: [0x11; 32],
            mailbox_deposit_cap: [0x22; 32],
            their_deposit_capability: Some([0x44; 32]),
            their_envelope_secret: Some([0x55; 32]),
        });
        let alice_storage_handle = alice_storage.clone();
        let alice = MessagingService::new(
            Ed25519KeyPair::from_seed(&ALICE_IK_SEED),
            alice_storage,
            alice_mailbox,
        );

        // ---- Message 1: the Initial, through alice's REAL send path ----
        alice
            .send_message(1, MessageContent::Text("establish".into()))
            .await
            .expect("initial send");
        let initial_blob = {
            let d = alice_mailbox_handle.deposited.lock().unwrap();
            assert_eq!(d.len(), 1, "initial deposited");
            d[0].1.clone()
        };

        // ---- Bob accepts the Initial through his REAL poll loop ----
        bob_mailbox_handle.set_fetched(vec![MailboxMessage {
            id: "m1".into(),
            blob: initial_blob.clone(),
            deposited_at: 0,
            size: 0,
            cap_hint: None,
        }]);
        // Probe: surface the raw processing error (the poll loop swallows
        // per-message failures with only a warn!).
        // The deposit is envelope-sealed (S07 §3.2) — decrypt as the poll does.
        let inner = najwa_protocol::message::envelope::envelope_decrypt(
            &[0x55; 32],
            &[0x44; 32],
            &initial_blob,
        )
        .unwrap_or_else(|e| panic!("envelope decrypt failed: {e:?}"));
        if let Err(e) = bob.process_message(&inner, None).await {
            panic!("initial processing failed: {e:?}");
        }
        let received = bob.poll_messages().await.unwrap();
        assert!(
            CoreStorage::get_ratchet_state(&bob_storage_handle, 1)
                .await
                .unwrap()
                .is_some(),
            "initial establishes the session"
        );
        let _ = received; // the Initial's content may or may not surface; the session is the contract here

        // ---- Message 2: Normal over the established session ----
        alice
            .send_message(1, MessageContent::Text("hello bob".into()))
            .await
            .expect("normal send");
        bob_mailbox_handle.set_fetched(vec![MailboxMessage {
            id: "m2".into(),
            blob: alice_mailbox_handle.last_deposit(),
            deposited_at: 0,
            size: 0,
            cap_hint: None,
        }]);
        // Probe the Normal message directly: envelope-decrypt (as the poll
        // does) then process. The earlier probe consumed this deposit once
        // already — logical dedup would absorb a re-send, so probe the SAME
        // decrypted inner bytes freshly taken from the deposit.
        let normal_inner = najwa_protocol::message::envelope::envelope_decrypt(
            &[0x55; 32],
            &[0x44; 32],
            &alice_mailbox_handle.last_deposit(),
        )
        .unwrap_or_else(|e| panic!("normal envelope decrypt failed: {e:?}"));
        let received2 = bob.process_message(&normal_inner, None).await.unwrap();
        let msg2 = received2.expect("normal message surfaces");
        assert_eq!(msg2.content, b"hello bob");
        assert_eq!(msg2.contact_id, 1);

        // ---- Message 3: D15 DisappearTimer control via alice's REAL send path
        // (row 10, S12 §2.2). Timer changes ride the same ratchet as a Normal
        // message (Raw content delegation); bob's receive arm merges
        // last-writer-wins on `set_at` (D15 body: timer_secs(4 BE) ||
        // set_at(8 BE)).
        alice
            .send_message(
                1,
                MessageContent::Raw {
                    content_type: 0x20, // ContentType::Control
                    bytes: najwa_protocol::message::control::ControlMessage::DisappearTimer {
                        duration_secs: 3600,
                        set_at: 1_700_000_000,
                    }
                    .to_bytes(),
                    reply_to: None,
                },
            )
            .await
            .expect("timer control send");
        // Surface the raw processing error (the poll loop acks + swallows
        // per-message failures with only a warn!).
        let timer_inner = najwa_protocol::message::envelope::envelope_decrypt(
            &[0x55; 32],
            &[0x44; 32],
            &alice_mailbox_handle.last_deposit(),
        )
        .unwrap_or_else(|e| panic!("timer envelope decrypt failed: {e:?}"));
        let timer_result = bob.process_message(&timer_inner, None).await;
        if let Err(e) = &timer_result {
            panic!("timer control processing failed: {e:?}");
        }
        let received = bob.poll_messages().await.unwrap();
        assert_eq!(
            received.len(),
            0,
            "S12 §2.3: timer controls surface no UI message"
        );
        let stored = CoreStorage::get_conversation_timer_setting(&bob_storage_handle, 1)
            .await
            .unwrap()
            .expect("timer setting stored at merge");
        assert_eq!(stored.0, Some(3600), "timer_secs merged");
        assert_eq!(stored.1, 1_700_000_000, "set_at merged (D15 LWW)");

        // ---- Message 4: a 0x11 ReadReceipt (row-8 ack semantics) ----
        // Built from alice's CURRENT stored state (ns=3 after the timer send)
        // so it consumes the next chain position in lockstep with bob.
        let session_ad = CoreStorage::get_session_ad(&alice_storage_handle, 1)
            .await
            .unwrap()
            .expect("session AD stored at bootstrap");
        let before_state = CoreStorage::get_ratchet_state(&bob_storage_handle, 1)
            .await
            .unwrap()
            .unwrap();
        let (nr_before, nr_before_ns, nr_before_ckr) =
            (before_state.nr, before_state.ns, before_state.ckr.is_some());
        let alice_state = CoreStorage::get_ratchet_state(&alice_storage_handle, 1)
            .await
            .unwrap()
            .expect("alice session");
        let mut alice_state = najwa_protocol::ratchet::prelude::deserialize_state(
            &najwa_protocol::ratchet::prelude::serialize_state(&alice_state).unwrap(),
        )
        .unwrap();
        let receipt = ReadReceiptContent {
            msg_id: [0x11; 16],
            timestamp: 1_777_777_777,
        };
        let plaintext = to_padded_plaintext(&receipt.to_bytes(), 96).unwrap();
        let meta = najwa_protocol::message::WirePrefixMeta {
            version: WIRE_VERSION,
            message_type: MessageType::ReadReceipt.as_byte(),
            x3dh_header: None,
        };
        let (header, ct) = najwa_protocol::ratchet::prelude::ratchet_encrypt(
            &mut alice_state,
            &plaintext,
            &session_ad,
            &meta,
        )
        .unwrap();
        let wire = najwa_protocol::message::types::WireMessage {
            version: WIRE_VERSION,
            message_type: MessageType::ReadReceipt,
            header: najwa_protocol::message::types::MessageHeader::Ratchet(header),
            x3dh_header: None,
            encrypted_payload: ct,
        }
        .to_bytes();

        // Direct probe: surface any receipt-processing error (the poll acks +
        // swallows per-message failures).
        let receipt_inner = najwa_protocol::message::envelope::envelope_decrypt(
            &[0x55; 32],
            &[0x44; 32],
            &najwa_protocol::message::envelope::envelope_encrypt(&[0x55; 32], &[0x44; 32], &wire)
                .unwrap(),
        )
        .unwrap();
        let receipt_result = bob.process_message(&receipt_inner, None).await;
        match &receipt_result {
            Err(e) => panic!("receipt processing failed: {e:?}"),
            Ok(Some(m)) => panic!(
                "receipt surfaced as UI message: type={} content={:?}",
                m.content_type, m.content
            ),
            Ok(None) => {}
        }
        let received = bob.poll_messages().await.unwrap();
        assert!(received.is_empty(), "§8.1: receipts surface no UI message");

        // §8.1 coverage rule: the receiving chain (nr) durably advances on the
        // receipt; the sending chain (ns) and chain keys are untouched.
        let after_state = CoreStorage::get_ratchet_state(&bob_storage_handle, 1)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            nr_before + 1,
            after_state.nr,
            "receiving chain advances by exactly one"
        );
        assert_eq!(nr_before_ns, after_state.ns, "sending chain unchanged");
        assert_eq!(
            nr_before_ckr,
            after_state.ckr.is_some(),
            "receiving chain key still present"
        );
    }

    mod row9_cover_tests {
        include!("row9_cover_tests.rs");
    }
}
