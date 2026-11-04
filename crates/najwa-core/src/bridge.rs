//! Bridge between `najwa-storage::SqliteStorage` and `najwa-core::CoreStorage` (S08 §3).
//!
//! Converts between storage-layer types and protocol-layer types,
//! enabling `MessagingService` to operate on a real SQLCipher database.

use async_trait::async_trait;
use najwa_crypto::keys::x25519::{X25519KeyPair, X25519Public};
use najwa_protocol::mailbox::types::MailboxConfig;
use najwa_protocol::ratchet::state::RatchetState as ProtocolRatchetState;
use najwa_storage::database::SqliteStorage;
use najwa_storage::types as st;
use serde::{Deserialize, Serialize};

use crate::storage::{CoreStorage, EphemeralHandshakeCapability};
use crate::types::*;

fn commit_sqlite_outgoing(
    db: &SqliteStorage,
    i: &crate::pipeline::Outgoing<'_>,
    timer: Option<(Option<u32>, u64, [u8; 32])>,
) -> Result<(i64, Option<MessageId>), String> {
    let ratchet = protocol_to_storage_ratchet(i.state);
    let message = i.message.map(core_to_new_message);
    let repair = i.repair.map(|r| st::OutboundRepairRecord {
        contact_id: i.contact_id as i64, dh_pub: r.original_dh_pub,
        message_number: r.original_n, msg_id: r.original_msg_id,
        timestamp: r.original_timestamp, logical_seq: r.original_logical_seq,
        content_type: r.original_content_type, flags: r.original_flags,
        content: r.original_content.clone(), created_at: najwa_crypto::time::now() as i64,
    });
    let skipped = skipped_set_for(i.state);
    let input = najwa_storage::messaging::Outgoing {
        contact_id: i.contact_id as i64, ratchet: &ratchet, skipped: &skipped,
        ad: i.ad, message: message.as_ref(), existing_message_id: i.existing_message_id,
        wire: i.wire, dh_pub: i.dh_pub, n: i.n, requires_ack: i.requires_ack,
        disappearing: i.disappearing, repair: repair.as_ref(), logical_id: i.logical_id,
        acknowledging: i.acknowledging,
    };
    match timer {
        Some(timer) => SqliteStorage::commit_outgoing_timer(db, &input, timer),
        None => SqliteStorage::commit_outgoing(db, &input),
    }.map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// Type conversion helpers
// ---------------------------------------------------------------------------

/// Convert storage Contact → core Contact.
fn storage_to_core_contact(sc: &st::Contact) -> Contact {
    Contact {
        id: sc.id as u64,
        their_pseudonym: sc.pseudonym,
        our_pseudonym: sc.our_pseudonym,
        their_ik_pub: sc.their_ik_pub,
        display_name: sc.display_name.clone(),
        blocked: sc.blocked,
        verified: sc.verified,
        avatar_hash: sc.avatar_hash.clone(),
        created_at: Some(sc.created_at),
        last_message_at: sc.last_message_at,
    }
}

/// Convert core Contact → storage Contact (for updates).
fn core_to_storage_contact(cc: &Contact) -> st::Contact {
    st::Contact {
        id: cc.id as i64,
        pseudonym: cc.their_pseudonym,
        their_ik_pub: cc.their_ik_pub,
        // Single-device: device_pub == ik_pub (S03 §5.2). The core Contact has
        // no per-device rows.
        their_device_pub: cc.their_ik_pub,
        our_pseudonym: cc.our_pseudonym,
        display_name: cc.display_name.clone(),
        blocked: cc.blocked,
        verified: cc.verified,
        avatar_hash: cc.avatar_hash.clone(),
        created_at: cc.created_at.unwrap_or(0),
        last_message_at: cc.last_message_at,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredContactTarget {
    onion: String,
    deposit_cap_hex: String,
    envelope_secret_hex: String,
    #[serde(default)]
    mailbox_entry: Vec<u8>,
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;

    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn hex_decode_32(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let pair = std::str::from_utf8(chunk).ok()?;
        out[i] = u8::from_str_radix(pair, 16).ok()?;
    }
    Some(out)
}

fn target_from_entry(
    entry: &najwa_protocol::contact::mailbox_key::MailboxEntry,
) -> StoredContactTarget {
    StoredContactTarget {
        onion: String::from_utf8_lossy(&entry.onion_address)
            .trim_end_matches('\0')
            .to_string(),
        deposit_cap_hex: hex_encode(&entry.deposit_capability),
        envelope_secret_hex: hex_encode(&entry.envelope_secret),
        mailbox_entry: entry.to_bytes().to_vec(),
    }
}

pub(crate) fn mailbox_update_effect(
    cid: ContactId,
    entries: &[najwa_protocol::contact::mailbox_key::MailboxEntry],
) -> crate::error::Result<najwa_storage::messaging::ReceiveEffect> {
    let targets: Vec<StoredContactTarget> = entries.iter().map(target_from_entry).collect();
    let mut settings = vec![(
        format!("contact_targets:{cid}"),
        serde_json::to_vec(&targets)
            .map_err(|e| crate::error::MessagingError::SerializationError(e.to_string()))?,
    )];
    if let Some(first) = targets.first() {
        settings.push((
            format!("contact_target:{cid}"),
            serde_json::to_vec(first)
                .map_err(|e| crate::error::MessagingError::SerializationError(e.to_string()))?,
        ));
    }
    Ok(najwa_storage::messaging::ReceiveEffect::Settings(settings))
}

/// Load the persisted skipped message keys for a contact into a freshly-loaded
/// protocol `RatchetState`.
///
/// `RatchetState.skipped` is `#[serde(skip)]`, so it is NOT carried in the
/// ratchet-session blob; the keys live in the separate `skipped_keys` table
/// (S03 §5.5). Without this, out-of-order delivery would break across the
/// load/save cycle every receive performs: a key skipped for a later message
/// would be dropped when the state is reloaded, so the earlier message could
/// never be recovered (S06 §3.10).
fn load_skipped_into(
    storage: &SqliteStorage,
    contact_id: i64,
    proto: &mut ProtocolRatchetState,
) -> Result<(), String> {
    use najwa_protocol::ratchet::state::SkippedKey as ProtoSkipped;
    let rows = SqliteStorage::load_skipped_keys(storage, contact_id).map_err(|e| e.to_string())?;
    for sk in rows {
        proto.skipped.insert(
            (sk.dh_pub, sk.message_number),
            ProtoSkipped {
                message_key: sk.message_key,
                created_at: sk.created_at as u64,
            },
        );
    }
    Ok(())
}

/// Persist a protocol `RatchetState`'s in-memory skipped keys to the
/// `skipped_keys` table, mirroring the current set: keys consumed during this
/// receive (present in the table but no longer in the state) are deleted, and
/// newly-skipped keys are upserted. Bounded by `MAX_SKIP` per chain. For the
/// common in-order case `state.skipped` is empty, so this is a near no-op.
fn persist_skipped(
    storage: &SqliteStorage,
    contact_id: i64,
    proto: &ProtocolRatchetState,
) -> Result<(), String> {
    use najwa_protocol::ratchet::state::SKIP_KEY_EXPIRY_SECS;
    let existing =
        SqliteStorage::load_skipped_keys(storage, contact_id).map_err(|e| e.to_string())?;
    let in_state: std::collections::HashSet<([u8; 32], u32)> =
        proto.skipped.keys().copied().collect();
    // Delete keys that were consumed (present in the table, gone from the state).
    for sk in &existing {
        if !in_state.contains(&(sk.dh_pub, sk.message_number)) {
            SqliteStorage::delete_skipped_key(storage, contact_id, &sk.dh_pub, sk.message_number)
                .map_err(|e| e.to_string())?;
        }
    }
    // Upsert the current set (new keys added; unchanged keys are a no-op replace).
    for ((dh_pub, msg_num), v) in &proto.skipped {
        let row = st::SkippedKey {
            dh_pub: *dh_pub,
            message_number: *msg_num,
            message_key: v.message_key,
            created_at: v.created_at as i64,
            expires_at: v.created_at.saturating_add(SKIP_KEY_EXPIRY_SECS) as i64,
        };
        SqliteStorage::save_skipped_key(storage, contact_id, &row).map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Convert a core `Message` → storage `NewMessage` with received-message
/// defaults. Shared by `save_message` and the atomic `commit_received`.
pub(crate) fn core_to_new_message(msg: &Message) -> st::NewMessage {
    st::NewMessage {
        contact_id: msg.contact_id as i64,
        msg_id: msg.msg_id,
        direction: match msg.direction {
            Direction::Sent => st::MessageDirection::Sent,
            Direction::Received => st::MessageDirection::Received,
        },
        content_type: match msg.content_type {
            0x02 => st::ContentType::TextReply,
            0x03 => st::ContentType::Binary,
            0x04 => st::ContentType::ReciprocalHandshake,
            0x10 => st::ContentType::FileMetadata,
            0x11 => st::ContentType::FileChunk,
            0x20 => st::ContentType::Control,
            _ => st::ContentType::Text,
        },
        flags: msg.flags as i32,
        content: msg.content.clone(),
        file_path: None,
        timestamp: msg.timestamp as i64,
        received_at: if matches!(msg.direction, Direction::Received) {
            Some(najwa_crypto::time::now() as i64)
        } else {
            None
        },
        status: match msg.status {
            MessageStatus::Pending => st::MessageStatus::Pending,
            MessageStatus::Sent => st::MessageStatus::Sent,
            MessageStatus::Delivered => st::MessageStatus::Delivered,
            MessageStatus::Read => st::MessageStatus::Read,
            MessageStatus::Failed => st::MessageStatus::Failed,
        },
        reply_to_msg_id: (msg.content_type == 0x02)
            .then(|| {
                najwa_protocol::message::TextReplyContent::from_bytes(&msg.content)
                    .ok()
                    .map(|r| r.reply_to_msg_id.to_vec())
            })
            .flatten(),
        disappear_timer: None,
        encrypted_blob: None,
        group_id: None,
        sender_display_name: None,
        origin_timestamp_ms: None,
        retry_wire_blob: None,
    }
}

/// Build the storage skipped-key set from a protocol ratchet state's in-memory
/// skipped map, for the atomic `commit_received` (mirrors `persist_skipped`).
fn skipped_set_for(proto: &ProtocolRatchetState) -> Vec<st::SkippedKey> {
    use najwa_protocol::ratchet::state::SKIP_KEY_EXPIRY_SECS;
    proto
        .skipped
        .iter()
        .map(|((dh_pub, msg_num), v)| st::SkippedKey {
            dh_pub: *dh_pub,
            message_number: *msg_num,
            message_key: v.message_key,
            created_at: v.created_at as i64,
            expires_at: v.created_at.saturating_add(SKIP_KEY_EXPIRY_SECS) as i64,
        })
        .collect()
}

/// Convert storage RatchetState (blobs) → protocol RatchetState (typed keys).
///
/// Returns `Err` if the key material blobs have invalid lengths.
fn storage_to_protocol_ratchet(sr: &st::RatchetState) -> Result<ProtocolRatchetState, String> {
    // Build DH key pair from private key bytes
    let dhs_private = sr.dhs_private.as_ref().ok_or("missing dhs_private")?;
    if dhs_private.len() != 32 {
        return Err("dhs_private not 32 bytes".into());
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(dhs_private);
    let dhs = X25519KeyPair::from_seed(seed);

    // Their DH public key
    let dhr = match &sr.dhr {
        Some(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(bytes);
            Some(X25519Public::from_bytes(arr))
        }
        _ => None,
    };

    // Root key
    let mut rk = [0u8; 32];
    if let Some(bytes) = &sr.rk {
        if bytes.len() == 32 {
            rk.copy_from_slice(bytes);
        } else {
            return Err("rk not 32 bytes".into());
        }
    } else {
        return Err("missing rk".into());
    }

    // Chain keys
    let cks = sr.cks.as_ref().and_then(|b| {
        if b.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(b);
            Some(arr)
        } else {
            None
        }
    });

    let ckr = sr.ckr.as_ref().and_then(|b| {
        if b.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(b);
            Some(arr)
        } else {
            None
        }
    });

    Ok(ProtocolRatchetState {
        dhs,
        dhr,
        rk,
        cks,
        ckr,
        ns: sr.ns,
        nr: sr.nr,
        pn: sr.pn,
        // S06 §3.10: restored so `epoch_link` survives a reload. A pre-column
        // row reads `None` and sends zeros until its next DH step.
        prev_dhs_pub: sr.prev_dhs_pub.as_deref().and_then(|b| b.try_into().ok()),
        skipped: Default::default(),
    })
}

/// Convert protocol RatchetState (typed keys) → storage RatchetState (blobs).
fn protocol_to_storage_ratchet(pr: &ProtocolRatchetState) -> st::RatchetState {
    let now = najwa_crypto::time::now() as i64;
    st::RatchetState {
        dhs_private: Some(pr.dhs.private().to_bytes().to_vec()),
        dhs_public: Some(pr.dhs.public().to_bytes().to_vec()),
        dhr: pr.dhr.as_ref().map(|k| k.to_bytes().to_vec()),
        rk: Some(pr.rk.to_vec()),
        cks: pr.cks.map(|k| k.to_vec()),
        ckr: pr.ckr.map(|k| k.to_vec()),
        ns: pr.ns,
        nr: pr.nr,
        pn: pr.pn,
        prev_dhs_pub: pr.prev_dhs_pub.map(|k| k.to_vec()),
        established_at: now,
        last_activity: now,
    }
}

/// Convert storage Message → core Message.
pub(crate) fn storage_to_core_message(sm: &st::Message) -> Message {
    Message {
        id: sm.id,
        contact_id: sm.contact_id as u64,
        msg_id: sm.msg_id,
        direction: match sm.direction {
            st::MessageDirection::Sent => Direction::Sent,
            st::MessageDirection::Received => Direction::Received,
        },
        content_type: match sm.content_type {
            st::ContentType::Text => 0x01,
            st::ContentType::TextReply => 0x02,
            st::ContentType::ReciprocalHandshake => 0x04,
            st::ContentType::FileMetadata => 0x10,
            st::ContentType::FileChunk => 0x11,
            st::ContentType::Control | st::ContentType::System => 0x20,
            _ => 0x03,
        },
        flags: sm.flags as u8,
        content: sm.content.clone(),
        timestamp: sm.timestamp as u64,
        status: match sm.status {
            st::MessageStatus::Pending => MessageStatus::Pending,
            st::MessageStatus::Sent => MessageStatus::Sent,
            st::MessageStatus::Delivered => MessageStatus::Delivered,
            st::MessageStatus::Read => MessageStatus::Read,
            st::MessageStatus::Failed => MessageStatus::Failed,
            st::MessageStatus::PermanentlyFailed => MessageStatus::Failed,
        },
        ratchet_index: None,
    }
}

/// Convert storage ContactMailboxCap + Mailbox → core ContactCapability.
///
/// Per-contact fetch/deposit capabilities (S05 §8, HIGH-09) take precedence
/// over mailbox-level capabilities when present, enabling per-contact isolation.
fn storage_to_core_capability(
    cap: &st::ContactMailboxCap,
    mailbox: &st::Mailbox,
) -> ContactCapability {
    // Prefer per-contact fetch cap; fall back to mailbox-level fetch cap
    let mut fetch_cap = [0u8; 32];
    if let Some(ref fc) = cap.fetch_capability {
        if fc.len() == 32 {
            fetch_cap.copy_from_slice(fc);
        }
    } else if mailbox.fetch_capability.len() == 32 {
        fetch_cap.copy_from_slice(&mailbox.fetch_capability);
    }

    // Prefer per-contact deposit cap; fall back to mailbox-level deposit cap
    let mut deposit_cap = [0u8; 32];
    if cap.deposit_capability.len() == 32 && cap.deposit_capability != vec![0u8; 32] {
        deposit_cap.copy_from_slice(&cap.deposit_capability);
    } else if mailbox.deposit_capability.len() == 32 {
        deposit_cap.copy_from_slice(&mailbox.deposit_capability);
    }

    let to_arr32 = |b: &Vec<u8>| -> Option<[u8; 32]> {
        if b.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(b);
            Some(arr)
        } else {
            None
        }
    };
    let their_dep = cap.their_deposit_capability.as_ref().and_then(&to_arr32);
    let their_secret = cap.their_envelope_secret.as_ref().and_then(&to_arr32);

    ContactCapability {
        contact_id: cap.contact_id as u64,
        mailbox_id: cap.mailbox_id,
        mailbox_onion: mailbox.onion_address.clone(),
        mailbox_fetch_cap: fetch_cap,
        mailbox_deposit_cap: deposit_cap,
        their_deposit_capability: their_dep,
        their_envelope_secret: their_secret,
    }
}

/// Every real receive queue of every enabled mailbox (S08 §6.1): the mailbox's
/// own queue, registered per-contact queues and active invitation queues.
/// Synchronous so the native lock path can snapshot fetch capabilities.
pub fn receive_queues(
    db: &SqliteStorage,
) -> std::result::Result<Vec<(MailboxId, MailboxConfig)>, String> {
    let mailboxes = SqliteStorage::list_mailboxes(db).map_err(|e| e.to_string())?;
    let mut receive_queues = Vec::new();
    for mailbox in mailboxes.iter().filter(|mailbox| mailbox.enabled) {
        receive_queues.push((mailbox.id, storage_to_mailbox_config(mailbox)));
        let caps = SqliteStorage::get_capabilities_for_mailbox(db, mailbox.id)
            .map_err(|e| e.to_string())?;
        receive_queues.extend(caps.iter().filter_map(|cap| {
            registered_contact_cap_to_mailbox_config(cap, mailbox).map(|config| (mailbox.id, config))
        }));
        let ephemeral = SqliteStorage::get_active_ephemeral_handshake_caps_for_mailbox(
            db,
            mailbox.id,
            najwa_crypto::time::now() as i64,
        )
        .map_err(|e| e.to_string())?;
        receive_queues.extend(ephemeral.iter().filter_map(|cap| {
            ephemeral_cap_to_mailbox_config(cap, mailbox).map(|config| (mailbox.id, config))
        }));
    }
    Ok(receive_queues)
}

/// Convert storage Mailbox → protocol MailboxConfig.
fn storage_to_mailbox_config(mb: &st::Mailbox) -> MailboxConfig {
    let mut fetch_cap = [0u8; 32];
    if mb.fetch_capability.len() == 32 {
        fetch_cap.copy_from_slice(&mb.fetch_capability);
    }
    let mut deposit_cap = [0u8; 32];
    if mb.deposit_capability.len() == 32 {
        deposit_cap.copy_from_slice(&mb.deposit_capability);
    }
    // Option<Vec<u8>> → Option<[u8; 32]> (None on wrong length).
    fn opt32(b: &Option<Vec<u8>>) -> Option<[u8; 32]> {
        b.as_ref().and_then(|v| v.as_slice().try_into().ok())
    }

    let mut envelope_secret = [0u8; 32];
    if mb.envelope_secret.len() == 32 {
        envelope_secret.copy_from_slice(&mb.envelope_secret);
    }

    MailboxConfig {
        onion_address: mb.onion_address.clone(),
        fetch_capability: fetch_cap,
        deposit_capability: deposit_cap,
        envelope_secret,
        cover_deposit_capability: opt32(&mb.cover_deposit_capability),
        cover_fetch_capability: opt32(&mb.cover_fetch_capability),
        cover_envelope_secret: opt32(&mb.cover_envelope_secret),
    }
}

fn registered_contact_cap_to_mailbox_config(
    cap: &st::ContactMailboxCap,
    mailbox: &st::Mailbox,
) -> Option<MailboxConfig> {
    #[allow(clippy::question_mark)] // mixed None-reasons: early-None + fallible conversions
    if cap.registered_at.is_none() {
        return None;
    }
    let fetch_capability: [u8; 32] = cap.fetch_capability.as_deref()?.try_into().ok()?;
    let deposit_capability: [u8; 32] = cap.deposit_capability.as_slice().try_into().ok()?;
    let envelope_secret: [u8; 32] = cap.envelope_secret.as_deref()?.try_into().ok()?;
    Some(MailboxConfig {
        onion_address: mailbox.onion_address.clone(),
        fetch_capability,
        deposit_capability,
        envelope_secret,
        // Per-contact queues are real-message routes, never cover routes.
        cover_deposit_capability: None,
        cover_fetch_capability: None,
        cover_envelope_secret: None,
    })
}

fn ephemeral_cap_to_mailbox_config(
    cap: &st::EphemeralHandshakeCap,
    mailbox: &st::Mailbox,
) -> Option<MailboxConfig> {
    // `get_active_ephemeral_handshake_caps_for_mailbox` already applies the
    // registered_at/expiry/deactivated gates. Length checks remain fail-closed.
    let fetch_capability: [u8; 32] = cap.fetch_capability.as_slice().try_into().ok()?;
    let deposit_capability: [u8; 32] = cap.deposit_capability.as_slice().try_into().ok()?;
    let envelope_secret: [u8; 32] = cap.envelope_secret.as_slice().try_into().ok()?;
    Some(MailboxConfig {
        onion_address: mailbox.onion_address.clone(),
        fetch_capability,
        deposit_capability,
        envelope_secret,
        cover_deposit_capability: None,
        cover_fetch_capability: None,
        cover_envelope_secret: None,
    })
}

/// Convert storage Mailbox → core MailboxHealth.
fn storage_to_mailbox_health(mb: &st::Mailbox) -> MailboxHealth {
    MailboxHealth {
        mailbox_id: mb.id,
        onion_address: mb.onion_address.clone(),
        consecutive_failures: mb.failure_count as u32,
        total_successes: 0,
        total_failures: mb.failure_count as u64,
        last_success: mb.last_success.map(|t| t as u64),
        last_failure: mb.last_failure.map(|t| t as u64),
        enabled: mb.enabled,
    }
}

// ---------------------------------------------------------------------------
// CoreStorage implementation for SqliteStorage
// ---------------------------------------------------------------------------

#[async_trait]
impl CoreStorage for SqliteStorage {
    fn prekey_database(&self) -> Option<&SqliteStorage> { Some(self) }
    async fn commit_incoming(
        &self,
        i: &crate::pipeline::Incoming<'_>,
    ) -> Result<Option<MessageId>, String> {
        let ratchet = protocol_to_storage_ratchet(i.state);
        let message = i.message.map(core_to_new_message);
        SqliteStorage::commit_incoming(
            self,
            &najwa_storage::messaging::Incoming {
                contact_id: i.contact_id as i64,
                ratchet: &ratchet,
                skipped: &skipped_set_for(i.state),
                ad: i.ad,
                opk_id: i.opk_id,
                ephemeral_cap_id: i.ephemeral_cap_id,
                message: message.as_ref(),
                transport_id: i.transport_id,
                logical_id: i.logical_id,
                disappearing: i.disappearing,
                header_id: i.header_id,
                frame: i.frame,
                effects: i.effects,
            },
        )
        .map_err(|e| e.to_string())
    }
    async fn commit_outgoing(
        &self,
        i: &crate::pipeline::Outgoing<'_>,
    ) -> Result<(i64, Option<MessageId>), String> {
        commit_sqlite_outgoing(self, i, None)
    }
    async fn commit_outgoing_timer(
        &self,
        i: &crate::pipeline::Outgoing<'_>,
        timer: (Option<u32>, u64, [u8; 32]),
    ) -> Result<(i64, Option<MessageId>), String> {
        commit_sqlite_outgoing(self, i, Some(timer))
    }
    async fn pending_read_receipts(&self) -> Result<Vec<najwa_storage::read_receipts::ReadReceiptIntent>, String> {
        SqliteStorage::pending_read_receipts(self).map_err(|e| e.to_string())
    }
    async fn commit_read_receipt(
        &self, i: &crate::pipeline::Outgoing<'_>, msg_id: [u8; 16],
    ) -> Result<(i64, Option<MessageId>), String> {
        let ratchet = protocol_to_storage_ratchet(i.state);
        let skipped = skipped_set_for(i.state);
        SqliteStorage::commit_read_receipt(self, &najwa_storage::messaging::Outgoing {
            contact_id: i.contact_id as i64, ratchet: &ratchet, skipped: &skipped,
            ad: i.ad, message: None, existing_message_id: None,
            wire: i.wire, dh_pub: i.dh_pub, n: i.n, requires_ack: false,
            disappearing: None, repair: None, logical_id: None, acknowledging: &[],
        }, msg_id).map_err(|e| e.to_string())
    }
    async fn timer_change_pending(&self, cid: ContactId) -> Result<bool, String> {
        SqliteStorage::timer_change_pending(self, cid as i64).map_err(|e| e.to_string())
    }
    async fn outgoing_frames(
        &self,
    ) -> Result<Vec<najwa_storage::messaging::OutgoingFrame>, String> {
        SqliteStorage::outgoing_frames(self).map_err(|e| e.to_string())
    }
    async fn outgoing_frame_live(&self, id: i64) -> Result<bool, String> {
        SqliteStorage::outgoing_frame_live(self, id).map_err(|e| e.to_string())
    }
    async fn outgoing_file_session(&self, id: i64) -> Result<Option<[u8; 16]>, String> {
        SqliteStorage::outgoing_file_session(self, id).map_err(|e| e.to_string())
    }
    async fn outgoing_frame_ids(&self)->Result<Vec<i64>,String> {
        SqliteStorage::outgoing_frame_ids(self).map_err(|e|e.to_string())
    }
    async fn outgoing_frame(&self,id:i64)->Result<Option<najwa_storage::messaging::OutgoingFrame>,String> {
        SqliteStorage::outgoing_frame_page(self,Some(id),1).map(|mut v|v.pop()).map_err(|e|e.to_string())
    }
    async fn outgoing_frame_batch(&self)->Result<Vec<najwa_storage::messaging::OutgoingFrame>,String> {
        SqliteStorage::outgoing_frame_page(self,None,64).map_err(|e|e.to_string())
    }
    async fn finish_outgoing(&self, id: i64, success: bool, next: u64) -> Result<(), String> {
        SqliteStorage::finish_outgoing(self, id, success, next).map_err(|e| e.to_string())
    }
    async fn received_frame(
        &self,
        id: &[u8; 16],
    ) -> Result<Option<najwa_storage::messaging::ReceivedFrame>, String> {
        SqliteStorage::received_frame(self, id).map_err(|e| e.to_string())
    }
    async fn repeat_ack(&self, id: &[u8; 16]) -> Result<(), String> {
        SqliteStorage::repeat_ack(self, id).map_err(|e| e.to_string())
    }
    async fn pending_ack_contacts(&self) -> Result<Vec<ContactId>, String> {
        SqliteStorage::pending_ack_contacts(self)
            .map(|v| v.into_iter().map(|c| c as u64).collect())
            .map_err(|e| e.to_string())
    }
    fn durable_ack_intents(&self) -> bool { true }
    async fn pending_ack_ranges(
        &self,
        cid: ContactId,
    ) -> Result<Vec<najwa_storage::messaging::ChainRange>, String> {
        SqliteStorage::pending_ack_ranges(self, cid as i64).map_err(|e| e.to_string())
    }
    async fn inbound_work(&self) -> Result<Vec<najwa_storage::messaging::InboundWork>, String> {
        SqliteStorage::inbound_work(self).map_err(|e| e.to_string())
    }
    async fn advance_inbound_work(&self, id: i64, cursor: Option<i64>) -> Result<(), String> {
        SqliteStorage::advance_inbound_work(self, id, cursor).map_err(|e| e.to_string())
    }
    async fn outbound_history(
        &self,
        cid: ContactId,
        anchor: Option<[u8; 16]>,
        from: u64,
        to: u64,
        cursor: i64,
    ) -> Result<Vec<najwa_storage::messaging::HistoryMessage>, String> {
        SqliteStorage::outbound_history(self, cid as i64, anchor, from, to, cursor)
            .map_err(|e| e.to_string())
    }
    async fn outgoing_file_part(
        &self,
        cid: ContactId,
        session: &[u8; 16],
        index: u32,
    ) -> Result<Option<najwa_storage::messaging::HistoryMessage>, String> {
        SqliteStorage::outgoing_file_part(self, cid as i64, session, index).map_err(|e| e.to_string())
    }
    async fn file_nacks_due(
        &self,
        now: u64,
        interval: u64,
        max_attempts: u32,
    ) -> Result<Vec<najwa_storage::transfers::FileNackDue>, String> {
        SqliteStorage::file_nacks_due(self, now as i64, interval as i64, max_attempts)
            .map_err(|e| e.to_string())
    }
    async fn record_file_nack(&self, metadata_id: MessageId, attempts: u32, now: u64) -> Result<(), String> {
        SqliteStorage::record_file_nack(self, metadata_id, attempts, now as i64).map_err(|e| e.to_string())
    }
    async fn remote_mailbox_enabled(&self, onion: &str) -> Result<bool, String> {
        SqliteStorage::remote_mailbox_enabled(self, onion).map_err(|e| e.to_string())
    }
    async fn record_remote_mailbox(&self, onion: &str, success: bool) -> Result<(), String> {
        SqliteStorage::record_remote_mailbox(self, onion, success).map_err(|e| e.to_string())
    }

    async fn commit_confirmation(
        &self,
        contact_id: ContactId,
        state: &ProtocolRatchetState,
        header_id: &[u8; 16],
        effect: &DeliveryConfirmation,
    ) -> std::result::Result<(), String> {
        SqliteStorage::commit_received_with_confirmation(
            self,
            contact_id as i64,
            &protocol_to_storage_ratchet(state),
            &skipped_set_for(state),
            None,
            header_id,
            None,
            None,
            Some(effect),
        )
        .map(|_| ())
        .map_err(|e| e.to_string())
    }

    async fn update_remote_mailboxes(
        &self,
        contact_id: ContactId,
        entries: &[najwa_protocol::contact::mailbox_key::MailboxEntry],
    ) -> std::result::Result<(), String> {
        let targets: Vec<StoredContactTarget> = entries.iter().map(target_from_entry).collect();
        self.replace_remote_targets(contact_id as i64, &targets)
            .map_err(|e| e.to_string())
    }
    // -- Contact operations --

    async fn get_contact(&self, id: ContactId) -> std::result::Result<Option<Contact>, String> {
        self.get_contact(id as i64)
            .map(|opt| opt.map(|c| storage_to_core_contact(&c)))
            .map_err(|e| e.to_string())
    }

    async fn get_contact_by_pseudonym(
        &self,
        pseudonym: &[u8; 32],
    ) -> std::result::Result<Option<Contact>, String> {
        SqliteStorage::get_contact_by_pseudonym(self, pseudonym)
            .map(|opt| opt.map(|c| storage_to_core_contact(&c)))
            .map_err(|e| e.to_string())
    }

    async fn list_contacts(&self) -> std::result::Result<Vec<Contact>, String> {
        SqliteStorage::list_contacts(self)
            .map(|v| v.iter().map(storage_to_core_contact).collect())
            .map_err(|e| e.to_string())
    }

    async fn update_contact(&self, contact: &Contact) -> std::result::Result<(), String> {
        let sc = core_to_storage_contact(contact);
        SqliteStorage::update_contact(self, &sc).map_err(|e| e.to_string())
    }

    async fn create_reciprocal_contact(
        &self,
        payload: &najwa_protocol::contact::HandshakePayload,
        our_pseudonym: &[u8; 32],
        their_pseudonym: &[u8; 32],
    ) -> std::result::Result<Contact, String> {
        if SqliteStorage::get_contact_by_ik(self, &payload.ik_pub)
            .map_err(|e| e.to_string())?
            .is_some()
        {
            return Err("contact identity already exists".into());
        }

        // The receive path verifies the original signed payload before deriving
        // this supported-only view. Keep the storage boundary defensive so a
        // future caller cannot persist an unknown capability as a send target.
        let usable_entries: Vec<_> = payload
            .mailbox_entries
            .iter()
            .filter(|entry| {
                entry.capability_type == najwa_protocol::contact::mailbox_key::CAP_TYPE_EPHEMERAL
                    || entry.capability_type
                        == najwa_protocol::contact::mailbox_key::CAP_TYPE_LONG_TERM
            })
            .collect();
        let primary = usable_entries.first().ok_or_else(|| {
            "reciprocal handshake has no supported mailbox capabilities".to_string()
        })?;
        let new_contact = st::NewContact {
            pseudonym: *their_pseudonym,
            their_ik_pub: payload.ik_pub,
            // S03 §5.2 single-device mode: device_pub == IK. Contact
            // establishment carries no device certificates.
            their_device_pub: payload.ik_pub,
            our_pseudonym: *our_pseudonym,
            display_name: (!payload.display_name.is_empty()).then(|| payload.display_name.clone()),
        };
        let contact_id =
            SqliteStorage::create_contact(self, &new_contact).map_err(|e| e.to_string())?;

        let result = (|| -> std::result::Result<(), String> {
            let targets: Vec<StoredContactTarget> = usable_entries
                .iter()
                .map(|entry| target_from_entry(entry))
                .collect();
            self.set_setting(&format!("contact_target:{contact_id}"), &targets[0])
                .map_err(|e| e.to_string())?;
            // Preserve every supported signed coordinate even though the
            // current 1:1 delivery model selects the first as its primary.
            self.set_setting(&format!("contact_targets:{contact_id}"), &targets)
                .map_err(|e| e.to_string())?;

            let mailbox = SqliteStorage::list_mailboxes(self)
                .map_err(|e| e.to_string())?
                .into_iter()
                .find(|mailbox| mailbox.enabled)
                .ok_or_else(|| "no local mailbox available for reciprocal contact".to_string())?;
            let now = najwa_crypto::time::now() as i64;
            let cap = st::NewContactMailboxCap {
                contact_id,
                mailbox_id: mailbox.id,
                deposit_capability: najwa_crypto::random::random_bytes_vec(32),
                fetch_capability: Some(najwa_crypto::random::random_bytes_vec(32)),
                their_deposit_capability: Some(primary.deposit_capability.to_vec()),
                their_envelope_secret: Some(primary.envelope_secret.to_vec()),
                envelope_secret: Some(najwa_crypto::random::random_bytes_vec(32)),
                capability_type: najwa_protocol::contact::capability_lifecycle::CAP_TYPE_LONG_TERM
                    as i32,
                expires_at: None,
                // These locally-minted per-contact caps are not registered yet
                // and therefore MUST NOT be advertised (S05 scope boundary).
                registered_at: None,
                created_at: now,
            };
            SqliteStorage::save_contact_capability(self, &cap).map_err(|e| e.to_string())
        })();

        if let Err(error) = result {
            // Contact establishment is all-or-nothing from the caller's point of
            // view. Best-effort cleanup also removes capability rows via FK
            // cascade; settings are not FK-backed and are removed explicitly.
            let _ = self.delete_setting(&format!("contact_target:{contact_id}"));
            let _ = self.delete_setting(&format!("contact_targets:{contact_id}"));
            let _ = SqliteStorage::delete_contact(self, contact_id);
            return Err(error);
        }

        SqliteStorage::get_contact(self, contact_id)
            .map_err(|e| e.to_string())?
            .as_ref()
            .map(storage_to_core_contact)
            .ok_or_else(|| "reciprocal contact disappeared after creation".into())
    }

    async fn next_outbound_seq(&self, contact_id: ContactId) -> std::result::Result<u32, String> {
        SqliteStorage::next_outbound_seq(self, contact_id as i64).map_err(|e| e.to_string())
    }

    async fn buffer_outbound_repair(
        &self,
        contact_id: ContactId,
        item: &najwa_protocol::message::gap_repair::RepairedItem,
    ) -> std::result::Result<(), String> {
        const MAX_KEEP: u32 = 256;
        let record = st::OutboundRepairRecord {
            contact_id: contact_id as i64,
            dh_pub: item.original_dh_pub,
            message_number: item.original_n,
            msg_id: item.original_msg_id,
            timestamp: item.original_timestamp,
            logical_seq: item.original_logical_seq,
            content_type: item.original_content_type,
            flags: item.original_flags,
            content: item.original_content.clone(),
            created_at: najwa_crypto::time::now() as i64,
        };
        SqliteStorage::buffer_outbound_repair(self, &record, MAX_KEEP).map_err(|e| e.to_string())
    }

    async fn get_outbound_repair(
        &self,
        contact_id: ContactId,
        dh_pub: &[u8; 32],
        message_number: u32,
    ) -> std::result::Result<Option<najwa_protocol::message::gap_repair::RepairedItem>, String>
    {
        SqliteStorage::get_outbound_repair(self, contact_id as i64, dh_pub, message_number)
            .map(|opt| {
                opt.map(|record| najwa_protocol::message::gap_repair::RepairedItem {
                    original_dh_pub: record.dh_pub,
                    original_n: record.message_number,
                    original_msg_id: record.msg_id,
                    original_timestamp: record.timestamp,
                    original_logical_seq: record.logical_seq,
                    original_content_type: record.content_type,
                    original_flags: record.flags,
                    original_content: record.content,
                })
            })
            .map_err(|e| e.to_string())
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
        SqliteStorage::get_outbound_repair_entry(self, contact_id as i64, dh_pub, message_number)
            .map(|opt| {
                opt.map(|(record, sealed)| {
                    (
                        najwa_protocol::message::gap_repair::RepairedItem {
                            original_dh_pub: record.dh_pub,
                            original_n: record.message_number,
                            original_msg_id: record.msg_id,
                            original_timestamp: record.timestamp,
                            original_logical_seq: record.logical_seq,
                            original_content_type: record.content_type,
                            original_flags: record.flags,
                            original_content: record.content,
                        },
                        sealed,
                    )
                })
            })
            .map_err(|e| e.to_string())
    }

    async fn get_contact_capabilities(
        &self,
        contact_id: ContactId,
    ) -> Result<Vec<ContactCapability>, String> {
        let local = SqliteStorage::get_contact_capabilities(self, contact_id as i64)
            .map_err(|e| e.to_string())?;
        let targets = match self
            .get_setting::<Vec<StoredContactTarget>>(&format!("contact_targets:{contact_id}"))
            .map_err(|e| e.to_string())?
        {
            Some(targets) => Some(targets),
            None => self
                .get_setting::<StoredContactTarget>(&format!("contact_target:{contact_id}"))
                .map_err(|e| e.to_string())?
                .map(|t| vec![t]),
        };
        let mut result = Vec::new();
        if let Some(targets) = targets {
            for target in targets {
                if !SqliteStorage::remote_mailbox_enabled(self, &target.onion)
                    .map_err(|e| e.to_string())?
                {
                    continue;
                }
                let dep = hex_decode_32(&target.deposit_cap_hex)
                    .ok_or("invalid peer deposit capability")?;
                let secret = hex_decode_32(&target.envelope_secret_hex)
                    .ok_or("invalid peer envelope secret")?;
                let mut route = ContactCapability {
                    contact_id,
                    mailbox_id: 0,
                    mailbox_onion: target.onion.clone(),
                    mailbox_fetch_cap: [0; 32],
                    mailbox_deposit_cap: [0; 32],
                    their_deposit_capability: Some(dep),
                    their_envelope_secret: Some(secret),
                };
                // Remote coordinates need no matching local receive queue. Attach
                // local metadata only when it actually describes the same onion.
                for cap in &local {
                    if let Some(mb) = self
                        .get_mailbox(cap.mailbox_id)
                        .map_err(|e| e.to_string())?
                    {
                        if mb.onion_address == target.onion {
                            let own = storage_to_core_capability(cap, &mb);
                            route.mailbox_id = own.mailbox_id;
                            route.mailbox_fetch_cap = own.mailbox_fetch_cap;
                            route.mailbox_deposit_cap = own.mailbox_deposit_cap;
                            break;
                        }
                    }
                }
                result.push(route);
            }
        } else {
            for cap in &local {
                if let Some(mb) = self
                    .get_mailbox(cap.mailbox_id)
                    .map_err(|e| e.to_string())?
                {
                    if SqliteStorage::remote_mailbox_enabled(self, &mb.onion_address)
                        .map_err(|e| e.to_string())?
                    {
                        result.push(storage_to_core_capability(cap, &mb));
                    }
                }
            }
        }
        Ok(result)
    }

    // -- Ratchet state --

    async fn get_ratchet_state(
        &self,
        contact_id: ContactId,
    ) -> std::result::Result<Option<ProtocolRatchetState>, String> {
        let sr =
            SqliteStorage::get_ratchet_state(self, contact_id as i64).map_err(|e| e.to_string())?;
        match sr {
            Some(s) => {
                let mut proto = storage_to_protocol_ratchet(&s)?;
                load_skipped_into(self, contact_id as i64, &mut proto)?;
                Ok(Some(proto))
            }
            None => Ok(None),
        }
    }

    async fn save_ratchet_state(
        &self,
        contact_id: ContactId,
        state: &ProtocolRatchetState,
    ) -> std::result::Result<(), String> {
        let ss = protocol_to_storage_ratchet(state);
        SqliteStorage::save_ratchet_state(self, contact_id as i64, &ss)
            .map_err(|e| e.to_string())?;
        // Persist the skipped keys too — they are serde-skipped in the blob.
        persist_skipped(self, contact_id as i64, state)
    }

    async fn delete_ratchet_state(&self, contact_id: ContactId) -> std::result::Result<(), String> {
        SqliteStorage::delete_ratchet_state(self, contact_id as i64).map_err(|e| e.to_string())
    }

    async fn get_ratchet_state_by_dh_pub(
        &self,
        dh_pub: &[u8; 32],
    ) -> std::result::Result<Option<(ContactId, ProtocolRatchetState)>, String> {
        let result =
            SqliteStorage::get_ratchet_state_by_dh_pub(self, dh_pub).map_err(|e| e.to_string())?;
        match result {
            Some((cid, sr)) => {
                let mut ps = storage_to_protocol_ratchet(&sr)?;
                load_skipped_into(self, cid, &mut ps)?;
                Ok(Some((cid as u64, ps)))
            }
            None => Ok(None),
        }
    }

    // -- Session associated data --

    async fn get_session_ad(
        &self,
        contact_id: ContactId,
    ) -> std::result::Result<Option<Vec<u8>>, String> {
        SqliteStorage::get_session_ad(self, contact_id as i64).map_err(|e| e.to_string())
    }

    async fn save_session_ad(
        &self,
        contact_id: ContactId,
        ad: &[u8],
    ) -> std::result::Result<(), String> {
        SqliteStorage::save_session_ad(self, contact_id as i64, ad).map_err(|e| e.to_string())
    }

    async fn delete_session_ad(&self, contact_id: ContactId) -> std::result::Result<(), String> {
        SqliteStorage::delete_session_ad(self, contact_id as i64).map_err(|e| e.to_string())
    }

    // -- Message storage --

    async fn save_message(&self, msg: &Message) -> std::result::Result<MessageId, String> {
        let new_msg = core_to_new_message(msg);
        SqliteStorage::save_message(self, &new_msg).map_err(|e| e.to_string())
    }

    async fn commit_received(
        &self,
        contact_id: ContactId,
        ratchet_state: &ProtocolRatchetState,
        message: Option<&Message>,
        transport_msg_id: &[u8; 16],
        logical_msg_id: Option<&[u8; 16]>,
        disappearing: Option<(u32, u64)>,
    ) -> std::result::Result<Option<MessageId>, String> {
        let storage_ratchet = protocol_to_storage_ratchet(ratchet_state);
        let skipped = skipped_set_for(ratchet_state);
        let new_msg = message.map(core_to_new_message);
        SqliteStorage::commit_received(
            self,
            contact_id as i64,
            &storage_ratchet,
            &skipped,
            new_msg.as_ref(),
            transport_msg_id,
            logical_msg_id,
            disappearing,
        )
        .map_err(|e| e.to_string())
    }

    async fn commit_initial_received(
        &self,
        contact_id: ContactId,
        ratchet_state: &ProtocolRatchetState,
        session_ad: &[u8],
        opk_id: Option<[u8; 4]>,
        message: Option<&Message>,
        transport_msg_id: &[u8; 16],
        logical_msg_id: Option<&[u8; 16]>,
        disappearing: Option<(u32, u64)>,
        ephemeral_handshake_cap_id: Option<i64>,
    ) -> std::result::Result<Option<MessageId>, String> {
        let storage_ratchet = protocol_to_storage_ratchet(ratchet_state);
        let skipped = skipped_set_for(ratchet_state);
        let new_msg = message.map(core_to_new_message);
        SqliteStorage::commit_initial_received(
            self,
            contact_id as i64,
            &storage_ratchet,
            &skipped,
            session_ad,
            opk_id,
            new_msg.as_ref(),
            transport_msg_id,
            logical_msg_id,
            disappearing,
            ephemeral_handshake_cap_id,
        )
        .map_err(|e| e.to_string())
    }

    async fn commit_repaired_received(
        &self,
        contact_id: ContactId,
        message: &Message,
        transport_msg_id: &[u8; 16],
        logical_msg_id: &[u8; 16],
    ) -> std::result::Result<Option<MessageId>, String> {
        let new_msg = core_to_new_message(message);
        SqliteStorage::commit_repaired_received(
            self,
            contact_id as i64,
            &new_msg,
            transport_msg_id,
            logical_msg_id,
        )
        .map_err(|e| e.to_string())
    }

    async fn commit_sent(
        &self,
        contact_id: ContactId,
        ratchet_state: &ProtocolRatchetState,
        message: &Message,
        wire_blob: &[u8],
        disappearing: Option<(u32, u64)>,
        repair_item: Option<&najwa_protocol::message::gap_repair::RepairedItem>,
    ) -> std::result::Result<MessageId, String> {
        let storage_ratchet = protocol_to_storage_ratchet(ratchet_state);
        let new_msg = core_to_new_message(message);
        let repair_record = repair_item.map(|item| st::OutboundRepairRecord {
            contact_id: contact_id as i64,
            dh_pub: item.original_dh_pub,
            message_number: item.original_n,
            msg_id: item.original_msg_id,
            timestamp: item.original_timestamp,
            logical_seq: item.original_logical_seq,
            content_type: item.original_content_type,
            flags: item.original_flags,
            content: item.original_content.clone(),
            created_at: najwa_crypto::time::now() as i64,
        });
        let wire = najwa_protocol::message::WireMessage::from_bytes(wire_blob)
            .map_err(|e| e.to_string())?;
        let najwa_protocol::message::MessageHeader::Ratchet(header) = wire.header;
        SqliteStorage::commit_sent_with_position(
            self,
            contact_id as i64,
            &storage_ratchet,
            &new_msg,
            wire_blob,
            disappearing,
            repair_record.as_ref(),
            Some((header.dh_pub.to_bytes(), header.n)),
        )
        .map_err(|e| e.to_string())
    }

    async fn check_logical_msg_id_seen(
        &self,
        contact_id: ContactId,
        logical_msg_id: &[u8; 16],
    ) -> std::result::Result<bool, String> {
        SqliteStorage::check_logical_msg_id_seen(self, contact_id as i64, logical_msg_id)
            .map_err(|e| e.to_string())
    }

    async fn mark_logical_msg_id_seen(
        &self,
        contact_id: ContactId,
        logical_msg_id: &[u8; 16],
    ) -> std::result::Result<(), String> {
        SqliteStorage::mark_logical_msg_id_seen(self, contact_id as i64, logical_msg_id)
            .map_err(|e| e.to_string())
    }

    async fn get_message_by_msg_id(
        &self,
        msg_id: &[u8; 16],
    ) -> std::result::Result<Option<Message>, String> {
        SqliteStorage::get_message_by_msg_id(self, msg_id)
            .map(|opt| opt.map(|m| storage_to_core_message(&m)))
            .map_err(|e| e.to_string())
    }

    async fn update_message_status(
        &self,
        id: MessageId,
        status: MessageStatus,
    ) -> std::result::Result<(), String> {
        let ss = match status {
            MessageStatus::Pending => st::MessageStatus::Pending,
            MessageStatus::Sent => st::MessageStatus::Sent,
            MessageStatus::Delivered => st::MessageStatus::Delivered,
            MessageStatus::Read => st::MessageStatus::Read,
            MessageStatus::Failed => st::MessageStatus::Failed,
        };
        SqliteStorage::update_message_status(self, id, ss).map_err(|e| e.to_string())
    }

    async fn get_pending_messages(&self) -> std::result::Result<Vec<Message>, String> {
        SqliteStorage::get_pending_messages(self)
            .map(|v| v.iter().map(storage_to_core_message).collect())
            .map_err(|e| e.to_string())
    }

    async fn update_message_blob(
        &self,
        id: MessageId,
        blob: &[u8],
    ) -> std::result::Result<(), String> {
        SqliteStorage::update_retry_wire_blob(self, id, blob).map_err(|e| e.to_string())
    }

    async fn clear_message_blob(&self, id: MessageId) -> std::result::Result<(), String> {
        SqliteStorage::clear_retry_wire_blob(self, id).map_err(|e| e.to_string())
    }

    async fn increment_retry_count(&self, id: MessageId) -> std::result::Result<(), String> {
        SqliteStorage::increment_retry_count(self, id).map_err(|e| e.to_string())
    }

    async fn get_message_blob(
        &self,
        id: MessageId,
    ) -> std::result::Result<Option<Vec<u8>>, String> {
        // Retry ciphertext is separate from the encrypted reply metadata.
        SqliteStorage::get_message(self, id)
            .map(|opt| opt.and_then(|m| m.retry_wire_blob))
            .map_err(|e| e.to_string())
    }

    // -- Message deduplication --

    async fn check_msg_id_seen(&self, msg_id: &[u8; 16]) -> std::result::Result<bool, String> {
        SqliteStorage::check_msg_id_seen(self, msg_id).map_err(|e| e.to_string())
    }

    async fn mark_msg_id_seen(
        &self,
        contact_id: ContactId,
        msg_id: &[u8; 16],
    ) -> std::result::Result<(), String> {
        SqliteStorage::mark_msg_id_seen(self, contact_id as i64, msg_id).map_err(|e| e.to_string())
    }

    // -- Mailbox --

    async fn list_mailboxes(&self) -> std::result::Result<Vec<MailboxConfig>, String> {
        SqliteStorage::list_mailboxes(self)
            .map(|v| {
                v.iter()
                    .filter(|mb| mb.enabled)
                    .map(storage_to_mailbox_config)
                    .collect()
            })
            .map_err(|e| e.to_string())
    }

    async fn list_mailboxes_with_ids(
        &self,
    ) -> std::result::Result<Vec<(MailboxId, MailboxConfig)>, String> {
        receive_queues(self)
    }

    // -- Deposit capability lookup --

    async fn list_deposit_capabilities_for_mailbox(
        &self,
        mailbox_id: MailboxId,
    ) -> std::result::Result<Vec<([u8; 32], [u8; 32])>, String> {
        // (their_deposit_capability, their_envelope_secret) pairs for this mailbox.
        let caps = SqliteStorage::get_capabilities_for_mailbox(self, mailbox_id)
            .map_err(|e| e.to_string())?;
        let to_arr32 = |b: &Vec<u8>| -> Option<[u8; 32]> {
            if b.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(b);
                Some(arr)
            } else {
                None
            }
        };
        let mut result = Vec::new();
        for cap in &caps {
            if let (Some(dep), Some(sec)) = (
                cap.their_deposit_capability.as_ref().and_then(&to_arr32),
                cap.their_envelope_secret.as_ref().and_then(&to_arr32),
            ) {
                result.push((dep, sec));
            }
        }
        Ok(result)
    }

    async fn get_ephemeral_handshake_capability(
        &self,
        mailbox_id: MailboxId,
        fetch_capability: &[u8; 32],
    ) -> std::result::Result<Option<EphemeralHandshakeCapability>, String> {
        let caps = SqliteStorage::get_active_ephemeral_handshake_caps_for_mailbox(
            self,
            mailbox_id,
            najwa_crypto::time::now() as i64,
        )
        .map_err(|e| e.to_string())?;
        Ok(caps
            .iter()
            .find(|cap| cap.fetch_capability.as_slice() == fetch_capability)
            .map(|cap| EphemeralHandshakeCapability {
                id: cap.id,
                accepted: cap.accepted_at.is_some(),
            }))
    }

    async fn mark_ephemeral_handshake_cap_accepted(
        &self,
        capability_id: i64,
    ) -> std::result::Result<(), String> {
        SqliteStorage::mark_ephemeral_handshake_cap_accepted(
            self,
            capability_id,
            najwa_crypto::time::now() as i64,
        )
        .map_err(|e| e.to_string())
    }

    async fn mark_ephemeral_handshake_cap_deactivated(
        &self,
        capability_id: i64,
    ) -> std::result::Result<(), String> {
        SqliteStorage::mark_ephemeral_handshake_cap_deactivated(
            self,
            capability_id,
            najwa_crypto::time::now() as i64,
        )
        .map_err(|e| e.to_string())
    }

    async fn get_contact_mailbox_signing_key(
        &self, contact_id: ContactId, onion: &str,
    ) -> std::result::Result<Option<[u8; 32]>, String> {
        let mut targets = self.get_setting::<Vec<StoredContactTarget>>(
            &format!("contact_targets:{contact_id}")).map_err(|e| e.to_string())?
            .unwrap_or_default();
        if targets.is_empty() {
            if let Some(target) = self.get_setting::<StoredContactTarget>(
                &format!("contact_target:{contact_id}")).map_err(|e| e.to_string())? {
                targets.push(target);
            }
        }
        for target in targets {
            if target.onion == onion && !target.mailbox_entry.is_empty() {
                let entry = najwa_protocol::contact::mailbox_key::MailboxEntry::from_bytes(
                    &target.mailbox_entry).map_err(|e| e.to_string())?;
                if target_from_entry(&entry).onion != onion
                    || hex_encode(&entry.deposit_capability) != target.deposit_cap_hex {
                    return Err("contact mailbox entry mismatch".into());
                }
                return Ok(Some(entry.mailbox_ik_pub));
            }
        }
        Ok(None)
    }

    // -- Prekey access --

    async fn get_spk_keypair(
        &self,
        id: &[u8; 4],
    ) -> std::result::Result<Option<X25519KeyPair>, String> {
        let prekey = self.get_prekey(id).map_err(|e| e.to_string())?;
        match prekey {
            Some(pk) if pk.private_key.len() == 32 && !pk.used
                && pk.key_type == st::PrekeyType::Spk
                && pk.expires_at.is_none_or(|expires| expires > najwa_crypto::time::now() as i64) => {
                let mut seed = zeroize::Zeroizing::new([0u8; 32]);
                seed.copy_from_slice(&pk.private_key);
                Ok(Some(X25519KeyPair::from_seed(*seed)))
            }
            _ => Ok(None),
        }
    }

    async fn get_opk_keypair(
        &self,
        id: &[u8; 4],
    ) -> std::result::Result<Option<X25519KeyPair>, String> {
        let prekey = self.get_prekey(id).map_err(|e| e.to_string())?;
        match prekey {
            Some(pk) if pk.private_key.len() == 32 && !pk.used
                && pk.key_type == st::PrekeyType::Opk
                && pk.expires_at.is_none_or(|expires| expires > najwa_crypto::time::now() as i64) => {
                let mut seed = zeroize::Zeroizing::new([0u8; 32]);
                seed.copy_from_slice(&pk.private_key);
                Ok(Some(X25519KeyPair::from_seed(*seed)))
            }
            _ => Ok(None),
        }
    }

    async fn mark_opk_used(&self, id: &[u8; 4]) -> std::result::Result<(), String> {
        SqliteStorage::mark_opk_used(self, id).map_err(|e| e.to_string())
    }

    // -- Mailbox health tracking --

    async fn list_mailbox_health(&self) -> std::result::Result<Vec<MailboxHealth>, String> {
        SqliteStorage::list_mailboxes(self)
            .map(|v| v.iter().map(storage_to_mailbox_health).collect())
            .map_err(|e| e.to_string())
    }

    async fn get_mailbox_health(
        &self,
        mailbox_id: MailboxId,
    ) -> std::result::Result<Option<MailboxHealth>, String> {
        self.get_mailbox(mailbox_id)
            .map(|opt| opt.map(|mb| storage_to_mailbox_health(&mb)))
            .map_err(|e| e.to_string())
    }

    async fn record_mailbox_success(
        &self,
        mailbox_id: MailboxId,
        _timestamp: u64,
    ) -> std::result::Result<(), String> {
        self.update_mailbox_health(mailbox_id, true)
            .map_err(|e| e.to_string())
    }

    async fn record_mailbox_failure(
        &self,
        mailbox_id: MailboxId,
        _timestamp: u64,
    ) -> std::result::Result<(), String> {
        self.update_mailbox_health(mailbox_id, false)
            .map_err(|e| e.to_string())
    }

    async fn disable_mailbox(&self, mailbox_id: MailboxId) -> std::result::Result<(), String> {
        SqliteStorage::disable_mailbox(self, mailbox_id).map_err(|e| e.to_string())
    }

    async fn enable_mailbox(&self, mailbox_id: MailboxId) -> std::result::Result<(), String> {
        SqliteStorage::enable_mailbox(self, mailbox_id).map_err(|e| e.to_string())
    }

    // -- Contact mailbox capabilities (HIGH-12) --

    async fn save_contact_capability(
        &self,
        contact_id: ContactId,
        mailbox_id: MailboxId,
        deposit_cap: &[u8; 32],
        fetch_cap: Option<&[u8; 32]>,
        their_deposit_cap: Option<&[u8; 32]>,
    ) -> std::result::Result<(), String> {
        let cap = st::NewContactMailboxCap {
            contact_id: contact_id as i64,
            mailbox_id,
            deposit_capability: deposit_cap.to_vec(),
            fetch_capability: fetch_cap.map(|f| f.to_vec()),
            their_deposit_capability: their_deposit_cap.map(|d| d.to_vec()),
            // D3 envelope_secret is NOT in this trait signature, so this method
            // cannot persist it. It is currently unused (all establishment writes
            // the secret via SqliteStorage::save_contact_capability with the full
            // cap struct — FFI lib.rs and protocol accept.rs). Do NOT route a
            // send-capable contact's caps through here: without the secret the send
            // path fails closed and skips the target (no leak, but no delivery).
            their_envelope_secret: None,
            // Same limitation as `their_envelope_secret` above: OUR per-contact
            // envelope secret is not in this trait signature either, so a cap
            // written through here is not advertisable. `registered_at: None`
            // records that honestly rather than implying a live capability.
            envelope_secret: None,
            capability_type: najwa_protocol::contact::capability_lifecycle::CAP_TYPE_LONG_TERM
                as i32,
            expires_at: None,
            registered_at: None,
            created_at: najwa_crypto::time::now() as i64,
        };
        SqliteStorage::save_contact_capability(self, &cap).map_err(|e| e.to_string())
    }

    async fn revoke_contact_capability(
        &self,
        contact_id: ContactId,
        mailbox_id: MailboxId,
    ) -> std::result::Result<(), String> {
        SqliteStorage::revoke_contact_capability(self, contact_id as i64, mailbox_id)
            .map_err(|e| e.to_string())
    }

    async fn delete_contact(&self, contact_id: ContactId) -> std::result::Result<(), String> {
        SqliteStorage::delete_contact(self, contact_id as i64).map_err(|e| e.to_string())
    }

    async fn set_message_disappearing(
        &self,
        id: MessageId,
        timer_secs: u32,
        disappear_at_ms: u64,
    ) -> std::result::Result<(), String> {
        SqliteStorage::set_message_disappear_pending(self, id, timer_secs)
            .map_err(|e| e.to_string())?;
        SqliteStorage::set_message_disappear_at(self, id, disappear_at_ms)
            .map_err(|e| e.to_string())
    }

    async fn start_sender_disappear_on_ack(
        &self,
        msg_id: &[u8; 16],
    ) -> std::result::Result<(), String> {
        SqliteStorage::start_sender_disappear_on_ack(self, msg_id).map_err(|e| e.to_string())
    }

    // -- Volatile keys (HIGH-12) --

    async fn save_volatile_key(
        &self,
        msg_id: &[u8; 16],
        encrypted_key: &[u8],
        expires_at: Option<u64>,
    ) -> std::result::Result<(), String> {
        SqliteStorage::save_volatile_key(self, msg_id, encrypted_key, expires_at.map(|t| t as i64))
            .map_err(|e| e.to_string())
    }

    async fn get_volatile_key(
        &self,
        msg_id: &[u8; 16],
    ) -> std::result::Result<Option<Vec<u8>>, String> {
        SqliteStorage::get_volatile_key(self, msg_id).map_err(|e| e.to_string())
    }

    async fn cleanup_expired_volatile_keys(&self) -> std::result::Result<u32, String> {
        SqliteStorage::cleanup_expired_volatile_keys(self).map_err(|e| e.to_string())
    }

    // -- Disappearing messages (HIGH-12) --

    async fn set_conversation_timer(
        &self,
        contact_id: ContactId,
        timer_secs: Option<u32>,
    ) -> std::result::Result<(), String> {
        SqliteStorage::set_conversation_timer(self, contact_id as i64, timer_secs)
            .map_err(|e| e.to_string())
    }

    async fn get_conversation_timer(
        &self,
        contact_id: ContactId,
    ) -> std::result::Result<Option<u32>, String> {
        SqliteStorage::get_conversation_timer(self, contact_id as i64).map_err(|e| e.to_string())
    }

    async fn set_conversation_timer_setting(
        &self,
        contact_id: ContactId,
        timer_secs: Option<u32>,
        set_at: u64,
        setter_ik: &[u8; 32],
    ) -> std::result::Result<(), String> {
        SqliteStorage::set_conversation_timer_setting(
            self,
            contact_id as i64,
            timer_secs,
            set_at,
            setter_ik,
        )
        .map_err(|e| e.to_string())
    }

    async fn get_conversation_timer_setting(
        &self,
        contact_id: ContactId,
    ) -> std::result::Result<Option<(Option<u32>, u64, [u8; 32])>, String> {
        SqliteStorage::get_conversation_timer_setting(self, contact_id as i64)
            .map_err(|e| e.to_string())
    }

    async fn get_expired_disappearing_messages(&self) -> std::result::Result<Vec<Message>, String> {
        let now = najwa_crypto::time::now_ms() as u64;
        SqliteStorage::get_expired_disappearing_messages(self, now)
            .map(|v| v.iter().map(storage_to_core_message).collect())
            .map_err(|e| e.to_string())
    }

    async fn overwrite_message_content(
        &self,
        id: MessageId,
        zeros: &[u8],
    ) -> std::result::Result<(), String> {
        SqliteStorage::overwrite_message_content(self, id, zeros).map_err(|e| e.to_string())
    }

    // -- Identity history (HIGH-12) --

    async fn save_identity_history(
        &self,
        contact_id: ContactId,
        old_ik_pub: &[u8; 32],
        new_ik_pub: &[u8; 32],
        reason: Option<&str>,
    ) -> std::result::Result<(), String> {
        let entry = st::IdentityHistoryEntry {
            id: None,
            contact_id: contact_id as i64,
            old_ik_pub: old_ik_pub.to_vec(),
            new_ik_pub: new_ik_pub.to_vec(),
            rotated_at: najwa_crypto::time::now() as i64,
            reason: reason.map(|s| s.to_string()),
        };
        SqliteStorage::save_identity_history(self, &entry).map_err(|e| e.to_string())
    }

    // -- Skipped keys (HIGH-12) --

    async fn save_skipped_key(
        &self,
        contact_id: ContactId,
        dh_pub: &[u8; 32],
        msg_num: u32,
        message_key: &[u8; 32],
    ) -> std::result::Result<(), String> {
        let now = najwa_crypto::time::now() as i64;
        let key = st::SkippedKey {
            dh_pub: *dh_pub,
            message_number: msg_num,
            message_key: *message_key,
            created_at: now,
            expires_at: now + 7 * 86400, // 7-day expiry
        };
        SqliteStorage::save_skipped_key(self, contact_id as i64, &key).map_err(|e| e.to_string())
    }

    async fn get_skipped_key(
        &self,
        contact_id: ContactId,
        dh_pub: &[u8; 32],
        msg_num: u32,
    ) -> std::result::Result<Option<[u8; 32]>, String> {
        SqliteStorage::get_skipped_key(self, contact_id as i64, dh_pub, msg_num)
            .map_err(|e| e.to_string())
    }

    async fn delete_skipped_key(
        &self,
        contact_id: ContactId,
        dh_pub: &[u8; 32],
        msg_num: u32,
    ) -> std::result::Result<(), String> {
        SqliteStorage::delete_skipped_key(self, contact_id as i64, dh_pub, msg_num)
            .map_err(|e| e.to_string())
    }

    // -- Epoch-reorder quarantine (S08 §6.3) --

    async fn save_quarantined_frame(
        &self,
        blob_hash: &[u8; 32],
        blob: &[u8],
        quarantined_at: u64,
    ) -> std::result::Result<(), String> {
        SqliteStorage::save_quarantined_frame(self, blob_hash, blob, quarantined_at as i64)
            .map_err(|e| e.to_string())
    }

    async fn load_quarantined_frames(&self) -> std::result::Result<Vec<(Vec<u8>, u64)>, String> {
        SqliteStorage::load_quarantined_frames(self)
            .map(|v| v.into_iter().map(|(b, t)| (b, t as u64)).collect())
            .map_err(|e| e.to_string())
    }

    async fn delete_quarantined_frame(
        &self,
        blob_hash: &[u8; 32],
    ) -> std::result::Result<(), String> {
        SqliteStorage::delete_quarantined_frame(self, blob_hash).map_err(|e| e.to_string())
    }

    // -- Maintenance (HIGH-12) --

    async fn cleanup_old_msg_ids(&self, older_than_secs: u64) -> std::result::Result<u32, String> {
        let cutoff = najwa_crypto::time::now().saturating_sub(older_than_secs) as i64;
        SqliteStorage::cleanup_old_msg_ids(self, cutoff).map_err(|e| e.to_string())
    }

    async fn cleanup_expired_skipped_keys(&self) -> std::result::Result<u32, String> {
        SqliteStorage::cleanup_expired_skipped_keys(self).map_err(|e| e.to_string())
    }

    async fn count_available_opks(
        &self,
        mailbox_id: Option<MailboxId>,
    ) -> std::result::Result<u32, String> {
        SqliteStorage::count_opks(self, mailbox_id).map_err(|e| e.to_string())
    }

    // -- Pending introductions (S05 §11) --

    async fn save_pending_introduction(
        &self,
        intro: &st::NewPendingIntroduction,
    ) -> std::result::Result<i64, String> {
        SqliteStorage::save_pending_introduction(self, intro).map_err(|e| e.to_string())
    }

    async fn get_pending_introduction(
        &self,
        id: i64,
    ) -> std::result::Result<Option<st::PendingIntroduction>, String> {
        SqliteStorage::get_pending_introduction(self, id).map_err(|e| e.to_string())
    }

    async fn list_pending_introductions(
        &self,
    ) -> std::result::Result<Vec<st::PendingIntroduction>, String> {
        SqliteStorage::list_pending_introductions(self).map_err(|e| e.to_string())
    }

    async fn list_introductions_for_contact(
        &self,
        introducer_contact_id: ContactId,
    ) -> std::result::Result<Vec<st::PendingIntroduction>, String> {
        SqliteStorage::list_introductions_for_contact(self, introducer_contact_id as i64)
            .map_err(|e| e.to_string())
    }

    async fn update_introduction_status(
        &self,
        id: i64,
        status: st::IntroductionStatus,
    ) -> std::result::Result<(), String> {
        SqliteStorage::update_introduction_status(self, id, status).map_err(|e| e.to_string())
    }

    async fn count_pending_introductions(&self) -> std::result::Result<u32, String> {
        SqliteStorage::count_pending_introductions(self).map_err(|e| e.to_string())
    }

    async fn get_contact_by_ik(
        &self,
        ik_pub: &[u8; 32],
    ) -> std::result::Result<Option<Contact>, String> {
        SqliteStorage::get_contact_by_ik(self, ik_pub)
            .map(|opt| opt.map(|c| storage_to_core_contact(&c)))
            .map_err(|e| e.to_string())
    }

    async fn get_contact_by_ik_device(
        &self,
        ik_pub: &[u8; 32],
        device_pub: &[u8; 32],
    ) -> std::result::Result<Option<Contact>, String> {
        SqliteStorage::get_contact_by_ik_device(self, ik_pub, device_pub)
            .map(|opt| opt.map(|c| storage_to_core_contact(&c)))
            .map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use najwa_storage::types::NewContact;

    fn test_db() -> SqliteStorage {
        SqliteStorage::open_in_memory(&[0x42; 32]).expect("open in-memory db")
    }

    #[tokio::test]
    async fn bridge_get_contact() {
        let db = test_db();
        let cid = db
            .create_contact(&NewContact {
                pseudonym: [0x11; 32],
                their_ik_pub: [0x22; 32],
                their_device_pub: [0x22; 32],
                our_pseudonym: [0x33; 32],
                display_name: Some("Alice".into()),
            })
            .expect("create contact");

        let core_storage: &dyn CoreStorage = &db;
        let contact = core_storage
            .get_contact(cid as u64)
            .await
            .expect("get contact")
            .expect("contact exists");

        assert_eq!(contact.their_pseudonym, [0x11; 32]);
        assert_eq!(contact.our_pseudonym, [0x33; 32]);
        assert_eq!(contact.their_ik_pub, [0x22; 32]);
        assert_eq!(contact.display_name.as_deref(), Some("Alice"));
        assert!(!contact.blocked);
        assert!(!contact.verified);
    }

    #[tokio::test]
    async fn bridge_contact_by_pseudonym() {
        let db = test_db();
        db.create_contact(&NewContact {
            pseudonym: [0xAA; 32],
            their_ik_pub: [0xBB; 32],
            their_device_pub: [0xBB; 32],
            our_pseudonym: [0xCC; 32],
            display_name: None,
        })
        .expect("create");

        let core_storage: &dyn CoreStorage = &db;
        let contact = core_storage
            .get_contact_by_pseudonym(&[0xAA; 32])
            .await
            .expect("lookup")
            .expect("found");
        assert_eq!(contact.their_ik_pub, [0xBB; 32]);
    }

    #[tokio::test]
    async fn bridge_update_contact_preserves_fields() {
        let db = test_db();
        let cid = db
            .create_contact(&NewContact {
                pseudonym: [0x01; 32],
                their_ik_pub: [0x02; 32],
                their_device_pub: [0x02; 32],
                our_pseudonym: [0x03; 32],
                display_name: Some("Bob".into()),
            })
            .expect("create");

        let core_storage: &dyn CoreStorage = &db;

        // Read, modify, write back
        let mut contact = core_storage.get_contact(cid as u64).await.unwrap().unwrap();
        contact.blocked = true;
        core_storage.update_contact(&contact).await.unwrap();

        // Verify the change persisted and other fields survived
        let loaded = core_storage.get_contact(cid as u64).await.unwrap().unwrap();
        assert!(loaded.blocked);
        assert_eq!(loaded.display_name.as_deref(), Some("Bob"));
    }

    // Regression: skipped message keys (serde-skipped in the ratchet blob) must
    // survive the save → reload cycle the receive path performs, and consumed
    // keys must be deleted. Without this, out-of-order delivery breaks across
    // receives (S06 §3.10).
    #[tokio::test]
    async fn bridge_persists_and_reloads_skipped_keys() {
        use najwa_crypto::keys::x25519::X25519KeyPair;
        use najwa_protocol::ratchet::init::init_bob;
        use najwa_protocol::ratchet::state::SkippedKey;

        let db = test_db();
        let cid = db
            .create_contact(&NewContact {
                pseudonym: [0x11; 32],
                their_ik_pub: [0x22; 32],
                their_device_pub: [0x22; 32],
                our_pseudonym: [0x33; 32],
                display_name: None,
            })
            .expect("create contact");

        // A ratchet state carrying two skipped keys. Use a current timestamp so
        // the keys are not treated as expired (load filters out expired rows).
        let t = najwa_crypto::time::now();
        let mut rng = rand::thread_rng();
        let spk = X25519KeyPair::generate(&mut rng);
        let mut state = init_bob(&[0x42u8; 32], spk);
        state.skipped.insert(
            ([0xAA; 32], 0),
            SkippedKey {
                message_key: [0x01; 32],
                created_at: t,
            },
        );
        state.skipped.insert(
            ([0xAA; 32], 1),
            SkippedKey {
                message_key: [0x02; 32],
                created_at: t,
            },
        );

        let core: &dyn CoreStorage = &db;
        core.save_ratchet_state(cid as u64, &state)
            .await
            .expect("save");

        // Reload: both skipped keys must come back (previously dropped).
        let reloaded = core
            .get_ratchet_state(cid as u64)
            .await
            .expect("get")
            .expect("present");
        assert_eq!(reloaded.skipped.len(), 2);
        assert_eq!(
            reloaded.skipped.get(&([0xAA; 32], 0)).unwrap().message_key,
            [0x01; 32]
        );
        assert_eq!(
            reloaded.skipped.get(&([0xAA; 32], 1)).unwrap().message_key,
            [0x02; 32]
        );

        // Consume one key (as an out-of-order decrypt would) and save again.
        let mut advanced = reloaded;
        advanced.skipped.remove(&([0xAA; 32], 0));
        core.save_ratchet_state(cid as u64, &advanced)
            .await
            .expect("save 2");

        let reloaded2 = core
            .get_ratchet_state(cid as u64)
            .await
            .expect("get2")
            .expect("present2");
        assert_eq!(reloaded2.skipped.len(), 1);
        assert!(reloaded2.skipped.contains_key(&([0xAA; 32], 1)));
        assert!(!reloaded2.skipped.contains_key(&([0xAA; 32], 0)));
    }

    // S06 §3.10: `prev_DHs_pub` must survive a save → reload, or every frame
    // sent after a restart carries a zero `epoch_link` and the receiver's
    // missed-epoch check (§3.5 step 3) is switched off.
    #[tokio::test]
    async fn bridge_persists_prev_dhs_pub_so_reloaded_sender_links_its_epoch() {
        use najwa_crypto::keys::x25519::X25519KeyPair;
        use najwa_protocol::message::WirePrefixMeta;
        use najwa_protocol::ratchet::{encrypt::ratchet_encrypt, init::init_alice};

        let db = test_db();
        let cid = db
            .create_contact(&NewContact {
                pseudonym: [0x44; 32],
                their_ik_pub: [0x55; 32],
                their_device_pub: [0x55; 32],
                our_pseudonym: [0x66; 32],
                display_name: None,
            })
            .expect("create contact");
        let spk = X25519KeyPair::generate(&mut rand::thread_rng());
        let mut state = init_alice(&[0x42; 32], spk.public(), &[0x43; 32]).unwrap();
        state.prev_dhs_pub = Some([0x5A; 32]); // as after a DH step

        let core: &dyn CoreStorage = &db;
        core.save_ratchet_state(cid as u64, &state).await.expect("save");
        let mut reloaded = core
            .get_ratchet_state(cid as u64)
            .await
            .expect("get")
            .expect("present");
        assert_eq!(reloaded.prev_dhs_pub, Some([0x5A; 32]));

        let meta = WirePrefixMeta {
            version: 1,
            message_type: 2,
            x3dh_header: None,
        };
        let (header, _) = ratchet_encrypt(&mut reloaded, b"after restart", b"ad", &meta).unwrap();
        assert_eq!(header.epoch_link, [0x5A; 32], "reloaded sender must link its epoch");
    }

    // I3: commit_received is atomic — if the message insert fails (duplicate
    // msg_id), the ratchet advance and dedup mark must roll back too. Otherwise
    // a crash/failure mid-receive would advance the ratchet past a message that
    // was never stored, losing it on re-fetch.
    #[tokio::test]
    async fn commit_received_rolls_back_on_message_conflict() {
        use najwa_crypto::keys::x25519::X25519KeyPair;
        use najwa_protocol::ratchet::init::init_bob;

        let db = test_db();
        let cid = db
            .create_contact(&NewContact {
                pseudonym: [0x11; 32],
                their_ik_pub: [0x22; 32],
                their_device_pub: [0x22; 32],
                our_pseudonym: [0x33; 32],
                display_name: None,
            })
            .expect("create contact");
        let core: &dyn CoreStorage = &db;

        // Save the base ratchet state at ns = 0.
        let mut rng = rand::thread_rng();
        let spk = X25519KeyPair::generate(&mut rng);
        let mut state = init_bob(&[0x42u8; 32], spk);
        state.ns = 0;
        core.save_ratchet_state(cid as u64, &state)
            .await
            .expect("save base");

        // Pre-insert a message so the next insert with the same msg_id conflicts.
        let dup_id = [0x55u8; 16];
        let first = Message {
            id: 0,
            contact_id: cid as u64,
            msg_id: dup_id,
            direction: Direction::Received,
            content_type: 0,
            flags: 0,
            content: b"first".to_vec(),
            timestamp: 1,
            status: MessageStatus::Delivered,
            ratchet_index: None,
        };
        core.save_message(&first).await.expect("save first");

        // Commit an ADVANCED ratchet (ns = 9) together with a DUPLICATE message.
        state.ns = 9;
        let dup_msg = Message {
            content: b"second".to_vec(),
            ..first.clone()
        };
        let result = core
            .commit_received(cid as u64, &state, Some(&dup_msg), &dup_id, None, None)
            .await;
        assert!(result.is_err(), "duplicate message must fail the commit");

        // Atomicity: the ratchet must NOT have advanced (whole tx rolled back).
        let reloaded = core.get_ratchet_state(cid as u64).await.unwrap().unwrap();
        assert_eq!(
            reloaded.ns, 0,
            "ratchet must not advance when the atomic commit fails"
        );
    }

    #[tokio::test]
    async fn bridge_msg_id_dedup() {
        let db = test_db();
        let cid = db
            .create_contact(&NewContact {
                pseudonym: [0x11; 32],
                their_ik_pub: [0x22; 32],
                their_device_pub: [0x22; 32],
                our_pseudonym: [0x33; 32],
                display_name: Some("Alice".into()),
            })
            .expect("create contact");
        let core_storage: &dyn CoreStorage = &db;
        let mid = [0xDD; 16];

        assert!(!core_storage.check_msg_id_seen(&mid).await.unwrap());
        core_storage
            .mark_msg_id_seen(cid as u64, &mid)
            .await
            .unwrap();
        assert!(core_storage.check_msg_id_seen(&mid).await.unwrap());
    }

    #[tokio::test]
    async fn bridge_session_ad_roundtrip() {
        let db = test_db();
        let core_storage: &dyn CoreStorage = &db;
        let ad = vec![0x11u8; 64];

        assert!(core_storage.get_session_ad(1).await.unwrap().is_none());
        core_storage.save_session_ad(1, &ad).await.unwrap();
        let loaded = core_storage.get_session_ad(1).await.unwrap().unwrap();
        assert_eq!(loaded, ad);

        core_storage.delete_session_ad(1).await.unwrap();
        assert!(core_storage.get_session_ad(1).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn bridge_list_mailboxes_filters_disabled() {
        let db = test_db();
        let mid1 = db
            .save_mailbox(&najwa_storage::types::NewMailbox {
                onion_address: "active.onion".into(),
                fetch_capability: vec![0x01; 32],
                deposit_capability: vec![0x02; 32],
                envelope_secret: vec![0x05; 32],
                cover_deposit_capability: None,
                cover_fetch_capability: None,
                cover_envelope_secret: None,
                priority: 1,
                created_at: 1000,
            })
            .unwrap();
        let mid2 = db
            .save_mailbox(&najwa_storage::types::NewMailbox {
                onion_address: "disabled.onion".into(),
                fetch_capability: vec![0x03; 32],
                deposit_capability: vec![0x04; 32],
                envelope_secret: vec![0x06; 32],
                cover_deposit_capability: None,
                cover_fetch_capability: None,
                cover_envelope_secret: None,
                priority: 1,
                created_at: 1000,
            })
            .unwrap();
        db.disable_mailbox(mid2).unwrap();

        let core_storage: &dyn CoreStorage = &db;
        let mailboxes = core_storage.list_mailboxes().await.unwrap();
        assert_eq!(mailboxes.len(), 1);
        assert_eq!(mailboxes[0].onion_address, "active.onion");

        let contact_id = db
            .create_contact(&najwa_storage::types::NewContact {
                pseudonym: [0x31; 32],
                their_ik_pub: [0x32; 32],
                their_device_pub: [0x32; 32],
                our_pseudonym: [0x33; 32],
                display_name: None,
            })
            .unwrap();
        db.save_contact_capability(&najwa_storage::types::NewContactMailboxCap {
            contact_id,
            mailbox_id: mid1,
            deposit_capability: vec![0x41; 32],
            fetch_capability: Some(vec![0x42; 32]),
            their_deposit_capability: None,
            their_envelope_secret: None,
            envelope_secret: Some(vec![0x43; 32]),
            capability_type: 2,
            expires_at: None,
            registered_at: None,
            created_at: 1001,
        })
        .unwrap();
        let cap_id = db.get_contact_capabilities(contact_id).unwrap()[0].id;
        assert_eq!(
            core_storage.list_mailboxes_with_ids().await.unwrap().len(),
            1,
            "an unregistered per-contact queue must not be polled"
        );
        db.mark_contact_capability_registered(cap_id, 1002).unwrap();
        let receive_queues = core_storage.list_mailboxes_with_ids().await.unwrap();
        assert_eq!(receive_queues.len(), 2);
        assert_eq!(receive_queues[1].1.fetch_capability, [0x42; 32]);
        assert_eq!(receive_queues[1].1.deposit_capability, [0x41; 32]);
        assert_eq!(receive_queues[1].1.envelope_secret, [0x43; 32]);
    }

    #[tokio::test]
    async fn bridge_persists_reciprocal_contact_and_remote_target() {
        use najwa_crypto::keys::ed25519::Ed25519KeyPair;

        let db = test_db();
        db.save_mailbox(&najwa_storage::types::NewMailbox {
            onion_address: "our-mailbox".into(),
            fetch_capability: vec![0x01; 32],
            deposit_capability: vec![0x02; 32],
            envelope_secret: vec![0x03; 32],
            cover_deposit_capability: None,
            cover_fetch_capability: None,
            cover_envelope_secret: None,
            priority: 1,
            created_at: 1000,
        })
        .unwrap();
        let peer = Ed25519KeyPair::from_seed(&[0x44; 32]);
        let mut remote = MailboxConfig::new("remote-mailbox".into(), [0x10; 32], [0x11; 32]);
        remote.envelope_secret = [0x12; 32];
        let payload =
            najwa_protocol::contact::HandshakePayload::create(&peer, &[remote], "Peer", 24)
                .unwrap();

        let core_storage: &dyn CoreStorage = &db;
        let contact = core_storage
            .create_reciprocal_contact(&payload, &[0x21; 32], &[0x22; 32])
            .await
            .unwrap();
        let caps = core_storage
            .get_contact_capabilities(contact.id)
            .await
            .unwrap();
        assert_eq!(caps.len(), 1);
        assert_eq!(caps[0].mailbox_onion, "remote-mailbox");
        assert_eq!(caps[0].their_deposit_capability, Some([0x11; 32]));
        assert_eq!(caps[0].their_envelope_secret, Some([0x12; 32]));
        let targets: Vec<StoredContactTarget> = db
            .get_setting(&format!("contact_targets:{}", contact.id))
            .unwrap()
            .unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].onion, "remote-mailbox");
    }

    #[tokio::test]
    async fn bridge_prekey_lookup() {
        let db = test_db();
        db.save_prekey(&najwa_storage::types::Prekey {
            key_id: [0x01, 0x02, 0x03, 0x04],
            key_type: najwa_storage::types::PrekeyType::Opk,
            private_key: vec![0xAA; 32],
            public_key: vec![0xBB; 32],
            signature: None,
            created_at: 1000,
            expires_at: None,
            used: false,
            used_at: None,
            mailbox_id: None,
        })
        .unwrap();

        let core_storage: &dyn CoreStorage = &db;
        let kp = core_storage
            .get_opk_keypair(&[0x01, 0x02, 0x03, 0x04])
            .await
            .unwrap()
            .expect("key found");
        assert_eq!(kp.public().to_bytes().len(), 32);

        // Mark used
        core_storage
            .mark_opk_used(&[0x01, 0x02, 0x03, 0x04])
            .await
            .unwrap();
        // Now should return None (used)
        assert!(core_storage
            .get_opk_keypair(&[0x01, 0x02, 0x03, 0x04])
            .await
            .unwrap()
            .is_none());
    }
}
