//! Data model types for the storage layer.
//!
//! Defines all structs and enums used by the storage operations.

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

// ---------------------------------------------------------------------------
// Type aliases for row IDs
// ---------------------------------------------------------------------------

/// Contact row ID.
pub type ContactId = i64;

/// Message row ID.
pub type MessageId = i64;

/// Mailbox row ID.
pub type MailboxId = i64;

// ---------------------------------------------------------------------------
// Contacts
// ---------------------------------------------------------------------------

/// Data required to create a new contact.
#[derive(Debug, Clone)]
pub struct NewContact {
    /// Their pseudonym for us (32 bytes).
    pub pseudonym: [u8; 32],
    /// Their identity public key (32 bytes).
    pub their_ik_pub: [u8; 32],
    /// Their device signing public key (DK_n_pub, 32 bytes) — S03 §5.2, S06 §7.
    /// Equals `their_ik_pub` for a single-device peer.
    pub their_device_pub: [u8; 32],
    /// Our pseudonym for them (32 bytes).
    pub our_pseudonym: [u8; 32],
    /// Optional display name.
    pub display_name: Option<String>,
}

/// Full contact record from the database.
#[derive(Debug, Clone)]
pub struct Contact {
    pub id: ContactId,
    pub pseudonym: [u8; 32],
    pub their_ik_pub: [u8; 32],
    /// Their device signing public key (S03 §5.2); = their_ik_pub single-device.
    pub their_device_pub: [u8; 32],
    pub our_pseudonym: [u8; 32],
    pub display_name: Option<String>,
    pub avatar_hash: Option<Vec<u8>>,
    pub created_at: i64,
    pub last_message_at: Option<i64>,
    pub verified: bool,
    pub blocked: bool,
}

// ---------------------------------------------------------------------------
// Ratchet Sessions
// ---------------------------------------------------------------------------

/// Double Ratchet session state for a contact.
#[derive(Clone)]
pub struct RatchetState {
    /// Our current sending ratchet private key (32 bytes).
    pub dhs_private: Option<Vec<u8>>,
    /// Our current sending ratchet public key (32 bytes).
    pub dhs_public: Option<Vec<u8>>,
    /// Their current ratchet public key (32 bytes).
    pub dhr: Option<Vec<u8>>,
    /// Root key (32 bytes).
    pub rk: Option<Vec<u8>>,
    /// Sending chain key (32 bytes).
    pub cks: Option<Vec<u8>>,
    /// Receiving chain key (32 bytes).
    pub ckr: Option<Vec<u8>>,
    /// Messages sent in current sending chain.
    pub ns: u32,
    /// Messages received in current receiving chain.
    pub nr: u32,
    /// Previous sending chain length.
    pub pn: u32,
    /// Our previous sending-epoch public key (32 bytes), sent as `epoch_link`
    /// (S06 §3.10). `None` before the first DH step and on pre-column rows.
    pub prev_dhs_pub: Option<Vec<u8>>,
    /// Session established timestamp.
    pub established_at: i64,
    /// Last activity timestamp.
    pub last_activity: i64,
}

// ---------------------------------------------------------------------------
// Skipped Keys
// ---------------------------------------------------------------------------

/// A skipped message key (for out-of-order message delivery).
#[derive(Clone)]
pub struct SkippedKey {
    /// DH public key this chain is associated with (32 bytes).
    pub dh_pub: [u8; 32],
    /// Message number in the chain.
    pub message_number: u32,
    /// The actual message key (32 bytes).
    pub message_key: [u8; 32],
    /// When the key was stored.
    pub created_at: i64,
    /// When the key expires: `created_at + SKIP_KEY_EXPIRY_SECS` (90 days).
    pub expires_at: i64,
}

impl Drop for RatchetState {
    fn drop(&mut self) {
        self.dhs_private.zeroize();
        self.rk.zeroize();
        self.cks.zeroize();
        self.ckr.zeroize();
    }
}

impl Drop for SkippedKey {
    fn drop(&mut self) {
        self.message_key.zeroize();
    }
}

impl Drop for Prekey {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

/// Message direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum MessageDirection {
    Received = 0,
    Sent = 1,
}

impl MessageDirection {
    pub fn from_i32(v: i32) -> Self {
        match v {
            0 => Self::Received,
            _ => Self::Sent,
        }
    }
}

/// Content type for messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ContentType {
    Text = 0,
    Image = 1,
    Audio = 2,
    Video = 3,
    File = 4,
    Location = 5,
    Contact = 6,
    System = 7,
    TextReply = 8,
    Binary = 9,
    FileMetadata = 10,
    FileChunk = 11,
    ReciprocalHandshake = 12,
    Control = 13,
}

impl ContentType {
    pub fn from_i32(v: i32) -> Self {
        match v {
            0 => Self::Text,
            1 => Self::Image,
            2 => Self::Audio,
            3 => Self::Video,
            4 => Self::File,
            5 => Self::Location,
            6 => Self::Contact,
            7 => Self::System,
            8 => Self::TextReply,
            9 => Self::Binary,
            10 => Self::FileMetadata,
            11 => Self::FileChunk,
            12 => Self::ReciprocalHandshake,
            13 => Self::Control,
            _ => Self::Text,
        }
    }
}

/// Message delivery/read status (for sent messages).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum MessageStatus {
    Pending = 0,
    Sent = 1,
    Delivered = 2,
    Read = 3,
    Failed = 4,
    /// Exceeded max retries — user must manually re-send.
    PermanentlyFailed = 5,
}

impl MessageStatus {
    pub fn from_i32(v: i32) -> Self {
        match v {
            0 => Self::Pending,
            1 => Self::Sent,
            2 => Self::Delivered,
            3 => Self::Read,
            4 => Self::Failed,
            5 => Self::PermanentlyFailed,
            _ => Self::Pending,
        }
    }
}

/// Full message record.
#[derive(Debug, Clone)]
pub struct Message {
    pub id: MessageId,
    pub contact_id: ContactId,
    /// Unique message ID (16 bytes).
    pub msg_id: [u8; 16],
    pub direction: MessageDirection,
    pub content_type: ContentType,
    pub flags: i32,
    /// Encrypted content blob.
    pub content: Vec<u8>,
    /// Local path to associated media file.
    pub file_path: Option<String>,
    pub timestamp: i64,
    pub received_at: Option<i64>,
    pub read_at: Option<i64>,
    pub status: MessageStatus,
    pub retry_count: i32,
    pub last_retry_at: Option<i64>,
    /// Optional reply reference (16-byte msg_id).
    pub reply_to_msg_id: Option<Vec<u8>>,
    /// Disappearing message timer duration in seconds (full `u32` range, S12 §2.1).
    pub disappear_timer: Option<u32>,
    /// Unix timestamp when message should be deleted.
    pub disappear_at: Option<i64>,
    /// Encrypted wire message bytes for retry (cleared after successful send).
    pub encrypted_blob: Option<Vec<u8>>,
    /// Group ID (32 bytes) for group messages. None for 1:1 messages.
    pub group_id: Option<[u8; 32]>,
    /// Display name of the sender (for group messages).
    pub sender_display_name: Option<String>,
    /// Sender's clock at send time, embedded in the wire plaintext and stored by both parties.
    /// Used as the stable cross-device correlation ID for reply scroll-to-original.
    pub origin_timestamp_ms: Option<i64>,
    /// Fully-encrypted wire blob for send retry. Separate from `encrypted_blob`
    /// which stores reply metadata. Cleared after successful send or permanent failure.
    pub retry_wire_blob: Option<Vec<u8>>,
}

/// Data required to save a new message.
#[derive(Debug, Clone)]
pub struct NewMessage {
    pub contact_id: ContactId,
    pub msg_id: [u8; 16],
    pub direction: MessageDirection,
    pub content_type: ContentType,
    pub flags: i32,
    pub content: Vec<u8>,
    pub file_path: Option<String>,
    pub timestamp: i64,
    pub received_at: Option<i64>,
    pub status: MessageStatus,
    pub reply_to_msg_id: Option<Vec<u8>>,
    pub disappear_timer: Option<u32>,
    /// Encrypted wire message bytes for retry.
    pub encrypted_blob: Option<Vec<u8>>,
    /// Group ID (32 bytes) for group messages. None for 1:1 messages.
    pub group_id: Option<[u8; 32]>,
    /// Display name of the sender (for group messages).
    pub sender_display_name: Option<String>,
    /// Sender's clock at send time, embedded in the wire plaintext and stored by both parties.
    pub origin_timestamp_ms: Option<i64>,
    /// Fully-encrypted wire blob for send retry.
    pub retry_wire_blob: Option<Vec<u8>>,
}

/// Durable S07 §8.5 source record for one sent user-content message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundRepairRecord {
    pub contact_id: ContactId,
    pub dh_pub: [u8; 32],
    pub message_number: u32,
    pub msg_id: [u8; 16],
    pub timestamp: u64,
    pub logical_seq: u32,
    pub content_type: u8,
    pub flags: u8,
    pub content: Vec<u8>,
    pub created_at: i64,
}

/// Effects committed atomically with an authenticated S07 confirmation frame.
#[derive(Debug, Clone)]
pub enum DeliveryConfirmation {
    /// Inclusive ranges on the original sender's chain, never a global cursor.
    Ack(Vec<([u8; 32], u32, u32)>),
    ReadReceipt {
        msg_id: [u8; 16],
        timestamp: u64,
    },
}

// ---------------------------------------------------------------------------
// Prekeys
// ---------------------------------------------------------------------------

/// Prekey type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum PrekeyType {
    /// Signed prekey.
    Spk = 0,
    /// One-time prekey.
    Opk = 1,
}

impl PrekeyType {
    pub fn from_i32(v: i32) -> Self {
        match v {
            0 => Self::Spk,
            _ => Self::Opk,
        }
    }
}

/// Prekey record.
#[derive(Clone)]
pub struct Prekey {
    /// Key ID (4 bytes).
    pub key_id: [u8; 4],
    pub key_type: PrekeyType,
    /// Private key (32 bytes).
    pub private_key: Vec<u8>,
    /// Public key (32 bytes).
    pub public_key: Vec<u8>,
    /// Signature (64 bytes, only for SPK).
    pub signature: Option<Vec<u8>>,
    pub created_at: i64,
    /// Grace deadline for retired SPKs or served but unreceived OPKs.
    pub expires_at: Option<i64>,
    /// For OPKs: true when consumed.
    pub used: bool,
    pub used_at: Option<i64>,
    /// Which mailbox this was uploaded to.
    pub mailbox_id: Option<MailboxId>,
}

impl std::fmt::Debug for RatchetState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RatchetState")
            .field("ns", &self.ns)
            .field("nr", &self.nr)
            .field("pn", &self.pn)
            .finish_non_exhaustive()
    }
}
impl std::fmt::Debug for SkippedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SkippedKey")
            .field("message_number", &self.message_number)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}
impl std::fmt::Debug for Prekey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Prekey")
            .field("key_id", &self.key_id)
            .field("key_type", &self.key_type)
            .field("used", &self.used)
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Mailboxes
// ---------------------------------------------------------------------------

/// Mailbox record.
#[derive(Debug, Clone)]
pub struct Mailbox {
    pub id: MailboxId,
    /// .onion address.
    pub onion_address: String,
    /// Fetch capability (32 bytes).
    pub fetch_capability: Vec<u8>,
    /// Primary deposit capability (32 bytes).
    pub deposit_capability: Vec<u8>,
    /// D3 envelope secret (32 bytes) that keys the deposit envelope for this
    /// mailbox's deposit cap. Empty for rows created before D3.
    pub envelope_secret: Vec<u8>,
    /// Cover traffic deposit capability (S10 §5).
    pub cover_deposit_capability: Option<Vec<u8>>,
    /// Cover traffic fetch capability (S10 §5).
    pub cover_fetch_capability: Option<Vec<u8>>,
    /// S10 §5: self-generated envelope secret keying cover deposits.
    /// Never shared with anyone, never sent to the server.
    pub cover_envelope_secret: Option<Vec<u8>>,
    /// Set only after the mailbox server accepts this cover capability pair.
    /// NULL pairs must never enter the cover scheduler snapshot.
    pub cover_registered_at: Option<i64>,
    pub priority: i32,
    pub last_success: Option<i64>,
    pub last_failure: Option<i64>,
    pub failure_count: i32,
    pub messages_stored: i32,
    pub quota_limit: Option<i32>,
    pub enabled: bool,
    pub created_at: i64,
    /// Server-assigned ID of the last fetched message (poll cursor).
    pub last_seen_id: Option<String>,
}

/// Data required to create a new mailbox.
#[derive(Debug, Clone)]
pub struct NewMailbox {
    pub onion_address: String,
    pub fetch_capability: Vec<u8>,
    pub deposit_capability: Vec<u8>,
    /// D3 envelope secret (32 bytes); empty if not yet minted.
    pub envelope_secret: Vec<u8>,
    pub cover_deposit_capability: Option<Vec<u8>>,
    pub cover_fetch_capability: Option<Vec<u8>>,
    /// S10 §5: cover envelope secret (self-generated, never leaves the device).
    pub cover_envelope_secret: Option<Vec<u8>>,
    pub priority: i32,
    pub created_at: i64,
}

impl NewMailbox {
    /// Create a new mailbox with auto-generated cover capabilities (S10 §5).
    ///
    /// Cover caps are separate CSPRNG(32) values not linked to the
    /// primary fetch/deposit caps, preventing traffic correlation.
    pub fn with_cover_caps(
        onion_address: String,
        fetch_capability: Vec<u8>,
        deposit_capability: Vec<u8>,
        priority: i32,
        created_at: i64,
    ) -> Self {
        Self {
            onion_address,
            fetch_capability,
            deposit_capability,
            // D3: mint the envelope secret alongside the deposit cap.
            envelope_secret: najwa_crypto::random::random_bytes_vec(32),
            cover_deposit_capability: Some(najwa_crypto::random::random_bytes_vec(32)),
            cover_fetch_capability: Some(najwa_crypto::random::random_bytes_vec(32)),
            // S10 §5: cover blobs get their own envelope secret, never shared.
            cover_envelope_secret: Some(najwa_crypto::random::random_bytes_vec(32)),
            priority,
            created_at,
        }
    }
}

// ---------------------------------------------------------------------------
// Contact Mailbox Capabilities
// ---------------------------------------------------------------------------

/// Per-contact mailbox capability record.
#[derive(Debug, Clone)]
pub struct ContactMailboxCap {
    pub id: i64,
    pub contact_id: ContactId,
    pub mailbox_id: MailboxId,
    /// Capability they use to send to us (32 bytes).
    pub deposit_capability: Vec<u8>,
    /// Per-contact fetch capability for incoming messages (32 bytes, S05 §8).
    pub fetch_capability: Option<Vec<u8>>,
    /// Their capabilities for us to send to them (32 bytes).
    pub their_deposit_capability: Option<Vec<u8>>,
    /// D3: their envelope secret, paired with `their_deposit_capability`, used to
    /// key the deposit envelope when sending to them (32 bytes). None pre-D3.
    pub their_envelope_secret: Option<Vec<u8>>,
    /// S05 §8 step 10: OUR envelope secret for this per-contact capability —
    /// the one the CONTACT uses when depositing to us. Never sent to a server.
    pub envelope_secret: Option<Vec<u8>>,
    /// 0x01 ephemeral (TTL via `expires_at`) / 0x02 long-term (S05 §5/§8).
    pub capability_type: i32,
    pub expires_at: Option<i64>,
    /// None ⇒ NOT registered on the mailbox server; MUST NOT be advertised.
    pub registered_at: Option<i64>,
    pub created_at: i64,
    pub revoked_at: Option<i64>,
}

/// Data required to save a new contact capability.
#[derive(Debug, Clone)]
pub struct NewContactMailboxCap {
    pub contact_id: ContactId,
    pub mailbox_id: MailboxId,
    pub deposit_capability: Vec<u8>,
    /// Per-contact fetch capability (32 bytes, S05 §8).
    pub fetch_capability: Option<Vec<u8>>,
    pub their_deposit_capability: Option<Vec<u8>>,
    /// D3: their envelope secret, paired with `their_deposit_capability`. None pre-D3.
    pub their_envelope_secret: Option<Vec<u8>>,
    /// S05 §8 step 10: OUR envelope secret for this per-contact capability —
    /// the one the CONTACT uses to envelope-encrypt deposits to us. Handed to
    /// them in the handshake / MailboxUpdate; NEVER sent to a server (S07 §3).
    pub envelope_secret: Option<Vec<u8>>,
    /// S05 §5/§8: 0x01 = ephemeral handshake cap (TTL via `expires_at`),
    /// 0x02 = long-term per-contact cap.
    pub capability_type: i32,
    /// Unix seconds after which an ephemeral cap is dead. None for long-term.
    pub expires_at: Option<i64>,
    /// When this cap was registered on the mailbox server. **None means NOT
    /// registered** — such a cap MUST NOT be advertised to a contact, because
    /// deposits to it would be rejected.
    pub registered_at: Option<i64>,
    pub created_at: i64,
}

// ---------------------------------------------------------------------------
// Ephemeral Handshake Capabilities (S05 §5)
// ---------------------------------------------------------------------------

/// A pre-contact, per-mailbox capability advertised in exactly one QR or URI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EphemeralHandshakeCap {
    pub id: i64,
    pub mailbox_id: MailboxId,
    pub deposit_capability: Vec<u8>,
    pub fetch_capability: Vec<u8>,
    /// Device-held envelope secret; never sent to the mailbox server.
    pub envelope_secret: Vec<u8>,
    /// Always 0x01 for this table.
    pub capability_type: i32,
    pub expires_at: i64,
    /// None means registration has not succeeded and the cap MUST NOT be advertised.
    pub registered_at: Option<i64>,
    /// Set atomically with the first successfully committed X3DH Initial.
    pub accepted_at: Option<i64>,
    /// Set after the server accepts deactivation keyed by `fetch_capability`.
    pub deactivated_at: Option<i64>,
    pub created_at: i64,
}

/// Data required to mint one pre-contact capability for one mailbox.
#[derive(Debug, Clone)]
pub struct NewEphemeralHandshakeCap {
    pub mailbox_id: MailboxId,
    pub deposit_capability: Vec<u8>,
    pub fetch_capability: Vec<u8>,
    pub envelope_secret: Vec<u8>,
    pub capability_type: i32,
    pub expires_at: i64,
    pub created_at: i64,
}

/// A self-owned type-2 queue that pads real polls (S08 §6.1.1). It is never
/// shared, its deposits are cover blobs (S10 §5.1) and it has no envelope secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DummyCapability {
    pub id: i64,
    pub mailbox_id: MailboxId,
    pub fetch_capability: Vec<u8>,
    pub deposit_capability: Vec<u8>,
    /// None until the server accepts the registration; only then is it polled.
    pub registered_at: Option<i64>,
}

// ---------------------------------------------------------------------------
// Pending Introductions (S05 §11)
// ---------------------------------------------------------------------------

/// Introduction row ID.
pub type IntroductionId = i64;

/// Status of a pending introduction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum IntroductionStatus {
    Pending = 0,
    Accepted = 1,
    Rejected = 2,
    Expired = 3,
}

impl IntroductionStatus {
    pub fn from_i32(v: i32) -> Self {
        match v {
            0 => Self::Pending,
            1 => Self::Accepted,
            2 => Self::Rejected,
            3 => Self::Expired,
            _ => Self::Pending,
        }
    }
}

/// Full pending introduction record from the database.
#[derive(Debug, Clone)]
pub struct PendingIntroduction {
    pub id: IntroductionId,
    pub introducer_contact_id: ContactId,
    pub introduced_ik_pub: [u8; 32],
    pub introduced_display_name: String,
    pub introducer_ik_pub: [u8; 32],
    pub payload_blob: Vec<u8>,
    pub is_anonymous: bool,
    pub status: IntroductionStatus,
    pub created_at: i64,
    pub expires_at: i64,
    pub resolved_at: Option<i64>,
}

/// Data required to save a new pending introduction.
#[derive(Debug, Clone)]
pub struct NewPendingIntroduction {
    pub introducer_contact_id: ContactId,
    pub introduced_ik_pub: [u8; 32],
    pub introduced_display_name: String,
    pub introducer_ik_pub: [u8; 32],
    pub payload_blob: Vec<u8>,
    pub is_anonymous: bool,
    pub created_at: i64,
    pub expires_at: i64,
}

// ---------------------------------------------------------------------------
// Identity History (S02 §18.1: contact identity rotation)
// ---------------------------------------------------------------------------

/// Identity history entry for key rotation tracking.
#[derive(Debug, Clone)]
pub struct IdentityHistoryEntry {
    pub id: Option<i64>,
    /// Contact whose identity key rotated (S03 §5.14). FK contacts(id) ON DELETE
    /// CASCADE, so a deleted contact's rotation history does not survive.
    pub contact_id: ContactId,
    /// Previous identity public key (32 bytes).
    pub old_ik_pub: Vec<u8>,
    /// New identity public key (32 bytes).
    pub new_ik_pub: Vec<u8>,
    pub rotated_at: i64,
    pub reason: Option<String>,
}

// ---------------------------------------------------------------------------
// Onion Pinning (S03 §5.15; the application does not use this table)
// ---------------------------------------------------------------------------

/// Onion address pin for trust-on-first-use.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnionPin {
    pub onion_address: String,
    /// Expected public key hash (32 bytes).
    pub expected_key_hash: Vec<u8>,
    pub first_seen: i64,
    pub last_verified: i64,
    pub pin_count: i32,
}
