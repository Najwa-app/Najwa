//! Core messaging types (S08 §2, §9).

use najwa_protocol::mailbox::types::MailboxConfig;
pub use najwa_storage::types::DeliveryConfirmation;

/// Unique identifier for a contact (database row ID).
pub type ContactId = u64;

/// Database row ID for a message.
pub type MessageId = i64;

/// A contact record.
#[derive(Debug, Clone)]
pub struct Contact {
    pub id: ContactId,
    pub their_pseudonym: [u8; 32],
    pub our_pseudonym: [u8; 32],
    pub their_ik_pub: [u8; 32],
    pub display_name: Option<String>,
    pub blocked: bool,
    /// Whether the contact's identity key has been verified out-of-band.
    pub verified: bool,
    /// SHA-256 hash of the contact's avatar image (if any).
    pub avatar_hash: Option<Vec<u8>>,
    /// Unix timestamp when the contact was created.
    pub created_at: Option<i64>,
    /// Unix timestamp of the last message in this conversation.
    pub last_message_at: Option<i64>,
}

/// Message direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Sent,
    Received,
}

/// Message delivery status (S08 §5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageStatus {
    /// Queued but not yet deposited.
    Pending,
    /// Deposited to mailbox.
    Sent,
    /// Delivery ACK received.
    Delivered,
    /// Read receipt received.
    Read,
    /// Send failed (will retry).
    Failed,
}

/// A stored message record.
#[derive(Debug, Clone)]
pub struct Message {
    pub id: MessageId,
    pub contact_id: ContactId,
    pub msg_id: [u8; 16],
    pub direction: Direction,
    pub content_type: u8,
    /// Authenticated S07 flags, retained for receipt opt-in and UI hints.
    pub flags: u8,
    pub content: Vec<u8>,
    pub timestamp: u64,
    pub status: MessageStatus,
    /// Ratchet chain index for ordering.
    pub ratchet_index: Option<u32>,
}

/// Result of sending a message.
#[derive(Debug, Clone)]
pub struct SentMessage {
    pub id: MessageId,
    pub msg_id: [u8; 16],
}

/// A received and decrypted message.
#[derive(Debug, Clone)]
pub struct ReceivedMessage {
    pub contact_id: ContactId,
    pub msg_id: [u8; 16],
    pub content_type: u8,
    pub content: Vec<u8>,
    pub timestamp: u64,
    pub is_control: bool,
}

/// Per-contact mailbox capability.
#[derive(Debug, Clone)]
pub struct ContactCapability {
    pub contact_id: ContactId,
    /// Database mailbox ID used for health tracking (S08 §9.3).
    pub mailbox_id: MailboxId,
    pub mailbox_onion: String,
    pub mailbox_fetch_cap: [u8; 32],
    pub mailbox_deposit_cap: [u8; 32],
    pub their_deposit_capability: Option<[u8; 32]>,
    /// D3: their envelope secret, paired with `their_deposit_capability`, used to
    /// key the deposit envelope when sending to them.
    pub their_envelope_secret: Option<[u8; 32]>,
}

impl ContactCapability {
    /// Build a `MailboxConfig` from this capability.
    pub fn mailbox_config(&self) -> MailboxConfig {
        MailboxConfig::new(
            self.mailbox_onion.clone(),
            self.mailbox_fetch_cap,
            self.mailbox_deposit_cap,
        )
    }
}

// ---------------------------------------------------------------------------
// S08 §9: Multi-Path Delivery types (§9.1, §9.3)
// ---------------------------------------------------------------------------

/// Unique identifier for a mailbox.
pub type MailboxId = i64;

/// Delivery strategy for multi-path sending (S08 §9.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DeliveryStrategy {
    /// Send to primary mailbox only. Fallback on failure.
    Primary,
    /// Send to ALL mailboxes in random order, paced (S08 §9.1). Maximum reliability.
    Paranoid,
    /// Send to primary + one random backup. Balance reliability/traffic.
    #[default]
    Adaptive,
}

/// Result of a single mailbox delivery attempt.
#[derive(Debug, Clone)]
pub struct MailboxDeliveryResult {
    /// Which mailbox was targeted.
    pub mailbox_id: MailboxId,
    /// Whether the deposit succeeded.
    pub success: bool,
    /// Server-assigned message ID on success.
    pub message_id: Option<String>,
    /// Error description on failure.
    pub error: Option<String>,
}

/// Aggregated report of a multi-path delivery.
#[derive(Debug, Clone)]
pub struct DeliveryReport {
    /// Per-mailbox results.
    pub results: Vec<MailboxDeliveryResult>,
}

impl DeliveryReport {
    /// Create an empty report.
    pub fn new() -> Self {
        Self {
            results: Vec::new(),
        }
    }

    /// Record a successful deposit.
    pub fn record_success(&mut self, mailbox_id: MailboxId, message_id: Option<String>) {
        self.results.push(MailboxDeliveryResult {
            mailbox_id,
            success: true,
            message_id,
            error: None,
        });
    }

    /// Record a failed deposit.
    pub fn record_failure(&mut self, mailbox_id: MailboxId, error: String) {
        self.results.push(MailboxDeliveryResult {
            mailbox_id,
            success: false,
            message_id: None,
            error: Some(error),
        });
    }

    /// Whether at least one mailbox accepted the message.
    pub fn any_success(&self) -> bool {
        self.results.iter().any(|r| r.success)
    }

    /// Count of successful deliveries.
    pub fn success_count(&self) -> usize {
        self.results.iter().filter(|r| r.success).count()
    }

    /// Count of failed deliveries.
    pub fn failure_count(&self) -> usize {
        self.results.iter().filter(|r| !r.success).count()
    }
}

impl Default for DeliveryReport {
    fn default() -> Self {
        Self::new()
    }
}

/// Mailbox health record (S08 §9.3).
#[derive(Debug, Clone)]
pub struct MailboxHealth {
    pub mailbox_id: MailboxId,
    pub onion_address: String,
    pub consecutive_failures: u32,
    pub total_successes: u64,
    pub total_failures: u64,
    pub last_success: Option<u64>,
    pub last_failure: Option<u64>,
    pub enabled: bool,
}

/// Content wrapper for outgoing messages.
#[derive(Debug, Clone)]
pub enum MessageContent {
    /// Plain text message.
    Text(String),
    /// Text message with a reply reference.
    TextReply { text: String, reply_to: [u8; 16] },
    /// Arbitrary pre-encoded content with an explicit content-type byte (§4.1)
    /// and optional reply reference. Lets non-text sends — file chunks, and any
    /// future content type — delegate through `send_message` instead of
    /// duplicating the wire path. `content_type` MUST be a valid `ContentType`.
    Raw {
        content_type: u8,
        bytes: Vec<u8>,
        reply_to: Option<[u8; 16]>,
    },
}

impl MessageContent {
    /// Content type byte for the payload.
    pub fn content_type_byte(&self) -> u8 {
        match self {
            Self::Text(_) => 0x01,
            Self::TextReply { .. } => 0x02,
            Self::Raw {
                content_type: 0x01,
                reply_to: Some(_),
                ..
            } => 0x02,
            Self::Raw { content_type, .. } => *content_type,
        }
    }

    /// Serialize content to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::Text(s) => s.as_bytes().to_vec(),
            Self::TextReply { text, reply_to } => najwa_protocol::message::TextReplyContent {
                reply_to_msg_id: *reply_to,
                text: text.clone(),
            }
            .to_bytes(),
            Self::Raw {
                content_type: 0x01,
                bytes,
                reply_to: Some(id),
            } => {
                let mut out = id.to_vec();
                out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
                out.extend_from_slice(bytes);
                out
            }
            Self::Raw { bytes, .. } => bytes.clone(),
        }
    }

    /// Reply-to message ID, if any.
    pub fn reply_to(&self) -> Option<[u8; 16]> {
        match self {
            Self::Text(_) => None,
            Self::TextReply { reply_to, .. } => Some(*reply_to),
            Self::Raw { reply_to, .. } => *reply_to,
        }
    }
}

/// A group record. Not used by the app or the receive path.
#[derive(Debug, Clone)]
pub struct GroupRecord {
    /// 32-byte group identifier.
    pub group_id: [u8; 32],
    /// Human-readable group name.
    pub group_name: String,
    /// Unix timestamp of group creation.
    pub created_at: i64,
    /// Group version (incremented on membership changes).
    pub version: u32,
    /// Whether the group is active.
    pub is_active: bool,
    /// Shared group-key generation.
    pub generation: u32,
    /// Delivery mode: 0 = pairwise, 1 = shared group key.
    pub security_mode: u8,
}

/// A per-member sender-key state record. Not used by the app or the receive
/// path.
///
/// Stores the chain key and signing public key for a specific member in a group,
/// enabling decryption of their group messages.
#[derive(Debug, Clone)]
pub struct SenderKeyRecord {
    /// Current chain key (32 bytes, advanced on each message).
    pub chain_key: [u8; 32],
    /// Member's Ed25519 signing public key (32 bytes).
    pub signing_public: [u8; 32],
    /// Expected next counter value.
    pub expected_counter: u32,
}
