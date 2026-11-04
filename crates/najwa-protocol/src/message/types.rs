//! Message types and structures (S07 §2, §4).

use crate::ratchet::header::RatchetHeader;

use super::error::{MessageError, Result};

/// Current wire protocol version.
pub const WIRE_VERSION: u8 = 0x01;

/// Maximum plaintext content size before padding (S07 §5.4):
/// `262144 (largest bucket) − 160 (0x02 fixed overhead) − 66 (PAYLOAD_HEADER_SIZE)`.
/// Large content (files) should use the chunked file transfer protocol (S11).
pub const MAX_CONTENT_SIZE: usize = 262_144 - 160 - 66;

/// Final deposited-blob bucket sizes (S07 §5.1 — normative, 11 buckets). The
/// bucket is the byte count the mailbox server stores and an observer sees.
pub const PADDING_BUCKETS: [usize; 11] = [
    256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536, 131072, 262144,
];

/// Deposit-envelope overhead (S07 §3.1): envelope nonce(24) + tag(16).
pub const ENVELOPE_OVERHEAD: usize = 40;

/// Fixed per-message-type overhead in the deposited blob (S07 §5.1.1):
/// envelope overhead(40) + wire_prefix(80 for 0x02/0x11/0x12; 183/187 for
/// Initial without/with OPK) + AEAD nonce(24) + tag(16) = 160 / 263 / 267.
/// The padded plaintext target is
/// `bucket - fixed_overhead(message_type, has_opk)`.
pub fn fixed_overhead(message_type: MessageType, has_opk: bool) -> usize {
    match message_type {
        MessageType::Initial => 263 + usize::from(has_opk) * 4,
        _ => 160,
    }
}

/// §5.2: the smallest bucket whose padded-plaintext target fits `plaintext_len`,
/// or `None` if no bucket can hold it (payload exceeds the largest bucket —
/// callers MUST chunk per S11 rather than send). Buckets smaller than the
/// fixed overhead have no valid target and are skipped (e.g. Initial cannot
/// land on the 256-byte bucket, §5.1.1). Returns `Option` rather than
/// panicking: `plaintext_len` can be attacker-influenced via received content.
pub fn pad_to_bucket(plaintext_len: usize, fixed_overhead: usize) -> Option<usize> {
    PADDING_BUCKETS
        .iter()
        .filter(|&&b| b > fixed_overhead)
        .find(|&&b| plaintext_len <= b - fixed_overhead)
        .copied()
}

/// Message type discriminant (S07 §2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    /// First message (contains X3DH header).
    Initial,
    /// Regular message.
    Normal,
    /// Delivery read receipt (S07 §8.2): plaintext is the 24-byte
    /// `ReadReceiptContent` under a u16 length prefix (no Payload wrap).
    ReadReceipt,
    /// Cumulative delivery acknowledgment (S07 §8.1 — the only ACK format):
    /// plaintext is the `CumulativeAck` struct under a u16 length prefix.
    CumulativeAck,
    /// Preserve the authenticated wire byte for S07 §10 receiver handling.
    Unknown(u8),
}

impl MessageType {
    pub fn as_byte(self) -> u8 {
        match self {
            Self::Initial => 0x01,
            Self::Normal => 0x02,
            Self::ReadReceipt => 0x11,
            Self::CumulativeAck => 0x12,
            Self::Unknown(byte) => byte,
        }
    }
}

impl TryFrom<u8> for MessageType {
    type Error = MessageError;

    /// Unknown types retain their byte so the receiver can authenticate and
    /// durably consume their chain position before discarding the plaintext.
    fn try_from(byte: u8) -> Result<Self> {
        match byte {
            0x01 => Ok(Self::Initial),
            0x02 => Ok(Self::Normal),
            0x11 => Ok(Self::ReadReceipt),
            0x12 => Ok(Self::CumulativeAck),
            unknown => Ok(Self::Unknown(unknown)),
        }
    }
}

/// Content type discriminant (S07 §4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ContentType {
    Text = 0x01,
    TextReply = 0x02,
    Binary = 0x03,
    /// S05 §8.2: the acceptor's own `HandshakePayload`, carried inside the
    /// Initial message's encrypted body so the QR/URI creator learns where to
    /// reply. `content` is exactly the §2.1 HandshakePayload serialisation.
    ///
    /// Load-bearing, not an optimisation: X3DH is asymmetric, so a single scan
    /// already lets the acceptor DECRYPT the creator's Initial (it carries the
    /// creator's IK + EK and the acceptor uses its own prekey privates). What
    /// the acceptor cannot otherwise obtain is the creator's mailbox address
    /// and deposit capability — an addressing gap, not a decryption one.
    /// Without this variant the handshake cannot complete bidirectionally and
    /// both parties are forced to exchange QR/URI out of band.
    ReciprocalHandshake = 0x04,
    /// S11 §2.2.1: file-transfer metadata (session_id, filename, total size,
    /// MIME type, chunk_count, SHA-256). Registry:
    /// docs/reference/message-types.md.
    FileMetadata = 0x10,
    /// S11 §2.2.1: one chunk of a file transfer (session_id, index, data).
    FileChunk = 0x11,
    Control = 0x20,
}

impl TryFrom<u8> for ContentType {
    type Error = MessageError;

    fn try_from(byte: u8) -> Result<Self> {
        match byte {
            0x01 => Ok(Self::Text),
            0x02 => Ok(Self::TextReply),
            0x03 => Ok(Self::Binary),
            0x04 => Ok(Self::ReciprocalHandshake),
            0x10 => Ok(Self::FileMetadata),
            0x11 => Ok(Self::FileChunk),
            0x20 => Ok(Self::Control),
            unknown => Err(MessageError::UnknownContentType(unknown)),
        }
    }
}

/// Message header. Every WireMessage carries the 72-byte Double Ratchet
/// header (S07 §2.2); there is no other header kind.
#[derive(Debug, Clone)]
pub enum MessageHeader {
    /// 1:1 Double Ratchet header (72 bytes) — S06.
    Ratchet(RatchetHeader),
}



/// Outer wire message sent over the mailbox (S07 §2).
#[derive(Debug, Clone)]
pub struct WireMessage {
    /// Protocol version (currently 0x01).
    pub version: u8,
    /// Message type discriminant.
    pub message_type: MessageType,
    /// Polymorphic header.
    pub header: MessageHeader,
    /// Cleartext X3DH header (S06 §2.4), present ONLY for `Initial`
    /// bootstrap messages. It travels in the wire prefix — NOT inside the AEAD
    /// (the ratchet key is derived from it) — and is integrity-bound via the
    /// message AAD (S07 §2.3). `None` for every other message type.
    pub x3dh_header: Option<Vec<u8>>,
    /// AEAD payload: `nonce(24) || ciphertext || tag(16)` for ratchet messages.
    pub encrypted_payload: Vec<u8>,
}

/// Decrypted payload of an Initial or Standard frame (S07 §4).
#[derive(Debug, Clone)]
pub struct Payload {
    /// Sender's pairwise pseudonym (32 bytes).
    pub sender_pseudonym: [u8; 32],
    /// Content type.
    pub content_type: ContentType,
    /// Flags byte.
    pub flags: u8,
    /// Unix timestamp (seconds).
    pub timestamp: u64,
    /// Unique message ID (16 bytes).
    pub msg_id: [u8; 16],
    /// Per-contact monotonic outbound uniqueness component (S07 §4).
    /// Receivers MUST treat it as opaque, never as a delivery cursor; gap
    /// detection uses authenticated ratchet message numbers (S07 §8.5).
    pub logical_seq: u32,
    /// Type-dependent content.
    pub content: Vec<u8>,
}

#[cfg(test)]
mod content_type_tests {
    use super::*;

    // S05 §8.2 / message-type registry: 0x04 ReciprocalHandshake. The registry
    // has carried this since 2026-06-10 while the enum did not, which is why
    // the acceptor's mailbox coordinates could never reach the creator in-band
    // and both parties had to exchange QR/URI out of band.
    #[test]
    fn reciprocal_handshake_is_0x04() {
        assert_eq!(ContentType::ReciprocalHandshake as u8, 0x04);
        assert_eq!(
            ContentType::try_from(0x04u8).unwrap(),
            ContentType::ReciprocalHandshake
        );
    }

    // Pin the neighbours so a future insertion cannot silently shift slots.
    // 0x10/0x11 are the S11 §2.2.1 file-transfer payloads
    // (docs/reference/message-types.md).
    #[test]
    fn content_type_discriminants_are_stable() {
        for (byte, expected) in [
            (0x01u8, ContentType::Text),
            (0x02, ContentType::TextReply),
            (0x03, ContentType::Binary),
            (0x04, ContentType::ReciprocalHandshake),
            (0x10, ContentType::FileMetadata),
            (0x11, ContentType::FileChunk),
            (0x20, ContentType::Control),
        ] {
            assert_eq!(ContentType::try_from(byte).unwrap(), expected);
            assert_eq!(expected as u8, byte);
        }
        // 0x05 is unassigned and must still be rejected, not silently mapped.
        assert!(ContentType::try_from(0x05u8).is_err());
    }
}
