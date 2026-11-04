//! Payload flag semantics (S07 §4.2) and the `TextReplyContent` reply format
//! (S07 §4.3).
//!
//! Replies use `content_type = 0x02 TextReply` carrying a [`TextReplyContent`].
//! The Payload header is always 66 bytes; flag bit 0 means `Ephemeral`.

use super::error::{MessageError, Result};

/// Payload flag bits (S07 §4.2). Reply semantics do NOT live here — they live in
/// `content_type = 0x02 TextReply` (§4.3).
pub mod payload_flags {
    /// Bit 0 — disappearing message; the conversation timer applies (§4.2).
    pub const EPHEMERAL: u8 = 0x01;
    /// Bit 1 — UI hint only; user-visible delivered/read indicator. Does NOT
    /// gate transport ACKs (§4.2).
    pub const SHOW_DELIVERY_STATUS: u8 = 0x02;
    /// Bit 2 — sender requests a read receipt (§4.2).
    pub const READ_RECEIPT_REQUESTED: u8 = 0x04;
    /// Bits 3–7 — reserved; MUST be zero on the wire (§4.2).
    pub const RESERVED_MASK: u8 = 0xF8;
}

/// Validate a Payload `flags` byte per S07 §4.2: bits 3–7 MUST be zero.
pub fn validate_flags(flags: u8) -> Result<()> {
    if flags & payload_flags::RESERVED_MASK != 0 {
        return Err(MessageError::InvalidFlags(flags));
    }
    Ok(())
}

/// The `content` of a `content_type = 0x02 TextReply` message (S07 §4.3).
///
/// Byte layout: `reply_to_msg_id[16] || text_length(u16 BE) || text(UTF-8)`.
/// `reply_to_msg_id` is the transport `msg_id` of the message being replied to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextReplyContent {
    /// Transport `msg_id` (16 bytes) of the message being replied to.
    pub reply_to_msg_id: [u8; 16],
    /// UTF-8 reply text.
    pub text: String,
}

/// Fixed size of the `TextReplyContent` header (before the variable text).
const TEXT_REPLY_HEADER: usize = 16 + 2;

impl TextReplyContent {
    /// Serialize to the §4.3 content bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let text = self.text.as_bytes();
        let mut out = Vec::with_capacity(TEXT_REPLY_HEADER + text.len());
        out.extend_from_slice(&self.reply_to_msg_id);
        // text_length is a u16 BE — a reply text longer than 65535 bytes is
        // rejected by `from_bytes`; senders MUST keep replies within that bound
        // (far below MAX_CONTENT_SIZE, which the padding layer also enforces).
        out.extend_from_slice(&(text.len() as u16).to_be_bytes());
        out.extend_from_slice(text);
        out
    }

    /// Parse the §4.3 content bytes. The declared `text_length` is authoritative
    /// (any trailing bytes beyond it are rejected as a malformed reply).
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < TEXT_REPLY_HEADER {
            return Err(MessageError::TruncatedPayload);
        }
        let mut reply_to_msg_id = [0u8; 16];
        reply_to_msg_id.copy_from_slice(&data[..16]);
        let text_len = u16::from_be_bytes([data[16], data[17]]) as usize;
        if data.len() != TEXT_REPLY_HEADER + text_len {
            return Err(MessageError::TruncatedPayload);
        }
        let text = std::str::from_utf8(&data[TEXT_REPLY_HEADER..])
            .map_err(|_| MessageError::InvalidUtf8)?
            .to_string();
        Ok(Self {
            reply_to_msg_id,
            text,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_reply_round_trips() {
        let r = TextReplyContent {
            reply_to_msg_id: [0xAB; 16],
            text: "réply 👍".to_string(),
        };
        let bytes = r.to_bytes();
        // reply_to(16) || len(2) || utf8 text
        assert_eq!(&bytes[..16], &[0xAB; 16]);
        let text_bytes = r.text.as_bytes();
        assert_eq!(
            u16::from_be_bytes([bytes[16], bytes[17]]) as usize,
            text_bytes.len()
        );
        assert_eq!(TextReplyContent::from_bytes(&bytes).unwrap(), r);
    }

    #[test]
    fn text_reply_rejects_truncated_and_trailing() {
        // Too short for the header.
        assert!(TextReplyContent::from_bytes(&[0u8; 10]).is_err());
        // Declared length shorter than the actual trailing bytes → rejected
        // (content_length is authoritative, §4.3 / §5).
        let mut bytes = TextReplyContent {
            reply_to_msg_id: [0x01; 16],
            text: "hi".to_string(),
        }
        .to_bytes();
        bytes.push(0xFF); // stray trailing byte
        assert!(TextReplyContent::from_bytes(&bytes).is_err());
    }

    #[test]
    fn text_reply_rejects_bad_utf8() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0x02; 16]);
        bytes.extend_from_slice(&2u16.to_be_bytes());
        bytes.extend_from_slice(&[0xFF, 0xFE]); // invalid UTF-8
        assert!(TextReplyContent::from_bytes(&bytes).is_err());
    }

    #[test]
    fn flag_semantics_match_spec_and_reserved_bits_rejected() {
        // §4.2 bit assignments.
        assert_eq!(payload_flags::EPHEMERAL, 0x01);
        assert_eq!(payload_flags::SHOW_DELIVERY_STATUS, 0x02);
        assert_eq!(payload_flags::READ_RECEIPT_REQUESTED, 0x04);
        // Any combination of the three defined bits is valid.
        assert!(validate_flags(0x00).is_ok());
        assert!(validate_flags(0x07).is_ok());
        // A reserved bit (3–7) set is rejected.
        assert!(validate_flags(0x08).is_err());
        assert!(validate_flags(0x80).is_err());
    }
}
