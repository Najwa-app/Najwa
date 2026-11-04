//! Wire message and payload serialization (S07 §2, §4).

use crate::ratchet::header::RatchetHeader;

use super::error::{MessageError, Result};
use super::types::*;

impl MessageHeader {
    /// Serialize header to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::Ratchet(h) => h.to_bytes().to_vec(),
        }
    }

    /// Deserialize header from bytes, dispatched by message type.
    pub fn from_bytes(_msg_type: &MessageType, data: &[u8]) -> Result<Self> {
        let rh = RatchetHeader::from_bytes(data)
            .map_err(|e| MessageError::InvalidHeader(e.to_string()))?;
        Ok(Self::Ratchet(rh))
    }
}

/// Does this message type carry a cleartext X3DH header in its wire prefix?
/// Only `Initial` carries this header (S07 §2 / S06 §2.4).
fn carries_x3dh_header(t: MessageType) -> bool {
    matches!(t, MessageType::Initial)
}

/// Build the canonical **wire prefix** (S07 §2.3 / S06 §3.4): every wire byte
/// preceding the AEAD ciphertext, byte-exact as transmitted. This is BOTH the
/// serialized header region of a 1:1 ratchet `WireMessage` AND the tail of the
/// ratchet AEAD AAD, so a single builder keeps `to_bytes`, `wire_prefix`, and
/// `ratchet_encrypt`/`ratchet_decrypt` from ever diverging.
///
/// ```text
/// version(1) || message_type(1) || reserved(2)=0x0000 || payload_length(4 BE) ||
///   [ x3dh_header_len(2 BE) || x3dh_header ]   (Initial only) ||
///   ratchet_header(72)
/// ```
/// `payload_length` is the length of `encrypted_payload` (= `nonce(24) || ct || tag(16)`).
pub fn build_wire_prefix(
    version: u8,
    message_type: u8,
    x3dh_header: Option<&[u8]>,
    ratchet_header: &[u8; RATCHET_HEADER_SIZE],
    payload_length: u32,
) -> Vec<u8> {
    let x = x3dh_header.map_or(0, |h| 2 + h.len());
    let mut out = Vec::with_capacity(8 + x + RATCHET_HEADER_SIZE);
    out.push(version);
    out.push(message_type);
    out.extend_from_slice(&[0u8, 0u8]); // reserved[2] = 0x0000
    out.extend_from_slice(&payload_length.to_be_bytes());
    if let Some(h) = x3dh_header {
        out.extend_from_slice(&(h.len() as u16).to_be_bytes());
        out.extend_from_slice(h);
    }
    out.extend_from_slice(ratchet_header);
    out
}

/// Fixed ratchet-header size on the wire (S07 §2.2).
const RATCHET_HEADER_SIZE: usize = 72;

/// The message-format context `ratchet_encrypt` needs to build the canonical
/// wire prefix / AAD for the frame it is about to emit (S07 §2.3). The ratchet
/// layer stays format-agnostic except for this small descriptor.
pub struct WirePrefixMeta<'a> {
    /// Wire protocol version (`WIRE_VERSION`).
    pub version: u8,
    /// Message type discriminant as its wire byte.
    pub message_type: u8,
    /// Cleartext X3DH header bytes for `Initial`; `None` for Standard.
    pub x3dh_header: Option<&'a [u8]>,
}

impl WireMessage {
    /// The canonical wire prefix (S07 §2.3) for a 1:1 ratchet message — the tail
    /// of the AEAD AAD. `None` for group messages (they have no ratchet AAD).
    pub fn wire_prefix(&self) -> Option<Vec<u8>> {
        match &self.header {
            MessageHeader::Ratchet(h) => Some(build_wire_prefix(
                self.version,
                self.message_type.as_byte(),
                self.x3dh_header.as_deref(),
                &h.to_bytes(),
                self.encrypted_payload.len() as u32,
            )),
        }
    }

    /// Serialize to wire format.
    ///
    /// 1:1 ratchet messages use the S07 §2 layout (fixed 72-byte ratchet header,
    /// `reserved[2]`, `payload_length` before the header, optional cleartext X3DH
    /// header). The ratchet header is the only header form.
    pub fn to_bytes(&self) -> Vec<u8> {
        match &self.header {
            MessageHeader::Ratchet(h) => {
                let mut out = build_wire_prefix(
                    self.version,
                    self.message_type.as_byte(),
                    self.x3dh_header.as_deref(),
                    &h.to_bytes(),
                    self.encrypted_payload.len() as u32,
                );
                out.extend_from_slice(&self.encrypted_payload);
                out
            }
        }
    }

    /// Deserialize from wire format (dispatched by message type at offset 1).
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 8 {
            return Err(MessageError::TooShort);
        }
        let version = data[0];
        if version != super::types::WIRE_VERSION {
            return Err(MessageError::UnsupportedVersion(version));
        }
        let message_type = MessageType::try_from(data[1])?;

        // 1:1 ratchet layout (S07 §2), also used to authenticate unknown types.
        if data[2] != 0 || data[3] != 0 {
            return Err(MessageError::InvalidHeader(
                "reserved bytes must be 0x0000".into(),
            ));
        }
        let payload_length = u32::from_be_bytes(data[4..8].try_into()?) as usize;
        let mut off = 8;

                let x3dh_header = if carries_x3dh_header(message_type) {
                    if data.len() < off + 2 {
                        return Err(MessageError::TruncatedPayload);
                    }
                    let xlen = u16::from_be_bytes(data[off..off + 2].try_into()?) as usize;
                    off += 2;
                    if data.len() < off + xlen {
                        return Err(MessageError::TruncatedPayload);
                    }
                    let x = data[off..off + xlen].to_vec();
                    off += xlen;
                    Some(x)
                } else {
                    None
                };

        if data.len() < off + RATCHET_HEADER_SIZE {
            return Err(MessageError::TruncatedPayload);
        }
        let header =
            MessageHeader::from_bytes(&message_type, &data[off..off + RATCHET_HEADER_SIZE])?;
        off += RATCHET_HEADER_SIZE;

        if data.len() < off + payload_length {
            return Err(MessageError::TruncatedPayload);
        }
        Ok(Self {
            version,
            message_type,
            header,
            x3dh_header,
            encrypted_payload: data[off..off + payload_length].to_vec(),
        })
    }
}

impl Payload {
    /// Serialize payload to bytes (S07 §4).
    ///
    /// Layout: `sender_pseudonym (32) | content_type (1) | flags (1) |
    ///          timestamp (8 BE) | msg_id (16) | logical_seq (4 BE) |
    ///          content_len (4 BE) | content`
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(66 + self.content.len());
        out.extend_from_slice(&self.sender_pseudonym);
        out.push(self.content_type as u8);
        out.push(self.flags);
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        out.extend_from_slice(&self.msg_id);
        out.extend_from_slice(&self.logical_seq.to_be_bytes());
        out.extend_from_slice(&(self.content.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.content);
        out
    }

    /// Deserialize payload from bytes (S07 §4).
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 66 {
            return Err(MessageError::TooShort);
        }

        let mut sender_pseudonym = [0u8; 32];
        sender_pseudonym.copy_from_slice(&data[0..32]);
        let content_type = ContentType::try_from(data[32])?;
        let flags = data[33];
        super::reply::validate_flags(flags)?;
        let timestamp = u64::from_be_bytes(data[34..42].try_into()?);
        let mut msg_id = [0u8; 16];
        msg_id.copy_from_slice(&data[42..58]);
        let logical_seq = u32::from_be_bytes(data[58..62].try_into()?);

        let content_offset = 62;

        if data.len() < content_offset + 4 {
            return Err(MessageError::TruncatedPayload);
        }
        let content_len =
            u32::from_be_bytes(data[content_offset..content_offset + 4].try_into()?) as usize;

        if content_len > super::types::MAX_CONTENT_SIZE {
            return Err(MessageError::ContentTooLarge {
                size: content_len,
                max: super::types::MAX_CONTENT_SIZE,
            });
        }

        let content_start = content_offset + 4;
        if data.len() < content_start + content_len {
            return Err(MessageError::TruncatedPayload);
        }

        let content = data[content_start..content_start + content_len].to_vec();
        match content_type {
            ContentType::Text => {
                std::str::from_utf8(&content).map_err(|_| MessageError::InvalidUtf8)?;
            }
            ContentType::TextReply => {
                super::reply::TextReplyContent::from_bytes(&content)?;
            }
            _ => {}
        }

        // S07 §5.3: `content_length` is authoritative; every byte after the
        // content is zero-fill padding (§5.2). The padding is AEAD-authenticated,
        // so a non-zero trailing byte is a non-canonical / tampered pad — reject
        // it. (An exact, unpadded payload has no trailing bytes → passes.)
        if data[content_start + content_len..]
            .iter()
            .any(|&b| b != 0x00)
        {
            return Err(MessageError::InvalidPadding);
        }

        Ok(Self {
            sender_pseudonym,
            content_type,
            flags,
            timestamp,
            msg_id,
            logical_seq,
            content,
        })
    }
}
