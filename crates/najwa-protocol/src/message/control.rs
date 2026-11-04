//! Control message types (S07 §4.1; registry in docs/reference/message-types.md).
//!
//! Central registry of all control message subtypes.
//! **All phases that add control messages MUST register them here.**
//!
//! Subtype ranges:
//!   0x00-0x0F: Core messaging (S08, S12)
//!   0x10-0x1F: Unassigned; the receiver rejects them
//!   0x20-0x2F: Contact management (S05 §11)
//!   0x30-0x3F: Session management
//!   0x40-0x5F: Unassigned; the receiver rejects them
//!   0xF0-0xFF: Reserved

use super::error::{MessageError, Result};
use super::gap_repair::{
    EpochGap, GapRange, GapRepairUnavailable, RepairedItem, GAP_REPAIR_MAX_EPOCHS,
    GAP_REPAIR_MAX_RANGE, GAP_REPAIR_MAX_RANGES_PER_EPOCH, REPAIRED_ITEM_HEADER_SIZE,
};

/// Re-export real IntroductionPayload from contact::introduction (S05 §11).
pub use crate::contact::introduction::IntroductionPayload;

/// Central registry of all control message subtypes
/// (docs/reference/message-types.md §5).
///
/// Subtypes not listed here (for example 0x33, 0x3B and 0x40-0x51) are
/// unassigned; the receiver handles them as unknown subtypes (S07 §10).
#[derive(Debug, Clone)]
pub enum ControlMessage {
    // --- Core messaging (0x00-0x0F) ---
    /// Disappearing message timer change (subtype 0x01, S12 §2.3).
    ///
    /// Body is 12 bytes fixed: `timer_secs: u32 BE || set_at: u64 BE`.
    /// `set_at` is the sender's Unix-seconds time the user changed the setting
    /// and is the merge input for the S12 §2.2 last-writer-wins rule — without
    /// it on the wire, the two sides cannot converge.
    DisappearTimer { duration_secs: u32, set_at: u64 },
    /// Typing indicator (0x02), with an empty body (S08 §6.4).
    TypingIndicator,
    /// Missing-chunk retransmit request (subtype 0x3C, S11 §2.2.1/§4.1).
    /// Strictly ascending indices, 1..=256 of them; the receiver of this
    /// control re-sends the named chunks from its retained outbound copy.
    FileChunkNack {
        session_id: [u8; 16],
        missing_indices: Vec<u32>,
    },
    /// Long-offline re-send request (subtype 0x05, S08 §10.2).
    ///
    /// `mode` 0x01: `body` = `since_logical_msg_id[16] ‖ fallback_floor(u64 BE)`
    /// (24 bytes). `mode` 0x02: `body` = `start_be(8) ‖ end_be(8)` (16 bytes).
    /// Validated on parse — any other mode/length is rejected.
    ReSendRequest { mode: u8, body: Vec<u8> },

    // --- Contact management (0x20-0x2F) ---
    /// Replacement long-term mailbox entries (S05 §12).
    MailboxUpdate {
        mailboxes: Vec<crate::contact::mailbox_key::MailboxEntry>,
    },
    /// Identity rotation (0x21, S02 §18.1): old IK, new IK, timestamp, old/new signatures.
    IdentityRotation { body: [u8; 200] },
    /// The peer revokes this relationship (0x22); empty body.
    RevocationNotice,
    /// Contact introduction (subtype 0x25, S05 §11).
    Introduction(IntroductionPayload),
    /// Request an identity-rotation announcement (0x26); empty body.
    RotationAnnouncementRequest,

    // --- Session management (0x30-0x3F) ---
    /// Session reset request (subtype 0x30) — triggers re-initialization via X3DH.
    ///
    /// **Nuclear fallback** — used only as a last resort after graceful repair
    /// (`SessionRepairInit`) retries are exhausted. See S06 §3.7.1.
    SessionReset,
    /// Graceful session repair initiation (subtype 0x31, S06 §3.7.1).
    ///
    /// Sent when ratchet decryption fails with `MissedEpochBoundary` or
    /// `TooManySkipped`. Carries a fresh X3DH initial message in the wire
    /// header (handled by the X3DH layer); this control payload only carries
    /// diagnostic fields so the peer can log the cause of the repair.
    ///
    /// Unlike `SessionReset`, this does NOT destroy the existing ratchet state
    /// on either side — the receiver atomically replaces state only after
    /// successfully processing the new X3DH handshake.
    ///
    /// Reason codes:
    ///   0x01 = MissedEpochBoundary
    ///   0x02 = TooManySkipped
    SessionRepairInit {
        reason: u8,
        failed_dh_pub: [u8; 32],
        failed_epoch_link: [u8; 32],
    },
    /// Missing ratchet message-number ranges (subtype 0x36, S07 §8.5).
    GapRepairRequest { epochs: Vec<EpochGap> },
    /// A requested ratchet range is no longer in durable history (subtype 0x37).
    GapRepairUnavailable(GapRepairUnavailable),
    /// Original user content for requested ratchet message numbers (subtype 0x38).
    GapRepairBundle { items: Vec<RepairedItem> },
}

impl ControlMessage {
    /// Subtype byte for this control message.
    pub fn subtype(&self) -> u8 {
        match self {
            Self::DisappearTimer { .. } => 0x01,
            Self::TypingIndicator => 0x02,
            Self::FileChunkNack { .. } => 0x3C,
            Self::ReSendRequest { .. } => 0x05,
            Self::MailboxUpdate { .. } => 0x20,
            Self::IdentityRotation { .. } => 0x21,
            Self::RevocationNotice => 0x22,
            Self::Introduction(_) => 0x25,
            Self::RotationAnnouncementRequest => 0x26,
            Self::SessionReset => 0x30,
            Self::SessionRepairInit { .. } => 0x31,
            Self::GapRepairRequest { .. } => 0x36,
            Self::GapRepairUnavailable(_) => 0x37,
            Self::GapRepairBundle { .. } => 0x38,
        }
    }

    /// Serialize to bytes: `[subtype: 1] [payload: variable]`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![self.subtype()];
        match self {
            Self::DisappearTimer {
                duration_secs,
                set_at,
            } => {
                out.extend_from_slice(&duration_secs.to_be_bytes());
                out.extend_from_slice(&set_at.to_be_bytes());
            }
            Self::FileChunkNack {
                session_id,
                missing_indices,
            } => {
                out.extend_from_slice(session_id);
                out.extend_from_slice(&(missing_indices.len() as u16).to_be_bytes());
                for idx in missing_indices {
                    out.extend_from_slice(&idx.to_be_bytes());
                }
            }
            Self::ReSendRequest { mode, body } => {
                out.push(*mode);
                out.extend_from_slice(body);
            }
            Self::MailboxUpdate { mailboxes } => {
                for entry in mailboxes {
                    out.extend_from_slice(&entry.to_bytes());
                }
            }
            Self::IdentityRotation { body } => out.extend_from_slice(body),
            Self::TypingIndicator
            | Self::RevocationNotice
            | Self::SessionReset
            | Self::RotationAnnouncementRequest => {}
            Self::SessionRepairInit {
                reason,
                failed_dh_pub,
                failed_epoch_link,
            } => {
                out.push(*reason);
                out.extend_from_slice(failed_dh_pub);
                out.extend_from_slice(failed_epoch_link);
            }
            Self::GapRepairRequest { epochs } => {
                assert!((1..=GAP_REPAIR_MAX_EPOCHS).contains(&epochs.len()));
                let total: u64 = epochs
                    .iter()
                    .flat_map(|epoch| &epoch.ranges)
                    .map(GapRange::len)
                    .sum();
                assert!(total <= GAP_REPAIR_MAX_RANGE as u64);
                out.push(epochs.len() as u8);
                for epoch in epochs {
                    assert!((1..=GAP_REPAIR_MAX_RANGES_PER_EPOCH).contains(&epoch.ranges.len()));
                    out.extend_from_slice(&epoch.dh_pub);
                    out.push(epoch.ranges.len() as u8);
                    for range in &epoch.ranges {
                        assert!(!range.is_empty());
                        out.extend_from_slice(&range.start_n.to_be_bytes());
                        out.extend_from_slice(&range.end_n.to_be_bytes());
                    }
                }
            }
            Self::GapRepairUnavailable(unavailable) => {
                out.extend_from_slice(&unavailable.dh_pub);
                out.extend_from_slice(&unavailable.start_n.to_be_bytes());
                out.extend_from_slice(&unavailable.end_n.to_be_bytes());
            }
            Self::GapRepairBundle { items } => {
                assert!((1..=u8::MAX as usize).contains(&items.len()));
                out.push(items.len() as u8);
                for item in items {
                    out.extend_from_slice(&item.original_dh_pub);
                    out.extend_from_slice(&item.original_n.to_be_bytes());
                    out.extend_from_slice(&item.original_msg_id);
                    out.extend_from_slice(&item.original_timestamp.to_be_bytes());
                    out.extend_from_slice(&item.original_logical_seq.to_be_bytes());
                    out.push(item.original_content_type);
                    out.push(item.original_flags);
                    out.extend_from_slice(&(item.original_content.len() as u32).to_be_bytes());
                    out.extend_from_slice(&item.original_content);
                }
            }
            Self::Introduction(payload) => {
                let intro_bytes = payload.to_bytes();
                out.extend_from_slice(&intro_bytes);
            }
        }
        out
    }

    /// Deserialize from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.is_empty() {
            return Err(MessageError::TooShort);
        }
        let subtype = data[0];
        let payload = &data[1..];
        match subtype {
            0x01 => {
                // S12 §2.3: body is 12 bytes fixed — timer_secs(4) || set_at(8).
                if payload.len() < 12 {
                    return Err(MessageError::TooShort);
                }
                let duration_secs = u32::from_be_bytes(payload[0..4].try_into()?);
                let set_at = u64::from_be_bytes(payload[4..12].try_into()?);
                Ok(Self::DisappearTimer {
                    duration_secs,
                    set_at,
                })
            }
            0x02 if payload.is_empty() => Ok(Self::TypingIndicator),
            0x02 => Err(MessageError::InvalidContent(
                "typing body must be empty".into(),
            )),
            0x3C => {
                // S11 §2.2.1: session_id[16] ‖ missing_count(u16 BE) ‖
                // missing_index_N(u32 BE); 1..=256 indices, strictly ascending.
                if payload.len() < 16 + 2 {
                    return Err(MessageError::TooShort);
                }
                let count = u16::from_be_bytes(payload[16..18].try_into().unwrap()) as usize;
                if count == 0
                    || count > crate::message::file_transfer::NACK_MAX_INDICES
                    || payload.len() != 18 + 4 * count
                {
                    return Err(MessageError::TruncatedPayload);
                }
                let mut missing_indices = Vec::with_capacity(count);
                let mut prev: Option<u32> = None;
                for i in 0..count {
                    let off = 18 + 4 * i;
                    let idx = u32::from_be_bytes(payload[off..off + 4].try_into().unwrap());
                    if let Some(p) = prev {
                        if idx <= p {
                            return Err(MessageError::InvalidHeader(
                                "FileChunkNack: indices not strictly ascending".into(),
                            ));
                        }
                    }
                    prev = Some(idx);
                    missing_indices.push(idx);
                }
                let mut session_id = [0u8; 16];
                session_id.copy_from_slice(&payload[..16]);
                Ok(Self::FileChunkNack {
                    session_id,
                    missing_indices,
                })
            }
            0x05 => {
                // S08 §10.2 / Wire Formats §10.3: mode 0x01 body is 24 bytes
                // (since_logical_msg_id[16] ‖ fallback_floor u64 BE); mode 0x02
                // body is 16 bytes (start u64 BE ‖ end u64 BE). Anything else
                // is rejected fail-closed.
                let Some((&mode, body)) = payload.split_first() else {
                    return Err(MessageError::TruncatedPayload);
                };
                match (mode, body.len()) {
                    (0x01, 24) | (0x02, 16) => Ok(Self::ReSendRequest {
                        mode,
                        body: body.to_vec(),
                    }),
                    _ => Err(MessageError::TruncatedPayload),
                }
            }
            0x20 => {
                use crate::contact::mailbox_key::{
                    MailboxEntry, CAP_TYPE_LONG_TERM, MAILBOX_ENTRY_SIZE,
                };
                if payload.is_empty()
                    || !payload.len().is_multiple_of(MAILBOX_ENTRY_SIZE)
                    || payload.len() / MAILBOX_ENTRY_SIZE > 8
                {
                    return Err(MessageError::InvalidContent(
                        "invalid mailbox-update list".into(),
                    ));
                }
                let mailboxes = payload
                    .as_chunks::<MAILBOX_ENTRY_SIZE>()
                    .0
                    .iter()
                    .map(|bytes| {
                        let entry = MailboxEntry::from_bytes(bytes)
                            .map_err(|e| MessageError::InvalidContent(e.to_string()))?;
                        if entry.capability_type != CAP_TYPE_LONG_TERM {
                            return Err(MessageError::InvalidContent(
                                "mailbox update requires long-term capabilities".into(),
                            ));
                        }
                        if !entry
                            .onion_address
                            .iter()
                            .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(b))
                        {
                            return Err(MessageError::InvalidContent(
                                "invalid mailbox onion address".into(),
                            ));
                        }
                        Ok(entry)
                    })
                    .collect::<Result<Vec<_>>>()?;
                Ok(Self::MailboxUpdate { mailboxes })
            }
            0x21 => Ok(Self::IdentityRotation {
                body: payload
                    .try_into()
                    .map_err(|_| MessageError::TruncatedPayload)?,
            }),
            0x22 if payload.is_empty() => Ok(Self::RevocationNotice),
            0x22 => Err(MessageError::InvalidContent(
                "revocation body must be empty".into(),
            )),
            0x25 => {
                let version = *payload.first().ok_or(MessageError::TooShort)?;
                if version != crate::contact::introduction::INTRODUCTION_VERSION {
                    return Err(MessageError::UnknownNestedVersion {
                        offset: 1,
                        value: version,
                    });
                }
                let intro = IntroductionPayload::from_bytes(payload)
                    .map_err(|e| MessageError::InvalidContent(e.to_string()))?;
                if intro.to_bytes() != payload {
                    return Err(MessageError::InvalidContent(
                        "trailing introduction bytes".into(),
                    ));
                }
                Ok(Self::Introduction(intro))
            }
            0x26 if payload.is_empty() => Ok(Self::RotationAnnouncementRequest),
            0x26 => Err(MessageError::InvalidContent(
                "rotation request body must be empty".into(),
            )),
            0x30 => Ok(Self::SessionReset),
            0x31 => {
                // reason(1) || failed_dh_pub(32) || failed_epoch_link(32)
                if payload.len() < 65 {
                    return Err(MessageError::TooShort);
                }
                let reason = payload[0];
                let mut failed_dh_pub = [0u8; 32];
                let mut failed_epoch_link = [0u8; 32];
                failed_dh_pub.copy_from_slice(&payload[1..33]);
                failed_epoch_link.copy_from_slice(&payload[33..65]);
                Ok(Self::SessionRepairInit {
                    reason,
                    failed_dh_pub,
                    failed_epoch_link,
                })
            }
            0x36 => parse_gap_repair_request(payload),
            0x37 => parse_gap_repair_unavailable(payload),
            0x38 => parse_gap_repair_bundle(payload),
            unknown => Err(MessageError::UnknownControlSubtype(unknown)),
        }
    }
}

fn parse_gap_repair_request(payload: &[u8]) -> Result<ControlMessage> {
    let Some(&epoch_count) = payload.first() else {
        return Err(MessageError::TruncatedPayload);
    };
    let epoch_count = epoch_count as usize;
    if !(1..=GAP_REPAIR_MAX_EPOCHS).contains(&epoch_count) {
        return Err(MessageError::InvalidContent(
            "gap-repair epoch_count outside 1..=8".into(),
        ));
    }

    let mut cursor = 1usize;
    let mut total = 0u64;
    let mut epochs = Vec::with_capacity(epoch_count);
    for _ in 0..epoch_count {
        if payload.len().saturating_sub(cursor) < 33 {
            return Err(MessageError::TruncatedPayload);
        }
        let mut dh_pub = [0u8; 32];
        dh_pub.copy_from_slice(&payload[cursor..cursor + 32]);
        cursor += 32;
        let gap_count = payload[cursor] as usize;
        cursor += 1;
        if !(1..=GAP_REPAIR_MAX_RANGES_PER_EPOCH).contains(&gap_count) {
            return Err(MessageError::InvalidContent(
                "gap-repair gap_count outside 1..=16".into(),
            ));
        }
        let ranges_len = gap_count
            .checked_mul(8)
            .ok_or_else(|| MessageError::InvalidContent("gap range overflow".into()))?;
        if payload.len().saturating_sub(cursor) < ranges_len {
            return Err(MessageError::TruncatedPayload);
        }
        let mut ranges = Vec::with_capacity(gap_count);
        for _ in 0..gap_count {
            let start_n = u32::from_be_bytes(payload[cursor..cursor + 4].try_into()?);
            let end_n = u32::from_be_bytes(payload[cursor + 4..cursor + 8].try_into()?);
            cursor += 8;
            let range = GapRange { start_n, end_n };
            if range.is_empty() {
                return Err(MessageError::InvalidContent(
                    "gap-repair range starts after it ends".into(),
                ));
            }
            total = total.saturating_add(range.len());
            if total > GAP_REPAIR_MAX_RANGE as u64 {
                return Err(MessageError::InvalidContent(
                    "gap-repair request exceeds 100 message numbers".into(),
                ));
            }
            ranges.push(range);
        }
        epochs.push(EpochGap { dh_pub, ranges });
    }
    if cursor != payload.len() {
        return Err(MessageError::InvalidContent(
            "trailing gap-repair request bytes".into(),
        ));
    }
    Ok(ControlMessage::GapRepairRequest { epochs })
}

fn parse_gap_repair_unavailable(payload: &[u8]) -> Result<ControlMessage> {
    if payload.len() < 40 {
        return Err(MessageError::TruncatedPayload);
    }
    if payload.len() != 40 {
        return Err(MessageError::InvalidContent(
            "GapRepairUnavailable body must be exactly 40 bytes".into(),
        ));
    }
    let mut dh_pub = [0u8; 32];
    dh_pub.copy_from_slice(&payload[..32]);
    let start_n = u32::from_be_bytes(payload[32..36].try_into()?);
    let end_n = u32::from_be_bytes(payload[36..40].try_into()?);
    if start_n > end_n {
        return Err(MessageError::InvalidContent(
            "unavailable range starts after it ends".into(),
        ));
    }
    Ok(ControlMessage::GapRepairUnavailable(GapRepairUnavailable {
        dh_pub,
        start_n,
        end_n,
    }))
}

fn parse_gap_repair_bundle(payload: &[u8]) -> Result<ControlMessage> {
    let Some(&item_count) = payload.first() else {
        return Err(MessageError::TruncatedPayload);
    };
    if item_count == 0 {
        return Err(MessageError::InvalidContent(
            "gap-repair bundle must contain at least one item".into(),
        ));
    }
    let mut cursor = 1usize;
    let mut items = Vec::with_capacity(item_count as usize);
    for _ in 0..item_count {
        if payload.len().saturating_sub(cursor) < REPAIRED_ITEM_HEADER_SIZE {
            return Err(MessageError::TruncatedPayload);
        }
        let mut original_dh_pub = [0u8; 32];
        original_dh_pub.copy_from_slice(&payload[cursor..cursor + 32]);
        cursor += 32;
        let original_n = u32::from_be_bytes(payload[cursor..cursor + 4].try_into()?);
        cursor += 4;
        let mut original_msg_id = [0u8; 16];
        original_msg_id.copy_from_slice(&payload[cursor..cursor + 16]);
        cursor += 16;
        let original_timestamp = u64::from_be_bytes(payload[cursor..cursor + 8].try_into()?);
        cursor += 8;
        let original_logical_seq = u32::from_be_bytes(payload[cursor..cursor + 4].try_into()?);
        cursor += 4;
        let original_content_type = payload[cursor];
        let original_flags = payload[cursor + 1];
        cursor += 2;
        let content_len = u32::from_be_bytes(payload[cursor..cursor + 4].try_into()?) as usize;
        cursor += 4;
        let content_end = cursor
            .checked_add(content_len)
            .ok_or_else(|| MessageError::InvalidContent("repaired content overflow".into()))?;
        if content_end > payload.len() {
            return Err(MessageError::TruncatedPayload);
        }
        let original_content = payload[cursor..content_end].to_vec();
        cursor = content_end;
        items.push(RepairedItem {
            original_dh_pub,
            original_n,
            original_msg_id,
            original_timestamp,
            original_logical_seq,
            original_content_type,
            original_flags,
            original_content,
        });
    }
    if cursor != payload.len() {
        return Err(MessageError::InvalidContent(
            "trailing gap-repair bundle bytes".into(),
        ));
    }
    Ok(ControlMessage::GapRepairBundle { items })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ack_roundtrip() {
        // ACKs are top-level 0x12 frames, never subtype 0x00.
        assert!(matches!(
            ControlMessage::from_bytes(&[0, 0, 0]),
            Err(MessageError::UnknownControlSubtype(0))
        ));
    }

    #[test]
    fn disappear_timer_roundtrip() {
        let msg = ControlMessage::DisappearTimer {
            duration_secs: 3600,
            set_at: 1_760_000_000,
        };
        let bytes = msg.to_bytes();
        assert_eq!(bytes[0], 0x01);
        let parsed = ControlMessage::from_bytes(&bytes).unwrap();
        match parsed {
            ControlMessage::DisappearTimer {
                duration_secs,
                set_at,
            } => {
                assert_eq!(duration_secs, 3600);
                assert_eq!(set_at, 1_760_000_000);
            }
            _ => panic!("expected DisappearTimer"),
        }
    }

    // S12 §2.3: the body is 12 bytes fixed — timer_secs(4 BE) || set_at(8 BE)
    // — and there is no `applies_to` byte. Pinned byte-exactly because a
    // receiver that mis-parses `set_at` cannot converge (§2.2).
    #[test]
    fn disappear_timer_body_is_12_bytes_fixed() {
        let bytes = ControlMessage::DisappearTimer {
            duration_secs: 0x0000_0E10, // 3600
            set_at: 0x0000_0000_6900_0000,
        }
        .to_bytes();
        assert_eq!(bytes.len(), 1 + 12, "subtype byte + 12-byte body");
        assert_eq!(&bytes[1..5], &[0x00, 0x00, 0x0E, 0x10]);
        assert_eq!(
            &bytes[5..13],
            &[0x00, 0x00, 0x00, 0x00, 0x69, 0x00, 0x00, 0x00]
        );
    }

    // A truncated body (the pre-§2.3 4-byte form) must be rejected, not
    // silently parsed with set_at = 0 — which would make every stale timer
    // change lose the merge and never converge.
    #[test]
    fn disappear_timer_rejects_short_body() {
        let short = [0x01u8, 0x00, 0x00, 0x0E, 0x10];
        assert!(ControlMessage::from_bytes(&short).is_err());
    }

    #[test]
    fn read_receipt_roundtrip() {
        // Read receipts are top-level 0x11 frames. 0x02 is an empty typing notice.
        assert!(ControlMessage::from_bytes(&[2, 0, 1]).is_err());
    }

    #[test]
    fn typing_indicator_roundtrip() {
        let bytes = ControlMessage::TypingIndicator.to_bytes();
        assert_eq!(bytes, [2]);
        assert!(matches!(
            ControlMessage::from_bytes(&bytes).unwrap(),
            ControlMessage::TypingIndicator
        ));
        assert!(ControlMessage::from_bytes(&[2, 1]).is_err());
    }

    #[test]
    fn key_rotation_roundtrip() {
        let bytes = ControlMessage::IdentityRotation { body: [0x22; 200] }.to_bytes();
        assert_eq!(bytes[0], 0x21);
        assert_eq!(bytes.len(), 201);
        assert!(
            matches!(ControlMessage::from_bytes(&bytes).unwrap(), ControlMessage::IdentityRotation { body } if body == [0x22; 200])
        );
        assert!(matches!(
            ControlMessage::from_bytes(&[0x10]),
            Err(MessageError::UnknownControlSubtype(0x10))
        ));
    }

    #[test]
    fn session_reset_roundtrip() {
        let msg = ControlMessage::SessionReset;
        let bytes = msg.to_bytes();
        assert_eq!(bytes[0], 0x30);
        let parsed = ControlMessage::from_bytes(&bytes).unwrap();
        assert!(matches!(parsed, ControlMessage::SessionReset));
    }

    #[test]
    fn gap_repair_request_layout_is_byte_exact() {
        let epochs = vec![
            EpochGap {
                dh_pub: [0xAA; 32],
                ranges: vec![
                    GapRange {
                        start_n: 1,
                        end_n: 3,
                    },
                    GapRange {
                        start_n: 9,
                        end_n: 9,
                    },
                ],
            },
            EpochGap {
                dh_pub: [0xBB; 32],
                ranges: vec![GapRange {
                    start_n: 0xFFFF_FFFE,
                    end_n: 0xFFFF_FFFF,
                }],
            },
        ];
        let bytes = ControlMessage::GapRepairRequest {
            epochs: epochs.clone(),
        }
        .to_bytes();
        let mut expected = vec![0x36, 2];
        expected.extend_from_slice(&[0xAA; 32]);
        expected.push(2);
        expected.extend_from_slice(&1u32.to_be_bytes());
        expected.extend_from_slice(&3u32.to_be_bytes());
        expected.extend_from_slice(&9u32.to_be_bytes());
        expected.extend_from_slice(&9u32.to_be_bytes());
        expected.extend_from_slice(&[0xBB; 32]);
        expected.push(1);
        expected.extend_from_slice(&0xFFFF_FFFEu32.to_be_bytes());
        expected.extend_from_slice(&0xFFFF_FFFFu32.to_be_bytes());
        assert_eq!(bytes, expected);
        match ControlMessage::from_bytes(&bytes).unwrap() {
            ControlMessage::GapRepairRequest { epochs: parsed } => assert_eq!(parsed, epochs),
            other => panic!("expected GapRepairRequest, got {other:?}"),
        }
    }

    #[test]
    fn gap_repair_unavailable_layout_is_byte_exact() {
        let unavailable = GapRepairUnavailable {
            dh_pub: [0xCC; 32],
            start_n: 7,
            end_n: 11,
        };
        let bytes = ControlMessage::GapRepairUnavailable(unavailable).to_bytes();
        let mut expected = vec![0x37];
        expected.extend_from_slice(&[0xCC; 32]);
        expected.extend_from_slice(&7u32.to_be_bytes());
        expected.extend_from_slice(&11u32.to_be_bytes());
        assert_eq!(bytes, expected);
        assert_eq!(bytes.len(), 1 + 40);
        match ControlMessage::from_bytes(&bytes).unwrap() {
            ControlMessage::GapRepairUnavailable(parsed) => assert_eq!(parsed, unavailable),
            other => panic!("expected GapRepairUnavailable, got {other:?}"),
        }
    }

    #[test]
    fn gap_repair_bundle_layout_is_byte_exact() {
        let item = RepairedItem {
            original_dh_pub: [0xDD; 32],
            original_n: 0x0102_0304,
            original_msg_id: [0xEE; 16],
            original_timestamp: 0x0102_0304_0506_0708,
            original_logical_seq: 0x1112_1314,
            original_content_type: 0x01,
            original_flags: 0x04,
            original_content: vec![0xFA, 0xFB, 0xFC],
        };
        let bytes = ControlMessage::GapRepairBundle {
            items: vec![item.clone()],
        }
        .to_bytes();
        let mut expected = vec![0x38, 1];
        expected.extend_from_slice(&[0xDD; 32]);
        expected.extend_from_slice(&0x0102_0304u32.to_be_bytes());
        expected.extend_from_slice(&[0xEE; 16]);
        expected.extend_from_slice(&0x0102_0304_0506_0708u64.to_be_bytes());
        expected.extend_from_slice(&0x1112_1314u32.to_be_bytes());
        expected.extend_from_slice(&[0x01, 0x04]);
        expected.extend_from_slice(&3u32.to_be_bytes());
        expected.extend_from_slice(&[0xFA, 0xFB, 0xFC]);
        assert_eq!(bytes, expected);
        assert_eq!(bytes.len(), 1 + 1 + REPAIRED_ITEM_HEADER_SIZE + 3);
        match ControlMessage::from_bytes(&bytes).unwrap() {
            ControlMessage::GapRepairBundle { items } => assert_eq!(items, vec![item]),
            other => panic!("expected GapRepairBundle, got {other:?}"),
        }
    }

    #[test]
    fn truncated_gap_repair_bodies_are_rejected() {
        let messages = [
            ControlMessage::GapRepairRequest {
                epochs: vec![EpochGap {
                    dh_pub: [1; 32],
                    ranges: vec![GapRange {
                        start_n: 2,
                        end_n: 3,
                    }],
                }],
            },
            ControlMessage::GapRepairUnavailable(GapRepairUnavailable {
                dh_pub: [4; 32],
                start_n: 5,
                end_n: 6,
            }),
            ControlMessage::GapRepairBundle {
                items: vec![RepairedItem {
                    original_dh_pub: [7; 32],
                    original_n: 8,
                    original_msg_id: [9; 16],
                    original_timestamp: 10,
                    original_logical_seq: 11,
                    original_content_type: 1,
                    original_flags: 0,
                    original_content: b"body".to_vec(),
                }],
            },
        ];
        for message in messages {
            let mut bytes = message.to_bytes();
            bytes.pop();
            assert!(ControlMessage::from_bytes(&bytes).is_err());
        }
    }

    #[test]
    fn legacy_gap_repair_subtype_is_not_accepted() {
        assert!(matches!(
            ControlMessage::from_bytes(&[0x32, 0, 0]),
            Err(MessageError::UnknownControlSubtype(0x32))
        ));
    }

    #[test]
    fn session_repair_init_roundtrip() {
        // S06 §3.7.1: subtype 0x31 with (reason, failed_dh_pub, failed_epoch_link).
        let msg = ControlMessage::SessionRepairInit {
            reason: 0x01,
            failed_dh_pub: [0xAB; 32],
            failed_epoch_link: [0xCD; 32],
        };
        let bytes = msg.to_bytes();
        assert_eq!(bytes[0], 0x31);
        assert_eq!(bytes.len(), 1 + 1 + 32 + 32);
        let parsed = ControlMessage::from_bytes(&bytes).unwrap();
        match parsed {
            ControlMessage::SessionRepairInit {
                reason,
                failed_dh_pub,
                failed_epoch_link,
            } => {
                assert_eq!(reason, 0x01);
                assert_eq!(failed_dh_pub, [0xAB; 32]);
                assert_eq!(failed_epoch_link, [0xCD; 32]);
            }
            _ => panic!("expected SessionRepairInit"),
        }
    }

    #[test]
    fn session_repair_init_too_short_rejected() {
        // Missing one byte of the epoch link.
        let mut short = vec![0x31, 0x02];
        short.extend_from_slice(&[0u8; 32]);
        short.extend_from_slice(&[0u8; 31]);
        assert!(ControlMessage::from_bytes(&short).is_err());
    }

    #[test]
    fn account_deletion_roundtrip() {
        let bytes = ControlMessage::RevocationNotice.to_bytes();
        assert_eq!(bytes, [0x22]);
        assert!(matches!(
            ControlMessage::from_bytes(&bytes).unwrap(),
            ControlMessage::RevocationNotice
        ));
        assert!(ControlMessage::from_bytes(&[0x20]).is_err());
    }

    #[test]
    fn unknown_subtype_rejected() {
        assert!(ControlMessage::from_bytes(&[0xFE]).is_err());
        assert!(ControlMessage::from_bytes(&[0xFF]).is_err());
    }

    #[test]
    fn empty_input_rejected() {
        assert!(ControlMessage::from_bytes(&[]).is_err());
    }
}
