//! Delivery-confirmation wire structs (S07 §8).
//!
//! `0x11 ReadReceipt` and `0x12 CumulativeAck` are top-level WireMessage types
//! whose AEAD plaintext is `u16 struct_length(BE) ‖ struct ‖ zero-fill`
//! (S07 §5.5) — no `Payload` wrap, no `sender_pseudonym`, no flags. Neither
//! carries a received-at field: a receiver's clock would leak via every ACK
//! without serving any protocol purpose (S07 §8.1).

use super::MessageError;
use super::Result;

/// Read receipt plaintext (S07 §8.2): exactly 24 bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadReceiptContent {
    /// Transport `msg_id` of the message that was read.
    pub msg_id: [u8; 16],
    /// Unix-seconds time of the read event (sender's claim; UI-only).
    pub timestamp: u64,
}

pub const READ_RECEIPT_SIZE: usize = 24;

impl ReadReceiptContent {
    pub fn to_bytes(&self) -> [u8; READ_RECEIPT_SIZE] {
        let mut out = [0u8; READ_RECEIPT_SIZE];
        out[..16].copy_from_slice(&self.msg_id);
        out[16..].copy_from_slice(&self.timestamp.to_be_bytes());
        out
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() != READ_RECEIPT_SIZE {
            return Err(MessageError::TruncatedPayload);
        }
        Ok(Self {
            msg_id: data[..16].try_into().unwrap(),
            timestamp: u64::from_be_bytes(data[16..].try_into().unwrap()),
        })
    }
}

/// One acknowledged chain range (S07 §8.1). `start_n <= end_n`, both
/// inclusive, on the `sender_dh_pub` chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AckRange {
    /// `RatchetHeader.dh_pub` of the acknowledged sending chain.
    pub sender_dh_pub: [u8; 32],
    /// Inclusive, big-endian on the wire.
    pub start_n: u32,
    /// Inclusive, big-endian on the wire. MUST be `>= start_n`.
    pub end_n: u32,
}

impl AckRange {
    pub const SIZE: usize = 32 + 4 + 4;

    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut out = [0u8; Self::SIZE];
        out[..32].copy_from_slice(&self.sender_dh_pub);
        out[32..36].copy_from_slice(&self.start_n.to_be_bytes());
        out[36..].copy_from_slice(&self.end_n.to_be_bytes());
        out
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() != Self::SIZE {
            return Err(MessageError::TruncatedPayload);
        }
        let start_n = u32::from_be_bytes(data[32..36].try_into().unwrap());
        let end_n = u32::from_be_bytes(data[36..].try_into().unwrap());
        if start_n > end_n {
            return Err(MessageError::InvalidContent("inverted ACK range".into()));
        }
        Ok(Self {
            sender_dh_pub: data[..32].try_into().unwrap(),
            start_n,
            end_n,
        })
    }
}

/// Cumulative acknowledgment (S07 §8.1 — the only ACK format). A range with
/// `start_n == end_n` covers a single message. TCP-style cumulative ack past
/// gaps is FORBIDDEN: ranges MUST NOT span numbers not decrypted-and-persisted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CumulativeAck {
    /// 1..=16 ranges; split around gaps.
    pub ranges: Vec<AckRange>,
}

pub const MAX_ACK_RANGES: usize = 16;

impl CumulativeAck {
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        if self.ranges.is_empty() || self.ranges.len() > MAX_ACK_RANGES {
            return Err(MessageError::TruncatedPayload);
        }
        let mut out = vec![0x12u8, self.ranges.len() as u8];
        for r in &self.ranges {
            if r.start_n > r.end_n {
                return Err(MessageError::InvalidContent("inverted ACK range".into()));
            }
            out.extend_from_slice(&r.to_bytes());
        }
        Ok(out)
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 2 || data[0] != 0x12 {
            return Err(MessageError::TruncatedPayload);
        }
        let count = data[1] as usize;
        if count == 0 || count > MAX_ACK_RANGES || data.len() != 2 + count * AckRange::SIZE {
            return Err(MessageError::TruncatedPayload);
        }
        let mut ranges = Vec::with_capacity(count);
        for i in 0..count {
            let off = 2 + i * AckRange::SIZE;
            ranges.push(AckRange::from_bytes(&data[off..off + AckRange::SIZE])?);
        }
        Ok(Self { ranges })
    }
}

/// §5.5 plaintext shaping: `u16 struct_length(BE) ‖ struct ‖ zero-fill` up to
/// `target` (the padded-plaintext target for the message type, §5.1.1).
pub fn to_padded_plaintext(struct_bytes: &[u8], target: usize) -> Result<Vec<u8>> {
    let len = u16::try_from(struct_bytes.len()).map_err(|_| MessageError::TruncatedPayload)?;
    let total = 2 + struct_bytes.len();
    if total > target {
        return Err(MessageError::TruncatedPayload);
    }
    let mut out = vec![0u8; target];
    out[..2].copy_from_slice(&len.to_be_bytes());
    out[2..total].copy_from_slice(struct_bytes);
    Ok(out)
}

/// Inverse of [`to_padded_plaintext`]: parse the length prefix and struct from
/// a zero-filled plaintext, rejecting nonzero padding (S07 §5.5).
pub fn from_padded_plaintext(plaintext: &[u8]) -> Result<&[u8]> {
    if plaintext.len() < 2 {
        return Err(MessageError::TooShort);
    }
    let len = u16::from_be_bytes(plaintext[..2].try_into().unwrap()) as usize;
    if 2 + len > plaintext.len() {
        return Err(MessageError::TruncatedPayload);
    }
    if plaintext[2 + len..].iter().any(|&b| b != 0) {
        return Err(MessageError::InvalidPadding);
    }
    Ok(&plaintext[2..2 + len])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_receipt_roundtrip_24_bytes() {
        let r = ReadReceiptContent {
            msg_id: [0x5A; 16],
            timestamp: 1_700_000_000,
        };
        assert_eq!(r.to_bytes().len(), 24);
        assert_eq!(ReadReceiptContent::from_bytes(&r.to_bytes()).unwrap(), r);
    }

    #[test]
    fn cumulative_ack_roundtrip_and_bounds() {
        let ack = CumulativeAck {
            ranges: vec![
                AckRange {
                    sender_dh_pub: [0x01; 32],
                    start_n: 3,
                    end_n: 7,
                },
                AckRange {
                    sender_dh_pub: [0x02; 32],
                    start_n: 1,
                    end_n: 1,
                },
            ],
        };
        let bytes = ack.to_bytes().unwrap();
        assert_eq!(bytes[0], 0x12);
        assert_eq!(bytes[1], 2);
        assert_eq!(bytes.len(), 2 + 2 * AckRange::SIZE);
        assert_eq!(CumulativeAck::from_bytes(&bytes).unwrap(), ack);

        // Empty and over-full are rejected (1..=16).
        assert!(CumulativeAck { ranges: vec![] }.to_bytes().is_err());
        let over = CumulativeAck {
            ranges: vec![AckRange { sender_dh_pub: [0; 32], start_n: 0, end_n: 0 }; 17],
        };
        assert!(over.to_bytes().is_err());
    }

    #[test]
    fn padded_plaintext_roundtrip_ignores_zero_fill() {
        let bytes = [0xAB; 10];
        let padded = to_padded_plaintext(&bytes, 96).unwrap();
        assert_eq!(padded.len(), 96);
        assert_eq!(u16::from_be_bytes(padded[..2].try_into().unwrap()), 10);
        assert!(padded[12..].iter().all(|&b| b == 0));
        assert_eq!(from_padded_plaintext(&padded).unwrap(), &bytes);
        // Oversize for the target is an error, never a silent truncation.
        assert!(to_padded_plaintext(&[0u8; 96], 96).is_err());
    }
}
