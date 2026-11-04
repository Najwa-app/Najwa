//! Double Ratchet message header (S06 §3.9).

use najwa_crypto::keys::x25519::X25519Public;
use serde::{Deserialize, Serialize};

use super::error::{RatchetError, Result};

/// Fixed size of a serialized RatchetHeader (S07 §2.2).
pub const HEADER_SIZE: usize = 72;

/// Header attached to every ratchet-encrypted message (S07 §2.2).
///
/// Layout (72 bytes, fixed):
///   offset  0: dh_pub (32) — current DH ratchet public key (X25519)
///   offset 32: pn (4, BE) — previous_chain_length
///   offset 36: n (4, BE) — message_number
///   offset 40: epoch_link (32) — previous sending-epoch dh_pub, or zeros (S06 §3.9)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RatchetHeader {
    /// Current DH ratchet public key.
    pub dh_pub: X25519Public,
    /// Previous chain message count.
    pub pn: u32,
    /// Message number in current sending chain.
    pub n: u32,
    /// Previous sending-epoch DH public key, or `zeros(32)` when there is no
    /// previous sending epoch (S06 §3.9). The receiver accepts zeros or the
    /// current `DHr` (S06 §3.5 step 3).
    ///
    /// Not serialized via bincode — the wire format uses `to_bytes`/`from_bytes`.
    #[serde(skip)]
    pub epoch_link: [u8; 32],
}

impl RatchetHeader {
    /// Create a new header with `epoch_link` set to zeros (legacy / first-epoch).
    ///
    /// Use [`RatchetHeader::with_epoch_link`] to attach a non-zero previous
    /// sending-epoch DH public key.
    pub fn new(dh_pub: X25519Public, pn: u32, n: u32) -> Self {
        Self {
            dh_pub,
            pn,
            n,
            epoch_link: [0u8; 32],
        }
    }

    /// Create a new header with an explicit `epoch_link` value (S06 §3.9).
    pub fn with_epoch_link(dh_pub: X25519Public, pn: u32, n: u32, epoch_link: [u8; 32]) -> Self {
        Self {
            dh_pub,
            pn,
            n,
            epoch_link,
        }
    }

    /// Serialize to a fixed 72-byte representation (S07 §2.2).
    ///
    /// Layout: `dh_pub(32) || pn(4,BE) || n(4,BE) || epoch_link(32)`.
    pub fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut out = [0u8; HEADER_SIZE];
        out[0..32].copy_from_slice(&self.dh_pub.to_bytes());
        out[32..36].copy_from_slice(&self.pn.to_be_bytes());
        out[36..40].copy_from_slice(&self.n.to_be_bytes());
        out[40..72].copy_from_slice(&self.epoch_link);
        out
    }

    /// Deserialize from a 72-byte representation (S07 §2.2).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != HEADER_SIZE {
            return Err(RatchetError::InvalidHeader(format!(
                "expected {} bytes, got {}",
                HEADER_SIZE,
                bytes.len()
            )));
        }
        let mut dh_bytes = [0u8; 32];
        dh_bytes.copy_from_slice(&bytes[0..32]);

        let pn = u32::from_be_bytes(
            bytes[32..36]
                .try_into()
                .map_err(|_| RatchetError::InvalidHeader("pn parse failed".into()))?,
        );
        let n = u32::from_be_bytes(
            bytes[36..40]
                .try_into()
                .map_err(|_| RatchetError::InvalidHeader("n parse failed".into()))?,
        );

        let mut epoch_link = [0u8; 32];
        epoch_link.copy_from_slice(&bytes[40..72]);

        Ok(Self {
            dh_pub: X25519Public::from_bytes(dh_bytes),
            pn,
            n,
            epoch_link,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use najwa_crypto::keys::x25519::X25519KeyPair;

    #[test]
    fn header_roundtrip() {
        let mut rng = rand::thread_rng();
        let kp = X25519KeyPair::generate(&mut rng);
        let header = RatchetHeader::new(kp.public().clone(), 42, 7);

        let bytes = header.to_bytes();
        assert_eq!(bytes.len(), HEADER_SIZE);
        assert_eq!(bytes.len(), 72);

        let restored = RatchetHeader::from_bytes(&bytes).unwrap();
        assert_eq!(restored.dh_pub.to_bytes(), header.dh_pub.to_bytes());
        assert_eq!(restored.pn, 42);
        assert_eq!(restored.n, 7);
        assert_eq!(restored.epoch_link, [0u8; 32]);
    }

    #[test]
    fn header_wrong_length_rejected() {
        assert!(RatchetHeader::from_bytes(&[0u8; 40]).is_err()); // old size
        assert!(RatchetHeader::from_bytes(&[0u8; 71]).is_err());
        assert!(RatchetHeader::from_bytes(&[0u8; 73]).is_err());
    }

    #[test]
    fn header_epoch_link_preserved() {
        let mut rng = rand::thread_rng();
        let kp = X25519KeyPair::generate(&mut rng);
        let link = [0xAB; 32];
        let header = RatchetHeader::with_epoch_link(kp.public().clone(), 1, 2, link);
        let bytes = header.to_bytes();
        let restored = RatchetHeader::from_bytes(&bytes).unwrap();
        assert_eq!(restored.epoch_link, link);
    }
}
