//! Handshake payload encoding for QR codes and URIs (S05 §6, §7).
//!
//! - QR: `NAJWA:` + Base45(zlib(payload_bytes)) + six-character checksum
//! - URI: `najwa://contact?data=` + Base64URL(payload_bytes)

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use std::io::{Read, Write};

use super::error::HandshakeError;
use super::types::{HandshakePayload, MAX_HANDSHAKE_SIZE};

// Bound both the encoded input and the inflated output. The compressed budget
// includes ample zlib framing overhead for a maximum-size payload.
const MAX_COMPRESSED_SIZE: usize = MAX_HANDSHAKE_SIZE + 128;
const MAX_QR_SIZE: usize = 6 + MAX_COMPRESSED_SIZE.div_ceil(2) * 3 + 6;
const MAX_URI_DATA_SIZE: usize = (MAX_HANDSHAKE_SIZE * 4).div_ceil(3);

/// QR code prefix.
const QR_PREFIX: &str = "NAJWA:";

/// URI prefix.
const URI_PREFIX: &str = "najwa://contact?data=";

// ---------------------------------------------------------------------------
// Base45 encoding/decoding (ISO/IEC 18004, used in EU DCC)
// ---------------------------------------------------------------------------

const BASE45_CHARSET: &[u8; 45] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";

/// Encode bytes as Base45.
fn base45_encode(data: &[u8]) -> String {
    let mut out = String::new();
    let mut i = 0;
    while i < data.len() {
        if i + 1 < data.len() {
            // Encode pair
            let val = (data[i] as u16) * 256 + (data[i + 1] as u16);
            let c = val % 45;
            let val = val / 45;
            let b = val % 45;
            let a = val / 45;
            out.push(BASE45_CHARSET[c as usize] as char);
            out.push(BASE45_CHARSET[b as usize] as char);
            out.push(BASE45_CHARSET[a as usize] as char);
            i += 2;
        } else {
            // Encode single byte
            let val = data[i] as u16;
            let c = val % 45;
            let b = val / 45;
            out.push(BASE45_CHARSET[c as usize] as char);
            out.push(BASE45_CHARSET[b as usize] as char);
            i += 1;
        }
    }
    out
}

/// Decode a Base45 string to bytes.
fn base45_decode(s: &str) -> Result<Vec<u8>, HandshakeError> {
    let chars: Vec<u8> = s
        .bytes()
        .map(|b| {
            BASE45_CHARSET
                .iter()
                .position(|&c| c == b)
                .map(|p| p as u8)
                .ok_or_else(|| {
                    HandshakeError::Base45DecodeError(format!("invalid character: {:02x}", b))
                })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        if i + 2 < chars.len() {
            // Decode triple → 2 bytes. Compute in u32: a malformed triple can
            // exceed 0xFFFF (max valid is 65535), which would overflow u16 and
            // panic in debug — reject it as a decode error instead.
            let val = (chars[i] as u32) + (chars[i + 1] as u32) * 45 + (chars[i + 2] as u32) * 2025;
            if val > 0xFFFF {
                return Err(HandshakeError::Base45DecodeError(
                    "value overflow in triple".into(),
                ));
            }
            out.push((val / 256) as u8);
            out.push((val % 256) as u8);
            i += 3;
        } else if i + 1 < chars.len() {
            // Decode pair → 1 byte
            let val = (chars[i] as u16) + (chars[i + 1] as u16) * 45;
            if val > 255 {
                return Err(HandshakeError::Base45DecodeError(
                    "value overflow in pair".into(),
                ));
            }
            out.push(val as u8);
            i += 2;
        } else {
            return Err(HandshakeError::Base45DecodeError(
                "trailing character".into(),
            ));
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// zlib compression
// ---------------------------------------------------------------------------

/// Compress data using zlib.
fn zlib_compress(data: &[u8]) -> Result<Vec<u8>, HandshakeError> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
    encoder
        .write_all(data)
        .map_err(|e| HandshakeError::CompressionFailed(e.to_string()))?;
    encoder
        .finish()
        .map_err(|e| HandshakeError::CompressionFailed(e.to_string()))
}

/// Decompress zlib data.
fn zlib_decompress(data: &[u8]) -> Result<Vec<u8>, HandshakeError> {
    let decoder = ZlibDecoder::new(data);
    let mut out = Vec::new();
    decoder
        .take((MAX_HANDSHAKE_SIZE + 1) as u64)
        .read_to_end(&mut out)
        .map_err(|e| HandshakeError::DecompressionFailed(e.to_string()))?;
    if out.len() > MAX_HANDSHAKE_SIZE {
        return Err(HandshakeError::InvalidFormat(
            "decompressed payload too large".into(),
        ));
    }
    Ok(out)
}

/// CRC-32 (IEEE 802.3 / zlib variant) over `data`. Used only for accidental
/// error detection on the QR string (S05 §6.2) — integrity is the Ed25519 signature.
fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// Length of the Base45-encoded CRC32 checksum suffix: a 4-byte CRC32 encodes to
/// exactly 6 Base45 characters (two byte-pairs → 3 chars each).
const QR_CHECKSUM_LEN: usize = 6;

// ---------------------------------------------------------------------------
// Public encoding/decoding API
// ---------------------------------------------------------------------------

impl HandshakePayload {
    /// Encode for QR code: `"NAJWA:" || Base45(zlib(payload)) || Base45(CRC32(encoded_data))` (S05 §6).
    pub fn to_qr_string(&self) -> Result<String, HandshakeError> {
        self.validate_structure()?;
        let bytes = self.to_bytes();
        let compressed = zlib_compress(&bytes)?;
        let encoded_data = base45_encode(&compressed);
        // CRC32 over the encoded_data string, itself Base45-encoded (S05 §6.2).
        let checksum = base45_encode(&crc32(encoded_data.as_bytes()).to_be_bytes());
        Ok(format!("{QR_PREFIX}{encoded_data}{checksum}"))
    }

    /// Decode from a QR code string, verifying the CRC32 checksum (S05 §6).
    pub fn from_qr_string(s: &str) -> Result<Self, HandshakeError> {
        if s.len() > MAX_QR_SIZE || !s.is_ascii() {
            return Err(HandshakeError::InvalidFormat(
                "QR input too large or non-ASCII".into(),
            ));
        }
        let body = s
            .strip_prefix(QR_PREFIX)
            .ok_or_else(|| HandshakeError::InvalidFormat("missing 'NAJWA:' prefix".into()))?;
        // Split the trailing Base45(CRC32) checksum (6 chars) from encoded_data.
        if body.len() < QR_CHECKSUM_LEN {
            return Err(HandshakeError::InvalidFormat(
                "QR string too short for checksum".into(),
            ));
        }
        let (encoded_data, checksum_str) = body.split_at(body.len() - QR_CHECKSUM_LEN);
        let checksum_bytes = base45_decode(checksum_str)?;
        let expected = <[u8; 4]>::try_from(checksum_bytes.as_slice())
            .map_err(|_| HandshakeError::InvalidFormat("malformed QR checksum".into()))?;
        if crc32(encoded_data.as_bytes()) != u32::from_be_bytes(expected) {
            return Err(HandshakeError::InvalidFormat("QR checksum mismatch".into()));
        }
        let compressed = base45_decode(encoded_data)?;
        let bytes = zlib_decompress(&compressed)?;
        Self::from_bytes(&bytes)
    }

    /// Encode as URI: `najwa://contact?data=` + Base64URL without padding (S05 §7).
    pub fn to_uri(&self) -> Result<String, HandshakeError> {
        self.validate_structure()?;
        let bytes = self.to_bytes();
        Ok(format!("{}{}", URI_PREFIX, URL_SAFE_NO_PAD.encode(&bytes)))
    }

    /// Decode from URI (S05 §7).
    pub fn from_uri(uri: &str) -> Result<Self, HandshakeError> {
        let data = uri.strip_prefix(URI_PREFIX).ok_or_else(|| {
            HandshakeError::InvalidFormat("missing 'najwa://contact?data=' prefix".into())
        })?;
        if data.len() > MAX_URI_DATA_SIZE {
            return Err(HandshakeError::InvalidFormat(
                "URI payload too large".into(),
            ));
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(data)
            .map_err(|e| HandshakeError::Base64DecodeError(e.to_string()))?;
        Self::from_bytes(&bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contact::mailbox_key::{MailboxEntry, CAP_TYPE_EPHEMERAL};
    use crate::contact::types::{MailboxInfo, HANDSHAKE_VERSION};

    fn test_payload() -> HandshakePayload {
        let mut onion_bytes = [0u8; 56];
        let onion_str = b"testmailbox123456";
        onion_bytes[..onion_str.len()].copy_from_slice(onion_str);

        HandshakePayload {
            version: HANDSHAKE_VERSION,
            ik_pub: [0x01; 32],
            mailbox_entries: vec![MailboxEntry {
                onion_address: onion_bytes,
                deposit_capability: [0x04; 32],
                envelope_secret: [0x07; 32],
                mailbox_ik_pub: [0x02; 32],
                cert_signature: [0x03; 64],
                capability_type: CAP_TYPE_EPHEMERAL,
            }],
            mailboxes: vec![MailboxInfo {
                onion_address: "testmailbox123456".to_string(),
                deposit_capability: [0x04; 32],
            }],
            display_name: "Alice".to_string(),
            created_at: 1700000000,
            expires_at: 1700003600,
            signature: [0x05; 64],
        }
    }

    // Base45 unit tests
    #[test]
    fn base45_roundtrip_simple() {
        let data = b"Hello World";
        let encoded = base45_encode(data);
        let decoded = base45_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn base45_roundtrip_empty() {
        let encoded = base45_encode(b"");
        assert!(encoded.is_empty());
        let decoded = base45_decode("").unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn base45_roundtrip_single_byte() {
        for b in 0..=255u8 {
            let encoded = base45_encode(&[b]);
            let decoded = base45_decode(&encoded).unwrap();
            assert_eq!(decoded, vec![b], "failed for byte {b}");
        }
    }

    #[test]
    fn base45_invalid_char_rejected() {
        assert!(base45_decode("!@#").is_err());
    }

    // QR encoding tests
    #[test]
    fn qr_string_roundtrip() {
        let payload = test_payload();
        let qr = payload.to_qr_string().unwrap();
        assert!(qr.starts_with("NAJWA:"));
        let restored = HandshakePayload::from_qr_string(&qr).unwrap();
        assert_eq!(restored.ik_pub, payload.ik_pub);
        assert_eq!(restored.display_name, payload.display_name);
        assert_eq!(restored.mailboxes.len(), 1);
    }

    #[test]
    fn qr_string_bad_prefix_rejected() {
        assert!(HandshakePayload::from_qr_string("bad:data").is_err());
    }

    #[test]
    fn qr_string_detects_corruption() {
        // S05 §6: a flipped character in the body must fail the CRC32 check.
        let qr = test_payload().to_qr_string().unwrap();
        let mut chars: Vec<char> = qr.chars().collect();
        // Corrupt a char in the encoded_data region (just after the prefix).
        let i = QR_PREFIX.len() + 1;
        chars[i] = if chars[i] == 'A' { 'B' } else { 'A' };
        let corrupted: String = chars.into_iter().collect();
        assert!(HandshakePayload::from_qr_string(&corrupted).is_err());
    }

    #[test]
    fn qr_string_has_checksum_suffix() {
        // The QR string carries a 6-char Base45(CRC32) checksum after the body.
        let qr = test_payload().to_qr_string().unwrap();
        let body = qr.strip_prefix(QR_PREFIX).unwrap();
        assert!(body.len() > QR_CHECKSUM_LEN);
        // Truncating the checksum must be rejected.
        assert!(HandshakePayload::from_qr_string(&qr[..qr.len() - 1]).is_err());
    }

    // URI encoding tests
    #[test]
    fn uri_roundtrip() {
        let payload = test_payload();
        let uri = payload.to_uri().unwrap();
        assert!(uri.starts_with("najwa://contact?data="));
        let restored = HandshakePayload::from_uri(&uri).unwrap();
        assert_eq!(restored.ik_pub, payload.ik_pub);
        assert_eq!(restored.display_name, payload.display_name);
    }

    #[test]
    fn uri_bad_prefix_rejected() {
        assert!(HandshakePayload::from_uri("https://bad/data").is_err());
    }

    // Compression tests
    #[test]
    fn zlib_roundtrip() {
        let data = vec![0xAA; 256];
        let compressed = zlib_compress(&data).unwrap();
        let decompressed = zlib_decompress(&compressed).unwrap();
        assert_eq!(decompressed, data);
        // Compression should shrink repetitive data
        assert!(compressed.len() < data.len());
    }
}
