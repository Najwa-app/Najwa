//! Message format and encryption (S07).
//!
//! Provides:
//! - Wire message format (S07 §2)
//! - Control message types (S07 §4.1, §8.5)
//! - Bucket padding (S07 §5)
//! - Message ID generation (S07 §6)
//! - Timestamp validation (S07 §7.1)
//! - Serialization/deserialization (S07 §2, §4)

pub mod ack;
pub mod control;
pub mod envelope;
pub mod error;
pub mod file_transfer;
pub mod gap_repair;
pub mod id;
pub mod padding;
pub mod reply;
pub mod serialize;
pub mod timestamp;
pub mod types;

pub use control::{ControlMessage, IntroductionPayload};
pub use envelope::{
    cap_hint, envelope_decrypt, envelope_encrypt, CAP_HINT_SIZE, ENVELOPE_OVERHEAD,
};
pub use error::{MessageError, Result};
pub use gap_repair::{EpochGap, GapRange, GapRepairUnavailable, RepairedItem};
pub use id::generate_msg_id;
pub use padding::{pad_payload, pad_to_bucket, unpad, BUCKETS};
pub use reply::{payload_flags, validate_flags, TextReplyContent};
pub use serialize::{build_wire_prefix, WirePrefixMeta};
pub use timestamp::{validate_timestamp, MAX_FUTURE_SKEW_SECS, MAX_PAST_SKEW_SECS};
pub use types::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ratchet::header::RatchetHeader;
    use najwa_crypto::keys::x25519::X25519KeyPair;

    fn make_ratchet_header() -> RatchetHeader {
        let mut rng = rand::thread_rng();
        let kp = X25519KeyPair::generate(&mut rng);
        RatchetHeader::new(kp.public().clone(), 5, 42)
    }

    // --- MessageType ---

    #[test]
    fn message_type_roundtrip() {
        let cases = [
            (0x01u8, MessageType::Initial),
            (0x02, MessageType::Normal),
            (0x03, MessageType::Unknown(3)),
        ];
        for (byte, expected) in cases {
            let mt = MessageType::try_from(byte).unwrap();
            assert_eq!(mt, expected);
            assert_eq!(mt.as_byte(), byte);
        }
    }

    #[test]
    fn message_type_unknown_rejected() {
        for byte in [0, 3, 4, 0xff] {
            assert_eq!(
                MessageType::try_from(byte).unwrap(),
                MessageType::Unknown(byte)
            );
        }
    }

    // --- ContentType ---

    #[test]
    fn content_type_roundtrip() {
        let cases = [
            (0x01u8, ContentType::Text),
            (0x02, ContentType::TextReply),
            (0x03, ContentType::Binary),
            (0x10, ContentType::FileMetadata),
            (0x11, ContentType::FileChunk),
            (0x20, ContentType::Control),
        ];
        for (byte, expected) in cases {
            let ct = ContentType::try_from(byte).unwrap();
            assert_eq!(ct, expected);
            assert_eq!(ct as u8, byte);
        }
    }

    #[test]
    fn content_type_unknown_rejected() {
        assert!(ContentType::try_from(0x00).is_err());
        assert!(ContentType::try_from(0x05).is_err());
        assert!(ContentType::try_from(0xFE).is_err());
    }

    // --- WireMessage ---

    #[test]
    fn wire_message_ratchet_roundtrip() {
        let header = make_ratchet_header();
        let msg = WireMessage {
            version: WIRE_VERSION,
            message_type: MessageType::Normal,
            header: MessageHeader::Ratchet(header.clone()),
            x3dh_header: None,
            encrypted_payload: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };

        let bytes = msg.to_bytes();
        assert_eq!(bytes[0], WIRE_VERSION);
        assert_eq!(bytes[1], 0x02); // Normal

        let parsed = WireMessage::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.version, WIRE_VERSION);
        assert_eq!(parsed.message_type, MessageType::Normal);
        assert_eq!(parsed.encrypted_payload, vec![0xDE, 0xAD, 0xBE, 0xEF]);

        match &parsed.header {
            MessageHeader::Ratchet(rh) => {
                assert_eq!(rh.dh_pub.to_bytes(), header.dh_pub.to_bytes());
                assert_eq!(rh.pn, 5);
                assert_eq!(rh.n, 42);
            }
        }
    }

    #[test]
    fn wire_message_too_short_rejected() {
        assert!(WireMessage::from_bytes(&[]).is_err());
        assert!(WireMessage::from_bytes(&[0x01; 7]).is_err());
    }

    #[test]
    fn wire_message_truncated_payload_rejected() {
        let header = make_ratchet_header();
        let msg = WireMessage {
            version: WIRE_VERSION,
            message_type: MessageType::Normal,
            header: MessageHeader::Ratchet(header),
            x3dh_header: None,
            encrypted_payload: vec![0xFF; 100],
        };
        let mut bytes = msg.to_bytes();
        bytes.truncate(bytes.len() - 50); // Chop off half the payload
        assert!(WireMessage::from_bytes(&bytes).is_err());
    }

    #[test]
    fn wire_message_unknown_type_rejected() {
        let mut bytes = vec![0x01, 0xFF, 0x00, 0x28];
        bytes.extend_from_slice(&[0u8; 40]);
        bytes.extend_from_slice(&0u32.to_be_bytes());
        assert!(WireMessage::from_bytes(&bytes).is_err());
    }

    // --- Payload ---

    #[test]
    fn payload_roundtrip() {
        let payload = Payload {
            sender_pseudonym: [0xAA; 32],
            content_type: ContentType::Text,
            flags: 0x00,
            timestamp: 1700000000,
            msg_id: [0xBB; 16],
            logical_seq: 0,
            content: b"Hello, Najwa!".to_vec(),
        };

        let bytes = payload.to_bytes();
        assert!(bytes.len() >= 62);

        let parsed = Payload::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.sender_pseudonym, [0xAA; 32]);
        assert_eq!(parsed.content_type, ContentType::Text);
        assert_eq!(parsed.flags, 0x00);
        assert_eq!(parsed.timestamp, 1700000000);
        assert_eq!(parsed.msg_id, [0xBB; 16]);
        assert_eq!(parsed.content, b"Hello, Najwa!");
    }

    #[test]
    fn payload_empty_content() {
        let payload = Payload {
            sender_pseudonym: [0x00; 32],
            content_type: ContentType::Binary,
            flags: 0x00,
            timestamp: 0,
            msg_id: [0x00; 16],
            logical_seq: 0,
            content: vec![],
        };

        let bytes = payload.to_bytes();
        // 32 + 1 + 1 + 8 + 16 + 4 (logical_seq) + 4 (content_len) = 66.
        assert_eq!(bytes.len(), 66);

        let parsed = Payload::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.content_type, ContentType::Binary);
        assert!(parsed.content.is_empty());
        assert_eq!(parsed.logical_seq, 0);
    }

    #[test]
    fn payload_logical_seq_roundtrips() {
        // The sequence and all defined flags use the same fixed header layout.
        for flags in 0..=7 {
            let payload = Payload {
                sender_pseudonym: [0x01; 32],
                content_type: ContentType::Text,
                flags,
                timestamp: 1700000000,
                msg_id: [0x02; 16],
                logical_seq: 0xDEAD_BEEF,

                content: b"gap-repair seq".to_vec(),
            };
            let parsed = Payload::from_bytes(&payload.to_bytes()).unwrap();
            assert_eq!(parsed.logical_seq, 0xDEAD_BEEF);
            assert_eq!(parsed.flags, flags);
            assert_eq!(parsed.content, b"gap-repair seq");
        }
    }

    #[test]
    fn payload_too_short_rejected() {
        assert!(Payload::from_bytes(&[0u8; 61]).is_err());
        assert!(Payload::from_bytes(&[]).is_err());
    }

    #[test]
    fn payload_truncated_content_rejected() {
        let payload = Payload {
            sender_pseudonym: [0; 32],
            content_type: ContentType::Text,
            flags: 0,
            timestamp: 1000,
            msg_id: [0; 16],
            logical_seq: 0,
            content: vec![0xFF; 100],
        };
        let mut bytes = payload.to_bytes();
        bytes.truncate(bytes.len() - 50);
        assert!(Payload::from_bytes(&bytes).is_err());
    }

    // --- Padding + Payload integration ---

    // S07 §5.2/§5.3: the 1:1 path pads a Payload with 0x00 zero-fill (no length
    // prefix) and `Payload::from_bytes` reads the authoritative `content_length`
    // + rejects a non-zero (tampered/non-canonical) padding byte.
    #[test]
    fn payload_pad_payload_roundtrip_and_rejects_nonzero_pad() {
        let payload = Payload {
            sender_pseudonym: [0xCC; 32],
            content_type: ContentType::Text,
            flags: 0x00,
            timestamp: 42,
            msg_id: [0xDD; 16],
            logical_seq: 7,

            content: b"hello padded world".to_vec(),
        };
        // 0x02 fixed overhead = 160; an 84-byte payload fits 256−160=96, so the
        // DEPOSITED blob lands on the 256 bucket (S07 §5.1.1).
        let padded = pad_payload(&payload.to_bytes(), 160).unwrap();
        assert_eq!(
            160 + padded.len(),
            256,
            "84-byte payload + 0x02 overhead → 256"
        );

        // Parses directly from the zero-padded bytes (no unpad step).
        let recovered = Payload::from_bytes(&padded).unwrap();
        assert_eq!(recovered.content, b"hello padded world");
        assert_eq!(recovered.msg_id, [0xDD; 16]);

        // A non-zero byte in the padding region is rejected.
        let mut tampered = padded.clone();
        *tampered.last_mut().unwrap() = 0xFF;
        assert!(Payload::from_bytes(&tampered).is_err());
    }

    // S07 §5.1.1: the FINAL deposited blob (envelope + wire prefix + AEAD +
    // padded plaintext) must land EXACTLY on a §5.1 bucket. This ties the
    // send-path fixed-overhead constants (160 / 263 / 267) to the real wire
    // layout via `build_wire_prefix` — a wrong constant fails here even though an
    // off-bucket deposit would still decrypt fine (so the over-Tor E2E can't
    // catch it: bucketing is a pure size property, not a functional one).
    #[test]
    fn deposited_blob_lands_exactly_on_bucket() {
        const AEAD_OVERHEAD: usize = 40; // nonce(24) + tag(16)
        let ratchet_header = [0u8; 72];
        // (fixed_overhead, message_type_byte, cleartext X3DH header)
        let cases: [(usize, u8, Option<Vec<u8>>); 3] = [
            (160, 0x02, None),                 // 0x02 Standard
            (263, 0x01, Some(vec![0u8; 101])), // 0x01 Initial, no OPK
            (267, 0x01, Some(vec![0u8; 105])), // 0x01 Initial, with OPK
        ];
        for (fixed, mtype, x3dh) in cases {
            for payload_len in [1usize, 96, 97, 5_000, 200_000] {
                let Ok(padded) = pad_payload(&vec![0u8; payload_len], fixed) else {
                    continue; // too large for this overhead — not a bucket case
                };
                // encrypted_payload = nonce(24) || ciphertext(=padded) || tag(16)
                let encrypted_payload_len = AEAD_OVERHEAD + padded.len();
                let wire_prefix = build_wire_prefix(
                    WIRE_VERSION,
                    mtype,
                    x3dh.as_deref(),
                    &ratchet_header,
                    encrypted_payload_len as u32,
                );
                // deposited = envelope(nonce+tag=40) wrapping the full WireMessage
                let deposited = ENVELOPE_OVERHEAD + wire_prefix.len() + encrypted_payload_len;
                assert!(
                    BUCKETS.contains(&deposited),
                    "mtype {mtype:#x} payload {payload_len}: deposited {deposited} not a bucket"
                );
            }
        }
    }

    #[test]
    fn payload_pad_unpad_roundtrip() {
        let payload = Payload {
            sender_pseudonym: [0xCC; 32],
            content_type: ContentType::Binary,
            flags: 0x01,
            timestamp: 9999999999,
            msg_id: [0xDD; 16],
            logical_seq: 0,
            content: vec![0x42; 500],
        };

        let payload_bytes = payload.to_bytes();
        let padded = pad_to_bucket(&payload_bytes).unwrap();
        // 562 bytes payload → needs 1024 bucket
        assert_eq!(padded.len(), 1024);

        let unpadded = unpad(&padded).unwrap();
        let recovered = Payload::from_bytes(unpadded).unwrap();
        assert_eq!(recovered.sender_pseudonym, [0xCC; 32]);
        assert_eq!(recovered.content_type, ContentType::Binary);
        assert_eq!(recovered.content, vec![0x42; 500]);
    }

    // --- Message ID + Payload integration ---

    #[test]
    fn msg_id_matches_payload_content() {
        let pseudo = [0xAA; 32];
        let content = b"test message";
        let content_hash = najwa_crypto::hash::sha256(content);
        let ts = 1700000000u64;

        let dh_pub = [0x11; 32];
        let id = generate_msg_id(&dh_pub, 0, &content_hash, &pseudo);

        let payload = Payload {
            sender_pseudonym: pseudo,
            content_type: ContentType::Text,
            flags: 0,
            timestamp: ts,
            msg_id: id,
            logical_seq: 0,
            content: content.to_vec(),
        };

        let bytes = payload.to_bytes();
        let parsed = Payload::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.msg_id, id);
    }

    // --- Fuzz-style tests ---

    #[test]
    fn fuzz_wire_message_no_panic() {
        // Random-ish byte patterns should not panic, only return errors
        let patterns: Vec<Vec<u8>> = vec![
            vec![],
            vec![0x00],
            vec![0x01, 0x02],
            vec![0x01, 0x02, 0x00, 0x28],
            vec![0xFF; 100],
            vec![0x01, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            vec![0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        ];
        for p in patterns {
            let _ = WireMessage::from_bytes(&p);
        }
    }

    #[test]
    fn fuzz_payload_no_panic() {
        let patterns: Vec<Vec<u8>> = vec![
            vec![],
            vec![0x00; 61],
            vec![0x00; 62],
            vec![0xFF; 100],
            vec![0x00; 66], // 62 header + content_len=0 but 4 extra bytes
        ];
        for p in patterns {
            let _ = Payload::from_bytes(&p);
        }
    }

    #[test]
    fn fuzz_control_message_no_panic() {
        let patterns: Vec<Vec<u8>> = vec![
            vec![],
            vec![0x00],
            vec![0x00, 0x00, 0x01],
            vec![0x01, 0x00],
            vec![0xFF; 200],
            vec![0x40; 10],
        ];
        for p in patterns {
            let _ = ControlMessage::from_bytes(&p);
        }
    }

    #[test]
    fn fuzz_padding_no_panic() {
        let patterns: Vec<Vec<u8>> = vec![
            vec![],
            vec![0x00; 3],
            vec![0x00; 4],
            vec![0xFF; 10],
            vec![0x00, 0x00, 0x00, 0x01, 0x42, 0x00], // valid: len=1, content=0x42
        ];
        for p in &patterns {
            let _ = unpad(p);
        }
        // pad_to_bucket should succeed for small inputs
        for p in &patterns {
            let padded = pad_to_bucket(p).unwrap();
            assert!(BUCKETS.contains(&padded.len()));
        }
    }

    // --- All content types serializable ---

    // --- All message types with ratchet header ---

    #[test]
    fn initial_prekey_normal_all_use_ratchet_header() {
        for mt in [
            MessageType::Initial,
            MessageType::Normal,
            MessageType::Unknown(3),
        ] {
            let header = make_ratchet_header();
            // Initial/Prekey carry a cleartext X3DH header in the wire prefix
            // (S07 §2); Normal does not.
            let x3dh_header = if matches!(mt, MessageType::Initial) {
                Some(vec![0x07u8; 101])
            } else {
                None
            };
            let msg = WireMessage {
                version: WIRE_VERSION,
                message_type: mt,
                header: MessageHeader::Ratchet(header),
                x3dh_header: x3dh_header.clone(),
                encrypted_payload: vec![0xAB],
            };
            let bytes = msg.to_bytes();
            let parsed = WireMessage::from_bytes(&bytes).unwrap();
            assert_eq!(parsed.message_type, mt);
            assert!(matches!(parsed.header, MessageHeader::Ratchet(_)));
            assert_eq!(parsed.x3dh_header, x3dh_header);
        }
    }
}
