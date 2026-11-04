#[cfg(test)]
mod tests {
    use najwa_protocol::message::ack::{
        from_padded_plaintext, to_padded_plaintext, AckRange, CumulativeAck, ReadReceiptContent,
    };
    use najwa_protocol::message::control::ControlMessage;
    use najwa_protocol::message::id::generate_logical_msg_id;
    use najwa_protocol::message::{ContentType, Payload};

    // Independent S07 section 4 layout, not Payload::to_bytes.
    fn spec_payload(content_type: u8, flags: u8, content: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0x44; 32];
        bytes.extend_from_slice(&[content_type, flags]);
        bytes.extend_from_slice(&1_700_000_000u64.to_be_bytes());
        bytes.extend_from_slice(&[0x77; 16]);
        bytes.extend_from_slice(&7u32.to_be_bytes());
        bytes.extend_from_slice(&(content.len() as u32).to_be_bytes());
        bytes.extend_from_slice(content);
        bytes.resize(96, 0);
        bytes
    }

    #[test]
    fn resend_request_without_mode_returns_error_not_panic() {
        let result = std::panic::catch_unwind(|| ControlMessage::from_bytes(&[0x05]));
        assert!(result.is_ok(), "network-controlled ReSendRequest panicked");
        assert!(result.unwrap().is_err());
        for byte in 0..=255u8 {
            assert!(std::panic::catch_unwind(|| ControlMessage::from_bytes(&[byte])).is_ok());
        }
    }

    #[test]
    fn ephemeral_flag_survives_encoding() {
        let p = Payload {
            sender_pseudonym: [0x44; 32],
            content_type: ContentType::Text,
            flags: 1,
            timestamp: 1_700_000_000,
            msg_id: [0x77; 16],
            logical_seq: 7,
            content: b"hello".to_vec(),
        };
        assert_eq!(p.to_bytes()[33], 1, "S07 bit 0 is Ephemeral");
    }

    #[test]
    fn ephemeral_spec_payload_preserves_content_and_flag() {
        let p = Payload::from_bytes(&spec_payload(0x01, 0x01, b"hello")).unwrap();
        assert_eq!(
            p.content, b"hello",
            "the 66-byte header must not consume content as reply ID"
        );
        assert_eq!(p.flags, 1);
    }

    #[test]
    fn reserved_payload_flags_are_rejected() {
        assert!(Payload::from_bytes(&spec_payload(0x01, 0x08, b"hello")).is_err());
    }

    #[test]
    fn text_reply_uses_registered_content_type() {
        let mut content = vec![0x5a; 16];
        content.extend_from_slice(&5u16.to_be_bytes());
        content.extend_from_slice(b"hello");
        let p = Payload::from_bytes(&spec_payload(0x02, 0, &content)).unwrap();
        assert_eq!(format!("{:?}", p.content_type), "TextReply");
    }

    #[test]
    fn binary_content_type_is_recognized() {
        assert!(Payload::from_bytes(&spec_payload(0x03, 0, &[1, 2, 3])).is_ok());
    }

    #[test]
    fn mailbox_update_does_not_decode_as_account_deletion() {
        // The buggy dispatch ignores every byte after the subtype, so body
        // contents cannot affect its destructive interpretation.
        let bytes = [0x20, 0x01, 0x02, 0x03];
        assert!(ControlMessage::from_bytes(&bytes).is_err());
    }

    #[test]
    fn registered_typing_indicator_accepts_empty_body() {
        assert!(matches!(
            ControlMessage::from_bytes(&[0x02]),
            Ok(ControlMessage::TypingIndicator)
        ));
    }

    #[test]
    fn ack_receipt_nonzero_padding_is_rejected() {
        let receipt = ReadReceiptContent {
            msg_id: [0x55; 16],
            timestamp: 1_700_000_000,
        };
        let mut bytes = to_padded_plaintext(&receipt.to_bytes(), 96).unwrap();
        bytes[95] = 1;
        assert!(
            from_padded_plaintext(&bytes).is_err(),
            "S07 section 5.5 requires every padding byte to be zero"
        );
    }

    #[test]
    fn inverted_cumulative_ack_range_is_rejected() {
        let mut bytes = vec![0x12, 1];
        bytes.extend_from_slice(&[0x55; 32]);
        bytes.extend_from_slice(&9u32.to_be_bytes());
        bytes.extend_from_slice(&3u32.to_be_bytes());
        assert!(
            CumulativeAck::from_bytes(&bytes).is_err(),
            "start_n must not exceed end_n"
        );
    }

    #[test]
    fn logical_message_id_matches_spec_preimage() {
        let a = [0x11; 32];
        let b = [0x22; 32];
        let text = b"same second, same text";
        let mut preimage = a.to_vec();
        preimage.extend_from_slice(&b);
        preimage.push(0);
        preimage.extend_from_slice(&1_700_000_000u64.to_be_bytes());
        preimage.push(0);
        preimage.extend_from_slice(&7u32.to_be_bytes());
        preimage.push(0);
        preimage.push(0x01);
        preimage.push(0);
        preimage.extend_from_slice(text);
        let expected = najwa_crypto::prelude::sha256(&preimage);
        let actual = generate_logical_msg_id(&a, &b, 1_700_000_000, 7, 0x01, text);
        assert_eq!(actual.as_slice(), &expected[..16]);
    }

    #[test]
    fn known_valid_receipt_and_ack_are_accepted() {
        let r = ReadReceiptContent {
            msg_id: [0x55; 16],
            timestamp: 1_700_000_000,
        };
        let padded = to_padded_plaintext(&r.to_bytes(), 96).unwrap();
        assert_eq!(
            ReadReceiptContent::from_bytes(from_padded_plaintext(&padded).unwrap()).unwrap(),
            r
        );
        let a = CumulativeAck {
            ranges: vec![AckRange {
                sender_dh_pub: [0x66; 32],
                start_n: 3,
                end_n: 9,
            }],
        };
        assert_eq!(
            CumulativeAck::from_bytes(&a.to_bytes().unwrap()).unwrap(),
            a
        );
    }
}
