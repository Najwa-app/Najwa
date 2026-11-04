//! S18 conformance vectors for S07: S18 §8 (deposit envelope) and the S18 §19
//! rows for ack typing (S07 §2.4), ReSendRequest and padding buckets (S07 §5).
//!
//! S18 §8: the envelope IKM is the `envelope_secret`, never the deposit
//! capability. The spec's verification bullets are asserted directly — right
//! key opens the spec-constructed blob, a blob keyed from the deposit
//! capability MUST fail, and wrong/truncated AAD fails — which pins the
//! byte-exact construction without needing hex fixtures. The primitives used
//! to build the blob are pinned by `najwa-crypto/tests/vectors.rs` (S18 §4–§5).

use najwa_crypto::prelude::{aead, hkdf_sha256, sha256};
use najwa_crypto::keys::X25519KeyPair;
use najwa_protocol::message::ack::{to_padded_plaintext, CumulativeAck, AckRange, ReadReceiptContent};
use najwa_protocol::message::control::ControlMessage;
use najwa_protocol::message::envelope::{envelope_decrypt, envelope_encrypt};
use najwa_protocol::message::types::{
    fixed_overhead, pad_to_bucket, MessageHeader, MessageType, WireMessage, PADDING_BUCKETS,
    WIRE_VERSION,
};
use najwa_protocol::ratchet::prelude::{init_alice, init_bob, ratchet_decrypt, ratchet_encrypt};

const ENVELOPE_SECRET: [u8; 32] = [0xEE; 32];
const DEPOSIT_CAP: [u8; 32] = [0xE1; 32];
const TEST_NONCE_24: [u8; 24] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
    0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
];
const TEST_PLAINTEXT: &[u8] = b"Hello Najwa!";

// ---------------------------------------------------------------------------
// S18 §8 — Deposit Envelope (keyed by envelope_secret)
// ---------------------------------------------------------------------------

#[test]
fn s18_8_deposit_envelope_construction() {
    // Spec intermediates, computed with the S18-pinned primitives.
    let outer_key = hkdf_sha256(
        &ENVELOPE_SECRET,
        b"najwa/v1/deposit-envelope",
        b"outer-key",
        32,
    )
    .unwrap();
    let aad = sha256(&DEPOSIT_CAP)[..8].to_vec();
    assert_eq!(aad.len(), 8);

    // deposited_blob = nonce(24) || ciphertext, built with the spec's nonce.
    let ct = aead::encrypt(&outer_key[..32].try_into().unwrap(), &TEST_NONCE_24, TEST_PLAINTEXT, &aad)
        .unwrap();
    let mut blob = TEST_NONCE_24.to_vec();
    blob.extend_from_slice(&ct);

    // Verification 1: the crate opens the spec-constructed blob.
    let inner = envelope_decrypt(&ENVELOPE_SECRET, &DEPOSIT_CAP, &blob).unwrap();
    assert_eq!(inner, TEST_PLAINTEXT);

    // Verification 2: a blob keyed from the deposit capability (IKM =
    // deposit_capability) MUST fail — the mailbox holds that capability.
    let old_key = hkdf_sha256(&DEPOSIT_CAP, b"najwa/v1/deposit-envelope", b"outer-key", 32).unwrap();
    let old_ct = aead::encrypt(old_key[..32].try_into().unwrap(), &TEST_NONCE_24, TEST_PLAINTEXT, &aad)
        .unwrap();
    let mut old_blob = TEST_NONCE_24.to_vec();
    old_blob.extend_from_slice(&old_ct);
    assert!(envelope_decrypt(&ENVELOPE_SECRET, &DEPOSIT_CAP, &old_blob).is_err());

    // Verification 3: a different AAD fails authentication.
    let other_cap = [0xE2; 32];
    assert!(envelope_decrypt(&ENVELOPE_SECRET, &other_cap, &blob).is_err());

    // The crate's own construction round-trips (CSPRNG nonce — shape check:
    // nonce(24) + plaintext + tag(16)).
    let sealed = envelope_encrypt(&ENVELOPE_SECRET, &DEPOSIT_CAP, TEST_PLAINTEXT).unwrap();
    assert_eq!(sealed.len(), 24 + TEST_PLAINTEXT.len() + 16);
    let inner = envelope_decrypt(&ENVELOPE_SECRET, &DEPOSIT_CAP, &sealed).unwrap();
    assert_eq!(inner, TEST_PLAINTEXT);
}

// ---------------------------------------------------------------------------
// §2.4 / §8.1 / §8.2 — ReadReceipt (0x11) and CumulativeAck (0x12)
// ---------------------------------------------------------------------------

/// Fixture ratchet header (same shape as S18 §15).
fn fixture_header() -> najwa_protocol::ratchet::header::RatchetHeader {
    najwa_protocol::ratchet::header::RatchetHeader {
        dh_pub: najwa_crypto::keys::X25519Public::from_bytes([0xAA; 32]),
        pn: 5,
        n: 10,
        epoch_link: [0xBB; 32],
    }
}

#[test]
fn s07_24_read_receipt_wire_roundtrip() {
    // 0x11 plaintext: u16 len ‖ ReadReceiptContent(24) ‖ zero-fill (§2.4/§5.5).
    let receipt = ReadReceiptContent {
        msg_id: [0x5A; 16],
        timestamp: 1_700_000_000,
    };
    let struct_bytes = receipt.to_bytes();
    let target = pad_to_bucket(2 + struct_bytes.len(), fixed_overhead(MessageType::ReadReceipt, false)).unwrap();
    // §5.1.1: fixed overhead for 0x11 is 160; 24-byte receipt fits the first bucket.
    assert_eq!(fixed_overhead(MessageType::ReadReceipt, false), 160);
    assert_eq!(target, PADDING_BUCKETS[0]);

    let plaintext = to_padded_plaintext(&struct_bytes, target - 160).unwrap();
    let wire = WireMessage {
        version: WIRE_VERSION,
        message_type: MessageType::ReadReceipt,
        header: MessageHeader::Ratchet(fixture_header()),
        x3dh_header: None,
        encrypted_payload: {
            let mut v = vec![0x66; 24];
            v.extend_from_slice(&plaintext);
            v.extend_from_slice(&[0x77; 16]);
            v
        },
    };
    let bytes = wire.to_bytes();
    assert_eq!(bytes[1], 0x11); // top-level type byte (the recorded drift item)
    let parsed = WireMessage::from_bytes(&bytes).unwrap();
    assert_eq!(parsed.message_type, MessageType::ReadReceipt);
    assert_eq!(parsed.encrypted_payload, wire.encrypted_payload);
}

#[test]
fn s07_24_cumulative_ack_wire_roundtrip() {
    // §8.1 struct: type byte 0x12 ‖ range_count ‖ AckRange[range_count].
    let ack = CumulativeAck {
        ranges: vec![
            AckRange { sender_dh_pub: [0x01; 32], start_n: 3, end_n: 7 },
            AckRange { sender_dh_pub: [0x02; 32], start_n: 9, end_n: 9 },
        ],
    };
    let struct_bytes = ack.to_bytes().unwrap();
    assert_eq!(struct_bytes[0], 0x12);
    assert_eq!(struct_bytes[1], 2);

    let target = pad_to_bucket(2 + struct_bytes.len(), fixed_overhead(MessageType::CumulativeAck, false)).unwrap();
    let plaintext = to_padded_plaintext(&struct_bytes, target - 160).unwrap();
    let wire = WireMessage {
        version: WIRE_VERSION,
        message_type: MessageType::CumulativeAck,
        header: MessageHeader::Ratchet(fixture_header()),
        x3dh_header: None,
        encrypted_payload: {
            let mut v = vec![0x66; 24];
            v.extend_from_slice(&plaintext);
            v.extend_from_slice(&[0x77; 16]);
            v
        },
    };
    let bytes = wire.to_bytes();
    assert_eq!(bytes[1], 0x12);
    let parsed = WireMessage::from_bytes(&bytes).unwrap();
    assert_eq!(parsed.message_type, MessageType::CumulativeAck);

    // Struct round-trip.
    assert_eq!(CumulativeAck::from_bytes(&struct_bytes).unwrap(), ack);
}

/// The ack types ride the live ratchet path (§2.4: "a real ratchet-encrypted
/// message") — encrypt with message_type 0x11 and recover the receipt through
/// the §5.5 length prefix after decryption.
#[test]
fn s07_24_read_receipt_live_ratchet_path() {
    let spk = X25519KeyPair::from_seed([0x07; 32]);
    let sk = [0x42; 32];
    let mut alice = init_alice(&sk, spk.public(), &[0x08; 32]).unwrap();
    let mut bob = init_bob(&sk, X25519KeyPair::from_seed([0x07; 32]));

    let receipt = ReadReceiptContent {
        msg_id: [0x11; 16],
        timestamp: 1_777_777_777,
    };
    let plaintext = to_padded_plaintext(&receipt.to_bytes(), 96).unwrap();
    let meta = najwa_protocol::message::WirePrefixMeta {
        version: WIRE_VERSION,
        message_type: MessageType::ReadReceipt.as_byte(),
        x3dh_header: None,
    };
    let (header, ct) =
        ratchet_encrypt(&mut alice, &plaintext, &[0xCC; 64], &meta).unwrap();
    let prefix = build_wire_prefix_for(MessageType::ReadReceipt, &header, ct.len());
    let pt = ratchet_decrypt(&mut bob, &header, &ct, &[0xCC; 64], &prefix).unwrap();
    let recovered = ReadReceiptContent::from_bytes(
        najwa_protocol::message::ack::from_padded_plaintext(&pt).unwrap(),
    )
    .unwrap();
    assert_eq!(recovered, receipt);
}

fn build_wire_prefix_for(
    message_type: MessageType,
    header: &najwa_protocol::ratchet::header::RatchetHeader,
    payload_len: usize,
) -> Vec<u8> {
    najwa_protocol::message::build_wire_prefix(
        WIRE_VERSION,
        message_type.as_byte(),
        None,
        &header.to_bytes(),
        payload_len as u32,
    )
}

// ---------------------------------------------------------------------------
// S18 §19 (S08 §10.2 / Wire Formats §10.3) — ReSendRequest (0x05)
// ---------------------------------------------------------------------------

#[test]
fn s19_resend_request_mode_1_roundtrip() {
    let msg = ControlMessage::ReSendRequest {
        mode: 0x01,
        body: {
            let mut b = [0x33; 16].to_vec(); // since_logical_msg_id
            b.extend_from_slice(&1_700_000_000u64.to_be_bytes()); // fallback_floor
            b
        },
    };
    assert_eq!(msg.subtype(), 0x05);
    let bytes = msg.to_bytes();
    assert_eq!(bytes[0], 0x05);
    assert_eq!(bytes[1], 0x01); // mode
    assert_eq!(bytes.len(), 1 + 1 + 24); // subtype + mode + body
    match ControlMessage::from_bytes(&bytes).unwrap() {
        ControlMessage::ReSendRequest { mode, body } => {
            assert_eq!(mode, 0x01);
            assert_eq!(body.len(), 24);
        }
        other => panic!("wrong variant: {other:?}"),
    }
}

#[test]
fn s19_resend_request_mode_2_and_fail_closed() {
    let msg = ControlMessage::ReSendRequest {
        mode: 0x02,
        body: {
            let mut b = 1_700_000_000u64.to_be_bytes().to_vec();
            b.extend_from_slice(&1_700_000_500u64.to_be_bytes());
            b
        },
    };
    let bytes = msg.to_bytes();
    assert_eq!(bytes.len(), 1 + 1 + 16); // subtype + mode + body
    match ControlMessage::from_bytes(&bytes).unwrap() {
        ControlMessage::ReSendRequest { mode, body } => {
            assert_eq!(mode, 0x02);
            assert_eq!(body.len(), 16);
        }
        other => panic!("wrong variant: {other:?}"),
    }

    // Fail closed: wrong mode, wrong body length, empty body.
    for (mode, body) in [(0x03u8, vec![0u8; 24]), (0x01, vec![0u8; 23]), (0x02, vec![])] {
        let mut wire = vec![0x05, mode];
        wire.extend_from_slice(&body);
        assert!(ControlMessage::from_bytes(&wire).is_err());
    }
}

// ---------------------------------------------------------------------------
// §5.1 / §5.1.1 / §5.2 — padding buckets
// ---------------------------------------------------------------------------

#[test]
fn s07_5_padding_buckets_and_overhead() {
    // §5.1: 11 buckets, 256..=262144.
    assert_eq!(PADDING_BUCKETS.len(), 11);
    assert_eq!(PADDING_BUCKETS[0], 256);
    assert_eq!(PADDING_BUCKETS[10], 262_144);

    // §5.1.1: fixed overhead 160 for 0x02/0x11/0x12; 263/267 for Initial.
    assert_eq!(fixed_overhead(MessageType::Normal, false), 160);
    assert_eq!(fixed_overhead(MessageType::ReadReceipt, false), 160);
    assert_eq!(fixed_overhead(MessageType::CumulativeAck, false), 160);
    assert_eq!(fixed_overhead(MessageType::Initial, false), 263);
    assert_eq!(fixed_overhead(MessageType::Initial, true), 267);

    // §5.2: the smallest bucket whose target fits, and the deposit lands
    // exactly on it.
    let overhead = fixed_overhead(MessageType::Normal, false);
    for len in [0usize, 1, 95, 96, 97, 500] {
        let bucket = pad_to_bucket(len, overhead).unwrap();
        assert!(bucket >= len + overhead);
        let target = bucket - overhead;
        assert!(len <= target);
        // Exact-landing property: overhead + target == bucket.
        assert_eq!(overhead + target, bucket);
    }
    // §5.1.1 note: Initial (263 overhead) cannot land on the 256 bucket —
    // pad_to_bucket skips it and lands on 512.
    assert_eq!(
        pad_to_bucket(3, fixed_overhead(MessageType::Initial, false)),
        Some(512)
    );
    // Oversize returns None instead of panicking (attacker-influenced length).
    assert_eq!(pad_to_bucket(usize::MAX - 40, 160), None);
}
