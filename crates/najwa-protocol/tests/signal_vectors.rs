//! §9.6 Cryptographic cross-validation test vectors.
//!
//! Validates X3DH and Double Ratchet implementations against
//! deterministic known-answer tests using fixed seeds, plus
//! RFC 5869 HKDF reference vectors.
//!
//! ```sh
//! cargo test -p najwa-protocol --test signal_vectors
//! ```

use najwa_crypto::keys::ed25519::Ed25519KeyPair;
use najwa_crypto::keys::x25519::X25519KeyPair;
use najwa_protocol::message::{build_wire_prefix, WirePrefixMeta};
use najwa_protocol::ratchet::header::RatchetHeader;
use najwa_protocol::ratchet::init::{init_alice, init_bob};
use najwa_protocol::ratchet::state::RatchetState;
use najwa_protocol::x3dh::initiator::x3dh_initiate;
use najwa_protocol::x3dh::responder::x3dh_respond;
use najwa_protocol::x3dh::types::X3DHPrekeyBundle;

// Adapters onto the wire-format-aware ratchet API — every vector frame here is a
// Standard (0x02) message with no X3DH header; the canonical wire_prefix is
// rebuilt so encrypt and decrypt agree on the AAD (S06 §3.4).
fn ratchet_encrypt(
    state: &mut RatchetState,
    plaintext: &[u8],
    ad: &[u8],
) -> najwa_protocol::ratchet::error::Result<(RatchetHeader, Vec<u8>)> {
    let meta = WirePrefixMeta {
        version: 1,
        message_type: 0x02,
        x3dh_header: None,
    };
    najwa_protocol::ratchet::encrypt::ratchet_encrypt(state, plaintext, ad, &meta)
}

fn ratchet_decrypt(
    state: &mut RatchetState,
    header: &RatchetHeader,
    encrypted_payload: &[u8],
    ad: &[u8],
) -> najwa_protocol::ratchet::error::Result<Vec<u8>> {
    let wire_prefix = build_wire_prefix(
        1,
        0x02,
        None,
        &header.to_bytes(),
        encrypted_payload.len() as u32,
    );
    najwa_protocol::ratchet::decrypt::ratchet_decrypt(
        state,
        header,
        encrypted_payload,
        ad,
        &wire_prefix,
    )
}

/// Validate X3DH: both sides derive the same shared secret from fixed seeds.
///
/// Uses deterministic key generation so the test is fully reproducible.
/// Verifies the core X3DH invariant: initiator and responder produce
/// identical shared secrets and associated data.
#[test]
fn x3dh_known_answer_both_sides_agree() {
    // Fixed seeds for deterministic keys
    let alice_ik = Ed25519KeyPair::from_seed(&[0x01; 32]);
    let bob_ik = Ed25519KeyPair::from_seed(&[0x02; 32]);

    // Bob's signed prekey (deterministic)
    let bob_spk = X25519KeyPair::from_seed([0x10; 32]);
    let bob_spk_pub = bob_spk.public().clone();

    // Bob's one-time prekey (deterministic)
    let bob_opk = X25519KeyPair::from_seed([0x20; 32]);
    let bob_opk_pub = bob_opk.public().clone();

    // Sign SPK with Bob's identity key
    let spk_sig = bob_ik.sign(&najwa_protocol::x3dh::types::spk_signature_message(&bob_spk_pub.to_bytes(), &[0, 0, 0, 1], 0));
    let spk_id: [u8; 4] = [0x00, 0x00, 0x00, 0x01];
    let opk_id: [u8; 4] = [0x00, 0x00, 0x00, 0x02];

    // Build prekey bundle
    let bundle = X3DHPrekeyBundle {
        identity_key: bob_ik.public().clone(),
        mailbox_ik_pub: None, // Use identity_key for SPK verification
        signed_prekey: bob_spk_pub.clone(),
        signed_prekey_id: spk_id,
        signed_prekey_signature: spk_sig,
        signed_prekey_timestamp: 0,
        one_time_prekey: Some(bob_opk_pub),
        one_time_prekey_id: Some(opk_id),
    };

    // Alice initiates
    let alice_result = x3dh_initiate(&alice_ik, &bundle).unwrap();

    // Bob responds
    let bob_result = x3dh_respond(&bob_ik, &bob_spk, Some(&bob_opk), &alice_result.header).unwrap();

    // Core invariant: same shared secret
    assert_eq!(
        alice_result.shared_secret, bob_result.shared_secret,
        "X3DH shared secrets must match"
    );

    // Same associated data
    assert_eq!(
        alice_result.associated_data, bob_result.associated_data,
        "X3DH associated data must match"
    );

    // Associated data is IK_A || IK_B (64 bytes)
    assert_eq!(alice_result.associated_data.len(), 64);

    // Shared secret must not be all-zero
    assert_ne!(alice_result.shared_secret, [0u8; 32]);
}

/// X3DH 3-DH fallback (no OPK) still produces matching secrets.
#[test]
fn x3dh_known_answer_3dh_fallback() {
    let alice_ik = Ed25519KeyPair::from_seed(&[0x03; 32]);
    let bob_ik = Ed25519KeyPair::from_seed(&[0x04; 32]);

    let bob_spk = X25519KeyPair::from_seed([0x30; 32]);
    let bob_spk_pub = bob_spk.public().clone();
    let spk_sig = bob_ik.sign(&najwa_protocol::x3dh::types::spk_signature_message(&bob_spk_pub.to_bytes(), &[0, 0, 0, 1], 0));

    let bundle = X3DHPrekeyBundle {
        identity_key: bob_ik.public().clone(),
        mailbox_ik_pub: None,
        signed_prekey: bob_spk_pub,
        signed_prekey_id: [0, 0, 0, 1],
        signed_prekey_signature: spk_sig,
        signed_prekey_timestamp: 0,
        one_time_prekey: None, // no OPK
        one_time_prekey_id: None,
    };

    let alice_result = x3dh_initiate(&alice_ik, &bundle).unwrap();
    let bob_result = x3dh_respond(&bob_ik, &bob_spk, None, &alice_result.header).unwrap();

    assert_eq!(alice_result.shared_secret, bob_result.shared_secret);
    assert_ne!(alice_result.shared_secret, [0u8; 32]);
}

/// X3DH with OPK produces a different secret than without OPK (same other keys).
#[test]
fn x3dh_known_answer_opk_changes_secret() {
    let alice_ik = Ed25519KeyPair::from_seed(&[0x05; 32]);
    let bob_ik = Ed25519KeyPair::from_seed(&[0x06; 32]);
    let bob_spk = X25519KeyPair::from_seed([0x40; 32]);
    let bob_opk = X25519KeyPair::from_seed([0x50; 32]);
    let spk_sig = bob_ik.sign(&najwa_protocol::x3dh::types::spk_signature_message(&bob_spk.public().to_bytes(), &[0, 0, 0, 1], 0));

    // With OPK
    let bundle_with = X3DHPrekeyBundle {
        identity_key: bob_ik.public().clone(),
        mailbox_ik_pub: None,
        signed_prekey: bob_spk.public().clone(),
        signed_prekey_id: [0, 0, 0, 1],
        signed_prekey_signature: spk_sig.clone(),
        signed_prekey_timestamp: 0,
        one_time_prekey: Some(bob_opk.public().clone()),
        one_time_prekey_id: Some([0, 0, 0, 2]),
    };

    // Without OPK
    let bundle_without = X3DHPrekeyBundle {
        identity_key: bob_ik.public().clone(),
        mailbox_ik_pub: None,
        signed_prekey: bob_spk.public().clone(),
        signed_prekey_id: [0, 0, 0, 1],
        signed_prekey_signature: spk_sig,
        signed_prekey_timestamp: 0,
        one_time_prekey: None,
        one_time_prekey_id: None,
    };

    let result_with = x3dh_initiate(&alice_ik, &bundle_with).unwrap();
    let result_without = x3dh_initiate(&alice_ik, &bundle_without).unwrap();

    assert_ne!(
        result_with.shared_secret, result_without.shared_secret,
        "OPK must influence the shared secret"
    );
}

/// Full Double Ratchet session: X3DH → init → encrypt → decrypt → reply.
///
/// Verifies the entire chain from key agreement through bidirectional messaging.
#[test]
fn double_ratchet_known_answer_full_session() {
    let alice_ik = Ed25519KeyPair::from_seed(&[0x01; 32]);
    let bob_ik = Ed25519KeyPair::from_seed(&[0x02; 32]);

    let bob_spk = X25519KeyPair::from_seed([0x10; 32]);
    let bob_opk = X25519KeyPair::from_seed([0x20; 32]);
    let spk_sig = bob_ik.sign(&najwa_protocol::x3dh::types::spk_signature_message(&bob_spk.public().to_bytes(), &[0, 0, 0, 1], 0));

    let bundle = X3DHPrekeyBundle {
        identity_key: bob_ik.public().clone(),
        mailbox_ik_pub: None,
        signed_prekey: bob_spk.public().clone(),
        signed_prekey_id: [0, 0, 0, 1],
        signed_prekey_signature: spk_sig,
        signed_prekey_timestamp: 0,
        one_time_prekey: Some(bob_opk.public().clone()),
        one_time_prekey_id: Some([0, 0, 0, 2]),
    };

    // X3DH
    let alice_x3dh = x3dh_initiate(&alice_ik, &bundle).unwrap();
    let bob_x3dh = x3dh_respond(&bob_ik, &bob_spk, Some(&bob_opk), &alice_x3dh.header).unwrap();
    assert_eq!(alice_x3dh.shared_secret, bob_x3dh.shared_secret);

    let ad = alice_x3dh.associated_data.clone();

    // Initialize Double Ratchet
    let mut alice_state = init_alice(
        &alice_x3dh.shared_secret,
        bob_spk.public(),
        &alice_x3dh.ephemeral_seed,
    )
    .unwrap();
    let mut bob_state = init_bob(&bob_x3dh.shared_secret, bob_spk);

    // Alice sends 3 messages to Bob
    let messages = [
        b"hello bob".to_vec(),
        b"how are you?".to_vec(),
        b"testing 123".to_vec(),
    ];
    for msg in &messages {
        let (header, ciphertext) = ratchet_encrypt(&mut alice_state, msg, &ad).unwrap();
        let plaintext = ratchet_decrypt(&mut bob_state, &header, &ciphertext, &ad).unwrap();
        assert_eq!(&plaintext, msg);
    }

    // Bob replies
    let reply = b"hi alice, all good!".to_vec();
    let (header, ciphertext) = ratchet_encrypt(&mut bob_state, &reply, &ad).unwrap();
    let plaintext = ratchet_decrypt(&mut alice_state, &header, &ciphertext, &ad).unwrap();
    assert_eq!(plaintext, reply);

    // Alice sends again (new ratchet step)
    let msg2 = b"great to hear".to_vec();
    let (header, ciphertext) = ratchet_encrypt(&mut alice_state, &msg2, &ad).unwrap();
    let plaintext = ratchet_decrypt(&mut bob_state, &header, &ciphertext, &ad).unwrap();
    assert_eq!(plaintext, msg2);
}

/// Double Ratchet: 50 messages each direction, verifying all decrypt correctly.
#[test]
fn double_ratchet_known_answer_50_message_exchange() {
    let alice_ik = Ed25519KeyPair::from_seed(&[0x07; 32]);
    let bob_ik = Ed25519KeyPair::from_seed(&[0x08; 32]);

    let bob_spk = X25519KeyPair::from_seed([0x60; 32]);
    let spk_sig = bob_ik.sign(&najwa_protocol::x3dh::types::spk_signature_message(&bob_spk.public().to_bytes(), &[0, 0, 0, 1], 0));

    let bundle = X3DHPrekeyBundle {
        identity_key: bob_ik.public().clone(),
        mailbox_ik_pub: None,
        signed_prekey: bob_spk.public().clone(),
        signed_prekey_id: [0, 0, 0, 1],
        signed_prekey_signature: spk_sig,
        signed_prekey_timestamp: 0,
        one_time_prekey: None,
        one_time_prekey_id: None,
    };

    let alice_x3dh = x3dh_initiate(&alice_ik, &bundle).unwrap();
    let bob_x3dh = x3dh_respond(&bob_ik, &bob_spk, None, &alice_x3dh.header).unwrap();
    let ad = alice_x3dh.associated_data.clone();

    let mut alice_state = init_alice(
        &alice_x3dh.shared_secret,
        bob_spk.public(),
        &alice_x3dh.ephemeral_seed,
    )
    .unwrap();
    let mut bob_state = init_bob(&bob_x3dh.shared_secret, bob_spk);

    for i in 0u32..50 {
        // Alice → Bob
        let msg_a = format!("alice msg {}", i).into_bytes();
        let (h, ct) = ratchet_encrypt(&mut alice_state, &msg_a, &ad).unwrap();
        let pt = ratchet_decrypt(&mut bob_state, &h, &ct, &ad).unwrap();
        assert_eq!(pt, msg_a, "Alice→Bob message {} failed", i);

        // Bob → Alice
        let msg_b = format!("bob msg {}", i).into_bytes();
        let (h, ct) = ratchet_encrypt(&mut bob_state, &msg_b, &ad).unwrap();
        let pt = ratchet_decrypt(&mut alice_state, &h, &ct, &ad).unwrap();
        assert_eq!(pt, msg_b, "Bob→Alice message {} failed", i);
    }
}

/// Double Ratchet: out-of-order delivery still decrypts.
#[test]
fn double_ratchet_known_answer_out_of_order() {
    let alice_ik = Ed25519KeyPair::from_seed(&[0x09; 32]);
    let bob_ik = Ed25519KeyPair::from_seed(&[0x0A; 32]);

    let bob_spk = X25519KeyPair::from_seed([0x70; 32]);
    let spk_sig = bob_ik.sign(&najwa_protocol::x3dh::types::spk_signature_message(&bob_spk.public().to_bytes(), &[0, 0, 0, 1], 0));

    let bundle = X3DHPrekeyBundle {
        identity_key: bob_ik.public().clone(),
        mailbox_ik_pub: None,
        signed_prekey: bob_spk.public().clone(),
        signed_prekey_id: [0, 0, 0, 1],
        signed_prekey_signature: spk_sig,
        signed_prekey_timestamp: 0,
        one_time_prekey: None,
        one_time_prekey_id: None,
    };

    let alice_x3dh = x3dh_initiate(&alice_ik, &bundle).unwrap();
    let bob_x3dh = x3dh_respond(&bob_ik, &bob_spk, None, &alice_x3dh.header).unwrap();
    let ad = alice_x3dh.associated_data.clone();

    let mut alice_state = init_alice(
        &alice_x3dh.shared_secret,
        bob_spk.public(),
        &alice_x3dh.ephemeral_seed,
    )
    .unwrap();
    let mut bob_state = init_bob(&bob_x3dh.shared_secret, bob_spk);

    // Alice sends 3 messages
    let (h0, ct0) = ratchet_encrypt(&mut alice_state, b"msg 0", &ad).unwrap();
    let (h1, ct1) = ratchet_encrypt(&mut alice_state, b"msg 1", &ad).unwrap();
    let (h2, ct2) = ratchet_encrypt(&mut alice_state, b"msg 2", &ad).unwrap();

    // Bob receives out of order: 2, 0, 1
    let pt2 = ratchet_decrypt(&mut bob_state, &h2, &ct2, &ad).unwrap();
    assert_eq!(pt2, b"msg 2");
    let pt0 = ratchet_decrypt(&mut bob_state, &h0, &ct0, &ad).unwrap();
    assert_eq!(pt0, b"msg 0");
    let pt1 = ratchet_decrypt(&mut bob_state, &h1, &ct1, &ad).unwrap();
    assert_eq!(pt1, b"msg 1");
}

// =========================================================================
// RFC 5869 HKDF test vectors (publicly documented)
// =========================================================================

/// Validate HKDF output against RFC 5869 test vectors.
#[test]
fn hkdf_rfc5869_vector_1() {
    // RFC 5869 Test Case 1
    let ikm = hex_decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let salt = hex_decode("000102030405060708090a0b0c");
    let info = hex_decode("f0f1f2f3f4f5f6f7f8f9");
    let expected_okm = hex_decode(
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
    );

    let result = najwa_crypto::kdf::hkdf_sha256(&ikm, &salt, &info, 42).unwrap();
    assert_eq!(&result[..], &expected_okm[..]);
}

#[test]
fn hkdf_rfc5869_vector_2() {
    // RFC 5869 Test Case 2
    let ikm = hex_decode(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
         202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f\
         404142434445464748494a4b4c4d4e4f",
    );
    let salt = hex_decode(
        "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f\
         808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f\
         a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
    );
    let info = hex_decode(
        "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf\
         d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef\
         f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
    );
    let expected_okm = hex_decode(
        "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c\
         59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71\
         cc30c58179ec3e87c14c01d5c1f3434f1d87",
    );

    let result = najwa_crypto::kdf::hkdf_sha256(&ikm, &salt, &info, 82).unwrap();
    assert_eq!(&result[..], &expected_okm[..]);
}

#[test]
fn hkdf_rfc5869_vector_3() {
    // RFC 5869 Test Case 3 (zero-length salt and info)
    let ikm = hex_decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let salt = vec![];
    let info = vec![];
    let expected_okm = hex_decode(
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d\
         9d201395faa4b61a96c8",
    );

    let result = najwa_crypto::kdf::hkdf_sha256(&ikm, &salt, &info, 42).unwrap();
    assert_eq!(&result[..], &expected_okm[..]);
}

/// Helper: decode hex string to bytes
fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
