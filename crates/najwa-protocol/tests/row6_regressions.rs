use najwa_crypto::keys::{Ed25519KeyPair, X25519KeyPair};
use najwa_protocol::message::types::{MessageType, WIRE_VERSION};
use najwa_protocol::message::{build_wire_prefix, WirePrefixMeta};
use najwa_protocol::ratchet::{
    decrypt::ratchet_decrypt,
    encrypt::ratchet_encrypt,
    init::{init_alice, init_bob},
    persist::serialize_state,
};
use najwa_protocol::x3dh::{
    initiator::x3dh_initiate,
    responder::x3dh_respond,
    types::{spk_signature_message, X3DHPrekeyBundle},
};

fn pair() -> (
    najwa_protocol::ratchet::state::RatchetState,
    najwa_protocol::ratchet::state::RatchetState,
) {
    let spk = X25519KeyPair::from_seed([21; 32]);
    (
        init_alice(&[11; 32], spk.public(), &[31; 32]).unwrap(),
        init_bob(&[11; 32], spk),
    )
}
fn meta() -> WirePrefixMeta<'static> {
    WirePrefixMeta {
        version: WIRE_VERSION,
        message_type: MessageType::Normal.as_byte(),
        x3dh_header: None,
    }
}
fn prefix(header: &najwa_protocol::ratchet::header::RatchetHeader, len: usize) -> Vec<u8> {
    build_wire_prefix(
        WIRE_VERSION,
        MessageType::Normal.as_byte(),
        None,
        &header.to_bytes(),
        len as u32,
    )
}

#[test]
fn exhausted_sender_returns_error_without_mutation_or_panic() {
    let (mut alice, _) = pair();
    alice.ns = u32::MAX;
    let before = serialize_state(&alice).unwrap();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        ratchet_encrypt(&mut alice, b"message", &[9; 64], &meta())
    }));
    assert!(result.is_ok(), "counter exhaustion must not panic");
    assert!(result.unwrap().is_err());
    assert_eq!(serialize_state(&alice).unwrap(), before);
}

#[test]
fn receiving_near_counter_limit_does_not_overflow_skip_bound() {
    let (mut alice, mut bob) = pair();
    let (header, body) = ratchet_encrypt(&mut alice, b"first", &[9; 64], &meta()).unwrap();
    ratchet_decrypt(
        &mut bob,
        &header,
        &body,
        &[9; 64],
        &prefix(&header, body.len()),
    )
    .unwrap();
    alice.ns = u32::MAX - 10;
    bob.nr = alice.ns;
    let (header, body) = ratchet_encrypt(&mut alice, b"last stretch", &[9; 64], &meta()).unwrap();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        ratchet_decrypt(
            &mut bob,
            &header,
            &body,
            &[9; 64],
            &prefix(&header, body.len()),
        )
    }));
    assert!(
        result.is_ok(),
        "small valid skip near u32::MAX must not panic"
    );
    assert_eq!(result.unwrap().unwrap(), b"last stretch");
}

#[test]
fn modified_transmitted_nonce_is_rejected_without_consuming_key() {
    let (mut alice, mut bob) = pair();
    let (header, body) = ratchet_encrypt(&mut alice, b"secret", &[9; 64], &meta()).unwrap();
    let before = serialize_state(&bob).unwrap();
    let mut altered = body.clone();
    altered[0] ^= 1;
    assert!(ratchet_decrypt(
        &mut bob,
        &header,
        &altered,
        &[9; 64],
        &prefix(&header, body.len())
    )
    .is_err());
    assert_eq!(serialize_state(&bob).unwrap(), before);
    assert_eq!(
        ratchet_decrypt(
            &mut bob,
            &header,
            &body,
            &[9; 64],
            &prefix(&header, body.len())
        )
        .unwrap(),
        b"secret"
    );
}

fn bundle(
    bob: &Ed25519KeyPair,
    spk: &X25519KeyPair,
    opk: Option<&X25519KeyPair>,
) -> X3DHPrekeyBundle {
    X3DHPrekeyBundle {
        identity_key: bob.public().clone(),
        mailbox_ik_pub: None,
        signed_prekey: spk.public().clone(),
        signed_prekey_id: 7u32.to_be_bytes(),
        signed_prekey_signature: bob.sign(&spk_signature_message(
            &spk.public().to_bytes(),
            &7u32.to_be_bytes(),
            100,
        )),
        signed_prekey_timestamp: 100,
        one_time_prekey: opk.map(|k| k.public().clone()),
        one_time_prekey_id: opk.map(|_| 8u32.to_be_bytes()),
    }
}

#[test]
fn legacy_spk_signature_cannot_authorize_changed_id_or_timestamp() {
    let bob = Ed25519KeyPair::from_seed(&[4; 32]);
    let spk = X25519KeyPair::from_seed([5; 32]);
    let mut b = bundle(&bob, &spk, None);
    b.signed_prekey_signature = bob.sign(&spk.public().to_bytes());
    b.signed_prekey_id = [99; 4];
    b.signed_prekey_timestamp = u64::MAX;
    assert!(b.verify_spk_signature().is_err());
}

#[test]
fn x3dh_rejects_inconsistent_opk_presence() {
    let alice = Ed25519KeyPair::from_seed(&[3; 32]);
    let bob = Ed25519KeyPair::from_seed(&[4; 32]);
    let spk = X25519KeyPair::from_seed([5; 32]);
    let opk = X25519KeyPair::from_seed([6; 32]);
    let mut b = bundle(&bob, &spk, Some(&opk));
    b.one_time_prekey_id = None;
    assert!(x3dh_initiate(&alice, &b).is_err());
    let result = x3dh_initiate(&alice, &bundle(&bob, &spk, Some(&opk))).unwrap();
    assert!(x3dh_respond(&bob, &spk, None, &result.header).is_err());
}

#[test]
fn manifest_requires_a_valid_membership_witness() {
    use najwa_protocol::{
        mailbox::types::{OneTimePrekey, PrekeyBundle},
        x3dh::{initiator::check_bundle_manifest, types::build_wire_manifest},
    };
    let signer = Ed25519KeyPair::from_seed(&[71; 32]);
    let mut b = PrekeyBundle {
        identity_key: signer.public().to_bytes(),
        signed_prekey: [1; 32],
        signed_prekey_id: 7,
        signed_prekey_signature: vec![0; 64],
        signed_prekey_timestamp: 10,
        one_time_prekeys: vec![OneTimePrekey {
            id: 9,
            key: [2; 32],
        }],
        manifest: Some(build_wire_manifest(
            &signer,
            &7u32.to_be_bytes(),
            &[9, 10],
            10,
        )),
    };
    check_bundle_manifest(&b, signer.public()).unwrap();
    b.one_time_prekeys[0].id = 11;
    assert!(check_bundle_manifest(&b, signer.public()).is_err());
    b.one_time_prekeys[0].id = 9;
    b.manifest.as_mut().unwrap().opk_ids = vec![9, 11];
    assert!(check_bundle_manifest(&b, signer.public()).is_err());
    b.manifest = Some(build_wire_manifest(&signer, &7u32.to_be_bytes(), &[], 10));
    assert!(check_bundle_manifest(&b, signer.public()).is_err());
    b.one_time_prekeys.clear();
    check_bundle_manifest(&b, signer.public()).unwrap();
}

#[test]
fn ratchet_state_decode_rejects_trailing_and_unbounded_lengths() {
    use najwa_protocol::ratchet::persist::deserialize_state;
    let (state, _) = pair();
    let mut encoded = serialize_state(&state).unwrap();
    deserialize_state(&encoded).unwrap();
    encoded.push(0);
    assert!(deserialize_state(&encoded).is_err());
    assert!(deserialize_state(&[255; 512]).is_err());
}
