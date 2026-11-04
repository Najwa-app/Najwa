//! Criterion benchmarks for najwa-protocol operations (§6.3, §9.7, §9.10).

use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;

use najwa_crypto::keys::ed25519::Ed25519KeyPair;
use najwa_crypto::keys::x25519::X25519KeyPair;
use najwa_protocol::ratchet::encrypt::ratchet_encrypt;
use najwa_protocol::ratchet::init::{init_alice, init_bob};
use najwa_protocol::x3dh::initiator::x3dh_initiate;
use najwa_protocol::x3dh::responder::x3dh_respond;
use najwa_protocol::x3dh::types::X3DHPrekeyBundle;

fn make_bundle(
    bob_ik: &Ed25519KeyPair,
    bob_spk: &X25519KeyPair,
    bob_opk: Option<&X25519KeyPair>,
) -> X3DHPrekeyBundle {
    let sig = bob_ik.sign(&najwa_protocol::x3dh::types::spk_signature_message(&bob_spk.public().to_bytes(), &[0, 0, 0, 1], 0));
    X3DHPrekeyBundle {
        identity_key: bob_ik.public().clone(),
        mailbox_ik_pub: None,
        signed_prekey: bob_spk.public().clone(),
        signed_prekey_id: [0, 0, 0, 1],
        signed_prekey_signature: sig,
        signed_prekey_timestamp: 0,
        one_time_prekey: bob_opk.map(|k| k.public().clone()),
        one_time_prekey_id: bob_opk.map(|_| [0, 0, 0, 2]),
    }
}

fn bench_x3dh(c: &mut Criterion) {
    let mut rng = rand::thread_rng();
    let alice_ik = Ed25519KeyPair::generate(&mut rng);
    let bob_ik = Ed25519KeyPair::generate(&mut rng);
    let bob_spk = X25519KeyPair::generate(&mut rng);
    let bob_opk = X25519KeyPair::generate(&mut rng);

    let bundle = make_bundle(&bob_ik, &bob_spk, Some(&bob_opk));

    c.bench_function("x3dh_initiate_with_opk", |b| {
        b.iter(|| {
            let _ = x3dh_initiate(black_box(&alice_ik), black_box(&bundle));
        })
    });

    let bundle_no_opk = make_bundle(&bob_ik, &bob_spk, None);
    c.bench_function("x3dh_initiate_no_opk", |b| {
        b.iter(|| {
            let _ = x3dh_initiate(black_box(&alice_ik), black_box(&bundle_no_opk));
        })
    });

    // X3DH respond
    let result = x3dh_initiate(&alice_ik, &bundle).unwrap();
    c.bench_function("x3dh_respond_with_opk", |b| {
        b.iter(|| {
            let _ = x3dh_respond(
                black_box(&bob_ik),
                black_box(&bob_spk),
                black_box(Some(&bob_opk)),
                black_box(&result.header),
            );
        })
    });
}

fn bench_ratchet(c: &mut Criterion) {
    let mut rng = rand::thread_rng();
    let bob_spk = X25519KeyPair::generate(&mut rng);
    let sk = [0xAAu8; 32];
    let ad = [0xBBu8; 64];
    let plaintext = vec![0u8; 256]; // typical message size

    // init_alice
    c.bench_function("ratchet_init_alice", |b| {
        b.iter(|| {
            let _ = init_alice(
                black_box(&sk),
                black_box(bob_spk.public()),
                black_box(&[0x07u8; 32]),
            );
        })
    });

    // Encrypt single message (re-init each time since RatchetState is not Clone)
    let bob_spk_pub = bob_spk.public().clone();
    c.bench_function("ratchet_encrypt_256b", |b| {
        b.iter(|| {
            let mut state = init_alice(&sk, &bob_spk_pub, &[0x07u8; 32]).unwrap();
            let meta = najwa_protocol::message::WirePrefixMeta {
                version: najwa_protocol::message::types::WIRE_VERSION,
                message_type: najwa_protocol::message::types::MessageType::Normal.as_byte(),
                x3dh_header: None,
            };
            let _ = ratchet_encrypt(black_box(&mut state), black_box(&plaintext), black_box(&ad), &meta);
        })
    });

    // Decrypt single message (re-init each time)
    let bob_spk2 = X25519KeyPair::generate(&mut rng);
    let bob_spk2_pub = bob_spk2.public().clone();
    let mut alice2 = init_alice(&sk, &bob_spk2_pub, &[0x07u8; 32]).unwrap();
    let meta = najwa_protocol::message::WirePrefixMeta {
        version: najwa_protocol::message::types::WIRE_VERSION,
        message_type: najwa_protocol::message::types::MessageType::Normal.as_byte(),
        x3dh_header: None,
    };
    let (header, ct) = ratchet_encrypt(&mut alice2, &plaintext, &ad, &meta).unwrap();
    let prefix = najwa_protocol::message::build_wire_prefix(
        najwa_protocol::message::types::WIRE_VERSION,
        najwa_protocol::message::types::MessageType::Normal.as_byte(),
        None,
        &header.to_bytes(),
        ct.len() as u32,
    );

    c.bench_function("ratchet_decrypt_256b", |b| {
        b.iter(|| {
            let bob_spk_fresh = X25519KeyPair::from_seed(bob_spk2.private().to_bytes());
            let mut state = init_bob(&sk, bob_spk_fresh);
            let _ = najwa_protocol::ratchet::decrypt::ratchet_decrypt(
                black_box(&mut state),
                black_box(&header),
                black_box(&ct),
                black_box(&ad),
                black_box(&prefix),
            );
        })
    });
}

fn bench_wire_message(c: &mut Criterion) {
    use najwa_protocol::message::types::{MessageHeader, MessageType, WireMessage, WIRE_VERSION};
    use najwa_protocol::ratchet::header::RatchetHeader;

    let mut rng = rand::thread_rng();
    let dh = X25519KeyPair::generate(&mut rng);
    let header = RatchetHeader::new(dh.public().clone(), 0, 1);
    let wire = WireMessage {
        version: WIRE_VERSION,
        message_type: MessageType::Normal,
        header: MessageHeader::Ratchet(header),
        encrypted_payload: vec![0u8; 512],
        x3dh_header: None,
};
    let wire_bytes = wire.to_bytes();

    c.bench_function("wire_message_serialize", |b| {
        b.iter(|| {
            let _ = black_box(&wire).to_bytes();
        })
    });

    c.bench_function("wire_message_deserialize", |b| {
        b.iter(|| {
            let _ = WireMessage::from_bytes(black_box(&wire_bytes));
        })
    });
}

criterion_group!(benches, bench_x3dh, bench_ratchet, bench_wire_message,);
criterion_main!(benches);
