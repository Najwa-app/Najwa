use najwa_crypto::error::CryptoError;
use najwa_crypto::keys::{Ed25519KeyPair, X25519KeyPair, X25519Public};
use najwa_protocol::message::{build_wire_prefix, WirePrefixMeta};
use najwa_protocol::ratchet::error::RatchetError;
use najwa_protocol::ratchet::persist::serialize_state;
use najwa_protocol::ratchet::prelude::{
    init_alice, init_bob, ratchet_decrypt, ratchet_encrypt, RatchetHeader,
};
use najwa_protocol::x3dh::{
    error::X3DHError,
    initiator::x3dh_initiate,
    responder::x3dh_respond,
    types::{spk_signature_message, X3DHHeader, X3DHPrekeyBundle},
};

fn low_order_points() -> [[u8; 32]; 2] {
    let mut one = [0; 32];
    one[0] = 1;
    [[0; 32], one]
}

#[test]
fn x3dh_rejects_low_order_ephemeral_signed_and_one_time_prekeys() {
    let alice = Ed25519KeyPair::from_seed(&[1; 32]);
    let bob = Ed25519KeyPair::from_seed(&[2; 32]);
    let spk = X25519KeyPair::from_seed([3; 32]);
    for point in low_order_points() {
        let bad = X25519Public::from_bytes(point);
        let header = X3DHHeader {
            identity_key: alice.public().clone(),
            device_key: alice.public().clone(),
            ephemeral_key: bad.clone(),
            signed_prekey_id: [0, 0, 0, 1],
            used_one_time_prekey_id: None,
        };
        assert!(matches!(
            x3dh_respond(&bob, &spk, None, &header),
            Err(X3DHError::CryptoError(CryptoError::InvalidPublicKey))
        ));
        for bad_spk in [true, false] {
            let public = if bad_spk {
                bad.clone()
            } else {
                spk.public().clone()
            };
            let bundle = X3DHPrekeyBundle {
                identity_key: bob.public().clone(),
                mailbox_ik_pub: Some(bob.public().clone()),
                signed_prekey_signature: bob.sign(&spk_signature_message(
                    &public.to_bytes(),
                    &[0, 0, 0, 1],
                    1_000,
                )),
                signed_prekey: public,
                signed_prekey_id: [0, 0, 0, 1],
                signed_prekey_timestamp: 1_000,
                one_time_prekey: if bad_spk { None } else { Some(bad.clone()) },
                one_time_prekey_id: if bad_spk { None } else { Some([0, 0, 0, 2]) },
            };
            // A real signature ensures rejection comes from DH validation.
            bundle.verify_spk_signature().unwrap();
            assert!(matches!(
                x3dh_initiate(&alice, &bundle),
                Err(X3DHError::CryptoError(CryptoError::InvalidPublicKey))
            ));
        }
    }
}

#[test]
fn ratchet_rejects_low_order_headers_without_mutation_and_still_decrypts() {
    let spk = X25519KeyPair::from_seed([3; 32]);
    let mut alice = init_alice(&[7; 32], spk.public(), &[4; 32]).unwrap();
    let mut bob = init_bob(&[7; 32], spk);
    let ad = [8; 64];
    let meta = WirePrefixMeta {
        version: 1,
        message_type: 2,
        x3dh_header: None,
    };

    // Check both the first receive and an established receiving chain.
    for _ in 0..2 {
        let before = serialize_state(&bob).unwrap();
        let skipped_before = bob.skipped.len();
        for point in low_order_points() {
            let mut bytes = [0; 72];
            bytes[..32].copy_from_slice(&point);
            let header = RatchetHeader::from_bytes(&bytes).unwrap();
            assert!(matches!(
                ratchet_decrypt(&mut bob, &header, &[0; 40], &ad, &[]),
                Err(RatchetError::CryptoError(CryptoError::InvalidPublicKey))
            ));
            assert_eq!(serialize_state(&bob).unwrap(), before);
            assert_eq!(bob.skipped.len(), skipped_before);
        }
        let (header, ciphertext) =
            ratchet_encrypt(&mut alice, b"still receiving", &ad, &meta).unwrap();
        let prefix = build_wire_prefix(1, 2, None, &header.to_bytes(), ciphertext.len() as u32);
        assert_eq!(
            ratchet_decrypt(&mut bob, &header, &ciphertext, &ad, &prefix).unwrap(),
            b"still receiving"
        );
    }
}
