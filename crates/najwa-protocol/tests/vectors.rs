//! S18 conformance vectors: S18 §9 per-mailbox keys and S18 §11 pairwise
//! pseudonyms, plus a pin for the rendezvous library code (its 160-byte
//! Argon2id slice layout, `envelope_secret` at output[96:128]), which the app
//! does not use and S18 does not list.
//!
//! The expected values are reference pins: equality pins of this
//! implementation, not independent proofs. The S18 verification clauses
//! (different-onion unlinkability; cross-party pseudonym agreement) are
//! asserted as properties alongside the pins.

use najwa_crypto::keys::Ed25519KeyPair;
use najwa_protocol::contact::mailbox_key::derive_mailbox_signing_key;
use najwa_protocol::contact::rendezvous::RendezvousSession;
use najwa_protocol::mailbox::types::MailboxConfig;
use najwa_protocol::pseudonym::derive_pairwise_pseudonyms;

const TEST_IK_PRIV: [u8; 32] = [0xBB; 32];
const TEST_ONION_56: &str = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz";

/// RFC 8032 §7.1 TEST 1 seed (serves as party A in S18 §11).
const RFC8032_TEST1_SEED: [u8; 32] = [
    0x9D, 0x61, 0xB1, 0x9D, 0xEF, 0xFD, 0x5A, 0x60, 0xBA, 0x84, 0x4A, 0xF4, 0x92, 0xEC, 0x2C,
    0xC4, 0x44, 0x49, 0xC5, 0x69, 0x7B, 0x32, 0x69, 0x19, 0x70, 0x3B, 0xAC, 0x03, 0x1C, 0xAE,
    0x7F, 0x60,
];

#[test]
fn s18_9_per_mailbox_derived_key() {
    // Pin: Ed25519_Generate(HKDF(IK_priv, salt=onion, info=mailbox-signing-key)).
    let kp = derive_mailbox_signing_key(&TEST_IK_PRIV, TEST_ONION_56).unwrap();
    assert_eq!(
        hex::encode(kp.public().to_bytes()),
        "b4345fde880de11080a2b4c88a75a5b500f5a1d14d2d7c6103f3dc186ae16eb4"
    );

    // S18 §9 verification clause: a different onion with the same IK_priv yields a
    // different (unlinkable) mailbox_ik_pub.
    let other =
        derive_mailbox_signing_key(&TEST_IK_PRIV, "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq")
            .unwrap();
    assert_eq!(
        hex::encode(other.public().to_bytes()),
        "c29e8e6edd9e2f34bcb0b53d430e0606a0113be20ef8282ef6b72c36753d84a2"
    );
    assert_ne!(kp.public().to_bytes(), other.public().to_bytes());
}

#[test]
fn s18_10_rendezvous_derivation() {
    // Rendezvous library code (not used by the app): slices of the 160-byte
    // Argon2id output, envelope_secret at output[96:128].
    let slices = |caps: ([u8; 32], [u8; 32], [u8; 32])| {
        let mailbox = MailboxConfig {
            onion_address: TEST_ONION_56.to_string(),
            fetch_capability: caps.0,
            deposit_capability: caps.1,
            envelope_secret: caps.2,
            cover_deposit_capability: None,
            cover_fetch_capability: None,
            cover_envelope_secret: None,
        };
        RendezvousSession::from_phrase("correct horse battery staple extra words", &[mailbox])
            .unwrap()
    };
    let a = slices(([0x11; 32], [0x22; 32], [0x33; 32]));
    let b = slices(([0x99; 32], [0x88; 32], [0x77; 32])); // different known mailboxes

    // Reference pins.
    assert_eq!(
        hex::encode(a.rendezvous_id),
        "45502835690e61a18594ac196b32935e91703bf51c4f6f2fba35cc29873987ec"
    );
    assert_eq!(
        hex::encode(a.deposit_capability),
        "4fc2e6849a16d6786dcd903b7377e343be74288a5e81e46a0c5a48744e86c7cc"
    );
    assert_eq!(
        hex::encode(a.fetch_capability),
        "db1180c95863276e1385092016381642e6c758b8c785ab5ad265e72841ac2aec"
    );
    assert_eq!(
        hex::encode(a.envelope_secret),
        "4c185770f171940fab601a90f8f9ea3af6cec1b0930abdc251dd0bc02f2e97fa"
    );

    // Both parties derive identical values from the same phrase — the slices
    // do not depend on the known-mailbox capabilities.
    assert_eq!(a.rendezvous_id, b.rendezvous_id);
    assert_eq!(a.deposit_capability, b.deposit_capability);
    assert_eq!(a.fetch_capability, b.fetch_capability);
    assert_eq!(a.envelope_secret, b.envelope_secret);
}

#[test]
fn s18_11_pairwise_pseudonyms() {
    // S18 §11.1: party A = RFC 8032 §7.1 TEST 1 (independent anchor for the public
    // key); party B = fixed seed. Pub A > pub B bytewise, so B is "initiator".
    let a = Ed25519KeyPair::from_seed(&RFC8032_TEST1_SEED);
    let b = Ed25519KeyPair::from_seed(&[0x02; 32]);

    assert_eq!(
        hex::encode(a.public().to_bytes()),
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    );
    assert_eq!(
        hex::encode(b.public().to_bytes()),
        "8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394"
    );

    // Reference pins. The function returns (my_pseudo, their_pseudo) in the
    // CALLER's frame; pub A > pub B bytewise (S01 §8.2 ordering), so A is the
    // responder and B the initiator here.
    let from_a = derive_pairwise_pseudonyms(&a, b.public()).unwrap();
    assert_eq!(
        hex::encode(from_a.0.as_bytes()),
        "1f0e77a114e637cab6be629bb256c9ae8a0382b2a047abb88ed688485980ee3e"
    );
    assert_eq!(
        hex::encode(from_a.1.as_bytes()),
        "93f48e8e0da7d944b528021303cb7c325c28e050e6e9455063b070335070d962"
    );

    // S18 §11 verification clause: deriving from EITHER side yields the identical
    // pseudonym pair (each party's own frame, so the tuple is swapped).
    let from_b = derive_pairwise_pseudonyms(&b, a.public()).unwrap();
    assert_eq!(from_b.0.as_bytes(), from_a.1.as_bytes());
    assert_eq!(from_b.1.as_bytes(), from_a.0.as_bytes());
}
