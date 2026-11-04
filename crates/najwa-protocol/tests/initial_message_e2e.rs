//! Regression: end-to-end first-message X3DH + ratchet + wire roundtrip.
//!
//! Reproduces the production bug where Bob receives Alice's very first
//! message after a fresh-install contact exchange and `ratchet_decrypt`
//! returns a generic AEAD failure ("decryption failed"), even though both
//! sides have the matching identity / SPK / OPK keys.
//!
//! This test exercises everything *except* the Tor mailbox transport and
//! SQLCipher persistence:
//!
//!   1. Alice creates her real Ed25519 identity (the seed Bob will have
//!      stored as `their_ik_pub`).
//!   2. Bob creates his real Ed25519 identity and publishes a prekey
//!      bundle in the same shape `najwa-ffi::generate_prekey_bundle`
//!      produces (per-mailbox derived signing key, signed SPK, one OPK).
//!   3. Alice fetches the wire bundle, builds an `X3DHPrekeyBundle` the
//!      same way `najwa-ffi::send_message_internal` does, runs
//!      `x3dh_initiate`, initialises a Double Ratchet as Alice, and
//!      `ratchet_encrypt`s a plaintext.
//!   4. The X3DH header + ratchet header + ciphertext are packed into a
//!      wire blob using the exact byte layout from `najwa-ffi::pack_initial`.
//!   5. The blob is unpacked using the exact byte layout from
//!      `najwa-ffi::unpack_wire`.
//!   6. Bob looks up his SPK + OPK private keys, runs `x3dh_respond`,
//!      `init_bob`, and `ratchet_decrypt`.
//!
//! If the round-trip succeeds the assertion at the end passes; if any
//! step in the FFI-mirroring layer corrupts the AAD / shared secret /
//! header bytes, the AEAD verification fails and the test fails.

use najwa_crypto::keys::ed25519::Ed25519KeyPair;
use najwa_crypto::keys::x25519::X25519KeyPair;
use najwa_protocol::contact::mailbox_key::derive_mailbox_signing_key;
use najwa_protocol::message::{build_wire_prefix, WirePrefixMeta};
use najwa_protocol::ratchet::decrypt::ratchet_decrypt;
use najwa_protocol::ratchet::encrypt::ratchet_encrypt;
use najwa_protocol::ratchet::header::RatchetHeader;
use najwa_protocol::ratchet::init::{init_alice, init_bob};
use najwa_protocol::ratchet::state::RatchetState;
use najwa_protocol::x3dh::initiator::x3dh_initiate;
use najwa_protocol::x3dh::responder::x3dh_respond;
use najwa_protocol::x3dh::types::{X3DHHeader, X3DHPrekeyBundle};

// Adapters onto the wire-format-aware ratchet API (S06 §3.4). `enc`/`dec` build
// the canonical wire prefix from the frame context so encrypt and decrypt agree
// on the AAD — mirroring what send.rs / receive.rs do.
fn enc(
    state: &mut RatchetState,
    pt: &[u8],
    ad: &[u8],
    msg_type: u8,
    x3dh: Option<&[u8]>,
) -> (RatchetHeader, Vec<u8>) {
    let meta = WirePrefixMeta {
        version: 1,
        message_type: msg_type,
        x3dh_header: x3dh,
    };
    ratchet_encrypt(state, pt, ad, &meta).expect("ratchet_encrypt")
}

fn dec(
    state: &mut RatchetState,
    h: &RatchetHeader,
    ep: &[u8],
    ad: &[u8],
    msg_type: u8,
    x3dh: Option<&[u8]>,
) -> najwa_protocol::ratchet::error::Result<Vec<u8>> {
    let wire_prefix = build_wire_prefix(1, msg_type, x3dh, &h.to_bytes(), ep.len() as u32);
    ratchet_decrypt(state, h, ep, ad, &wire_prefix)
}

// ---------------------------------------------------------------------------
// Wire format helpers — byte-for-byte copies of the FFI layer's
// `pack_initial` / `unpack_wire` so the test catches any silent skew
// between the two.
// ---------------------------------------------------------------------------

const MSG_TYPE_INITIAL: u8 = 0x01;

fn pack_initial(x3dh_header: &X3DHHeader, ratchet_header: &RatchetHeader, ct: &[u8]) -> Vec<u8> {
    let x3dh_bytes = serde_json::to_vec(x3dh_header).expect("serialize x3dh header");
    let ratchet_bytes = ratchet_header.to_bytes();
    let mut wire = Vec::new();
    wire.push(MSG_TYPE_INITIAL);
    wire.extend_from_slice(&(x3dh_bytes.len() as u16).to_be_bytes());
    wire.extend_from_slice(&x3dh_bytes);
    wire.extend_from_slice(&(ratchet_bytes.len() as u16).to_be_bytes());
    wire.extend_from_slice(&ratchet_bytes);
    wire.extend_from_slice(ct);
    wire
}

fn unpack_wire(wire: &[u8]) -> (X3DHHeader, RatchetHeader, Vec<u8>) {
    assert!(wire.len() >= 4, "wire too short");
    assert_eq!(wire[0], MSG_TYPE_INITIAL, "expected MSG_TYPE_INITIAL");
    let mut pos = 1;
    let x3dh_len = u16::from_be_bytes([wire[pos], wire[pos + 1]]) as usize;
    pos += 2;
    let x3dh_header: X3DHHeader =
        serde_json::from_slice(&wire[pos..pos + x3dh_len]).expect("parse x3dh header");
    pos += x3dh_len;
    let ratchet_len = u16::from_be_bytes([wire[pos], wire[pos + 1]]) as usize;
    pos += 2;
    let ratchet_header =
        RatchetHeader::from_bytes(&wire[pos..pos + ratchet_len]).expect("parse ratchet header");
    pos += ratchet_len;
    let ct = wire[pos..].to_vec();
    (x3dh_header, ratchet_header, ct)
}

// ---------------------------------------------------------------------------
// Bob's side: build a prekey bundle that mirrors `generate_prekey_bundle`
// in `najwa-ffi::lib.rs` (per-mailbox derived signing key, signed SPK,
// at least one OPK).
// ---------------------------------------------------------------------------

struct BobPrekeyMaterial {
    spk_kp: X25519KeyPair,
    opk_kp: X25519KeyPair,
    bundle: X3DHPrekeyBundle,
}

fn generate_bob_bundle(bob_ik_seed: &[u8; 32], mailbox_onion: &str) -> BobPrekeyMaterial {
    let mailbox_kp =
        derive_mailbox_signing_key(bob_ik_seed, mailbox_onion).expect("derive mailbox signing key");

    let mut rng = rand::thread_rng();
    let spk_kp = X25519KeyPair::generate(&mut rng);
    let spk_public_bytes = spk_kp.public().to_bytes();
    let signature = mailbox_kp.sign(&najwa_protocol::x3dh::types::spk_signature_message(&spk_public_bytes, &1u32.to_be_bytes(), 0));

    let opk_kp = X25519KeyPair::generate(&mut rng);

    // Bob's REAL identity public — this is what Bob's invite advertises and
    // what Alice has stored as `their_ik_pub` after `add_contact`.
    let bob_real_ik_pub = Ed25519KeyPair::from_seed(bob_ik_seed).public().clone();

    let bundle = X3DHPrekeyBundle {
        identity_key: bob_real_ik_pub,
        mailbox_ik_pub: Some(mailbox_kp.public().clone()),
        signed_prekey: spk_kp.public().clone(),
        signed_prekey_id: 1u32.to_be_bytes(),
        signed_prekey_signature: signature,
        signed_prekey_timestamp: 0,
        one_time_prekey: Some(opk_kp.public().clone()),
        one_time_prekey_id: Some(7u32.to_be_bytes()),
    };

    BobPrekeyMaterial {
        spk_kp,
        opk_kp,
        bundle,
    }
}

#[test]
fn alice_first_message_decrypts_on_bob() {
    // ── Step 1: Both sides create real identities ────────────────────────
    let alice_ik_seed: [u8; 32] = [0x11; 32];
    let bob_ik_seed: [u8; 32] = [0x22; 32];
    let alice_ik = Ed25519KeyPair::from_seed(&alice_ik_seed);
    let _bob_ik = Ed25519KeyPair::from_seed(&bob_ik_seed);

    // ── Step 2: Bob publishes a prekey bundle ────────────────────────────
    let mailbox_onion = "abcdefghijklmnopqrstuvwxyz234567";
    let bob_material = generate_bob_bundle(&bob_ik_seed, mailbox_onion);

    // Sanity: Bob's bundle SPK signature must verify against the per-mailbox
    // derived key (this is what Alice's send path checks via x3dh_initiate).
    bob_material
        .bundle
        .verify_spk_signature()
        .expect("SPK signature must verify");

    // ── Step 3: Alice fetches the bundle and X3DH-initiates ─────────────
    let x3dh = x3dh_initiate(&alice_ik, &bob_material.bundle).expect("x3dh_initiate");

    // ── Step 4: Alice initialises Double Ratchet and encrypts ───────────
    let mut alice_ratchet = init_alice(
        &x3dh.shared_secret,
        &bob_material.bundle.signed_prekey,
        &x3dh.ephemeral_seed,
    )
    .expect("init_alice");

    // S08 §4.3 GUARD invariant: a fresh initiator's session (an un-answered
    // OUTBOUND Initial) has NO receiving chain yet. accept_session relies on
    // `ckr.is_none()` to tell this apart from an advanced session — routing a
    // crossing Initial to the EK tiebreak rather than treating it as a duplicate.
    assert!(
        alice_ratchet.ckr.is_none(),
        "un-answered outbound Initial must have no receiving chain (ckr None)"
    );

    let plaintext = b"hello bob, this is alice's very first message";
    let x3dh_bytes = serde_json::to_vec(&x3dh.header).expect("serialize x3dh header");
    let (ratchet_header, encrypted_payload) = enc(
        &mut alice_ratchet,
        plaintext,
        &x3dh.associated_data,
        MSG_TYPE_INITIAL,
        Some(&x3dh_bytes),
    );

    // ── Step 5: Pack into the FFI wire format ────────────────────────────
    let wire_blob = pack_initial(&x3dh.header, &ratchet_header, &encrypted_payload);

    // ── Step 6: Bob receives the blob, unpacks, and decrypts ────────────
    let (recv_x3dh_hdr, recv_ratchet_hdr, recv_ct) = unpack_wire(&wire_blob);

    // Bob's identity (recreated from the same seed Bob uses on the device).
    let bob_ik_for_respond = Ed25519KeyPair::from_seed(&bob_ik_seed);

    // x3dh_respond requires the SPK *pair* (not the X25519Public) so Bob
    // can DH with it. The `BobPrekeyMaterial.spk_kp` mirrors what
    // `najwa-ffi::try_decrypt_message_ffi` reconstructs from the saved
    // `our_spk_prekey.private_key`.
    let x3dh_result = x3dh_respond(
        &bob_ik_for_respond,
        &bob_material.spk_kp,
        Some(&bob_material.opk_kp),
        &recv_x3dh_hdr,
    )
    .expect("x3dh_respond");

    // Cross-check: both sides MUST have derived the same shared secret
    // and AAD before we even hit the ratchet.
    assert_eq!(
        x3dh.shared_secret, x3dh_result.shared_secret,
        "X3DH shared secret mismatch"
    );
    assert_eq!(
        x3dh.associated_data, x3dh_result.associated_data,
        "X3DH associated data mismatch"
    );

    // Bob initialises his side of the ratchet using *the same* SPK key
    // pair Alice ran DH against.
    let mut bob_ratchet = init_bob(
        &x3dh_result.shared_secret,
        X25519KeyPair::from_seed(bob_material.spk_kp.private().to_bytes()),
    );
    // Pre-decrypt, a fresh responder session also has ckr None — but accept_session
    // ALWAYS runs the decrypt before it commits, so a *stored* responder session
    // has already advanced ckr (asserted below). GUARD never observes this None.
    assert!(
        bob_ratchet.ckr.is_none(),
        "fresh responder ckr is None pre-decrypt"
    );

    let recv_x3dh_bytes = serde_json::to_vec(&recv_x3dh_hdr).expect("re-serialize x3dh header");
    let recovered = dec(
        &mut bob_ratchet,
        &recv_ratchet_hdr,
        &recv_ct,
        &x3dh_result.associated_data,
        MSG_TYPE_INITIAL,
        Some(&recv_x3dh_bytes),
    )
    .expect("ratchet_decrypt of first post-X3DH message must succeed");

    assert_eq!(recovered, plaintext);

    // S08 §4.3 GUARD invariant: once the responder decrypts the first message its
    // receiving chain IS established (ckr Some). accept_session persists the
    // responder session only after this decrypt, so every STORED responder /
    // advanced session has ckr Some — exactly the state GUARD treats as "advanced,
    // reject a plain duplicate Initial (but ACCEPT a SessionRepairInit)". Only an
    // un-answered outbound Initial (ckr None) reaches the crossing tiebreak.
    assert!(
        bob_ratchet.ckr.is_some(),
        "responder receiving chain established after first decrypt (advanced session)"
    );
}

/// Sanity check on `RatchetHeader::with_epoch_link` for the first
/// post-X3DH sending epoch: `prev_dhs_pub` is `None` so the header must
/// ship `epoch_link == zeros(32)`, which the receiver MUST treat as a
/// legacy / first-epoch link and accept (S06 §3.5 step 3).
///
/// This guards against a regression where someone changes
/// `ratchet_encrypt` to advertise the *current* `dhs.public()` (or any
/// other non-zero default) in the first message, which would break
/// backwards compatibility AND cause the receiver to reject the message
/// with `MissedEpochBoundary` instead of accepting it.
#[test]
fn first_post_x3dh_message_ships_zero_epoch_link() {
    let alice_ik_seed: [u8; 32] = [0x33; 32];
    let bob_ik_seed: [u8; 32] = [0x44; 32];
    let alice_ik = Ed25519KeyPair::from_seed(&alice_ik_seed);

    let bob_material = generate_bob_bundle(&bob_ik_seed, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

    let x3dh = x3dh_initiate(&alice_ik, &bob_material.bundle).expect("x3dh_initiate");
    let mut alice_ratchet = init_alice(
        &x3dh.shared_secret,
        &bob_material.bundle.signed_prekey,
        &x3dh.ephemeral_seed,
    )
    .expect("init_alice");

    let (header, _ep) = enc(
        &mut alice_ratchet,
        b"hello",
        &x3dh.associated_data,
        0x02,
        None,
    );

    assert_eq!(
        header.epoch_link, [0u8; 32],
        "first post-X3DH message must ship a zero epoch_link"
    );
    // The dh_pub must be Alice's freshly-generated DHs from init_alice,
    // never Bob's SPK.
    assert_ne!(
        header.dh_pub.to_bytes(),
        bob_material.bundle.signed_prekey.to_bytes(),
        "first message dh_pub must be Alice's own DHs, not Bob's SPK"
    );
}

/// Negative control: if Alice's saved `their_ik_pub` somehow differs
/// from Bob's real IK (e.g. an invite-generation bug stamps a per-mailbox
/// derived key into the contact row), `x3dh_initiate` will compute its
/// `associated_data` against the WRONG `their_bundle.identity_key`, and
/// Bob's `x3dh_respond` will produce a different AD. The shared secret
/// will *also* differ because DH1/DH2 are computed with the wrong key,
/// so the AEAD MUST fail.
///
/// This test is here to make the failure mode visible and to lock the
/// invariant: the `identity_key` field of `X3DHPrekeyBundle` MUST be
/// the responder's REAL Ed25519 identity public key, not any per-mailbox
/// derived key.
#[test]
fn wrong_identity_key_in_bundle_breaks_decrypt() {
    let alice_ik_seed: [u8; 32] = [0x55; 32];
    let bob_ik_seed: [u8; 32] = [0x66; 32];
    let alice_ik = Ed25519KeyPair::from_seed(&alice_ik_seed);

    let mut bob_material = generate_bob_bundle(&bob_ik_seed, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");

    // Tamper: replace the bundle's identity_key with Bob's per-mailbox
    // derived key (simulating the bug we're guarding against).
    let mailbox_kp = derive_mailbox_signing_key(&bob_ik_seed, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
        .expect("mailbox key");
    bob_material.bundle.identity_key = mailbox_kp.public().clone();

    let x3dh = x3dh_initiate(&alice_ik, &bob_material.bundle).expect("x3dh_initiate");
    let mut alice_ratchet = init_alice(
        &x3dh.shared_secret,
        &bob_material.bundle.signed_prekey,
        &x3dh.ephemeral_seed,
    )
    .expect("init_alice");
    let (rh, ct) = enc(&mut alice_ratchet, b"hi", &x3dh.associated_data, 0x02, None);

    // Bob still uses his REAL identity to respond — exactly what
    // try_decrypt_message_ffi does.
    let bob_ik_for_respond = Ed25519KeyPair::from_seed(&bob_ik_seed);

    let x3dh_result = x3dh_respond(
        &bob_ik_for_respond,
        &bob_material.spk_kp,
        Some(&bob_material.opk_kp),
        &x3dh.header,
    )
    .expect("x3dh_respond");

    // The shared secret AND/OR AD MUST diverge.
    let secrets_match = x3dh.shared_secret == x3dh_result.shared_secret;
    let ads_match = x3dh.associated_data == x3dh_result.associated_data;
    assert!(
        !(secrets_match && ads_match),
        "expected divergence when bundle identity_key is wrong"
    );

    let mut bob_ratchet = init_bob(
        &x3dh_result.shared_secret,
        X25519KeyPair::from_seed(bob_material.spk_kp.private().to_bytes()),
    );
    let result = dec(
        &mut bob_ratchet,
        &rh,
        &ct,
        &x3dh_result.associated_data,
        0x02,
        None,
    );
    assert!(
        result.is_err(),
        "wrong bundle identity_key must fail decryption"
    );
}

/// Verify the `Ed25519KeyPair::from_seed(kp.private().to_bytes())`
/// roundtrip is identity for Ed25519. Locks in the invariant the FFI
/// unlock path relies on (`identity.keypair.private().to_bytes()` is
/// the seed, not an expanded scalar).
#[test]
fn ed25519_seed_roundtrip_is_identity() {
    let seed: [u8; 32] = [0x77; 32];
    let kp1 = Ed25519KeyPair::from_seed(&seed);
    let recovered_seed = kp1.private().to_bytes();
    let kp2 = Ed25519KeyPair::from_seed(&recovered_seed);
    assert_eq!(kp1.public().to_bytes(), kp2.public().to_bytes());
    assert_eq!(seed, recovered_seed);
}

/// Verify the `X25519KeyPair::from_seed(kp.private().to_bytes())`
/// roundtrip preserves the public key. Locks in the invariant that
/// `try_decrypt_message_ffi` relies on when reconstructing the SPK
/// keypair from the saved private bytes.
#[test]
fn x25519_seed_roundtrip_preserves_public() {
    let mut rng = rand::thread_rng();
    let kp1 = X25519KeyPair::generate(&mut rng);
    let pub1 = kp1.public().to_bytes();
    let priv_bytes = kp1.private().to_bytes();
    let kp2 = X25519KeyPair::from_seed(priv_bytes);
    assert_eq!(
        kp1.public().to_bytes(),
        kp2.public().to_bytes(),
        "X25519 from_seed(private.to_bytes()) must preserve the public key"
    );
    let pub2 = kp2.public().to_bytes();
    assert_eq!(pub1, pub2);
}
