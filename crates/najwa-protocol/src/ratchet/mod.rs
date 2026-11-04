//! Double Ratchet protocol (Phase 7).
//!
//! Implements the Signal Double Ratchet algorithm for ongoing message
//! encryption with forward secrecy and post-compromise security.
//!
//! - Forward secrecy: compromise of current keys doesn't reveal past messages
//! - Post-compromise security: session self-heals after key compromise
//! - Out-of-order message handling via skipped message keys

pub mod cleanup;
pub mod decrypt;
pub mod encrypt;
pub mod error;
pub mod header;
pub mod init;
pub mod kdf;
pub mod persist;
pub mod state;

/// Convenience re-exports for common ratchet types.
pub mod prelude {
    pub use crate::ratchet::cleanup::cleanup_expired_skipped_keys;
    pub use crate::ratchet::decrypt::ratchet_decrypt;
    pub use crate::ratchet::encrypt::ratchet_encrypt;
    pub use crate::ratchet::error::{RatchetError, Result};
    pub use crate::ratchet::header::RatchetHeader;
    pub use crate::ratchet::init::{init_alice, init_bob};
    pub use crate::ratchet::kdf::{derive_message_keys, kdf_ck, kdf_rk, MessageKeys};
    pub use crate::ratchet::persist::{deserialize_state, serialize_state};
    pub use crate::ratchet::state::{RatchetState, SkippedKey, MAX_SKIP, SKIP_KEY_EXPIRY_SECS};
}

#[cfg(test)]
mod tests {
    use najwa_crypto::keys::x25519::X25519KeyPair;

    use super::init::{init_alice, init_bob};
    use super::state::MAX_SKIP;

    // Shim the pre-wire-format calling convention onto the new wire-format-aware
    // ratchet API so the behavioural tests below read unchanged: every test frame
    // is a Standard (0x02) message with no X3DH header. `ad` here IS the session
    // AD. The shim rebuilds the canonical wire_prefix so encrypt and decrypt agree.
    fn ratchet_encrypt(
        state: &mut super::state::RatchetState,
        plaintext: &[u8],
        ad: &[u8],
    ) -> super::error::Result<(super::header::RatchetHeader, Vec<u8>)> {
        let meta = crate::message::WirePrefixMeta {
            version: 1,
            message_type: 0x02,
            x3dh_header: None,
        };
        super::encrypt::ratchet_encrypt(state, plaintext, ad, &meta)
    }

    fn ratchet_decrypt(
        state: &mut super::state::RatchetState,
        header: &super::header::RatchetHeader,
        encrypted_payload: &[u8],
        ad: &[u8],
    ) -> super::error::Result<Vec<u8>> {
        let wire_prefix = crate::message::build_wire_prefix(
            1,
            0x02,
            None,
            &header.to_bytes(),
            encrypted_payload.len() as u32,
        );
        super::decrypt::ratchet_decrypt(state, header, encrypted_payload, ad, &wire_prefix)
    }

    /// Helper: set up Alice and Bob ratchet states from a shared secret.
    fn setup_alice_bob() -> (super::state::RatchetState, super::state::RatchetState) {
        let mut rng = rand::thread_rng();
        let sk = [0x42u8; 32];
        let bob_spk = X25519KeyPair::generate(&mut rng);
        let bob_spk_pub = bob_spk.public().clone();

        let alice = init_alice(&sk, &bob_spk_pub, &[0x07u8; 32]).unwrap();
        let bob = init_bob(&sk, bob_spk);
        (alice, bob)
    }

    // S06 §3.2: the first sending-ratchet DH key MUST be the authenticated X3DH
    // ephemeral EK_A, not a fresh unrelated key — init_alice's `dhs` is EK_A.
    #[test]
    fn init_alice_first_dh_is_ek_a() {
        let mut rng = rand::thread_rng();
        let sk = [0x11u8; 32];
        let bob_spk = X25519KeyPair::generate(&mut rng).public().clone();
        let ek_a_seed = [0x5Au8; 32];
        let state = init_alice(&sk, &bob_spk, &ek_a_seed).unwrap();
        let ek_a = X25519KeyPair::from_seed(ek_a_seed);
        assert_eq!(state.dhs.public().to_bytes(), ek_a.public().to_bytes());
    }

    // S06 §3.4–§3.5: Alice↔Bob sequential messages
    #[test]
    fn alice_sends_bob_receives() {
        let (mut alice, mut bob) = setup_alice_bob();
        let ad = b"test-ad";

        let (header, ct) = ratchet_encrypt(&mut alice, b"hello bob", ad).unwrap();
        let pt = ratchet_decrypt(&mut bob, &header, &ct, ad).unwrap();
        assert_eq!(pt, b"hello bob");
    }

    #[test]
    fn alice_bob_ping_pong() {
        let (mut alice, mut bob) = setup_alice_bob();
        let ad = b"test-ad";

        // Alice → Bob
        let (h1, ct1) = ratchet_encrypt(&mut alice, b"msg1", ad).unwrap();
        let pt1 = ratchet_decrypt(&mut bob, &h1, &ct1, ad).unwrap();
        assert_eq!(pt1, b"msg1");

        // Bob → Alice
        let (h2, ct2) = ratchet_encrypt(&mut bob, b"msg2", ad).unwrap();
        let pt2 = ratchet_decrypt(&mut alice, &h2, &ct2, ad).unwrap();
        assert_eq!(pt2, b"msg2");

        // Alice → Bob again
        let (h3, ct3) = ratchet_encrypt(&mut alice, b"msg3", ad).unwrap();
        let pt3 = ratchet_decrypt(&mut bob, &h3, &ct3, ad).unwrap();
        assert_eq!(pt3, b"msg3");
    }

    #[test]
    fn multiple_messages_same_direction() {
        let (mut alice, mut bob) = setup_alice_bob();
        let ad = b"ad";

        // Alice sends 5 messages before Bob replies
        let mut headers = Vec::new();
        let mut ciphertexts = Vec::new();
        for i in 0..5 {
            let msg = format!("msg-{}", i);
            let (h, ct) = ratchet_encrypt(&mut alice, msg.as_bytes(), ad).unwrap();
            headers.push(h);
            ciphertexts.push(ct);
        }

        // Bob decrypts all 5 in order
        for i in 0..5 {
            let pt = ratchet_decrypt(&mut bob, &headers[i], &ciphertexts[i], ad).unwrap();
            assert_eq!(pt, format!("msg-{}", i).as_bytes());
        }
    }

    // S06 §3.7: Out-of-order message delivery
    #[test]
    fn out_of_order_delivery() {
        let (mut alice, mut bob) = setup_alice_bob();
        let ad = b"ad";

        // Alice sends 3 messages
        let (h0, ct0) = ratchet_encrypt(&mut alice, b"msg-0", ad).unwrap();
        let (h1, ct1) = ratchet_encrypt(&mut alice, b"msg-1", ad).unwrap();
        let (h2, ct2) = ratchet_encrypt(&mut alice, b"msg-2", ad).unwrap();

        // Bob receives msg-2 first (skips 0 and 1)
        let pt2 = ratchet_decrypt(&mut bob, &h2, &ct2, ad).unwrap();
        assert_eq!(pt2, b"msg-2");

        // Bob receives msg-0 (from skipped keys)
        let pt0 = ratchet_decrypt(&mut bob, &h0, &ct0, ad).unwrap();
        assert_eq!(pt0, b"msg-0");

        // Bob receives msg-1 (from skipped keys)
        let pt1 = ratchet_decrypt(&mut bob, &h1, &ct1, ad).unwrap();
        assert_eq!(pt1, b"msg-1");
    }

    #[test]
    fn out_of_order_across_ratchet_steps() {
        let (mut alice, mut bob) = setup_alice_bob();
        let ad = b"ad";

        // Alice sends msg-0
        let (h0, ct0) = ratchet_encrypt(&mut alice, b"msg-0", ad).unwrap();

        // Bob receives msg-0 and replies → triggers DH ratchet
        let _ = ratchet_decrypt(&mut bob, &h0, &ct0, ad).unwrap();
        let (hb0, ctb0) = ratchet_encrypt(&mut bob, b"bob-0", ad).unwrap();

        // Alice receives Bob's reply → triggers DH ratchet
        let _ = ratchet_decrypt(&mut alice, &hb0, &ctb0, ad).unwrap();

        // Alice sends msg-1 and msg-2 (new ratchet step)
        let (h1, ct1) = ratchet_encrypt(&mut alice, b"msg-1", ad).unwrap();
        let (h2, ct2) = ratchet_encrypt(&mut alice, b"msg-2", ad).unwrap();

        // Bob receives msg-2 first (skips msg-1)
        let pt2 = ratchet_decrypt(&mut bob, &h2, &ct2, ad).unwrap();
        assert_eq!(pt2, b"msg-2");

        // Bob receives msg-1 from skipped keys
        let pt1 = ratchet_decrypt(&mut bob, &h1, &ct1, ad).unwrap();
        assert_eq!(pt1, b"msg-1");
    }

    // S06 §3.7: MAX_SKIP limit enforcement
    #[test]
    fn max_skip_limit_enforcement() {
        let (mut alice, mut bob) = setup_alice_bob();
        let ad = b"ad";

        // Alice sends MAX_SKIP + 2 messages
        let mut headers = Vec::new();
        let mut ciphertexts = Vec::new();
        for i in 0..(MAX_SKIP + 2) {
            let msg = format!("msg-{}", i);
            let (h, ct) = ratchet_encrypt(&mut alice, msg.as_bytes(), ad).unwrap();
            headers.push(h);
            ciphertexts.push(ct);
        }

        // Bob tries to decrypt the last message — should fail (too many skipped)
        let last = (MAX_SKIP + 1) as usize;
        let result = ratchet_decrypt(&mut bob, &headers[last], &ciphertexts[last], ad);
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(super::error::RatchetError::TooManySkipped { .. })
        ));
    }

    // S06 §3.8: Skipped key expiration
    #[test]
    fn skipped_key_expiration() {
        use super::cleanup::cleanup_expired_skipped_keys;
        use najwa_crypto::time::now;

        let (mut alice, mut bob) = setup_alice_bob();
        let ad = b"ad";

        // Alice sends 3 messages
        let (h0, ct0) = ratchet_encrypt(&mut alice, b"msg-0", ad).unwrap();
        let (_h1, _ct1) = ratchet_encrypt(&mut alice, b"msg-1", ad).unwrap();
        let (h2, ct2) = ratchet_encrypt(&mut alice, b"msg-2", ad).unwrap();

        // Bob receives msg-2 (skips 0, 1)
        let _ = ratchet_decrypt(&mut bob, &h2, &ct2, ad).unwrap();
        assert_eq!(bob.skipped.len(), 2);

        // Simulate key expiration by back-dating the skipped keys beyond the
        // 90-day expiry.
        for v in bob.skipped.values_mut() {
            v.created_at = now().saturating_sub(91 * 24 * 3600); // 91 days ago
        }

        let removed = cleanup_expired_skipped_keys(&mut bob);
        assert_eq!(removed, 2);
        assert!(bob.skipped.is_empty());

        // msg-0 should now fail because its skipped key was cleaned up
        let result = ratchet_decrypt(&mut bob, &h0, &ct0, ad);
        assert!(result.is_err());
    }

    // S06 §3.6: Many ratchet steps (hundreds of messages)
    #[test]
    fn many_messages_sequential() {
        let (mut alice, mut bob) = setup_alice_bob();
        let ad = b"ad";

        for i in 0..200 {
            let msg = format!("alice-{}", i);
            let (h, ct) = ratchet_encrypt(&mut alice, msg.as_bytes(), ad).unwrap();
            let pt = ratchet_decrypt(&mut bob, &h, &ct, ad).unwrap();
            assert_eq!(pt, msg.as_bytes());

            let reply = format!("bob-{}", i);
            let (h2, ct2) = ratchet_encrypt(&mut bob, reply.as_bytes(), ad).unwrap();
            let pt2 = ratchet_decrypt(&mut alice, &h2, &ct2, ad).unwrap();
            assert_eq!(pt2, reply.as_bytes());
        }
    }

    // Wrong AD fails decryption
    #[test]
    fn wrong_ad_fails() {
        let (mut alice, mut bob) = setup_alice_bob();

        let (h, ct) = ratchet_encrypt(&mut alice, b"secret", b"correct-ad").unwrap();
        let result = ratchet_decrypt(&mut bob, &h, &ct, b"wrong-ad");
        assert!(result.is_err());
    }

    // Tampered ciphertext fails
    #[test]
    fn tampered_ciphertext_fails() {
        let (mut alice, mut bob) = setup_alice_bob();
        let ad = b"ad";

        let (h, mut ct) = ratchet_encrypt(&mut alice, b"secret", ad).unwrap();
        *ct.last_mut().unwrap() ^= 0xFF;
        let result = ratchet_decrypt(&mut bob, &h, &ct, ad);
        assert!(result.is_err());
    }

    // Empty plaintext works
    #[test]
    fn empty_plaintext_works() {
        let (mut alice, mut bob) = setup_alice_bob();
        let ad = b"ad";

        let (h, ct) = ratchet_encrypt(&mut alice, b"", ad).unwrap();
        let pt = ratchet_decrypt(&mut bob, &h, &ct, ad).unwrap();
        assert!(pt.is_empty());
    }

    // State serialization survives encrypt/decrypt
    #[test]
    fn state_serialization_survives_session() {
        use super::persist::{deserialize_state, serialize_state};

        let (mut alice, mut bob) = setup_alice_bob();
        let ad = b"ad";

        // Exchange a few messages
        let (h1, ct1) = ratchet_encrypt(&mut alice, b"msg1", ad).unwrap();
        let _ = ratchet_decrypt(&mut bob, &h1, &ct1, ad).unwrap();
        let (h2, ct2) = ratchet_encrypt(&mut bob, b"msg2", ad).unwrap();
        let _ = ratchet_decrypt(&mut alice, &h2, &ct2, ad).unwrap();

        // Serialize and deserialize Alice's state
        let data = serialize_state(&alice).unwrap();
        let mut restored_alice = deserialize_state(&data).unwrap();

        // Continue session with restored state
        let (h3, ct3) = ratchet_encrypt(&mut restored_alice, b"msg3", ad).unwrap();
        let pt3 = ratchet_decrypt(&mut bob, &h3, &ct3, ad).unwrap();
        assert_eq!(pt3, b"msg3");
    }

    // Verify message counters advance correctly
    #[test]
    fn message_counters_advance() {
        let (mut alice, _bob) = setup_alice_bob();
        let ad = b"ad";

        assert_eq!(alice.ns, 0);
        let _ = ratchet_encrypt(&mut alice, b"msg0", ad).unwrap();
        assert_eq!(alice.ns, 1);
        let _ = ratchet_encrypt(&mut alice, b"msg1", ad).unwrap();
        assert_eq!(alice.ns, 2);
    }

    // Fresh DH ratchet key on each step
    #[test]
    fn dh_ratchet_key_changes_on_reply() {
        let (mut alice, mut bob) = setup_alice_bob();
        let ad = b"ad";

        let (h1, ct1) = ratchet_encrypt(&mut alice, b"msg1", ad).unwrap();
        let alice_dh_1 = h1.dh_pub.to_bytes();

        let _ = ratchet_decrypt(&mut bob, &h1, &ct1, ad).unwrap();
        let (h2, ct2) = ratchet_encrypt(&mut bob, b"reply", ad).unwrap();
        let bob_dh = h2.dh_pub.to_bytes();

        let _ = ratchet_decrypt(&mut alice, &h2, &ct2, ad).unwrap();
        let (h3, _ct3) = ratchet_encrypt(&mut alice, b"msg3", ad).unwrap();
        let alice_dh_2 = h3.dh_pub.to_bytes();

        // Alice's DH key must change after receiving Bob's reply
        assert_ne!(alice_dh_1, alice_dh_2);
        assert_ne!(alice_dh_1, bob_dh);
    }

    // ---------------------------------------------------------------------
    // S06 §3.5 step 3 — epoch_link tests
    // ---------------------------------------------------------------------

    /// (a) Lost-epoch-boundary recovery: if the first message of a new
    /// sending epoch is dropped, the second message of that same epoch
    /// still carries the same `epoch_link` and must be accepted.
    #[test]
    fn epoch_link_lost_boundary_recovered() {
        let (mut alice, mut bob) = setup_alice_bob();
        let ad = b"ad";

        // Alice → Bob (epoch alice1).
        let (h_a1, ct_a1) = ratchet_encrypt(&mut alice, b"a1", ad).unwrap();
        let _ = ratchet_decrypt(&mut bob, &h_a1, &ct_a1, ad).unwrap();

        // Bob rotates and replies. Both B1 and B2 are in bob's epoch1,
        // and therefore carry the same epoch_link (= Bob's SPK).
        let (h_b1, _ct_b1) = ratchet_encrypt(&mut bob, b"b1", ad).unwrap();
        let (h_b2, ct_b2) = ratchet_encrypt(&mut bob, b"b2", ad).unwrap();
        assert_eq!(h_b1.epoch_link, h_b2.epoch_link);

        // Alice never receives B1 — only B2 arrives.
        let pt_b2 = ratchet_decrypt(&mut alice, &h_b2, &ct_b2, ad).unwrap();
        assert_eq!(pt_b2, b"b2");
    }

    /// (b) All messages from an intermediate epoch lost → `MissedEpochBoundary`.
    ///
    /// Drive a real sender forward by two sending epochs without delivering
    /// the intermediate epoch to the receiver. The third-epoch messages'
    /// `epoch_link` points at an epoch the receiver has never seen.
    #[test]
    fn epoch_link_all_lost_returns_missed_epoch_boundary() {
        let (mut alice, mut bob) = setup_alice_bob();
        let ad = b"ad";

        // 1. Alice→Bob: establishes Bob→Alice sending chain on receive.
        let (h_a1, ct_a1) = ratchet_encrypt(&mut alice, b"a1", ad).unwrap();
        let _ = ratchet_decrypt(&mut bob, &h_a1, &ct_a1, ad).unwrap();

        // 2. Bob→Alice in bob-epoch-1 (link = SPK bytes). Delivered so
        //    Alice can ratchet once and open a new sending epoch of her own.
        let (h_b1, ct_b1) = ratchet_encrypt(&mut bob, b"b1", ad).unwrap();
        let _ = ratchet_decrypt(&mut alice, &h_b1, &ct_b1, ad).unwrap();

        // 3. Alice→Bob in alice-epoch-2 (link = alice-epoch-1 pub). Delivered
        //    so Bob ratchets into bob-epoch-2.
        let (h_a2, ct_a2) = ratchet_encrypt(&mut alice, b"a2", ad).unwrap();
        let _ = ratchet_decrypt(&mut bob, &h_a2, &ct_a2, ad).unwrap();

        // 4. Bob→Alice in bob-epoch-2 (link = bob-epoch-1 pub). The real
        //    Alice never sees this message.
        let (h_b2, ct_b2) = ratchet_encrypt(&mut bob, b"b2", ad).unwrap();

        // 5. Force Bob forward once more without the real Alice ratcheting.
        //    Clone Alice's state, drive the clone through bob-epoch-2 and
        //    send a fresh message from the clone so Bob advances to
        //    bob-epoch-3. The real Alice remains pinned at dhr = bob-epoch-1.
        let mut alice_ghost = clone_state_via_bincode(&alice);
        let _ = ratchet_decrypt(&mut alice_ghost, &h_b2, &ct_b2, ad).unwrap();
        let (h_ag, ct_ag) = ratchet_encrypt(&mut alice_ghost, b"ghost", ad).unwrap();
        let _ = ratchet_decrypt(&mut bob, &h_ag, &ct_ag, ad).unwrap();

        // 6. Bob→Alice in bob-epoch-3 (link = bob-epoch-2 pub). From the
        //    real Alice's perspective, dhr is still bob-epoch-1 pub, so the
        //    link does not match and is not zeros → MissedEpochBoundary.
        let (h_b3, ct_b3) = ratchet_encrypt(&mut bob, b"b3", ad).unwrap();
        assert_ne!(h_b3.epoch_link, [0u8; 32]);
        let result = ratchet_decrypt(&mut alice, &h_b3, &ct_b3, ad);
        assert!(
            matches!(result, Err(super::error::RatchetError::MissedEpochBoundary)),
            "expected MissedEpochBoundary, got {:?}",
            result.err()
        );
    }

    /// Duplicate a ratchet state (via bincode round-trip) so one copy can
    /// be advanced to drive the counterparty forward while the original
    /// stays pinned for the test assertion.
    fn clone_state_via_bincode(s: &super::state::RatchetState) -> super::state::RatchetState {
        let data = super::persist::serialize_state(s).unwrap();
        super::persist::deserialize_state(&data).unwrap()
    }

    /// (c) A peer that always sends `epoch_link = zeros(32)` is accepted.
    ///
    /// Simulates a sender whose `prev_dhs_pub`
    /// is never populated, so every header ships zeros. The receiver must
    /// still advance through DH ratchet steps normally.
    #[test]
    fn epoch_link_legacy_zeros_accepted() {
        let (mut alice, mut bob) = setup_alice_bob();
        let ad = b"ad";

        // Alice→Bob first message — this one naturally has zeros because
        // Alice has never rotated yet.
        let (h_a1, ct_a1) = ratchet_encrypt(&mut alice, b"a1", ad).unwrap();
        assert_eq!(h_a1.epoch_link, [0u8; 32]);
        let _ = ratchet_decrypt(&mut bob, &h_a1, &ct_a1, ad).unwrap();

        // Bob replies — force legacy behavior by clearing `prev_dhs_pub`
        // after the DH ratchet step that set it.
        bob.prev_dhs_pub = None;
        let (h_b1, ct_b1) = ratchet_encrypt(&mut bob, b"b1", ad).unwrap();
        assert_eq!(
            h_b1.epoch_link, [0u8; 32],
            "legacy sender must ship zeros epoch_link"
        );

        // Receiver accepts unchanged and decrypts successfully.
        let pt = ratchet_decrypt(&mut alice, &h_b1, &ct_b1, ad).unwrap();
        assert_eq!(pt, b"b1");
    }

    /// (d) Bincode round-trip preserves `prev_dhs_pub`.
    #[test]
    fn epoch_link_state_roundtrip_preserves_prev_dhs_pub() {
        use super::persist::{deserialize_state, serialize_state};

        let (mut alice, mut bob) = setup_alice_bob();
        let ad = b"ad";

        // Drive Bob through one DH ratchet step so his prev_dhs_pub is
        // Some(SPK bytes) rather than None.
        let (h_a1, ct_a1) = ratchet_encrypt(&mut alice, b"a1", ad).unwrap();
        let _ = ratchet_decrypt(&mut bob, &h_a1, &ct_a1, ad).unwrap();
        assert!(bob.prev_dhs_pub.is_some());

        let before = bob.prev_dhs_pub;
        let bytes = serialize_state(&bob).unwrap();
        let restored = deserialize_state(&bytes).unwrap();
        assert_eq!(restored.prev_dhs_pub, before);

        // And a None round-trip also survives.
        let fresh = setup_alice_bob().0;
        assert!(fresh.prev_dhs_pub.is_none());
        let bytes = serialize_state(&fresh).unwrap();
        let restored = deserialize_state(&bytes).unwrap();
        assert!(restored.prev_dhs_pub.is_none());
    }

    // ---------------------------------------------------------------------
    // S06 §3.11 I1 — derive→verify→commit: a failed decrypt MUST NOT mutate
    // the ratchet state (regression for the "mutate before verify" desync).
    // ---------------------------------------------------------------------

    /// A forged frame carrying a valid `(dh_pub, n)` but a garbage body must
    /// not advance the receiving chain. The genuine frame at that position
    /// must still decrypt afterwards.
    #[test]
    fn forged_frame_does_not_corrupt_chain() {
        let (mut alice, mut bob) = setup_alice_bob();
        let ad = b"ad";

        let (h0, ct0) = ratchet_encrypt(&mut alice, b"msg-0", ad).unwrap();

        // Snapshot Bob's receive position, then feed a forged body at the
        // same header position.
        let nr_before = bob.nr;
        let ckr_before = bob.ckr;
        let mut forged = ct0.clone();
        *forged.last_mut().unwrap() ^= 0xFF; // break the AEAD tag
        let forged_result = ratchet_decrypt(&mut bob, &h0, &forged, ad);
        assert!(forged_result.is_err());

        // State must be untouched by the failed decrypt.
        assert_eq!(bob.nr, nr_before);
        assert_eq!(bob.ckr, ckr_before);

        // The genuine msg-0 still decrypts.
        let pt0 = ratchet_decrypt(&mut bob, &h0, &ct0, ad).unwrap();
        assert_eq!(pt0, b"msg-0");
    }

    /// A forged frame replaying an outstanding skipped-key position must not
    /// destroy the stored skipped key. The genuine out-of-order frame must
    /// still decrypt from the skipped store afterwards.
    #[test]
    fn forged_frame_does_not_destroy_skipped_key() {
        let (mut alice, mut bob) = setup_alice_bob();
        let ad = b"ad";

        let (h0, ct0) = ratchet_encrypt(&mut alice, b"msg-0", ad).unwrap();
        let (_h1, _ct1) = ratchet_encrypt(&mut alice, b"msg-1", ad).unwrap();
        let (h2, ct2) = ratchet_encrypt(&mut alice, b"msg-2", ad).unwrap();

        // Bob receives msg-2 first → keys for 0 and 1 are stored as skipped.
        let _ = ratchet_decrypt(&mut bob, &h2, &ct2, ad).unwrap();
        assert_eq!(bob.skipped.len(), 2);

        // Attacker replays msg-0's header with a garbage body.
        let mut forged = ct0.clone();
        *forged.last_mut().unwrap() ^= 0xFF;
        let forged_result = ratchet_decrypt(&mut bob, &h0, &forged, ad);
        assert!(forged_result.is_err());

        // The skipped key for msg-0 must NOT have been removed.
        assert_eq!(bob.skipped.len(), 2);

        // The genuine msg-0 still decrypts from the skipped store.
        let pt0 = ratchet_decrypt(&mut bob, &h0, &ct0, ad).unwrap();
        assert_eq!(pt0, b"msg-0");
    }

    /// A forged frame that opens a new (valid-looking) epoch but fails to
    /// authenticate must not perform the DH ratchet step on the live state.
    #[test]
    fn forged_epoch_frame_does_not_dh_ratchet() {
        let (mut alice, mut bob) = setup_alice_bob();
        let ad = b"ad";

        // Establish an epoch so Bob has a dhr, then have Bob reply and Alice
        // advance — producing a genuine new-epoch frame from Alice.
        let (h_a0, ct_a0) = ratchet_encrypt(&mut alice, b"a0", ad).unwrap();
        let _ = ratchet_decrypt(&mut bob, &h_a0, &ct_a0, ad).unwrap();
        let (h_b0, ct_b0) = ratchet_encrypt(&mut bob, b"b0", ad).unwrap();
        let _ = ratchet_decrypt(&mut alice, &h_b0, &ct_b0, ad).unwrap();
        let (h_a1, ct_a1) = ratchet_encrypt(&mut alice, b"a1", ad).unwrap();

        // Snapshot Bob's epoch state.
        let dhr_before = bob.dhr.as_ref().map(|p| p.to_bytes());
        let rk_before = bob.rk;
        let nr_before = bob.nr;

        // Forge the new-epoch frame body.
        let mut forged = ct_a1.clone();
        *forged.last_mut().unwrap() ^= 0xFF;
        assert!(ratchet_decrypt(&mut bob, &h_a1, &forged, ad).is_err());

        // No DH ratchet must have happened.
        assert_eq!(bob.dhr.as_ref().map(|p| p.to_bytes()), dhr_before);
        assert_eq!(bob.rk, rk_before);
        assert_eq!(bob.nr, nr_before);

        // The genuine frame still decrypts and advances the epoch.
        let pt = ratchet_decrypt(&mut bob, &h_a1, &ct_a1, ad).unwrap();
        assert_eq!(pt, b"a1");
    }
}
