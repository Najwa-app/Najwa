//! Double Ratchet initialization (S06 §3.2).

use std::collections::HashMap;

use najwa_crypto::keys::x25519::{X25519KeyPair, X25519Public};

use super::error::Result;
use super::kdf::kdf_rk;
use super::state::RatchetState;

/// Initialize as Alice (initiator) after X3DH (S06 §3.2).
///
/// Alice has completed X3DH and holds the shared secret `sk`.
/// She performs one DH ratchet step immediately to establish a
/// sending chain, using Bob's signed prekey as the initial
/// remote ratchet key.
///
/// # Arguments
///
/// * `sk` – 32-byte shared secret from X3DH.
/// * `their_spk` – Bob's signed prekey (used as initial DH ratchet key).
/// * `ek_a_seed` – the initiator's authenticated X3DH ephemeral private key
///   (EK_A). Per S06 §3.2 the FIRST sending-ratchet DH key MUST be EK_A — the
///   key already authenticated by the X3DH handshake — not a fresh, unrelated
///   key, so the ratchet is cryptographically bound to the X3DH. (No wire-format
///   change: the ratchet header still carries a 32-byte DH public; its value is
///   now EK_A's public, which the responder derives from exactly as before.)
pub fn init_alice(
    sk: &[u8; 32],
    their_spk: &X25519Public,
    ek_a_seed: &[u8; 32],
) -> Result<RatchetState> {
    let dhs = X25519KeyPair::from_seed(*ek_a_seed);
    let dh_out = dhs.diffie_hellman(their_spk)?;
    let (rk, cks) = kdf_rk(sk, dh_out.as_bytes())?;

    Ok(RatchetState {
        dhs,
        dhr: Some(their_spk.clone()),
        rk,
        cks: Some(cks),
        ckr: None,
        ns: 0,
        nr: 0,
        pn: 0,
        prev_dhs_pub: None,
        skipped: HashMap::new(),
    })
}

/// Initialize as Bob (responder) after X3DH (S06 §3.2).
///
/// Bob has completed X3DH and holds the shared secret `sk`.
/// He uses his signed prekey pair as the initial DH ratchet key pair.
/// Bob does NOT perform a DH ratchet step — he waits for Alice's
/// first message to trigger it.
///
/// # Arguments
///
/// * `sk` – 32-byte shared secret from X3DH.
/// * `our_spk` – Bob's signed prekey pair (becomes the initial DH ratchet key pair).
pub fn init_bob(sk: &[u8; 32], our_spk: X25519KeyPair) -> RatchetState {
    RatchetState {
        dhs: our_spk,
        dhr: None,
        rk: *sk,
        cks: None,
        ckr: None,
        ns: 0,
        nr: 0,
        pn: 0,
        prev_dhs_pub: None,
        skipped: HashMap::new(),
    }
}
