//! Double Ratchet decryption (S06 §3.5).
//!
//! # Derive → verify → commit (S06 §3.11 invariant I1)
//!
//! Decryption MUST NOT mutate the ratchet state until the AEAD tag has been
//! verified. A forged or transport-corrupted frame that carries a valid
//! `(dh_pub, n)` but a garbage body would otherwise advance the chain key,
//! consume the genuine message's key, or delete a stored skipped key —
//! permanently corrupting the session (denial-of-decryption). To prevent
//! this, every path here computes the candidate message key and a *plan* of
//! the state changes it would make WITHOUT touching `state`, attempts the
//! decrypt, and only applies the plan once the tag verifies. On failure the
//! state is left exactly as it was and the frame is dropped.

use najwa_crypto::aead;
use zeroize::Zeroizing;
use najwa_crypto::keys::x25519::{X25519KeyPair, X25519Public};
use najwa_crypto::time::now;

use super::cleanup::{cleanup_expired_skipped_keys, enforce_skipped_key_cap};
use super::error::{RatchetError, Result};
use super::header::RatchetHeader;
use super::kdf::{derive_message_keys, generate_nonce_from_iv, kdf_ck, kdf_rk};
use super::state::{RatchetState, SkippedKey, MAX_SKIP};

/// A speculative skipped-key insertion: ((ratchet_pub_bytes, msg_num), message_key).
type SkippedInsert = (([u8; 32], u32), Zeroizing<[u8; 32]>);

/// The DH-ratchet portion of a decrypt plan (only present when the header
/// opens a new sending epoch). All values are computed speculatively and are
/// applied to `state` only after the AEAD tag verifies.
struct DhStep {
    new_dhs: X25519KeyPair,
    new_rk: Zeroizing<[u8; 32]>,
    new_cks: Zeroizing<[u8; 32]>,
    new_dhr: X25519Public,
    new_pn: u32,
    prev_dhs_pub: [u8; 32],
}

/// The full set of state mutations a successful decrypt would commit. Built
/// against a read-only view of the state; applied via [`DecryptPlan::commit`]
/// only after the message body is authenticated.
struct DecryptPlan {
    /// The message key for the frame being decrypted.
    mk: Zeroizing<[u8; 32]>,
    /// Receiving chain key after consuming this message.
    new_ckr: Zeroizing<[u8; 32]>,
    /// Receive counter after consuming this message.
    new_nr: u32,
    /// Skipped keys to store for out-of-order delivery.
    new_skipped: Vec<SkippedInsert>,
    /// DH-ratchet results, if this frame crossed an epoch boundary.
    dh_step: Option<DhStep>,
}

impl DecryptPlan {
    /// Apply the planned mutations to `state`. Called ONLY after the AEAD tag
    /// of the corresponding frame has verified (S06 §3.11 I1).
    fn commit(self, state: &mut RatchetState) {
        if let Some(dh) = self.dh_step {
            state.pn = dh.new_pn;
            state.ns = 0;
            state.dhr = Some(dh.new_dhr);
            state.rk = *dh.new_rk;
            state.cks = Some(*dh.new_cks);
            state.dhs = dh.new_dhs;
            state.prev_dhs_pub = Some(dh.prev_dhs_pub);
        }
        state.ckr = Some(*self.new_ckr);
        state.nr = self.new_nr;
        let ts = now();
        for ((dhr_bytes, n), mk) in self.new_skipped {
            state.skipped.insert(
                (dhr_bytes, n),
                SkippedKey {
                    message_key: *mk,
                    created_at: ts,
                },
            );
        }
        // Bound the global skipped-key store (S06 §3.1 / D6): evict oldest
        // beyond MAX_SKIPPED_KEYS_PER_SESSION.
        enforce_skipped_key_cap(state);
    }
}

/// Decrypt a ciphertext message using the Double Ratchet (S06 §3.5).
///
/// # Steps
///
/// 0. Cleanup expired skipped keys (S06 §3.5 step 0).
/// 1. Try skipped message keys (non-destructive lookup; removed only on
///    successful decrypt).
/// 2. Otherwise build a decrypt plan (epoch-link check, DH ratchet, chain
///    advance) WITHOUT mutating `state`.
/// 3. Decrypt with the candidate key.
/// 4. Commit the plan only if the AEAD tag verified.
pub fn ratchet_decrypt(
    state: &mut RatchetState,
    header: &RatchetHeader,
    encrypted_payload: &[u8],
    session_ad: &[u8],
    wire_prefix: &[u8],
) -> Result<Vec<u8>> {
    // 0. Cleanup expired skipped keys (S06 §3.5 step 0). This only drops already-expired
    //    keys and is independent of the frame being decrypted.
    cleanup_expired_skipped_keys(state);

    // 1. Skipped-key path — NON-DESTRUCTIVE: look up, verify, then remove.
    //    A forged header replaying an outstanding (dh_pub, n) must not be able
    //    to delete the genuine skipped key (S06 §3.11 I1).
    let skipped_key = (header.dh_pub.to_bytes(), header.n);
    if let Some(skipped) = state.skipped.get(&skipped_key) {
        let mk = Zeroizing::new(skipped.message_key); // copy; do not remove yet
        let plaintext = decrypt_with_mk(&mk, encrypted_payload, session_ad, wire_prefix)?;
        state.skipped.remove(&skipped_key); // commit only on success
        return Ok(plaintext);
    }

    // 2. Build the plan against a read-only view of `state`.
    let plan = plan_decrypt(state, header)?;

    // 3. Verify the frame BEFORE committing any mutation.
    let plaintext = decrypt_with_mk(&plan.mk, encrypted_payload, session_ad, wire_prefix)?;

    // 4. Commit only now that the tag has verified.
    plan.commit(state);
    Ok(plaintext)
}

/// Compute the candidate message key and the state mutations a successful
/// decrypt would apply, WITHOUT touching `state`. Returns an error (leaving
/// the state untouched) for a missed epoch boundary or an out-of-bounds skip.
fn plan_decrypt(state: &RatchetState, header: &RatchetHeader) -> Result<DecryptPlan> {
    let new_nr = header.n.checked_add(1).ok_or(RatchetError::CorruptedState)?;
    let header_pub_bytes = header.dh_pub.to_bytes();
    let need_dh_ratchet = match &state.dhr {
        Some(dhr) => dhr.to_bytes() != header_pub_bytes,
        None => true,
    };

    let mut new_skipped: Vec<SkippedInsert> = Vec::new();

    if !need_dh_ratchet {
        // Same epoch: advance the existing receiving chain to header.n.
        if header.n < state.nr { return Err(RatchetError::DecryptionFailed); }
        let mut ckr = Zeroizing::new(state.ckr.ok_or(RatchetError::NoReceivingChain)?);
        let mut nr = state.nr;
        let dhr_bytes = state.dhr.as_ref().ok_or(RatchetError::NoDHR)?.to_bytes();
        advance_chain(&mut ckr, &mut nr, header.n, dhr_bytes, &mut new_skipped)?;
        let (new_ck, mk) = kdf_ck(&ckr);
        return Ok(DecryptPlan {
            mk: Zeroizing::new(mk),
            new_ckr: Zeroizing::new(new_ck),
            new_nr,
            new_skipped,
            dh_step: None,
        });
    }

    // New sending epoch — S06 §3.5 step 3 epoch-link validation
    // (S06 §3.5 step 3). The header's `epoch_link` MUST be either zeros
    // (legacy / first post-X3DH epoch) or our last-seen `dhr`; anything else
    // means we missed an intermediate epoch and Layer 2 (session repair)
    // must take over. No state is mutated on this error.
    let link = header.epoch_link;
    let is_legacy = link == [0u8; 32];
    let matches_dhr = match &state.dhr {
        Some(dhr) => dhr.to_bytes() == link,
        None => false,
    };
    if !is_legacy && !matches_dhr {
        return Err(RatchetError::MissedEpochBoundary);
    }

    // Pre-DH: skip remaining keys in the OLD receiving chain up to header.pn,
    // keyed by the old `dhr`. The MAX_SKIP bound is enforced even when there
    // is no receiving chain yet (mirrors the legacy `skip_message_keys`).
    if header.pn.saturating_sub(state.nr) > MAX_SKIP {
        return Err(RatchetError::TooManySkipped {
            limit: MAX_SKIP,
            requested: header.pn - state.nr,
        });
    }
    if let Some(old_ckr0) = state.ckr {
        let mut old_ckr = Zeroizing::new(old_ckr0);
        let mut nr = state.nr;
        let old_dhr_bytes = state.dhr.as_ref().ok_or(RatchetError::NoDHR)?.to_bytes();
        advance_chain(
            &mut old_ckr,
            &mut nr,
            header.pn,
            old_dhr_bytes,
            &mut new_skipped,
        )?;
    }

    // Speculative DH ratchet step (mirrors the committed `dh_ratchet`, but the
    // results live in the plan until the frame verifies). Generating a fresh
    // key pair here is a harmless side effect if the decrypt later fails.
    let their_pub = &header.dh_pub;
    let new_pn = state.ns;
    let dh_out = state.dhs.diffie_hellman(their_pub)?;
    let (rk1, new_ckr0) = kdf_rk(&state.rk, dh_out.as_bytes())?;
    let rk1 = Zeroizing::new(rk1);
    let new_ckr0 = Zeroizing::new(new_ckr0);
    let prev_dhs_pub = state.dhs.public().to_bytes();
    let mut rng = rand::rngs::OsRng;
    let new_dhs = X25519KeyPair::generate(&mut rng);
    let dh_out2 = new_dhs.diffie_hellman(their_pub)?;
    let (new_rk, new_cks) = kdf_rk(&rk1, dh_out2.as_bytes())?;
    let new_rk = Zeroizing::new(new_rk);
    let new_cks = Zeroizing::new(new_cks);

    // Post-DH: skip in the NEW receiving chain (starting at 0) up to header.n,
    // keyed by the new `dhr` (= header.dh_pub).
    let mut ckr = new_ckr0;
    let mut nr = 0u32;
    let new_dhr_bytes = their_pub.to_bytes();
    advance_chain(&mut ckr, &mut nr, header.n, new_dhr_bytes, &mut new_skipped)?;
    let (new_ck, mk) = kdf_ck(&ckr);

    Ok(DecryptPlan {
        mk: Zeroizing::new(mk),
        new_ckr: Zeroizing::new(new_ck),
        new_nr,
        new_skipped,
        dh_step: Some(DhStep {
            new_dhs,
            new_rk,
            new_cks,
            new_dhr: their_pub.clone(),
            new_pn,
            prev_dhs_pub,
        }),
    })
}

/// Advance a (local) receiving chain from `*nr` up to `until` (exclusive),
/// collecting each intermediate message key as a skipped-key insertion keyed
/// by `(dhr_bytes, n)`. Enforces `MAX_SKIP` before doing any work (all-or-
/// nothing). Operates on local copies only — the caller commits later.
fn advance_chain(
    ckr: &mut [u8; 32],
    nr: &mut u32,
    until: u32,
    dhr_bytes: [u8; 32],
    out: &mut Vec<SkippedInsert>,
) -> Result<()> {
    if until.saturating_sub(*nr) > MAX_SKIP {
        return Err(RatchetError::TooManySkipped {
            limit: MAX_SKIP,
            requested: until - *nr,
        });
    }
    while *nr < until {
        let (new_ck, mk) = kdf_ck(ckr);
        *ckr = new_ck;
        out.push(((dhr_bytes, *nr), Zeroizing::new(mk)));
        *nr += 1;
    }
    Ok(())
}

/// Decrypt an `encrypted_payload` (`nonce(24) || ct || tag`) with a specific
/// message key, using the canonical AAD `session_ad(64) || wire_prefix`
/// (S06 §3.4). The on-wire nonce is redundant (derived from the message key),
/// so it is skipped and re-derived — matching the sender.
fn decrypt_with_mk(
    mk: &[u8; 32],
    encrypted_payload: &[u8],
    session_ad: &[u8],
    wire_prefix: &[u8],
) -> Result<Vec<u8>> {
    if encrypted_payload.len() < 40 {
        return Err(RatchetError::DecryptionFailed);
    }
    let ciphertext = &encrypted_payload[24..];

    let keys = derive_message_keys(mk)?;
    let nonce = generate_nonce_from_iv(&keys.iv);
    if encrypted_payload[..24] != nonce { return Err(RatchetError::DecryptionFailed); }

    let mut aad = Vec::with_capacity(session_ad.len() + wire_prefix.len());
    aad.extend_from_slice(session_ad);
    aad.extend_from_slice(wire_prefix);

    aead::decrypt(&keys.encryption_key, &nonce, ciphertext, &aad)
        .map_err(|_| RatchetError::DecryptionFailed)
}
