//! Proof-of-Work solver for mailbox anti-spam (S16 §7).
//!
//! S16 §7.1 preimage (all integers big-endian, fixed-width, concatenated):
//! `challenge(32) || cap_binding || timestamp(8) || blob_hash(32) || nonce(8)`
//! where `cap_binding` is `fetch_cap(32)||deposit_cap(32)` for registration or
//! `deposit_cap(32)` for deposit/prekey-fetch, and `blob_hash` is `SHA256(blob)`
//! for deposits (`zeros(32)` otherwise). Binding the capability + blob to each
//! solution prevents a challenge solution from being re-targeted to a different
//! request/endpoint/blob.

use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

use super::error::{MailboxError, Result};
use super::types::{PowChallenge, PowSolution};

/// Compute the S16 §7.1 PoW preimage hash.
pub(crate) fn pow_hash(
    challenge: &[u8],
    cap_binding: &[u8],
    timestamp: u64,
    blob_hash: &[u8; 32],
    nonce: u64,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(challenge);
    h.update(cap_binding);
    h.update(timestamp.to_be_bytes());
    h.update(blob_hash);
    h.update(nonce.to_be_bytes());
    h.finalize().into()
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Solve a PoW challenge bound to a capability (and, for deposits, a blob). Finds
/// a nonce whose §7.1 preimage hash has at least `challenge.difficulty` leading
/// zero bits. `timestamp` is stamped once at solve time.
///
/// Returns `Err(PowTimeout)` if the challenge expires before a solution is found,
/// or `Err(PowExhausted)` if all `u64` nonces are tried.
pub fn solve_pow(
    challenge: &PowChallenge,
    cap_binding: &[u8],
    blob_hash: &[u8; 32],
) -> Result<PowSolution> {
    let target_zeros = challenge.difficulty as usize;
    let timestamp = now_secs();
    let mut nonce: u64 = 0;

    loop {
        let hash = pow_hash(
            &challenge.challenge,
            cap_binding,
            timestamp,
            blob_hash,
            nonce,
        );
        if leading_zeros(&hash) >= target_zeros {
            return Ok(PowSolution {
                challenge: challenge.challenge.clone(),
                nonce,
                hash,
                timestamp,
            });
        }

        nonce = nonce.checked_add(1).ok_or(MailboxError::PowExhausted)?;

        // Check timeout periodically (every 65536 iterations to limit syscalls).
        if nonce.is_multiple_of(65536) && now_secs() >= challenge.expires_at {
            return Err(MailboxError::PowTimeout);
        }
    }
}

/// Count the number of leading zero bits in a 32-byte hash.
pub(crate) fn leading_zeros(hash: &[u8; 32]) -> usize {
    let mut count = 0;
    for byte in hash {
        if *byte == 0 {
            count += 8;
        } else {
            count += byte.leading_zeros() as usize;
            break;
        }
    }
    count
}

/// Verify that a `PowSolution` is valid for the given challenge + binding.
pub fn verify_pow(
    challenge: &PowChallenge,
    solution: &PowSolution,
    cap_binding: &[u8],
    blob_hash: &[u8; 32],
) -> bool {
    let hash = pow_hash(
        &solution.challenge,
        cap_binding,
        solution.timestamp,
        blob_hash,
        solution.nonce,
    );
    hash == solution.hash && leading_zeros(&hash) >= challenge.difficulty as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    fn future_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600
    }

    fn challenge(difficulty: u32) -> PowChallenge {
        PowChallenge {
            challenge: b"test-challenge-bytes-32-padding!!".to_vec(),
            difficulty,
            algorithm: "sha256-leading-zeros".to_string(),
            expires_at: future_timestamp(),
        }
    }

    #[test]
    fn leading_zeros_all_zero() {
        assert_eq!(leading_zeros(&[0u8; 32]), 256);
    }

    #[test]
    fn leading_zeros_first_byte_0x0f() {
        let mut hash = [0xFFu8; 32];
        hash[0] = 0x0F;
        assert_eq!(leading_zeros(&hash), 4);
    }

    #[test]
    fn solve_and_verify_deposit_binding() {
        let ch = challenge(8);
        let cap = [0xAB; 32]; // deposit_cap
        let blob_hash = Sha256::digest(b"the-blob").into();
        let sol = solve_pow(&ch, &cap, &blob_hash).unwrap();
        assert!(verify_pow(&ch, &sol, &cap, &blob_hash));
        assert_eq!(sol.hash[0], 0);
    }

    #[test]
    fn solve_and_verify_register_binding() {
        let ch = challenge(8);
        // register binding = fetch_cap || deposit_cap
        let mut cap = Vec::new();
        cap.extend_from_slice(&[0x11; 32]);
        cap.extend_from_slice(&[0x22; 32]);
        let sol = solve_pow(&ch, &cap, &[0u8; 32]).unwrap();
        assert!(verify_pow(&ch, &sol, &cap, &[0u8; 32]));
    }

    #[test]
    fn verify_rejects_wrong_binding() {
        let ch = challenge(4);
        let sol = solve_pow(&ch, &[0xAB; 32], &[0u8; 32]).unwrap();
        // A solution for one deposit_cap must not verify under another.
        assert!(!verify_pow(&ch, &sol, &[0xCD; 32], &[0u8; 32]));
    }

    #[test]
    fn verify_rejects_wrong_blob() {
        let ch = challenge(4);
        let cap = [0xAB; 32];
        let sol = solve_pow(&ch, &cap, &Sha256::digest(b"blob-a").into()).unwrap();
        // A deposit solution is bound to its blob hash.
        assert!(!verify_pow(
            &ch,
            &sol,
            &cap,
            &Sha256::digest(b"blob-b").into()
        ));
    }

    #[test]
    fn verify_rejects_wrong_nonce() {
        let ch = challenge(4);
        let cap = [0xAB; 32];
        let mut sol = solve_pow(&ch, &cap, &[0u8; 32]).unwrap();
        sol.nonce = sol.nonce.wrapping_add(1);
        assert!(!verify_pow(&ch, &sol, &cap, &[0u8; 32]));
    }

    #[test]
    fn solve_expired_challenge() {
        let mut ch = challenge(128);
        ch.expires_at = 0;
        assert!(matches!(
            solve_pow(&ch, &[0xAB; 32], &[0u8; 32]),
            Err(MailboxError::PowTimeout)
        ));
    }
}
