//! Proof-of-Work verifier — SHA-256 leading zeros (S16 §7).

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

use sha2::{Digest, Sha256};

/// Generate a fresh 32-byte random challenge (OS CSPRNG, S01 §5.1).
pub fn generate_challenge() -> [u8; 32] {
    najwa_crypto::random::random_bytes()
}

/// Most challenges held at once (S16 §3.2). Under 10 MiB when full.
pub const MAX_OUTSTANDING_CHALLENGES: usize = 65_536;

/// Outstanding PoW challenges (S16 §3.2, §7.1), held in memory so issuing one
/// writes nothing to disk. Issuance needs no capability, so the store is
/// bounded: at capacity the oldest challenge is dropped. A flood therefore
/// costs memory up to the bound, and to void an honest client's challenge
/// it must issue `MAX_OUTSTANDING_CHALLENGES` more while that client solves.
/// Challenges do not survive a restart; a client then gets `400` and asks
/// for a new one.
// ponytail: expired entries leave only by FIFO pressure or consumption;
// memory stays within the bound either way.
#[derive(Default)]
pub struct ChallengeStore {
    inner: Mutex<Challenges>,
}

#[derive(Default)]
struct Challenges {
    /// challenge -> (difficulty, expires_at)
    by_id: HashMap<[u8; 32], (u8, i64)>,
    /// Issue order, oldest first; also holds consumed ids, so bounding it
    /// bounds both.
    order: VecDeque<[u8; 32]>,
}

impl ChallengeStore {
    /// Store a new unused challenge, evicting the oldest one at capacity.
    pub fn issue(&self, challenge: [u8; 32], difficulty: u8, expires_at: i64) {
        let mut store = self.inner.lock().unwrap();
        if store.order.len() >= MAX_OUTSTANDING_CHALLENGES {
            if let Some(oldest) = store.order.pop_front() {
                store.by_id.remove(&oldest);
            }
        }
        store.by_id.insert(challenge, (difficulty, expires_at));
        store.order.push_back(challenge);
    }

    /// Spend a challenge: `Some(difficulty)` if it was issued, unused and
    /// unexpired. It is spent even when the caller's later checks fail.
    pub fn consume(&self, challenge: &[u8; 32], now: i64) -> Option<u8> {
        let (difficulty, expires_at) = self.inner.lock().unwrap().by_id.remove(challenge)?;
        (expires_at > now).then_some(difficulty)
    }
}

/// Compute the adaptive difficulty based on server load percentage (0–100).
///
/// S16 §7.2:
/// - load < 50%  → 8 bits
/// - load < 80%  → 16 bits
/// - load < 95%  → 20 bits
/// - else        → 24 bits
///
/// Total for every input. A bare `clamp(min, max)` panics when `min > max`, and
/// this runs inside request handlers where the two bounds come from different
/// places — a spec floor for the endpoint versus an operator's configured
/// ceiling — so nothing guarantees they are ordered. An unauthenticated client
/// could otherwise crash a worker thread by hitting an endpoint whose floor
/// happens to exceed the operator's `max_difficulty`.
///
/// When the bounds do invert, the FLOOR wins: it is a security minimum for that
/// endpoint, and a minimum a ceiling can suppress is not a minimum. Operators
/// who genuinely want no PoW lower the floor itself, which is now configurable
/// for the one endpoint that had it hardcoded.
pub fn adaptive_difficulty(load_percent: u8, min_diff: u8, max_diff: u8) -> u8 {
    let raw = if load_percent < 50 {
        8
    } else if load_percent < 80 {
        16
    } else if load_percent < 95 {
        20
    } else {
        24
    };
    raw.clamp(min_diff, max_diff.max(min_diff))
}

/// Compute the S16 §7.1 PoW preimage hash. This MUST byte-match the client
/// solver in `najwa-protocol::mailbox::pow::pow_hash`:
/// `SHA256(challenge(32) || cap_binding || timestamp(8 BE) || blob_hash(32) || nonce(8 BE))`
/// where `cap_binding` = `fetch_cap||deposit_cap` (register) or `deposit_cap`
/// (deposit/prekey), and `blob_hash` = `SHA256(blob)` for deposits else zeros.
pub fn pow_hash(
    challenge: &[u8; 32],
    cap_binding: &[u8],
    timestamp: u64,
    blob_hash: &[u8; 32],
    nonce: u64,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(challenge);
    hasher.update(cap_binding);
    hasher.update(timestamp.to_be_bytes());
    hasher.update(blob_hash);
    hasher.update(nonce.to_be_bytes());
    hasher.finalize().into()
}

/// Verify a §7.1-bound PoW solution: the recomputed hash must equal the client's
/// supplied `hash` (§7.1 requires the server to verify it) AND have at least
/// `difficulty` leading zero bits.
pub fn verify_pow_bound(
    challenge: &[u8; 32],
    cap_binding: &[u8],
    timestamp: u64,
    blob_hash: &[u8; 32],
    nonce: u64,
    difficulty: u8,
    supplied_hash: &[u8; 32],
) -> bool {
    let hash = pow_hash(challenge, cap_binding, timestamp, blob_hash, nonce);
    &hash == supplied_hash && has_leading_zeros(&hash, difficulty)
}

/// Check if a hash has at least `bits` leading zero bits.
fn has_leading_zeros(hash: &[u8; 32], bits: u8) -> bool {
    let full_bytes = (bits / 8) as usize;
    let remaining_bits = bits % 8;

    // Check full zero bytes
    for &byte in &hash[..full_bytes] {
        if byte != 0 {
            return false;
        }
    }

    // Check remaining bits in the next byte
    if remaining_bits > 0 && full_bytes < 32 {
        let mask = 0xFF << (8 - remaining_bits);
        if hash[full_bytes] & mask != 0 {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_has_leading_zeros() {
        let hash = [
            0x00, 0x00, 0x0F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF,
        ];
        assert!(has_leading_zeros(&hash, 16)); // first 2 bytes are zero
        assert!(has_leading_zeros(&hash, 20)); // first 20 bits are zero (0x00 0x00 0x0_)
        assert!(!has_leading_zeros(&hash, 21)); // 21st bit is 1
    }

    /// `/v1/challenge` needs no capability, so a flood must not grow the store
    /// past its bound: the oldest challenge goes, the newest stays usable,
    /// and a challenge is single-use and expires.
    #[test]
    fn challenge_store_is_bounded_single_use_and_expiring() {
        let store = ChallengeStore::default();
        let id = |i: usize| {
            let mut c = [0u8; 32];
            c[..8].copy_from_slice(&(i as u64).to_be_bytes());
            c
        };
        for i in 0..=MAX_OUTSTANDING_CHALLENGES {
            store.issue(id(i), 20, 1_000);
        }
        assert_eq!(
            store.inner.lock().unwrap().by_id.len(),
            MAX_OUTSTANDING_CHALLENGES
        );
        assert_eq!(store.consume(&id(0), 0), None, "oldest evicted at capacity");
        assert_eq!(store.consume(&id(MAX_OUTSTANDING_CHALLENGES), 0), Some(20));
        assert_eq!(
            store.consume(&id(MAX_OUTSTANDING_CHALLENGES), 0),
            None,
            "single use"
        );
        assert_eq!(store.consume(&id(1), 1_000), None, "expired");
    }

    #[test]
    fn test_has_leading_zeros_zero_difficulty() {
        let hash = [0xFF; 32];
        assert!(has_leading_zeros(&hash, 0));
    }

    #[test]
    fn test_adaptive_difficulty() {
        assert_eq!(adaptive_difficulty(0, 8, 24), 8);
        assert_eq!(adaptive_difficulty(49, 8, 24), 8);
        assert_eq!(adaptive_difficulty(50, 8, 24), 16);
        assert_eq!(adaptive_difficulty(79, 8, 24), 16);
        assert_eq!(adaptive_difficulty(80, 8, 24), 20);
        assert_eq!(adaptive_difficulty(94, 8, 24), 20);
        assert_eq!(adaptive_difficulty(95, 8, 24), 24);
        assert_eq!(adaptive_difficulty(100, 8, 24), 24);
    }

    /// Regression: `clamp` panics when `min > max`, and this function's two
    /// bounds come from unrelated sources (a per-endpoint spec floor vs the
    /// operator's configured ceiling). `/v1/deposit` to an ephemeral cap paired
    /// a hardcoded 16-bit floor with `config.pow.max_difficulty`, so any server
    /// configured below 16 crashed a worker thread on an unauthenticated
    /// request — and every QR handshake hands out exactly that kind of cap.
    #[test]
    fn inverted_bounds_do_not_panic_and_the_floor_wins() {
        for load in [0u8, 49, 50, 79, 80, 94, 95, 100] {
            assert_eq!(adaptive_difficulty(load, 16, 0), 16);
        }
        // Sanity: a ceiling above the floor still binds normally.
        assert_eq!(adaptive_difficulty(0, 16, 24), 16);
        assert_eq!(adaptive_difficulty(100, 16, 20), 20);
        // Equal bounds are the degenerate-but-valid case (test servers).
        assert_eq!(adaptive_difficulty(100, 0, 0), 0);
    }

    #[test]
    fn test_verify_pow_bound_brute_force() {
        let challenge = generate_challenge();
        let cap_binding = [0xABu8; 32];
        let blob_hash = [0u8; 32];
        let timestamp = 1_700_000_000u64;
        let difficulty = 8; // easy enough to brute-force in a test
        let mut nonce = 0u64;
        let hash = loop {
            let h = pow_hash(&challenge, &cap_binding, timestamp, &blob_hash, nonce);
            if has_leading_zeros(&h, difficulty) {
                break h;
            }
            nonce += 1;
            assert!(nonce < 100_000, "should find 8-bit PoW quickly");
        };
        assert!(verify_pow_bound(
            &challenge,
            &cap_binding,
            timestamp,
            &blob_hash,
            nonce,
            difficulty,
            &hash
        ));
        // A solution bound to one capability must not verify under another.
        assert!(!verify_pow_bound(
            &challenge,
            &[0xCDu8; 32],
            timestamp,
            &blob_hash,
            nonce,
            difficulty,
            &hash
        ));
    }
}
