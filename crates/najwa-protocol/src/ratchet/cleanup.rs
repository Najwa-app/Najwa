//! Skipped key cleanup (S06 §3.8).

use najwa_crypto::time::now;

use super::state::{RatchetState, MAX_SKIPPED_KEYS_PER_SESSION, SKIP_KEY_EXPIRY_SECS};

/// Remove expired skipped message keys (S06 §3.8).
///
/// Keys older than `SKIP_KEY_EXPIRY_SECS` (90 days) are removed and zeroized.
/// Returns the number of keys removed.
pub fn cleanup_expired_skipped_keys(state: &mut RatchetState) -> u32 {
    let cutoff = now().saturating_sub(SKIP_KEY_EXPIRY_SECS);
    let before = state.skipped.len();
    state.skipped.retain(|_, v| v.created_at > cutoff);
    (before - state.skipped.len()) as u32
}

/// Enforce the global per-session cap on stored skipped keys
/// (S06 §3.1 / D6). When the store exceeds `MAX_SKIPPED_KEYS_PER_SESSION`,
/// evict the oldest entries (by `created_at`, ties broken by key order) until
/// the store is back at the cap. Returns the number of keys evicted.
///
/// Call this after inserting newly-skipped keys so a lossy or adversarial peer
/// cannot grow the store without bound across epochs.
pub fn enforce_skipped_key_cap(state: &mut RatchetState) -> u32 {
    if state.skipped.len() <= MAX_SKIPPED_KEYS_PER_SESSION {
        return 0;
    }
    let mut evicted = 0u32;
    while state.skipped.len() > MAX_SKIPPED_KEYS_PER_SESSION {
        // Find the oldest entry. The store is bounded, so this linear scan is
        // acceptable and only runs while over the cap.
        let oldest = state
            .skipped
            .iter()
            .min_by(|a, b| {
                a.1.created_at
                    .cmp(&b.1.created_at)
                    .then_with(|| a.0.cmp(b.0))
            })
            .map(|(k, _)| *k);
        match oldest {
            Some(key) => {
                state.skipped.remove(&key);
                evicted += 1;
            }
            None => break,
        }
    }
    evicted
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ratchet::state::SkippedKey;

    #[test]
    fn cleanup_removes_expired_keys() {
        let mut rng = rand::thread_rng();
        let spk = najwa_crypto::keys::x25519::X25519KeyPair::generate(&mut rng);
        let sk = [0x42u8; 32];
        let mut state = crate::ratchet::init::init_bob(&sk, spk);

        let current_time = now();

        // Insert an expired key (created 91 days ago, beyond the 90-day expiry)
        state.skipped.insert(
            ([0xAA; 32], 0),
            SkippedKey {
                message_key: [0x01; 32],
                created_at: current_time.saturating_sub(91 * 24 * 3600),
            },
        );

        // Insert a fresh key (created now)
        state.skipped.insert(
            ([0xBB; 32], 0),
            SkippedKey {
                message_key: [0x02; 32],
                created_at: current_time,
            },
        );

        assert_eq!(state.skipped.len(), 2);
        let removed = cleanup_expired_skipped_keys(&mut state);
        assert_eq!(removed, 1);
        assert_eq!(state.skipped.len(), 1);
        assert!(state.skipped.contains_key(&([0xBB; 32], 0)));
    }

    #[test]
    fn cap_evicts_oldest_beyond_limit() {
        use super::super::state::MAX_SKIPPED_KEYS_PER_SESSION;

        let mut rng = rand::thread_rng();
        let spk = najwa_crypto::keys::x25519::X25519KeyPair::generate(&mut rng);
        let sk = [0x42u8; 32];
        let mut state = crate::ratchet::init::init_bob(&sk, spk);

        let base = now();
        // Insert cap + 10 keys, each with a distinct, increasing timestamp so
        // the "oldest" ordering is unambiguous.
        let total = MAX_SKIPPED_KEYS_PER_SESSION + 10;
        for i in 0..total {
            let mut dh = [0u8; 32];
            dh[0] = (i & 0xff) as u8;
            dh[1] = ((i >> 8) & 0xff) as u8;
            state.skipped.insert(
                (dh, i as u32),
                SkippedKey {
                    message_key: [0x11; 32],
                    created_at: base + i as u64, // older entries have smaller i
                },
            );
        }
        assert_eq!(state.skipped.len(), total);

        let evicted = enforce_skipped_key_cap(&mut state);
        assert_eq!(evicted, 10);
        assert_eq!(state.skipped.len(), MAX_SKIPPED_KEYS_PER_SESSION);

        // The 10 oldest (i = 0..10) must be gone; a recent one must remain.
        for i in 0..10u32 {
            let mut dh = [0u8; 32];
            dh[0] = (i & 0xff) as u8;
            assert!(!state.skipped.contains_key(&(dh, i)));
        }
        let mut newest_dh = [0u8; 32];
        let newest = (total - 1) as u32;
        newest_dh[0] = (newest & 0xff) as u8;
        newest_dh[1] = ((newest >> 8) & 0xff) as u8;
        assert!(state.skipped.contains_key(&(newest_dh, newest)));
    }

    #[test]
    fn cap_noop_under_limit() {
        let mut rng = rand::thread_rng();
        let spk = najwa_crypto::keys::x25519::X25519KeyPair::generate(&mut rng);
        let sk = [0x42u8; 32];
        let mut state = crate::ratchet::init::init_bob(&sk, spk);
        state.skipped.insert(
            ([0x01; 32], 0),
            SkippedKey {
                message_key: [0x22; 32],
                created_at: now(),
            },
        );
        assert_eq!(enforce_skipped_key_cap(&mut state), 0);
        assert_eq!(state.skipped.len(), 1);
    }

    #[test]
    fn cleanup_no_expired_keys() {
        let mut rng = rand::thread_rng();
        let spk = najwa_crypto::keys::x25519::X25519KeyPair::generate(&mut rng);
        let sk = [0x42u8; 32];
        let mut state = crate::ratchet::init::init_bob(&sk, spk);

        state.skipped.insert(
            ([0xCC; 32], 0),
            SkippedKey {
                message_key: [0x03; 32],
                created_at: now(),
            },
        );

        let removed = cleanup_expired_skipped_keys(&mut state);
        assert_eq!(removed, 0);
        assert_eq!(state.skipped.len(), 1);
    }
}
