//! Fetch-capability selection (S08 §6.1.1).
//!
//! A mailbox operator sees every fetch capability one poll circuit reads. Reading
//! every receive queue on every poll would let it count the user's contacts on
//! that mailbox. Each poll therefore reads `k`, drawn uniformly from
//! `[FETCH_CAPS_MIN, FETCH_CAPS_MAX]`, entries of the mailbox's *pool*: its real
//! receive queues followed by enough registered dummy queues to fill
//! `FETCH_CAPS_MAX`. Real and dummy entries share one round-robin rotation, so
//! each is read at the same rate and an entry read on every poll is not a tell.
//!
//! The plan holds onion addresses and fetch capabilities only. It outlives the
//! profile lock, so a locked app keeps the same schedule and the same rotation
//! while it only fetches (S13 §8.3).

use std::collections::HashMap;
use std::sync::Mutex;

use najwa_protocol::mailbox::client::MailboxClient;
use najwa_protocol::mailbox::types::MailboxConfig;
use rand::seq::SliceRandom;
use rand::Rng;
use zeroize::Zeroizing;

/// Blobs requested per fetch call.
pub const FETCH_COUNT: u32 = 10;
/// Fetch capabilities read per mailbox per poll: lower bound.
pub const FETCH_CAPS_MIN: usize = 4;
/// Fetch capabilities read per mailbox per poll: upper bound, and the pool size.
pub const FETCH_CAPS_MAX: usize = 10;
/// Dummy queues kept per mailbox. Its own queue is always a real receive
/// queue, so this many dummies fill a pool of `FETCH_CAPS_MAX`.
pub const DUMMY_CAPS_PER_MAILBOX: usize = FETCH_CAPS_MAX - 1;

/// How many registered dummies join the pool of a mailbox with `real` receive
/// queues. The remaining dummies idle: neither fetched nor deposited to.
pub fn active_dummies(real: usize) -> usize {
    FETCH_CAPS_MAX.saturating_sub(real)
}

/// A queue that can only be fetched: a dummy, or a real queue while locked. Its
/// zero envelope secret decrypts nothing, so the poll treats every blob as not ours.
pub fn fetch_only_queue(onion: &str, fetch_capability: &[u8; 32]) -> MailboxConfig {
    MailboxConfig {
        onion_address: onion.to_string(),
        fetch_capability: *fetch_capability,
        deposit_capability: [0; 32],
        envelope_secret: [0; 32],
        cover_deposit_capability: None,
        cover_fetch_capability: None,
        cover_envelope_secret: None,
    }
}

type Cap = Zeroizing<[u8; 32]>;

#[derive(Default)]
struct Pool {
    /// Real fetch capabilities at the last refresh. Read only by the locked poll.
    real: Vec<Cap>,
    /// Registered dummy fetch capabilities, in pool order.
    dummies: Vec<Cap>,
    cursor: usize,
}

/// Per-mailbox fetch pools shared by the unlocked receive poll and the locked
/// fetch-only poll. Dropping it zeroizes every capability it holds.
#[derive(Default)]
pub struct FetchPlan(Mutex<HashMap<String, Pool>>);

impl FetchPlan {
    /// Install `(onion, real fetch capabilities, registered dummy fetch
    /// capabilities)` per enabled mailbox. Each mailbox keeps its rotation.
    pub fn replace(&self, pools: Vec<(String, Vec<[u8; 32]>, Vec<[u8; 32]>)>) {
        let mut map = self.0.lock().unwrap();
        let next = pools
            .into_iter()
            .map(|(onion, real, dummies)| {
                let cursor = map.get(&onion).map_or(0, |pool| pool.cursor);
                let pool = Pool {
                    real: real.into_iter().map(Zeroizing::new).collect(),
                    dummies: dummies.into_iter().map(Zeroizing::new).collect(),
                    cursor,
                };
                (onion, pool)
            })
            .collect();
        *map = next;
    }

    /// This poll's entries on one mailbox, in random order. `real` are its
    /// receive queues in a stable order; `dummy` turns a dummy fetch
    /// capability into an entry.
    pub fn select<T>(&self, onion: &str, mut real: Vec<T>, dummy: impl Fn(&[u8; 32]) -> T) -> Vec<T> {
        let mut map = self.0.lock().unwrap();
        let pool = map.entry(onion.to_string()).or_default();
        let active = active_dummies(real.len()).min(pool.dummies.len());
        real.extend(pool.dummies[..active].iter().map(|cap| dummy(&**cap)));
        if real.is_empty() {
            return real;
        }
        let take = rand::thread_rng()
            .gen_range(FETCH_CAPS_MIN..=FETCH_CAPS_MAX)
            .min(real.len());
        let start = pool.cursor % real.len();
        pool.cursor = (start + take) % real.len();
        real.rotate_left(start);
        real.truncate(take);
        real.shuffle(&mut rand::thread_rng());
        real
    }

    /// A poll while the profile is locked: the same selection, one fetch per
    /// selected capability, and nothing else. Without keys nothing can be
    /// decrypted, so nothing is acknowledged and every blob stays on the
    /// mailbox for the first poll after unlock.
    pub async fn poll_locked<M: MailboxClient>(&self, client: &M) {
        let mut onions: Vec<String> = self.0.lock().unwrap().keys().cloned().collect();
        onions.shuffle(&mut rand::thread_rng());
        for onion in onions {
            let real = match self.0.lock().unwrap().get(&onion) {
                Some(pool) => pool.real.clone(),
                None => continue,
            };
            for cap in self.select(&onion, real, |cap| Zeroizing::new(*cap)) {
                // Like the unlocked poll, a failure ends this mailbox's poll.
                let queue = fetch_only_queue(&onion, &cap);
                if let Err(error) = client.fetch(&queue, &cap, None, FETCH_COUNT).await {
                    tracing::warn!(mailbox = %onion, %error, "locked fetch failed");
                    break;
                }
            }
        }
    }
}
