//! Main messaging service orchestration (S08 §2).

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

use najwa_crypto::keys::ed25519::Ed25519KeyPair;
use najwa_protocol::mailbox::client::MailboxClient;
use najwa_protocol::pseudonym::lookup::PseudonymTable;
use najwa_protocol::pseudonym::types::{ContactId as PseudoContactId, Pseudonym};
use najwa_transport::tor::TorTransport;

use crate::cover::SlotSource;
use crate::disappearing::VolatileKeyCache;
use crate::error::{MessagingError, Result};
use crate::rate_limit::OutboundRateLimiter;
use crate::storage::CoreStorage;
use crate::types::{Contact, ContactId};

/// Maximum number of graceful-repair retries before the local-only session
/// teardown (S08 §6.2). No `SessionReset` is sent.
pub const MAX_REPAIR_RETRIES: u32 = 3;

/// Grace window before a `MissedEpochBoundary` frame escalates to session
/// repair (S06 §3.7.1 / D8). The server holds each blob a randomised
/// `max_hold + jitter` and multi-path copies traverse different mailboxes, so
/// two epoch transitions can be in flight at once and a later epoch can be
/// released before the epoch that links it. A reordered (not lost) epoch
/// resolves once the intervening frame arrives, so the frame is quarantined and
/// retried for this long before a teardown is initiated.
pub const REPAIR_GRACE_SECS: u64 = 600;

/// Maximum number of frames held in the epoch-reorder quarantine at once
/// (S06 §3.1 / D8). Bounds the memory an adversary or a genuinely broken peer
/// can force; once full, the next `MissedEpochBoundary` escalates to repair
/// immediately instead of buffering.
pub const EPOCH_QUARANTINE_MAX: usize = 32;

/// Minimum interval between gap-repair requests to the SAME contact (S08 §6.5):
/// 1 hour. Bounds a peer-inducible stream of immediate, correlatable repair
/// requests that would otherwise defeat cover absorption.
pub const GAP_REPAIR_MIN_INTERVAL_SECS: u64 = 3600;

/// A frame quarantined after a `MissedEpochBoundary` (D8). The raw inner blob
/// (a decrypted `WireMessage`) is retried verbatim through the normal receive
/// path once intervening frames have advanced the session; if the gap has not
/// closed within `REPAIR_GRACE_SECS`, it escalates to session repair.
#[derive(Debug, Clone)]
pub struct QuarantinedFrame {
    /// `SHA256(blob)` — the key of the durable copy in the device-local store
    /// (S08 §6.3), used to delete it on recovery or grace expiry.
    pub blob_hash: [u8; 32],
    /// The decrypted inner `WireMessage` bytes (re-fed to `process_message`).
    pub blob: Vec<u8>,
    /// Unix time the frame was first quarantined.
    pub quarantined_at: u64,
}

/// Phase of a Layer 2 graceful repair for a single contact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepairPhase {
    /// A repair attempt has been initiated and we are waiting for the peer
    /// to process the new X3DH handshake (old ratchet state is still kept).
    InProgress,
    /// All `MAX_REPAIR_RETRIES` repair attempts failed — the client has
    /// torn down its local session (S08 §6.2). This phase is observable for
    /// diagnostics but is not user-actionable by itself.
    Failed,
}

/// In-memory repair tracker for a single contact.
///
/// Lifetime: one repair window. Cleared when a frame from the contact next
/// commits (normally the peer's ACK of the repair Initial, under the new
/// session) or when the peer's own `SessionRepairInit` arrives. The local
/// teardown leaves it as `Failed` until then.
#[derive(Debug, Clone, Copy)]
pub struct RepairState {
    pub phase: RepairPhase,
    pub retry_count: u32,
    pub last_attempt_unix: u64,
    /// Reason the current repair window was opened (0x01 = MissedEpochBoundary,
    /// 0x02 = TooManySkipped).
    pub reason: u8,
}

/// Core messaging service that orchestrates send/receive operations (S08 §2).
///
/// Generic over storage and mailbox client for testability.
/// Optionally holds a `TorTransport` handle for lifecycle management
/// and status queries (bootstrap progress, circuit count, etc.).
pub struct MessagingService<S: CoreStorage, M: MailboxClient> {
    /// The user's Ed25519 identity key pair.
    pub(crate) identity_key: Ed25519KeyPair,
    /// Storage backend.
    pub(crate) storage: S,
    /// Mailbox client.
    pub(crate) mailbox_client: M,
    /// Optional Tor transport handle for lifecycle and status queries.
    /// `None` in tests or when transport is managed externally.
    transport: Option<Arc<TorTransport>>,
    /// In-memory pseudonym → contact lookup table (§9.3).
    ///
    /// Populated at startup from contacts, updated on contact add/remove.
    /// Provides O(1) routing of incoming messages by sender pseudonym.
    pseudonym_table: RwLock<PseudonymTable>,
    /// In-memory graceful-repair state per contact (S06 §3.7.1).
    ///
    /// A contact appears here while a `SessionRepairInit` attempt is
    /// outstanding. On successful repair (new X3DH handshake confirmed) or
    /// on local teardown, the entry is cleared or transitioned to
    /// `RepairPhase::Failed`.
    pub(crate) repair_states: Mutex<HashMap<ContactId, RepairState>>,
    /// In-memory epoch-reorder quarantine (D8). Frames that hit
    /// `MissedEpochBoundary` are buffered here and retried at the end of each
    /// poll cycle (once fresh frames may have closed the gap) rather than
    /// immediately tearing the session down. Bounded by `EPOCH_QUARANTINE_MAX`.
    pub(crate) epoch_quarantine: Mutex<Vec<QuarantinedFrame>>,

    /// Set once the durable quarantine has been reloaded into `epoch_quarantine`
    /// on the first poll after startup (S08 §6.3 crash recovery). Ensures frames
    /// buffered before a restart resume their grace windows exactly once.
    pub(crate) quarantine_loaded: std::sync::atomic::AtomicBool,

    /// Outbound token-bucket rate limiter (S08 §8: 10 msg/s, burst 20) — gates
    /// `send_message` so the client cannot emit a suspicious burst.
    pub(crate) outbound_limiter: OutboundRateLimiter,
    pub(crate) inbound_limiter: crate::rate_limit::InboundRateLimiter,
    // Ratchet read/derive/commit must never overlap. Network deposits use a
    // separate guard so cover pacing does not block incoming decryption.
    pub(crate) state_gate: tokio::sync::Mutex<()>,
    pub(crate) dispatch_gate: Mutex<std::collections::HashSet<i64>>,
    // Reserve transport capacity for foreground chat, receive and setup work.
    // Retry scans share this admission budget and never wait behind each other.
    pub(crate) background_delivery: tokio::sync::Semaphore,
    pub(crate) poll_gate: tokio::sync::Mutex<()>,
    pub(crate) prekey_gate: tokio::sync::Mutex<()>,
    pub(crate) work_gate: tokio::sync::Mutex<()>,

    /// Per-message ephemeral-key cache for disappearing messages (S12 §4.1).
    /// Keys live only in volatile memory for the unlocked session; send/receive
    /// seal content under a fresh key here, the display path opens it, and expiry
    /// zeroises it (the primary deletion defence, §5.1). Shared by the FFI read /
    /// cleanup / lock paths via [`Self::volatile_cache`].
    pub(crate) volatile_cache: VolatileKeyCache,

    /// Per-contact time (unix secs) of the last gap-repair request sent (S08
    /// §6.5). Gap-repair is rate-limited to one request per contact per
    /// [`GAP_REPAIR_MIN_INTERVAL_SECS`] so a peer cannot induce a stream of
    /// immediate, correlatable repair requests that defeats cover absorption.
    pub(crate) last_gap_repair: Mutex<HashMap<ContactId, u64>>,
    /// Responder side of S08 §6.5: time of the last `GapRepairRequest`
    /// answered per contact, at most one per [`GAP_REPAIR_MIN_INTERVAL_SECS`].
    pub(crate) answered_gap_repairs: Mutex<HashMap<ContactId, u64>>,
    /// S11 §4.1: time of the last `FileChunkNack` answered per contact and
    /// file, at most one per `NACK_MIN_INTERVAL_SECS`.
    pub(crate) answered_file_nacks: Mutex<HashMap<(ContactId, [u8; 16]), u64>>,

    /// Deposit-slot source for outbound absorption (S10 §6.2).
    ///
    /// `None` means "deposit immediately" — the pre-absorption behaviour, and
    /// what every test and non-mobile embedder gets unless it opts in via
    /// [`Self::set_slot_source`]. Present in the app builds, where the FFI hands
    /// over the running scheduler's queues.
    pub(crate) slot_source: Option<Arc<SlotSource>>,

    /// Fetch-capability selection and dummy pools (S08 §6.1.1). The app hands
    /// over the plan it keeps across lock via [`Self::set_fetch_plan`]; the
    /// default has no dummies, so it can only round-robin real queues.
    pub(crate) fetch_plan: Arc<crate::fetch_plan::FetchPlan>,
}

impl<S: CoreStorage, M: MailboxClient> MessagingService<S, M> {
    /// Create a new messaging service.
    pub fn new(identity_key: Ed25519KeyPair, storage: S, mailbox_client: M) -> Self {
        Self {
            identity_key,
            storage,
            mailbox_client,
            transport: None,
            pseudonym_table: RwLock::new(PseudonymTable::new()),
            repair_states: Mutex::new(HashMap::new()),
            epoch_quarantine: Mutex::new(Vec::new()),
            quarantine_loaded: std::sync::atomic::AtomicBool::new(false),
            outbound_limiter: OutboundRateLimiter::default(),
            inbound_limiter: crate::rate_limit::InboundRateLimiter::default(),
            state_gate: tokio::sync::Mutex::new(()),
            dispatch_gate: Mutex::new(std::collections::HashSet::new()),
            background_delivery: tokio::sync::Semaphore::new(4),
            poll_gate: tokio::sync::Mutex::new(()),
            prekey_gate: tokio::sync::Mutex::new(()),
            work_gate: tokio::sync::Mutex::new(()),
            volatile_cache: VolatileKeyCache::new(),
            last_gap_repair: Mutex::new(HashMap::new()),
            answered_gap_repairs: Mutex::new(HashMap::new()),
            answered_file_nacks: Mutex::new(HashMap::new()),
            slot_source: None,
            fetch_plan: Default::default(),
        }
    }

    /// Create a messaging service with a Tor transport handle.
    pub fn with_transport(
        identity_key: Ed25519KeyPair,
        storage: S,
        mailbox_client: M,
        transport: Arc<TorTransport>,
    ) -> Self {
        Self {
            identity_key,
            storage,
            mailbox_client,
            transport: Some(transport),
            pseudonym_table: RwLock::new(PseudonymTable::new()),
            repair_states: Mutex::new(HashMap::new()),
            epoch_quarantine: Mutex::new(Vec::new()),
            quarantine_loaded: std::sync::atomic::AtomicBool::new(false),
            outbound_limiter: OutboundRateLimiter::default(),
            inbound_limiter: crate::rate_limit::InboundRateLimiter::default(),
            state_gate: tokio::sync::Mutex::new(()),
            dispatch_gate: Mutex::new(std::collections::HashSet::new()),
            background_delivery: tokio::sync::Semaphore::new(4),
            poll_gate: tokio::sync::Mutex::new(()),
            prekey_gate: tokio::sync::Mutex::new(()),
            work_gate: tokio::sync::Mutex::new(()),
            volatile_cache: VolatileKeyCache::new(),
            last_gap_repair: Mutex::new(HashMap::new()),
            answered_gap_repairs: Mutex::new(HashMap::new()),
            answered_file_nacks: Mutex::new(HashMap::new()),
            slot_source: None,
            fetch_plan: Default::default(),
        }
    }

    /// Share the app's fetch plan (S08 §6.1.1), so polls before and after a
    /// lock continue one rotation over the same dummy queues.
    pub fn set_fetch_plan(&mut self, plan: Arc<crate::fetch_plan::FetchPlan>) {
        self.fetch_plan = plan;
    }

    /// Route outbound deposits through the cover scheduler's slots (S10 §6.2).
    ///
    /// Call before sharing the service. The canonical `SlotSource` should be
    /// owned by whoever owns the scheduler and cloned in here, so fast mode
    /// stays toggleable across service rebuilds (identity transitions clear the
    /// service, and a user setting must survive that).
    pub fn set_slot_source(&mut self, source: Arc<SlotSource>) {
        self.slot_source = Some(source);
    }

    /// Access the disappearing-message ephemeral-key cache (S12 §4.1).
    ///
    /// The FFI layer uses this to open sealed content for display, zeroise keys
    /// on expiry, and persist/restore keys across lock — all against the same
    /// in-memory cache the send/receive paths seal into.
    pub fn volatile_cache(&self) -> &VolatileKeyCache {
        &self.volatile_cache
    }

    /// Share the unlocked application's cache, including keys restored before
    /// network bootstrap. Call before publishing the service to other tasks.
    pub fn set_volatile_cache(&mut self, cache: VolatileKeyCache) {
        self.volatile_cache = cache;
    }

    /// Get a snapshot of the in-memory graceful-repair state for a contact
    /// (S06 §3.7.1). Returns `None` if no repair is currently tracked.
    ///
    /// Consumed by the FFI layer to expose a `RepairInProgress` signal to
    /// the Android/iOS UI without leaking the storage backend.
    pub fn get_repair_state(&self, contact_id: ContactId) -> Option<RepairState> {
        let guard = self.repair_states.lock().ok()?;
        guard.get(&contact_id).copied()
    }

    /// End a contact's repair window once a frame from it has committed (S06
    /// §3.7.1). The repair replaced the old session, so a frame that decrypts is
    /// the peer answering in the new one — normally its ACK of the repair Initial.
    pub(crate) fn end_repair(&self, contact_id: ContactId) {
        if let Ok(mut states) = self.repair_states.lock() {
            states.remove(&contact_id);
        }
    }

    /// Decide whether a gap-repair request may be sent to `contact_id` now (S08
    /// §6.5), recording the send time if so. Suppressed while a session repair is
    /// already outstanding for the contact, and otherwise rate-limited to one
    /// request per [`GAP_REPAIR_MIN_INTERVAL_SECS`]. Atomic check-and-record, so
    /// a burst of forward-jumping messages yields at most one request per window.
    pub(crate) fn gap_repair_allowed(&self, contact_id: ContactId, now_secs: u64) -> bool {
        // Suppress ONLY while a graceful repair is actually in flight
        // (InProgress). A `Failed` entry is the stale record of a repair that
        // already exhausted its retries and tore the session down locally — it
        // is NOT in flight and must not suppress gap-repair forever (the session
        // re-establishes fresh on the next inbound frame), so GC it here.
        if let Ok(mut states) = self.repair_states.lock() {
            match states.get(&contact_id).map(|s| s.phase) {
                Some(RepairPhase::InProgress) => return false,
                Some(RepairPhase::Failed) => {
                    states.remove(&contact_id);
                }
                None => {}
            }
        }
        let mut last = match self.last_gap_repair.lock() {
            Ok(l) => l,
            Err(_) => return false,
        };
        match last.get(&contact_id) {
            Some(&t) if now_secs.saturating_sub(t) < GAP_REPAIR_MIN_INTERVAL_SECS => false,
            _ => {
                last.insert(contact_id, now_secs);
                true
            }
        }
    }

    /// Undo the rate-limit record set by a preceding `gap_repair_allowed` that
    /// returned `true`, for the case where the gap-repair request then failed to
    /// send. Without this, a request that never left the device would still
    /// suppress the next gap for a full [`GAP_REPAIR_MIN_INTERVAL_SECS`] window.
    pub(crate) fn rollback_gap_repair(&self, contact_id: ContactId) {
        if let Ok(mut last) = self.last_gap_repair.lock() {
            last.remove(&contact_id);
        }
    }
}

/// In-memory check-and-record: true at most once per `interval` for `key`.
/// Entries older than `interval` are dropped, so the map holds recent keys only.
pub(crate) fn admit<K: Eq + std::hash::Hash>(
    map: &Mutex<HashMap<K, u64>>,
    key: K,
    now: u64,
    interval: u64,
) -> bool {
    let Ok(mut map) = map.lock() else {
        return false;
    };
    map.retain(|_, at| now.saturating_sub(*at) < interval);
    if map.contains_key(&key) {
        return false;
    }
    map.insert(key, now);
    true
}

impl<S: CoreStorage, M: MailboxClient> MessagingService<S, M> {
    /// Get a reference to the transport handle, if available.
    pub fn transport(&self) -> Option<&Arc<TorTransport>> {
        self.transport.as_ref()
    }

    /// Timestamp source for protocol messages and their validation. Device-local
    /// retention timers continue using their original system-clock domain.
    pub(crate) fn message_time(&self) -> u64 {
        self.transport
            .as_ref()
            .map_or_else(najwa_crypto::time::now, |transport| transport.clock().now())
    }

    /// Populate the pseudonym table from all contacts in storage.
    ///
    /// Should be called once at startup after unlocking the identity.
    pub async fn load_pseudonym_table(&self) -> Result<usize> {
        let contacts = self
            .storage
            .list_contacts()
            .await
            .map_err(MessagingError::StorageError)?;

        let mut table = self
            .pseudonym_table
            .write()
            .map_err(|_| MessagingError::InternalError("pseudonym table lock poisoned".into()))?;

        let mut count = 0;
        for contact in &contacts {
            // their_pseudonym is the pseudonym the contact uses when sending to us
            if contact.their_pseudonym != [0u8; 32] {
                table.insert(
                    Pseudonym(contact.their_pseudonym),
                    PseudoContactId(contact.id),
                );
                count += 1;
            }
        }
        Ok(count)
    }

    /// Register a single contact's pseudonym in the table.
    ///
    /// Called when a new contact is added or after key exchange.
    pub fn register_pseudonym(&self, contact_id: i64, their_pseudonym: [u8; 32]) -> Result<()> {
        let mut table = self
            .pseudonym_table
            .write()
            .map_err(|_| MessagingError::InternalError("pseudonym table lock poisoned".into()))?;
        table.insert(
            Pseudonym(their_pseudonym),
            PseudoContactId(contact_id as u64),
        );
        Ok(())
    }

    /// Remove a contact's pseudonym from the table.
    ///
    /// Called when a contact is deleted.
    pub fn unregister_pseudonym(&self, their_pseudonym: [u8; 32]) -> Result<()> {
        let mut table = self
            .pseudonym_table
            .write()
            .map_err(|_| MessagingError::InternalError("pseudonym table lock poisoned".into()))?;
        table.remove(&Pseudonym(their_pseudonym));
        Ok(())
    }

    /// Look up a contact ID by their sender pseudonym (O(1)).
    ///
    /// Returns `None` if the pseudonym is not registered (unknown sender).
    pub fn lookup_pseudonym(&self, their_pseudonym: &[u8; 32]) -> Option<i64> {
        let table = self.pseudonym_table.read().ok()?;
        table
            .lookup(&Pseudonym(*their_pseudonym))
            .map(|cid| cid.0 as i64)
    }

    /// Build associated data for AEAD when we are the session initiator:
    /// AD = our_IK(32) || their_IK(32).
    pub(crate) fn build_ad_as_initiator(&self, contact: &Contact) -> Vec<u8> {
        let mut ad = Vec::with_capacity(64);
        ad.extend_from_slice(&self.identity_key.public().to_bytes());
        ad.extend_from_slice(&contact.their_ik_pub);
        ad
    }

    /// Build associated data for AEAD when they are the session initiator:
    /// AD = their_IK(32) || our_IK(32).
    #[allow(dead_code)]
    pub(crate) fn build_ad_as_responder(&self, contact: &Contact) -> Vec<u8> {
        let mut ad = Vec::with_capacity(64);
        ad.extend_from_slice(&contact.their_ik_pub);
        ad.extend_from_slice(&self.identity_key.public().to_bytes());
        ad
    }
}
