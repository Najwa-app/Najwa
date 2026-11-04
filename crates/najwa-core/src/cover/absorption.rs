//! Per-mailbox pending queues — the single normative absorption model (S10 §6.1).
//!
//! Every outbound real item that waits for a slot (user message, repair, ACK,
//! receipt, control, registration, prekey publication) is enqueued under its
//! **destination mailbox onion**. Each deposit slot fired by the scheduler
//! picks uniformly among mailboxes with pending work, pops that mailbox's
//! highest-priority item (FIFO within a tier), and hands it the slot —
//! absorbing it. An empty map means the slot emits pure cover.
//!
//! This map — and nothing else — is the absorption state (S10 §4). A boolean
//! suppress flag would under-absorb bursts (two real sends in one inter-slot
//! gap would suppress only one slot) and would let a real deposit on mailbox
//! A suppress cover on mailbox B — a cross-server-correlatable artefact.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use super::permit::SlotPermit;
use tokio::sync::oneshot;

/// Priority tiers for pending items (S10 §6.1).
///
/// Tier 2 holds two variants; order within a tier is FIFO, so the enum's
/// `tier()` — not its declaration order — is the priority. The application
/// never produces `GroupKeyDistribution` or `DummySelfDeposit` items.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbsorptionPriority {
    /// Tier 1 — highest: real user-content message (user is waiting).
    RealMessage,
    /// Tier 2 — `SessionRepairInit (0x31)`: session recovery must not wait.
    SessionRepairInit,
    /// Tier 2 — group-key distribution. Not produced by the application.
    GroupKeyDistribution,
    /// Tier 3 — delivery ACK.
    Ack,
    /// Tier 4 — read receipt (if enabled).
    ReadReceipt,
    /// Tier 5 — typing indicator (if enabled).
    TypingIndicator,
    /// Tier 6 — other control subtypes, capability registrations and prekey
    /// publications (S10 §5.2).
    Control,
    /// Tier 7 — dummy-capability self-deposits. Not produced by the application.
    DummySelfDeposit,
}

impl AbsorptionPriority {
    /// Spec priority tier (1 = highest). Tier 2 holds two variants.
    pub fn tier(self) -> u8 {
        match self {
            Self::RealMessage => 1,
            Self::SessionRepairInit | Self::GroupKeyDistribution => 2,
            Self::Ack => 3,
            Self::ReadReceipt => 4,
            Self::TypingIndicator => 5,
            Self::Control => 6,
            Self::DummySelfDeposit => 7,
        }
    }
}

/// Burst handling mode (S10 §8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BurstMode {
    /// Speed Priority (default): messages still flow through the slot queue,
    /// but a real burst opens a bounded scheduler-rate boost window; identical
    /// decoy windows fire randomly (S10 §8.1).
    #[default]
    SpeedPriority,
    /// Privacy Priority: unboosted slot release only; boosts (real-triggered
    /// and decoy) are disabled and the rate stays constant. Not used by the
    /// application.
    PrivacyPriority,
}

/// What a slot actually does when this item absorbs it.
///
/// Two shapes, because the two kinds of outbound work have different failure
/// owners. A `Blob` is fire-and-forget — nobody is waiting, so the scheduler
/// deposits it and a failure is only a lost dummy/receipt. A `Slot` is a
/// caller (the S08 send path) parked on a permit: the scheduler wakes it and
/// the CALLER performs the deposit.
///
/// The split is load-bearing, not stylistic. Having the scheduler deposit real
/// user content would put message delivery behind two silent-drop paths it
/// cannot recover from — an unresolvable destination and a failed deposit both
/// pop the item and return, with no storage handle available to mark the row
/// for retry (the scheduler deliberately holds none so it can keep running
/// while UI lock closes the database). Handing back a permit instead leaves
/// `commit_sent`'s durable Pending row + retry blob owned by the send path,
/// where the existing Failed/drain machinery already handles both cases.
#[derive(Debug)]
pub enum PendingPayload {
    /// The scheduler deposits this blob itself on the slot it absorbs.
    Blob {
        /// Deposit capability the item rides — pins the destination mailbox.
        deposit_cap: [u8; 32],
        /// The already envelope-encrypted deposit blob.
        blob: Vec<u8>,
    },
    /// A caller is awaiting this slot and will deposit on its own.
    Slot(oneshot::Sender<SlotPermit>),
}

/// An outbound real item pending absorption into a deposit slot.
#[derive(Debug)]
pub struct PendingItem {
    pub priority: AbsorptionPriority,
    /// Unique identifier for dedup / cancellation (None for typing/dummy).
    pub msg_id: Option<[u8; 16]>,
    pub payload: PendingPayload,
}

/// Per-mailbox pending queues keyed by destination onion (S10 §4 / §6.1).
pub struct PendingQueues {
    queues: Mutex<HashMap<String, VecDeque<PendingItem>>>,
    generation: AtomicU64,
}

impl PendingQueues {
    pub fn new() -> Self {
        Self {
            queues: Mutex::new(HashMap::new()),
            generation: AtomicU64::new(0),
        }
    }

    /// Enqueue an item under its destination mailbox onion.
    pub fn enqueue(&self, mailbox_onion: &str, item: PendingItem) {
        self.queues
            .lock()
            .unwrap()
            .entry(mailbox_onion.to_string())
            .or_default()
            .push_back(item);
    }

    /// Park a caller on the next deposit slot for `mailbox_onion` (S10 §6.2).
    ///
    /// Returns a receiver that resolves to a permit when this item wins a slot.
    /// The caller consumes it with `SlotPermit::begin` immediately before its
    /// own deposit, so the slot's observable effect is one
    /// deposit to that mailbox either way — the scheduler's fixed rate is what
    /// hides the send, not who issues the request.
    ///
    /// Awaiting the receiver is the entire latency cost of unobservability: at
    /// the default rate a first message waits on the order of the deposit
    /// interval. Dropping the receiver cancels the wait; the slot is then spent
    /// on cover instead (see `PendingPayload::Slot` handling in the scheduler).
    pub fn acquire_slot(
        &self,
        mailbox_onion: &str,
        priority: AbsorptionPriority,
        msg_id: Option<[u8; 16]>,
    ) -> oneshot::Receiver<SlotPermit> {
        let (tx, rx) = oneshot::channel();
        self.enqueue(
            mailbox_onion,
            PendingItem {
                priority,
                msg_id,
                payload: PendingPayload::Slot(tx),
            },
        );
        rx
    }

    // Queue insertion and shutdown share this mutex. No sender can enter a
    // generation after its final wake_all.
    fn acquire_running_slot(
        &self,
        running: &AtomicBool,
        onion: &str,
        priority: AbsorptionPriority,
        msg_id: Option<[u8; 16]>,
    ) -> oneshot::Receiver<SlotPermit> {
        let (tx, rx) = oneshot::channel();
        let mut queues = self.queues.lock().unwrap();
        if running.load(Ordering::SeqCst) {
            queues
                .entry(onion.to_owned())
                .or_default()
                .push_back(PendingItem {
                    priority,
                    msg_id,
                    payload: PendingPayload::Slot(tx),
                });
        }
        rx
    }

    pub(crate) fn is_generation(&self, generation: u64) -> bool {
        self.generation.load(Ordering::SeqCst) == generation
    }

    pub(crate) fn begin_run(&self, running: &AtomicBool) -> u64 {
        let _queues = self.queues.lock().unwrap();
        let generation = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
        running.store(true, Ordering::SeqCst);
        generation
    }

    pub(crate) fn end_run(&self, running: &AtomicBool, generation: Option<u64>) {
        let mut queues = self.queues.lock().unwrap();
        if generation.is_none_or(|g| g == self.generation.load(Ordering::SeqCst)) {
            running.store(false, Ordering::SeqCst);
            queues.clear();
        }
    }

    /// Onions that currently have pending work (S10 §6.1 slot service picks
    /// uniformly among these).
    pub fn nonempty_onions(&self) -> Vec<String> {
        self.queues
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, q)| !q.is_empty())
            .map(|(onion, _)| onion.clone())
            .collect()
    }

    /// Pop the highest-priority item for one mailbox — lowest `tier()`,
    /// FIFO within a tier (the FIRST enqueued item of the best tier wins).
    pub fn pop_highest(&self, mailbox_onion: &str) -> Option<PendingItem> {
        let mut queues = self.queues.lock().unwrap();
        let queue = queues.get_mut(mailbox_onion)?;
        // ponytail: O(n) scan per slot — queues are small (unsent backlog of
        // one mailbox); a BinaryHeap loses FIFO-within-tier for free.
        let best = queue
            .iter()
            .enumerate()
            .min_by_key(|(idx, item)| (item.priority.tier(), *idx))
            .map(|(idx, _)| idx)?;
        let item = queue.remove(best);
        if queue.is_empty() {
            queues.remove(mailbox_onion);
        }
        item
    }

    /// Drop every queued item, releasing all parked senders.
    ///
    /// Dropping a `Slot` sender makes its receiver resolve to `Err`, which the
    /// send path reads as "no scheduler" and answers by depositing immediately.
    /// That is the correct degraded behaviour: cover has stopped, so there are
    /// no slots left to hide in, and a message must never outlive the scheduler
    /// that was supposed to release it.
    pub fn wake_all(&self) {
        self.queues.lock().unwrap().clear();
    }

    /// Total pending items across all mailboxes.
    pub fn len(&self) -> usize {
        self.queues.lock().unwrap().values().map(|q| q.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.queues.lock().unwrap().values().all(|q| q.is_empty())
    }
}

impl Default for PendingQueues {
    fn default() -> Self {
        Self::new()
    }
}

/// The reason attached to the permit returned by `SlotSource::await_slot`.
///
/// Only `Granted` can hide a deposit in the cover rate, if consumed before expiry. The
/// others are all "deposit now", and they are distinguished rather than
/// collapsed into a bool so the send path can log which one happened: a
/// `SchedulerStopped` in a build that believes cover is running is a real
/// unobservability regression, and it is invisible if it looks like a bypass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotGrant {
    /// A deposit slot was granted; this send absorbs it.
    Granted,
    /// Responsive delivery mode is on (S10 §14) — the user opted out of slot
    /// pacing.
    Bypassed,
    /// Cover traffic is not running, so there are no slots to wait for.
    SchedulerIdle,
    /// The scheduler stopped while this sender was parked.
    SchedulerStopped,
}

impl SlotGrant {
    /// Whether the deposit rate actually hid this send.
    pub fn was_paced(self) -> bool {
        self == Self::Granted
    }
}

/// Send-path handle onto the scheduler's deposit slots (S10 §6.2).
///
/// Held by `MessagingService`; the deposit itself stays on the send path, so
/// this hands over timing and nothing else.
pub struct SlotSource {
    queues: Arc<PendingQueues>,
    /// The scheduler's own run flag, shared. Checked before parking so a send
    /// issued while cover is stopped goes out immediately instead of waiting
    /// for a slot that will never come.
    running: Arc<AtomicBool>,
    /// Responsive-mode opt-out (S10 §14). Runtime-toggleable (an `AtomicBool`, not a
    /// constructor argument) because it is a user setting that must take
    /// effect on the next send without rebuilding the messaging service.
    bypass: AtomicBool,
    /// Opens an S10 §8.1 Speed-Priority boost window on real user activity.
    ///
    /// A hook rather than the `BoostState` itself so this type does not have to
    /// know about the scheduler's internals or hold a reference back to the
    /// scheduler that owns it (which would be a cycle). `None` in tests and for
    /// embedders with no scheduler — the boost is an optimisation, never a
    /// correctness requirement.
    boost: Option<Arc<dyn Fn() + Send + Sync>>,
}

impl SlotSource {
    pub fn new(queues: Arc<PendingQueues>, running: Arc<AtomicBool>) -> Self {
        Self {
            queues,
            running,
            bypass: AtomicBool::new(false),
            boost: None,
        }
    }

    /// As [`Self::new`], plus the S10 §8.1 boost hook fired when real user content
    /// parks on a slot.
    pub fn with_boost(
        queues: Arc<PendingQueues>,
        running: Arc<AtomicBool>,
        boost: Arc<dyn Fn() + Send + Sync>,
    ) -> Self {
        Self {
            boost: Some(boost),
            ..Self::new(queues, running)
        }
    }

    /// Turn Responsive mode (S10 §14) on/off. On = deposit immediately,
    /// revealing send timing.
    pub fn set_bypass(&self, on: bool) {
        self.bypass.store(on, Ordering::SeqCst);
    }

    pub fn bypass(&self) -> bool {
        self.bypass.load(Ordering::SeqCst)
    }

    /// Park until this send wins a deposit slot for `mailbox_onion`.
    ///
    /// Never fails and never hangs past the scheduler's life: every non-granted
    /// outcome means "deposit now". Delivery is not allowed to depend on the
    /// cover subsystem being healthy.
    /// Call `SlotPermit::begin` immediately before the network attempt. A false
    /// result means the lease expired and the caller must await another slot.
    pub async fn await_slot(
        &self,
        mailbox_onion: &str,
        priority: AbsorptionPriority,
        msg_id: Option<[u8; 16]>,
    ) -> SlotPermit {
        if self.bypass() {
            return SlotPermit::unpaced(SlotGrant::Bypassed);
        }
        if !self.running.load(Ordering::SeqCst) {
            return SlotPermit::unpaced(SlotGrant::SchedulerIdle);
        }
        // S10 §8.1: real user content opens a fixed 120 s rate-boost window if
        // none is open, so the queue drains ~SPEED_BOOST_FACTOR× faster (Speed
        // Priority only; the hook itself enforces the mode). Tier 1 only. It
        // never extends an open window. The scheduler opens decoy windows
        // through the same path, so a rate change is evidence of *a boost*,
        // not proof of activity.
        if priority == AbsorptionPriority::RealMessage {
            if let Some(boost) = &self.boost {
                boost();
            }
        }
        match self
            .queues
            .acquire_running_slot(&self.running, mailbox_onion, priority, msg_id)
            .await
        {
            Ok(permit) => permit,
            // Sender dropped: `wake_all` on stop, or the loop task unwound.
            Err(_) => SlotPermit::unpaced(SlotGrant::SchedulerStopped),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(priority: AbsorptionPriority, tag: u8) -> PendingItem {
        PendingItem {
            priority,
            msg_id: Some([tag; 16]),
            payload: PendingPayload::Blob {
                deposit_cap: [tag; 32],
                blob: vec![tag],
            },
        }
    }

    /// Tag of a `Blob` item — panics on a `Slot`, which the ordering tests
    /// never enqueue.
    fn tag_of(item: &PendingItem) -> u8 {
        match &item.payload {
            PendingPayload::Blob { blob, .. } => blob[0],
            PendingPayload::Slot(_) => unreachable!("ordering tests enqueue blobs only"),
        }
    }

    // S10 §6.1: pop order is tier order, FIFO within a tier.
    #[test]
    fn priority_ordering_within_one_mailbox() {
        let q = PendingQueues::new();
        q.enqueue("mb", item(AbsorptionPriority::TypingIndicator, 5));
        q.enqueue("mb", item(AbsorptionPriority::Ack, 3));
        q.enqueue("mb", item(AbsorptionPriority::DummySelfDeposit, 7));
        q.enqueue("mb", item(AbsorptionPriority::RealMessage, 1));
        q.enqueue("mb", item(AbsorptionPriority::Control, 6));
        q.enqueue("mb", item(AbsorptionPriority::ReadReceipt, 4));
        q.enqueue("mb", item(AbsorptionPriority::SessionRepairInit, 2));

        let popped: Vec<u8> = std::iter::from_fn(|| q.pop_highest("mb"))
            .map(|i| tag_of(&i))
            .collect();
        assert_eq!(popped, vec![1, 2, 3, 4, 5, 6, 7]);
        assert!(q.is_empty());
    }

    // Tier 2 holds GroupKeyDistribution and SessionRepairInit — FIFO between
    // them, both above Ack (S10 §6.1 lists SessionRepairInit).
    #[test]
    fn tier2_includes_group_key_distribution_fifo() {
        let q = PendingQueues::new();
        q.enqueue("mb", item(AbsorptionPriority::Ack, 30));
        q.enqueue("mb", item(AbsorptionPriority::GroupKeyDistribution, 21));
        q.enqueue("mb", item(AbsorptionPriority::SessionRepairInit, 22));

        assert_eq!(tag_of(&q.pop_highest("mb").unwrap()), 21); // first tier-2 in
        assert_eq!(tag_of(&q.pop_highest("mb").unwrap()), 22);
        assert_eq!(tag_of(&q.pop_highest("mb").unwrap()), 30);
    }

    // S10 §4: absorption state is PER-MAILBOX — work on mailbox A never
    // dequeues from (or suppresses) mailbox B.
    #[test]
    fn queues_are_per_mailbox() {
        let q = PendingQueues::new();
        q.enqueue("a.onion", item(AbsorptionPriority::RealMessage, 1));
        q.enqueue("b.onion", item(AbsorptionPriority::Ack, 2));

        let mut nonempty = q.nonempty_onions();
        nonempty.sort();
        assert_eq!(nonempty, vec!["a.onion".to_string(), "b.onion".to_string()]);

        assert_eq!(tag_of(&q.pop_highest("a.onion").unwrap()), 1);
        assert!(q.pop_highest("a.onion").is_none());
        // b untouched
        assert_eq!(q.nonempty_onions(), vec!["b.onion".to_string()]);
        assert_eq!(tag_of(&q.pop_highest("b.onion").unwrap()), 2);
    }

    // S10 §6.2: a parked sender is woken by the slot it wins, and it is ordered
    // against blob items by the same tier rule — a tier-1 permit beats a
    // tier-3 ACK blob that was enqueued first.
    #[tokio::test]
    async fn slot_permit_is_granted_in_priority_order() {
        let q = PendingQueues::new();
        q.enqueue("mb", item(AbsorptionPriority::Ack, 3));
        let mut rx = q.acquire_slot("mb", AbsorptionPriority::RealMessage, Some([9u8; 16]));

        // Nothing has serviced a slot yet, so the caller is still parked.
        assert!(rx.try_recv().is_err());

        let first = q.pop_highest("mb").unwrap();
        match first.payload {
            PendingPayload::Slot(tx) => tx.send(SlotPermit::unpaced(SlotGrant::Granted)).unwrap(),
            PendingPayload::Blob { .. } => panic!("tier-1 permit must outrank the tier-3 blob"),
        }
        assert!(rx
            .await
            .expect("granted slot wakes the parked sender")
            .begin());

        // The ACK blob is still queued behind it.
        assert_eq!(tag_of(&q.pop_highest("mb").unwrap()), 3);
        assert!(q.is_empty());
    }

    // S10 §6.2: a caller that gave up (receiver dropped) must not silently consume
    // the slot as if it had deposited — `send` fails and the scheduler falls
    // back to cover. Proving the error surfaces is what makes that branch
    // reachable rather than dead defensive code.
    #[test]
    fn abandoned_permit_reports_failure_to_the_slot_service() {
        let q = PendingQueues::new();
        let rx = q.acquire_slot("mb", AbsorptionPriority::RealMessage, None);
        drop(rx);

        let item = q.pop_highest("mb").unwrap();
        match item.payload {
            PendingPayload::Slot(tx) => {
                assert!(tx.send(SlotPermit::unpaced(SlotGrant::Granted)).is_err())
            }
            PendingPayload::Blob { .. } => panic!("expected a slot permit"),
        }
    }

    #[test]
    fn empty_queue_returns_none() {
        let q = PendingQueues::new();
        assert!(q.pop_highest("nowhere").is_none());
        assert!(q.is_empty());
        assert_eq!(q.len(), 0);
        assert!(q.nonempty_onions().is_empty());
    }

    #[test]
    fn burst_mode_default_is_speed() {
        assert_eq!(BurstMode::default(), BurstMode::SpeedPriority);
    }
}
