//! Cover traffic scheduler (S10 §3, §4, §6, §8).
//!
//! Generates Poisson-scheduled cover polls and deposits. In Timing privacy
//! mode, real outbound items absorb deposit slots through the per-mailbox
//! pending queues (S10 §6.1) — the single normative absorption model — so the
//! deposit-slot rate is independent of user activity outside boost windows.
//! Speed-Priority bursts open a bounded rate boost that is also fired randomly
//! as a decoy (S10 §8.1), so a rate change is evidence of *a boost*, not proof
//! of activity.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use najwa_protocol::mailbox::client::MailboxClient;
use najwa_protocol::mailbox::types::MailboxConfig;
use najwa_protocol::message::{envelope_encrypt, ENVELOPE_OVERHEAD};
use rand::seq::SliceRandom;
use rand::Rng;

use crate::cover::absorption::{
    AbsorptionPriority, BurstMode, PendingItem, PendingPayload, PendingQueues, SlotSource,
};
use crate::cover::config::{
    CoverTrafficConfig, COVER_DEPOSIT_SIZES, DECOY_BOOST_MEAN_INTERVAL_SECS,
    MIN_JITTERED_INTERVAL_MS, SPEED_BOOST_FACTOR, SPEED_BOOST_WINDOW_SECS,
};
use crate::cover::SlotPermit;

/// Cover-only mailbox coordinates retained by the scheduler (S10 §5, §11).
///
/// This snapshot deliberately contains no real fetch/deposit capability and no
/// storage handle. It is therefore safe to keep in memory while UI lock closes
/// the SQLCipher database and zeroizes all message/identity keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverMailboxSnapshot {
    pub onion_address: String,
    pub cover_deposit_capability: [u8; 32],
    pub cover_fetch_capability: [u8; 32],
    pub cover_envelope_secret: [u8; 32],
    /// Deposit capabilities of this mailbox's active dummy queues (S10 §5.1).
    /// A cover deposit picks its target uniformly from these and the cover pair.
    pub dummy_deposit_capabilities: Vec<[u8; 32]>,
}

impl CoverMailboxSnapshot {
    fn mailbox_config(&self) -> MailboxConfig {
        // MailboxClient requires a MailboxConfig, but cover operations consume
        // only the onion plus the explicit cover capability. Populate its
        // required fields exclusively from cover-only material so this
        // conversion cannot accidentally retain real mailbox credentials.
        MailboxConfig {
            onion_address: self.onion_address.clone(),
            fetch_capability: self.cover_fetch_capability,
            deposit_capability: self.cover_deposit_capability,
            envelope_secret: self.cover_envelope_secret,
            cover_deposit_capability: Some(self.cover_deposit_capability),
            cover_fetch_capability: Some(self.cover_fetch_capability),
            cover_envelope_secret: Some(self.cover_envelope_secret),
        }
    }
}

/// Cover traffic scheduler (S10 §4).
pub struct CoverTrafficScheduler {
    config: CoverTrafficConfig,
    running: Arc<AtomicBool>,
    stats: Arc<CoverStats>,
    /// Per-mailbox pending real items (§6.1) — THE absorption state.
    pending: Arc<PendingQueues>,
    /// Speed-Priority / decoy boost window (§8.1).
    boost: Arc<BoostState>,
    /// Refreshable cover-only coordinates. Safe to retain across UI lock.
    mailboxes: Arc<RwLock<Vec<CoverMailboxSnapshot>>>,
    /// Send-path handle onto this scheduler's slots (§6.2). Built here because
    /// this is where the queues and the run flag are born; handed to the
    /// messaging service so outbound deposits can absorb slots.
    slot_source: Arc<SlotSource>,
    /// Handle to the spawned task (if running).
    handle: Option<tokio::task::JoinHandle<()>>,
}

/// Bandwidth/battery usage monitoring counters (S10 §10).
///
/// Internal-only; MUST NOT be exposed to any server or external party.
#[derive(Debug)]
pub struct CoverStats {
    /// Total cover polls performed.
    pub cover_polls: AtomicU64,
    /// Total cover deposits performed.
    pub cover_deposits: AtomicU64,
    /// Total bytes sent as cover deposits.
    pub cover_bytes_sent: AtomicU64,
    /// Slots serviced by tier 1–6 pending items (§6.1).
    pub real_sends_absorbed: AtomicU64,
    /// Tier 7 dummy-capability self-deposits. Never incremented by the
    /// application, which queues none (S10 §10).
    pub dummy_self_deposits: AtomicU64,
    /// Boost windows opened — real-triggered + decoy combined; MUST NOT be
    /// split in any export (§10).
    pub boost_windows: AtomicU64,
    /// Receive-maintenance deposits, kept separate from cover counters. Never
    /// incremented by the application (S10 §10).
    pub receive_maintenance_deposits: AtomicU64,
}

impl CoverStats {
    pub fn new() -> Self {
        Self {
            cover_polls: AtomicU64::new(0),
            cover_deposits: AtomicU64::new(0),
            cover_bytes_sent: AtomicU64::new(0),
            real_sends_absorbed: AtomicU64::new(0),
            dummy_self_deposits: AtomicU64::new(0),
            boost_windows: AtomicU64::new(0),
            receive_maintenance_deposits: AtomicU64::new(0),
        }
    }

    /// Snapshot the current stats for display/logging.
    pub fn snapshot(&self) -> CoverStatsSnapshot {
        CoverStatsSnapshot {
            cover_polls: self.cover_polls.load(Ordering::Relaxed),
            cover_deposits: self.cover_deposits.load(Ordering::Relaxed),
            cover_bytes_sent: self.cover_bytes_sent.load(Ordering::Relaxed),
            real_sends_absorbed: self.real_sends_absorbed.load(Ordering::Relaxed),
            dummy_self_deposits: self.dummy_self_deposits.load(Ordering::Relaxed),
            boost_windows: self.boost_windows.load(Ordering::Relaxed),
            receive_maintenance_deposits: self.receive_maintenance_deposits.load(Ordering::Relaxed),
        }
    }
}

impl Default for CoverStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Point-in-time snapshot of cover traffic statistics (S10 §10).
#[derive(Debug, Clone)]
pub struct CoverStatsSnapshot {
    pub cover_polls: u64,
    pub cover_deposits: u64,
    pub cover_bytes_sent: u64,
    pub real_sends_absorbed: u64,
    pub dummy_self_deposits: u64,
    pub boost_windows: u64,
    pub receive_maintenance_deposits: u64,
}

/// S10 §8.1 boost window state. Real-triggered and decoy boosts flow through
/// the SAME `open_window` path, and every window lasts exactly
/// `SPEED_BOOST_WINDOW_SECS` from its opening: a trigger inside an open window
/// does nothing, so a long real backlog cannot stretch a window past what a
/// decoy produces.
pub struct BoostState {
    until: Mutex<Option<Instant>>,
}

impl BoostState {
    fn new() -> Self {
        Self {
            until: Mutex::new(None),
        }
    }

    /// Open a fixed `SPEED_BOOST_WINDOW_SECS` window unless one is open; never
    /// extends. Returns true when this call opened a NEW window — callers
    /// count `boost_windows` only then.
    fn open_window(&self) -> bool {
        let mut until = self.until.lock().unwrap();
        if until.is_some_and(|t| Instant::now() < t) {
            return false;
        }
        *until = Some(Instant::now() + Duration::from_secs(SPEED_BOOST_WINDOW_SECS));
        true
    }

    fn is_active(&self) -> bool {
        self.until
            .lock()
            .unwrap()
            .map(|t| Instant::now() < t)
            .unwrap_or(false)
    }
}

impl CoverTrafficScheduler {
    /// Create a new scheduler (not yet running).
    pub fn new(config: CoverTrafficConfig) -> Self {
        let running = Arc::new(AtomicBool::new(false));
        let pending = Arc::new(PendingQueues::new());
        let stats = Arc::new(CoverStats::new());
        let boost = Arc::new(BoostState::new());

        // §8.1 boost hook handed to the send path. It captures only the boost
        // state, the stats and the mode — NOT the scheduler — because the
        // scheduler owns the `SlotSource` and capturing it would be a cycle.
        let hook_boost = Arc::clone(&boost);
        let hook_stats = Arc::clone(&stats);
        let burst_mode = config.burst_mode;
        let boost_hook: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
            if burst_mode == BurstMode::SpeedPriority && hook_boost.open_window() {
                hook_stats.boost_windows.fetch_add(1, Ordering::Relaxed);
            }
        });

        Self {
            config,
            slot_source: Arc::new(SlotSource::with_boost(
                Arc::clone(&pending),
                Arc::clone(&running),
                boost_hook,
            )),
            running,
            stats,
            pending,
            boost,
            mailboxes: Arc::new(RwLock::new(Vec::new())),
            handle: None,
        }
    }

    /// Handle the send path uses to park on deposit slots (S10 §6.2).
    ///
    /// Stable for the scheduler's whole life — it survives stop/start, so a
    /// messaging service built while cover is down still absorbs slots once
    /// cover comes back, and the fast-mode flag on it survives both.
    pub fn slot_source(&self) -> Arc<SlotSource> {
        Arc::clone(&self.slot_source)
    }

    /// Whether the scheduler is currently running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Get a reference to the live stats.
    pub fn stats(&self) -> &Arc<CoverStats> {
        &self.stats
    }

    /// Get a snapshot of the current stats (S10 §10).
    pub fn snapshot(&self) -> CoverStatsSnapshot {
        self.stats.snapshot()
    }

    /// Replace the scheduler's point-in-time cover-only mailbox view.
    ///
    /// Callers refresh this after unlock and whenever mailbox configuration or
    /// registration state changes. No SQLCipher handle crosses this boundary.
    pub fn replace_mailboxes(&self, mailboxes: Vec<CoverMailboxSnapshot>) {
        let count = mailboxes.len();
        *self.mailboxes.write().unwrap() = mailboxes;
        if count == 0 {
            tracing::warn!("cover traffic paused: no registered eligible cover mailbox");
        } else {
            tracing::info!(count, "cover mailbox snapshot refreshed");
        }
    }

    // -- Blob enqueue API ---------------------------------------------------
    //
    // Library helpers that queue an already-enveloped blob for the scheduler
    // to deposit itself. The application queues no blobs: its real sends wait
    // on `SlotSource::await_slot` and deposit on their own (S10 §6.2). Each
    // item is enqueued under its destination mailbox onion, pinned by the
    // deposit capability it will ride.

    /// Tier 2: `SessionRepairInit (0x31)`.
    pub fn queue_session_repair(
        &self,
        mailbox_onion: &str,
        deposit_cap: [u8; 32],
        blob: Vec<u8>,
        msg_id: [u8; 16],
    ) {
        self.enqueue(
            mailbox_onion,
            AbsorptionPriority::SessionRepairInit,
            deposit_cap,
            blob,
            Some(msg_id),
        );
    }

    /// Tier 2: group-key distribution.
    pub fn queue_sender_key_distribution(
        &self,
        mailbox_onion: &str,
        deposit_cap: [u8; 32],
        blob: Vec<u8>,
        msg_id: [u8; 16],
    ) {
        self.enqueue(
            mailbox_onion,
            AbsorptionPriority::GroupKeyDistribution,
            deposit_cap,
            blob,
            Some(msg_id),
        );
    }

    /// Tier 3: delivery ACK.
    pub fn queue_ack(
        &self,
        mailbox_onion: &str,
        deposit_cap: [u8; 32],
        blob: Vec<u8>,
        msg_id: [u8; 16],
    ) {
        self.enqueue(
            mailbox_onion,
            AbsorptionPriority::Ack,
            deposit_cap,
            blob,
            Some(msg_id),
        );
    }

    /// Tier 4: read receipt.
    pub fn queue_read_receipt(
        &self,
        mailbox_onion: &str,
        deposit_cap: [u8; 32],
        blob: Vec<u8>,
        msg_id: [u8; 16],
    ) {
        self.enqueue(
            mailbox_onion,
            AbsorptionPriority::ReadReceipt,
            deposit_cap,
            blob,
            Some(msg_id),
        );
    }

    /// Tier 5: typing indicator.
    pub fn queue_typing_indicator(
        &self,
        mailbox_onion: &str,
        deposit_cap: [u8; 32],
        blob: Vec<u8>,
    ) {
        self.enqueue(
            mailbox_onion,
            AbsorptionPriority::TypingIndicator,
            deposit_cap,
            blob,
            None,
        );
    }

    /// Tier 6: other control subtypes.
    pub fn queue_control(
        &self,
        mailbox_onion: &str,
        deposit_cap: [u8; 32],
        blob: Vec<u8>,
        msg_id: Option<[u8; 16]>,
    ) {
        self.enqueue(
            mailbox_onion,
            AbsorptionPriority::Control,
            deposit_cap,
            blob,
            msg_id,
        );
    }

    /// Tier 7: dummy-capability self-deposit.
    pub fn queue_dummy_self_deposit(
        &self,
        mailbox_onion: &str,
        deposit_cap: [u8; 32],
        blob: Vec<u8>,
    ) {
        self.enqueue(
            mailbox_onion,
            AbsorptionPriority::DummySelfDeposit,
            deposit_cap,
            blob,
            None,
        );
    }

    fn enqueue(
        &self,
        mailbox_onion: &str,
        priority: AbsorptionPriority,
        deposit_cap: [u8; 32],
        blob: Vec<u8>,
        msg_id: Option<[u8; 16]>,
    ) {
        self.pending.enqueue(
            mailbox_onion,
            PendingItem {
                priority,
                msg_id,
                payload: PendingPayload::Blob { deposit_cap, blob },
            },
        );
    }

    /// Per-mailbox pending queues, for the send path to park on a slot (§6.2).
    ///
    /// Handing out the queues rather than a `&self` send method is deliberate:
    /// the send path lives in `MessagingService` and must keep ownership of the
    /// deposit, its durable retry row, and its error handling. All it needs
    /// from the scheduler is the timing.
    pub fn pending_queues(&self) -> Arc<PendingQueues> {
        Arc::clone(&self.pending)
    }

    /// Start the cover traffic loop (S10 §4.1).
    pub fn start<M>(&mut self, mailbox_client: Arc<M>)
    where
        M: MailboxClient + 'static,
    {
        if !self.config.enabled {
            tracing::info!("cover traffic disabled, not starting");
            return;
        }

        if self.is_running() {
            tracing::warn!("cover traffic scheduler already running");
            return;
        }

        let generation = self.pending.begin_run(&self.running);

        let ctx = CoverLoopContext {
            generation,
            config: self.config.clone(),
            running: Arc::clone(&self.running),
            stats: Arc::clone(&self.stats),
            pending: Arc::clone(&self.pending),
            boost: Arc::clone(&self.boost),
            mailboxes: Arc::clone(&self.mailboxes),
        };

        let handle = tokio::spawn(async move {
            // Release parked senders however this task ends — normal exit,
            // `stop()`'s abort, or an unwinding panic. Without it a sender that
            // won no slot before the loop died would wait forever and its
            // message would never be deposited, turning a cover-subsystem fault
            // into silent message loss on the user's send path.
            let _release = LoopExitGuard {
                generation,
                running: Arc::clone(&ctx.running),
                pending: Arc::clone(&ctx.pending),
            };
            run_cover_loop(ctx, mailbox_client).await;
        });

        self.handle = Some(handle);
        tracing::info!(
            level = ?self.config.level,
            poll_interval = ?self.config.poll_interval,
            deposit_interval = ?self.config.deposit_interval,
            burst_mode = ?self.config.burst_mode,
            "cover traffic scheduler started"
        );
    }

    /// Stop the cover traffic loop.
    ///
    /// S10 §11: UI lock MUST NOT call this — cover continues under lock.
    /// Stop only on process exit, profile erase or a bridge-settings change.
    pub fn stop(&mut self) {
        self.pending.end_run(&self.running, None);
        if let Some(handle) = &self.handle {
            handle.abort();
        }
        tracing::info!("cover traffic scheduler stopped");
    }

    /// Wait for the background task to finish after `stop()`.
    pub async fn join(mut self) {
        self.stop();
        if let Some(handle) = self.handle.take() {
            let _ = handle.await;
        }
    }
}

impl Drop for CoverTrafficScheduler {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Sample a cover-event inter-arrival interval (S10 §3).
///
/// Poisson process: an exponential (memoryless) inter-arrival `-mean·ln(u)`, then
/// a secondary ±`jitter_percent`% perturbation, floored at `MIN_JITTERED_INTERVAL_MS`.
/// There is deliberately NO upper cutoff — the exponential tail is unbounded, which
/// is what makes cover a genuine Poisson process rather than the bounded point mass
/// §3 forbids. Mirrors the spec's `jittered_duration(mean_secs, jitter_percent)`.
pub fn jittered_duration(mean: Duration, jitter_percent: u32) -> Duration {
    // u in (0,1]: `gen::<f64>()` is [0,1), so `1.0 - x` is (0,1] and ln(u) is
    // always finite (never ln(0)).
    let u = 1.0 - rand::thread_rng().gen::<f64>();
    let mut interval_ms = -(mean.as_millis() as f64) * u.ln();
    // Secondary ±jitter% (guarded so a zero range never forms an empty gen_range).
    let jitter_range = interval_ms * (jitter_percent as f64 / 100.0);
    if jitter_range > 0.0 {
        interval_ms += rand::thread_rng().gen_range(-jitter_range..jitter_range);
    }
    let floored = interval_ms.max(MIN_JITTERED_INTERVAL_MS as f64);
    Duration::from_millis(floored as u64)
}

/// Clears the run flag and releases every parked sender when the cover loop
/// task ends for any reason (see the comment at the `tokio::spawn` site).
struct LoopExitGuard {
    generation: u64,
    running: Arc<AtomicBool>,
    pending: Arc<PendingQueues>,
}

impl Drop for LoopExitGuard {
    fn drop(&mut self) {
        self.pending.end_run(&self.running, Some(self.generation));
    }
}

/// Shared state for the cover traffic loop.
#[derive(Clone)]
struct CoverLoopContext {
    generation: u64,
    config: CoverTrafficConfig,
    running: Arc<AtomicBool>,
    stats: Arc<CoverStats>,
    pending: Arc<PendingQueues>,
    boost: Arc<BoostState>,
    mailboxes: Arc<RwLock<Vec<CoverMailboxSnapshot>>>,
}

/// Deposit-interval mean, divided by `SPEED_BOOST_FACTOR` inside a §8.1
/// boost window (Speed Priority only — Privacy Priority never boosts).
fn effective_deposit_interval(config: &CoverTrafficConfig, boost: &BoostState) -> Duration {
    if config.burst_mode == BurstMode::SpeedPriority && boost.is_active() {
        config.deposit_interval / SPEED_BOOST_FACTOR
    } else {
        config.deposit_interval
    }
}

/// Independent timers continue while network operations are in flight. Jobs
/// are bounded by the transport deadline and cancelled with their generation.
async fn run_cover_loop<M: MailboxClient + 'static>(ctx: CoverLoopContext, mailbox_client: Arc<M>) {
    use tokio::time::{sleep, timeout, Instant as Deadline};
    let poll = sleep(jittered_duration(
        ctx.config.poll_interval,
        ctx.config.jitter_percent,
    ));
    let deposit = sleep(jittered_duration(
        effective_deposit_interval(&ctx.config, &ctx.boost),
        ctx.config.jitter_percent,
    ));
    let decoy_delay = || {
        if ctx.config.burst_mode == BurstMode::SpeedPriority {
            jittered_duration(
                Duration::from_secs(DECOY_BOOST_MEAN_INTERVAL_SECS),
                ctx.config.jitter_percent,
            )
        } else {
            Duration::from_secs(u32::MAX as u64)
        }
    };
    let decoy = sleep(decoy_delay());
    tokio::pin!(poll, deposit, decoy);
    let mut jobs = tokio::task::JoinSet::new();
    while ctx.running.load(Ordering::SeqCst) && ctx.pending.is_generation(ctx.generation) {
        let is_deposit = tokio::select! {
            _ = &mut poll => {
                poll.as_mut().reset(Deadline::now() + jittered_duration(ctx.config.poll_interval, ctx.config.jitter_percent));
                false
            }
            _ = &mut deposit => {
                deposit.as_mut().reset(Deadline::now() + jittered_duration(effective_deposit_interval(&ctx.config, &ctx.boost), ctx.config.jitter_percent));
                true
            }
            _ = &mut decoy => {
                // S10 §8.1: like a real trigger, a decoy leaves the pending
                // deposit timer alone; the boosted mean applies from its next
                // reset, so real and decoy windows start the same way.
                if ctx.boost.open_window() { ctx.stats.boost_windows.fetch_add(1, Ordering::Relaxed); }
                decoy.as_mut().reset(Deadline::now() + decoy_delay());
                continue;
            }
            _ = jobs.join_next(), if !jobs.is_empty() => continue,
        };
        let ctx = ctx.clone();
        let client = mailbox_client.clone();
        jobs.spawn(async move {
            let operation = async {
                if !ctx.pending.is_generation(ctx.generation) {
                    return;
                }
                if is_deposit {
                    service_deposit_slot(&ctx, &*client).await;
                } else {
                    do_cover_poll(&ctx.mailboxes, &*client, &ctx.stats).await;
                }
            };
            if timeout(Duration::from_secs(120), operation).await.is_err() {
                tracing::warn!("cover operation timed out");
            }
        });
    }
}

/// Service one deposit slot (S10 §6.1 — THE absorption algorithm).
///
/// Uniform pick among mailboxes with pending work → highest-priority item
/// absorbs the slot; empty map → pure cover deposit.
async fn service_deposit_slot<M: MailboxClient>(ctx: &CoverLoopContext, mailbox_client: &M) {
    if !ctx.pending.is_generation(ctx.generation) {
        return;
    }
    let nonempty = ctx.pending.nonempty_onions();
    if nonempty.is_empty() {
        do_cover_deposit(&ctx.mailboxes, mailbox_client, &ctx.stats).await;
        return;
    }

    let onion = &nonempty[rand::thread_rng().gen_range(0..nonempty.len())];
    let Some(item) = ctx.pending.pop_highest(onion) else {
        // Raced with another consumer; treat as an empty slot.
        do_cover_deposit(&ctx.mailboxes, mailbox_client, &ctx.stats).await;
        return;
    };

    let (deposit_cap, blob) = match item.payload {
        PendingPayload::Blob { deposit_cap, blob } => (deposit_cap, blob),
        // §6.2: a parked sender wins the slot — wake it and let it deposit.
        // No cover-snapshot lookup happens on this branch on purpose: a real
        // destination the scheduler holds no cover capability for must still
        // be sendable, and the send path resolves its own mailbox anyway.
        PendingPayload::Slot(waiter) => {
            let (permit, state, completion) = SlotPermit::tracked();
            let sent = waiter.send(permit).is_ok();
            if sent {
                // A dropped or stalled grantee cannot create silence. The
                // atomic lease arbitrates expiry vs begin, preventing doubles.
                let _ = tokio::time::timeout(Duration::from_secs(1), completion).await;
            }
            if state
                .compare_exchange(0, 2, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                do_cover_deposit(&ctx.mailboxes, mailbox_client, &ctx.stats).await;
                return;
            }
            ctx.stats
                .real_sends_absorbed
                .fetch_add(1, Ordering::Relaxed);
            tracing::trace!(mailbox = %onion, tier = item.priority.tier(), "slot granted to parked sender");
            return;
        }
    };

    // Resolve from the cover-only snapshot. A destination disabled after
    // enqueue disappears on refresh; the send path's durable retry owns
    // redelivery of real messages.
    let mb = ctx
        .mailboxes
        .read()
        .unwrap()
        .iter()
        .find(|m| &m.onion_address == onion)
        .cloned();
    let Some(mb) = mb else {
        tracing::warn!(mailbox = %onion, "slot service: destination no longer eligible, dropping item");
        do_cover_deposit(&ctx.mailboxes, mailbox_client, &ctx.stats).await;
        return;
    };
    let config = mb.mailbox_config();

    if let Err(error) = mailbox_client
        .deposit_once(&config, &deposit_cap, &blob, None)
        .await
    {
        tracing::warn!(mailbox = %onion, %error, "pending slot deposit failed");
        return;
    }
    match item.priority.tier() {
        7 => ctx
            .stats
            .dummy_self_deposits
            .fetch_add(1, Ordering::Relaxed),
        _ => ctx
            .stats
            .real_sends_absorbed
            .fetch_add(1, Ordering::Relaxed),
    };
    tracing::trace!(mailbox = %onion, tier = item.priority.tier(), "pending item absorbed deposit slot");
}

/// Perform a cover poll (S10 §4.2): fetch on the dedicated cover fetch cap of
/// a random eligible mailbox, over a per-mailbox CoverTraffic circuit.
async fn do_cover_poll<M: MailboxClient>(
    mailboxes: &RwLock<Vec<CoverMailboxSnapshot>>,
    mailbox_client: &M,
    stats: &CoverStats,
) {
    let mb = mailboxes
        .read()
        .unwrap()
        .choose(&mut rand::thread_rng())
        .cloned();
    let Some(mb) = mb else {
        tracing::trace!("cover poll: no mailbox with a dedicated cover fetch cap");
        return;
    };
    let config = mb.mailbox_config();
    let messages = match mailbox_client
        .fetch_cover(&config, &mb.cover_fetch_capability, 100)
        .await
    {
        Ok(messages) => messages,
        Err(error) => {
            tracing::warn!(%error, "cover poll failed");
            return;
        }
    };
    let ids: Vec<_> = messages.into_iter().map(|m| m.id).collect();
    if !ids.is_empty() {
        if let Err(error) = mailbox_client
            .acknowledge_cover(&config, &mb.cover_fetch_capability, &ids)
            .await
        {
            tracing::warn!(%error, "cover acknowledgement deferred until next poll");
        }
    }
    stats.cover_polls.fetch_add(1, Ordering::Relaxed);
    tracing::trace!(mailbox = %mb.onion_address, "cover poll executed");
}

/// Build a cover blob per S10 §2.3: envelope-wrapped CSPRNG inner of
/// `bucket − ENVELOPE_OVERHEAD` bytes — the final blob size equals the bucket
/// exactly, byte-indistinguishable from a real deposit to a keyless observer.
fn build_cover_blob(
    cover_envelope_secret: &[u8; 32],
    cover_deposit_cap: &[u8; 32],
) -> Option<Vec<u8>> {
    let bucket = *COVER_DEPOSIT_SIZES.choose(&mut rand::thread_rng())?;
    let inner: Vec<u8> = (0..bucket - ENVELOPE_OVERHEAD)
        .map(|_| rand::thread_rng().gen())
        .collect();
    match envelope_encrypt(cover_envelope_secret, cover_deposit_cap, &inner) {
        Ok(blob) => {
            debug_assert_eq!(blob.len(), bucket);
            Some(blob)
        }
        Err(e) => {
            tracing::warn!(error = %e, "cover blob envelope encryption failed");
            None
        }
    }
}

/// Perform a cover deposit (S10 §4.3): the "nothing pending" outcome of §6.1.
async fn do_cover_deposit<M: MailboxClient>(
    mailboxes: &RwLock<Vec<CoverMailboxSnapshot>>,
    mailbox_client: &M,
    stats: &CoverStats,
) {
    let mb = mailboxes
        .read()
        .unwrap()
        .choose(&mut rand::thread_rng())
        .cloned();
    let Some(mb) = mb else {
        tracing::trace!("cover deposit: no mailbox with dedicated cover cap + envelope secret");
        return;
    };

    // S10 §5.1: the modelled self-deposits that give dummy queues a contact's
    // deposit profile. The cover envelope secret keys every target.
    let target = *std::iter::once(&mb.cover_deposit_capability)
        .chain(&mb.dummy_deposit_capabilities)
        .collect::<Vec<_>>()
        .choose(&mut rand::thread_rng())
        .expect("the cover pair is always a target");
    let Some(blob) = build_cover_blob(&mb.cover_envelope_secret, target) else {
        return;
    };

    let config = mb.mailbox_config();
    if let Err(error) = mailbox_client
        .deposit_cover(&config, target, &blob)
        .await
    {
        tracing::warn!(mailbox = %mb.onion_address, %error, "cover deposit failed");
        return;
    }
    stats.cover_deposits.fetch_add(1, Ordering::Relaxed);
    stats
        .cover_bytes_sent
        .fetch_add(blob.len() as u64, Ordering::Relaxed);
    tracing::trace!(mailbox = %mb.onion_address, size = blob.len(), "cover deposit executed");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cover::absorption::SlotGrant;
    use crate::cover::config::CoverLevel;
    use najwa_protocol::mailbox::error::{MailboxError, Result as MailboxResult};
    use najwa_protocol::mailbox::types::{
        CapabilitySettings, CapabilityStatus, DepositResult, MailboxMessage, PowChallenge,
        PowSolution, PrekeyBundle,
    };

    struct RecordingMailbox {
        deposits: Mutex<Vec<([u8; 32], Vec<u8>)>>,
        fail: Mutex<bool>,
    }

    #[async_trait::async_trait]
    impl MailboxClient for RecordingMailbox {
        async fn register_capability(
            &self,
            _: &MailboxConfig,
            _: &CapabilitySettings,
            _: Option<&PowSolution>,
        ) -> MailboxResult<()> {
            Ok(())
        }

        async fn get_challenge(
            &self,
            _: &MailboxConfig,
            _: &[u8; 8],
        ) -> MailboxResult<PowChallenge> {
            Err(MailboxError::CapabilityNotFound)
        }

        async fn deposit(
            &self,
            _: &MailboxConfig,
            deposit_cap: &[u8; 32],
            blob: &[u8],
            _: Option<&PowSolution>,
        ) -> MailboxResult<DepositResult> {
            if *self.fail.lock().unwrap() {
                return Err(MailboxError::CapabilityNotFound);
            }
            self.deposits
                .lock()
                .unwrap()
                .push((*deposit_cap, blob.to_vec()));
            Ok(DepositResult {
                accepted: true,
                message_id: Some("cover-test".into()),
            })
        }

        async fn fetch(
            &self,
            _: &MailboxConfig,
            _: &[u8; 32],
            _: Option<&str>,
            _: u32,
        ) -> MailboxResult<Vec<MailboxMessage>> {
            Ok(Vec::new())
        }

        async fn upload_prekey_bundle(
            &self,
            _: &MailboxConfig,
            _: &[u8; 32],
            _: &PrekeyBundle,
        ) -> MailboxResult<()> {
            Ok(())
        }

        async fn fetch_prekey_bundle(
            &self,
            _: &MailboxConfig,
            _: &[u8; 32],
            _: &[u8; 32],
        ) -> MailboxResult<PrekeyBundle> {
            Err(MailboxError::CapabilityNotFound)
        }

        async fn get_status(
            &self,
            _: &MailboxConfig,
            _: &[u8; 32],
        ) -> MailboxResult<CapabilityStatus> {
            Err(MailboxError::CapabilityNotFound)
        }

        async fn deactivate_capability(
            &self,
            _: &MailboxConfig,
            _: &[u8; 32],
        ) -> MailboxResult<()> {
            Ok(())
        }

        async fn acknowledge(
            &self,
            _: &MailboxConfig,
            _: &[u8; 32],
            _: &[String],
        ) -> MailboxResult<()> {
            Ok(())
        }
    }

    fn cover_mailbox() -> CoverMailboxSnapshot {
        CoverMailboxSnapshot {
            onion_address: "cover-test".into(),
            cover_deposit_capability: [0x41; 32],
            cover_fetch_capability: [0x42; 32],
            cover_envelope_secret: [0x43; 32],
            dummy_deposit_capabilities: Vec::new(),
        }
    }

    // S10 §3: Poisson inter-arrival is always floored, never sub-second.
    #[test]
    fn jittered_duration_floor() {
        let mean = Duration::from_millis(500);
        for _ in 0..1000 {
            let d = jittered_duration(mean, 25);
            assert!(d.as_millis() >= MIN_JITTERED_INTERVAL_MS as u128);
        }
    }

    // S10 §3: the sampler is NOT bounded above — over many draws it must exceed
    // the mean by a wide margin (a bounded ±jitter sampler could never), proving
    // the forbidden point-mass cutoff is gone.
    #[test]
    fn jittered_duration_has_no_upper_cutoff() {
        let mean = Duration::from_secs(10);
        let max = (0..5000)
            .map(|_| jittered_duration(mean, 25).as_millis())
            .max()
            .unwrap();
        // Exponential with mean 10s exceeds ~25s (2.5×mean) with prob ~0.082 per
        // draw; over 5000 draws seeing at least one is a near-certainty.
        assert!(
            max > 25_000,
            "no long tail — upper cutoff still present: max={max}"
        );
    }

    // S10 §3: the empirical mean tracks the configured mean (memoryless process;
    // the ±25% secondary jitter is zero-mean so it does not bias the average).
    #[test]
    fn jittered_duration_mean_is_approximately_correct() {
        let mean = Duration::from_secs(10);
        let n = 20_000u128;
        let sum: u128 = (0..n)
            .map(|_| jittered_duration(mean, 25).as_millis())
            .sum();
        let empirical = sum / n;
        // The 1s floor biases the mean slightly upward; 10s ±20% is a safe band.
        assert!(
            (8_000..=12_000).contains(&empirical),
            "empirical mean off: {empirical}ms"
        );
    }

    #[test]
    fn scheduler_construction() {
        let scheduler = CoverTrafficScheduler::new(CoverTrafficConfig::default());
        assert!(!scheduler.is_running());
    }

    // S10 §6.2: the send path parks on a slot (await_slot); a tier-1 park in
    // Speed Priority opens exactly one boost window (refresh ≠ new window).
    #[tokio::test]
    async fn real_message_park_opens_one_boost_window_refresh_keeps_one() {
        let scheduler = CoverTrafficScheduler::new(CoverTrafficConfig::default());
        scheduler.running.store(true, Ordering::SeqCst);
        let slots = scheduler.slot_source();

        for n in 0..2u8 {
            let slots = Arc::clone(&slots);
            let waiter = tokio::spawn(async move {
                slots
                    .await_slot("mb.onion", AbsorptionPriority::RealMessage, Some([n; 16]))
                    .await
            });
            while scheduler.pending.is_empty() {
                tokio::task::yield_now().await;
            }
            // First park opens the window; the second rides the SAME window
            // (a refresh must not count another — S10 §8.1, §10).
            assert_eq!(scheduler.snapshot().boost_windows, 1);
            if let Some(item) = scheduler.pending.pop_highest("mb.onion") {
                if let PendingPayload::Slot(tx) = item.payload {
                    let _ = tx.send(SlotPermit::unpaced(SlotGrant::Granted));
                }
            }
            assert_eq!(waiter.await.unwrap(), SlotGrant::Granted);
        }
        assert!(scheduler.boost.is_active());
        assert_eq!(scheduler.snapshot().boost_windows, 1);
    }

    // S10 §8.1: real and decoy windows are the same fixed-length process. A
    // window longer than SPEED_BOOST_WINDOW_SECS would prove real activity, so
    // no number of waiting tier-1 items, and no decoy inside the window, may
    // move its end.
    #[tokio::test]
    async fn real_backlog_never_stretches_a_boost_window() {
        let scheduler = CoverTrafficScheduler::new(CoverTrafficConfig::default());
        scheduler.running.store(true, Ordering::SeqCst);
        let slots = scheduler.slot_source();
        let window_end = || scheduler.boost.until.lock().unwrap().expect("window open");
        let mut first_end = None;
        let mut waiters = Vec::new();
        for n in 0..20u8 {
            let slots = Arc::clone(&slots);
            waiters.push(tokio::spawn(async move {
                slots
                    .await_slot("mb.onion", AbsorptionPriority::RealMessage, Some([n; 16]))
                    .await
            }));
            while scheduler.pending.len() <= n as usize {
                tokio::task::yield_now().await;
            }
            let first = *first_end.get_or_insert(window_end());
            assert!(first <= Instant::now() + Duration::from_secs(SPEED_BOOST_WINDOW_SECS));
            assert_eq!(window_end(), first, "tier-1 item {n} stretched the window");
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        assert!(!scheduler.boost.open_window(), "a decoy inside a window opens nothing");
        assert_eq!(window_end(), first_end.unwrap());
        assert_eq!(scheduler.snapshot().boost_windows, 1);

        scheduler.pending.wake_all();
        for waiter in waiters {
            assert_eq!(waiter.await.unwrap(), SlotGrant::SchedulerStopped);
        }
    }

    // S10 §8.1 via the ACTUAL send path: real sends park on a slot through
    // `SlotSource` — the same mechanism the production constructor wires.
    #[tokio::test]
    async fn parking_a_real_send_opens_one_boost_window() {
        let scheduler = CoverTrafficScheduler::new(CoverTrafficConfig::default());
        let slots = scheduler.slot_source();
        // `await_slot` parks, so drive it as a task and let it reach the park.
        scheduler.running.store(true, Ordering::SeqCst);
        let waiter = {
            let slots = Arc::clone(&slots);
            tokio::spawn(async move {
                slots
                    .await_slot("mb.onion", AbsorptionPriority::RealMessage, None)
                    .await
            })
        };
        while scheduler.pending.is_empty() {
            tokio::task::yield_now().await;
        }

        assert_eq!(scheduler.snapshot().boost_windows, 1);
        assert!(scheduler.boost.is_active());

        // Release the parked sender so the task does not leak.
        if let Some(item) = scheduler.pending.pop_highest("mb.onion") {
            if let PendingPayload::Slot(tx) = item.payload {
                let _ = tx.send(SlotPermit::unpaced(SlotGrant::Granted));
            }
        }
        assert_eq!(waiter.await.unwrap(), SlotGrant::Granted);
    }

    // Control-tier traffic must NOT boost — only real user content does, or a
    // background ACK would look like activity and move the rate.
    #[tokio::test]
    async fn parking_control_traffic_does_not_boost() {
        let scheduler = CoverTrafficScheduler::new(CoverTrafficConfig::default());
        let slots = scheduler.slot_source();
        scheduler.running.store(true, Ordering::SeqCst);
        let waiter = {
            let slots = Arc::clone(&slots);
            tokio::spawn(async move {
                slots
                    .await_slot("mb.onion", AbsorptionPriority::Control, None)
                    .await
            })
        };
        while scheduler.pending.is_empty() {
            tokio::task::yield_now().await;
        }
        assert_eq!(scheduler.snapshot().boost_windows, 0);
        assert!(!scheduler.boost.is_active());

        if let Some(item) = scheduler.pending.pop_highest("mb.onion") {
            if let PendingPayload::Slot(tx) = item.payload {
                let _ = tx.send(SlotPermit::unpaced(SlotGrant::Granted));
            }
        }
        let _ = waiter.await;
    }

    // Privacy Priority burst mode (not used by the application) never boosts —
    // the production hook checks burst_mode before opening a window, so a real
    // send in that mode opens nothing.
    #[tokio::test]
    async fn privacy_priority_never_boosts() {
        let burst_mode = BurstMode::PrivacyPriority;
        let config = CoverTrafficConfig {
            burst_mode,
            ..CoverTrafficConfig::default()
        };
        let scheduler = CoverTrafficScheduler::new(config);
        scheduler.running.store(true, Ordering::SeqCst);
        let boost = Arc::clone(&scheduler.boost);
        let stats = Arc::clone(&scheduler.stats);
        let slots = Arc::new(SlotSource::with_boost(
            Arc::clone(&scheduler.pending),
            Arc::clone(&scheduler.running),
            Arc::new(move || {
                if burst_mode == BurstMode::SpeedPriority {
                    boost.open_window();
                    stats.boost_windows.fetch_add(1, Ordering::Relaxed);
                }
            }),
        ));

        let slots2 = Arc::clone(&slots);
        let waiter = tokio::spawn(async move {
            slots2
                .await_slot("mb.onion", AbsorptionPriority::RealMessage, None)
                .await
        });
        while scheduler.pending.is_empty() {
            tokio::task::yield_now().await;
        }
        if let Some(item) = scheduler.pending.pop_highest("mb.onion") {
            if let PendingPayload::Slot(tx) = item.payload {
                let _ = tx.send(SlotPermit::unpaced(SlotGrant::Granted));
            }
        }
        assert_eq!(waiter.await.unwrap(), SlotGrant::Granted);
        assert_eq!(scheduler.snapshot().boost_windows, 0);
        assert!(!scheduler.boost.is_active());
    }

    // S10 §8.1: inside a boost window the deposit mean is divided by
    // SPEED_BOOST_FACTOR; outside (or in Privacy Priority) it is the base.
    #[test]
    fn boost_divides_deposit_mean() {
        let config = CoverTrafficConfig::default();
        let boost = BoostState::new();
        assert_eq!(
            effective_deposit_interval(&config, &boost),
            config.deposit_interval
        );
        boost.open_window();
        assert_eq!(
            effective_deposit_interval(&config, &boost),
            config.deposit_interval / SPEED_BOOST_FACTOR
        );

        let privacy = CoverTrafficConfig {
            burst_mode: BurstMode::PrivacyPriority,
            ..CoverTrafficConfig::default()
        };
        let boost2 = BoostState::new();
        boost2.open_window();
        assert_eq!(
            effective_deposit_interval(&privacy, &boost2),
            privacy.deposit_interval
        );
    }

    // S10 §2.3: a cover blob is envelope-wrapped and lands EXACTLY on a
    // §2.2 bucket — never a raw CSPRNG string of arbitrary size.
    #[test]
    fn cover_blob_lands_exactly_on_bucket() {
        for _ in 0..20 {
            let blob = build_cover_blob(&[7; 32], &[9; 32]).unwrap();
            assert!(
                COVER_DEPOSIT_SIZES.contains(&blob.len()),
                "cover blob size {} not a §2.2 bucket",
                blob.len()
            );
        }
    }

    #[tokio::test]
    async fn cover_deposit_reaches_mailbox_and_is_envelope_valid() {
        let mailbox = cover_mailbox();
        let mailboxes = RwLock::new(vec![mailbox.clone()]);
        let client = RecordingMailbox {
            deposits: Mutex::new(Vec::new()),
            fail: Mutex::new(false),
        };
        let stats = CoverStats::new();

        do_cover_deposit(&mailboxes, &client, &stats).await;

        let deposits = client.deposits.lock().unwrap();
        assert_eq!(deposits.len(), 1);
        assert_eq!(deposits[0].0, mailbox.cover_deposit_capability);
        let inner = najwa_protocol::message::envelope_decrypt(
            &mailbox.cover_envelope_secret,
            &mailbox.cover_deposit_capability,
            &deposits[0].1,
        )
        .expect("scheduler must send a valid cover envelope");
        assert_eq!(inner.len() + ENVELOPE_OVERHEAD, deposits[0].1.len());
        assert_eq!(stats.cover_deposits.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn failed_cover_deposit_is_not_counted_as_emitted() {
        let mailboxes = RwLock::new(vec![cover_mailbox()]);
        let client = RecordingMailbox {
            deposits: Mutex::new(Vec::new()),
            fail: Mutex::new(true),
        };
        let stats = CoverStats::new();
        do_cover_deposit(&mailboxes, &client, &stats).await;
        assert_eq!(stats.cover_deposits.load(Ordering::Relaxed), 0);
        assert!(client.deposits.lock().unwrap().is_empty());
    }

    // S10 §10: stats snapshot carries the §10 counter set.
    #[test]
    fn stats_snapshot() {
        let stats = CoverStats::new();
        stats.cover_polls.fetch_add(5, Ordering::Relaxed);
        stats.cover_deposits.fetch_add(3, Ordering::Relaxed);
        stats.cover_bytes_sent.fetch_add(4096, Ordering::Relaxed);
        stats.dummy_self_deposits.fetch_add(2, Ordering::Relaxed);

        let snap = stats.snapshot();
        assert_eq!(snap.cover_polls, 5);
        assert_eq!(snap.cover_deposits, 3);
        assert_eq!(snap.cover_bytes_sent, 4096);
        assert_eq!(snap.real_sends_absorbed, 0);
        assert_eq!(snap.dummy_self_deposits, 2);
        assert_eq!(snap.boost_windows, 0);
        assert_eq!(snap.receive_maintenance_deposits, 0);
    }

    #[test]
    fn config_levels() {
        let low = CoverTrafficConfig::from_level(CoverLevel::Low);
        assert_eq!(low.poll_interval, Duration::from_secs(60));

        let med = CoverTrafficConfig::from_level(CoverLevel::Medium);
        assert_eq!(med.poll_interval, Duration::from_secs(30));

        let high = CoverTrafficConfig::from_level(CoverLevel::High);
        assert_eq!(high.poll_interval, Duration::from_secs(10));
    }

    #[test]
    fn stop_clears_running() {
        let mut scheduler = CoverTrafficScheduler::new(CoverTrafficConfig::default());
        scheduler.running.store(true, Ordering::SeqCst);
        assert!(scheduler.is_running());
        scheduler.stop();
        assert!(!scheduler.is_running());
    }

    #[test]
    fn disabled_config_not_running() {
        let config = CoverTrafficConfig {
            enabled: false,
            ..CoverTrafficConfig::default()
        };
        let scheduler = CoverTrafficScheduler::new(config);
        assert!(!scheduler.is_running());
    }

    // -----------------------------------------------------------------------
    // S10 §6 invariants pinned as tests. The cover subsystem's failure
    // mode is silence, so these assert the EFFECTS of the slot-servicing
    // path, not just that it starts.
    // -----------------------------------------------------------------------

    fn loop_ctx(mailboxes: Vec<CoverMailboxSnapshot>) -> (CoverLoopContext, Arc<RecordingMailbox>) {
        let mailbox = Arc::new(RecordingMailbox {
            deposits: Mutex::new(Vec::new()),
            fail: Mutex::new(false),
        });
        let ctx = CoverLoopContext {
            generation: 0,
            config: CoverTrafficConfig::default(),
            running: Arc::new(AtomicBool::new(true)),
            stats: Arc::new(CoverStats::default()),
            pending: Arc::new(PendingQueues::new()),
            boost: Arc::new(BoostState::new()),
            mailboxes: Arc::new(RwLock::new(mailboxes)),
        };
        (ctx, mailbox)
    }

    /// §6.2 (invariant 1): a parked real sender WINS the slot and deposits
    /// itself — the scheduler must not deposit anything on its behalf. The
    /// deposited list stays empty; the grant is the scheduler's entire output.
    #[tokio::test]
    async fn inv_slot_grant_deposits_nothing_on_behalf_of_sender() {
        let (ctx, mailbox) = loop_ctx(vec![cover_mailbox()]);
        let boost = Arc::clone(&ctx.boost);
        let slots = Arc::new(SlotSource::with_boost(
            Arc::clone(&ctx.pending),
            Arc::clone(&ctx.running),
            Arc::new(move || {
                boost.open_window();
            }),
        ));

        let waiter = {
            let slots = Arc::clone(&slots);
            tokio::spawn(async move {
                let permit = slots
                    .await_slot("cover-test", AbsorptionPriority::RealMessage, None)
                    .await;
                assert!(permit.was_paced());
                assert!(permit.begin());
                SlotGrant::Granted
            })
        };
        while ctx.pending.nonempty_onions().is_empty() {
            tokio::task::yield_now().await;
        }

        service_deposit_slot(&ctx, mailbox.as_ref()).await;

        assert!(
            mailbox.deposits.lock().unwrap().is_empty(),
            "§6.2: the scheduler deposited on behalf of a parked real sender"
        );
        assert_eq!(waiter.await.unwrap(), SlotGrant::Granted);
        assert_eq!(
            ctx.stats.real_sends_absorbed.load(Ordering::Relaxed),
            1,
            "the absorbed slot is counted"
        );
    }

    /// §6.2 (invariant 2): a vanished grantee (lock drain / dropped future)
    /// must not leave the slot unspent — a cover deposit is emitted instead.
    /// A skipped deposit is exactly the observable gap §6.1 exists to prevent.
    #[tokio::test]
    async fn inv_vanished_grantee_still_emits_cover() {
        let (ctx, mailbox) = loop_ctx(vec![cover_mailbox()]);
        let slots: Arc<SlotSource> = Arc::new(SlotSource::new(
            Arc::clone(&ctx.pending),
            Arc::clone(&ctx.running),
        ));

        let waiter = {
            let slots = Arc::clone(&slots);
            tokio::spawn(async move {
                slots
                    .await_slot("cover-test", AbsorptionPriority::RealMessage, None)
                    .await
            })
        };
        while ctx.pending.nonempty_onions().is_empty() {
            tokio::task::yield_now().await;
        }
        // Abandon: abort the waiter so its oneshot sender fails on send.
        waiter.abort();
        tokio::task::yield_now().await;

        service_deposit_slot(&ctx, mailbox.as_ref()).await;

        let deposits = mailbox.deposits.lock().unwrap();
        assert_eq!(
            deposits.len(),
            1,
            "a vanished grantee must spend the slot on cover, not silence"
        );
        assert_eq!(deposits[0].0, [0x41; 32], "cover rides the cover cap");
    }

    /// Invariant 3: library Blob items (queued through the `queue_*` API; the
    /// application queues none) ARE deposited by the scheduler, byte-exact,
    /// on the item's pinned deposit cap.
    #[tokio::test]
    async fn inv_blob_item_is_deposited_by_scheduler() {
        let (ctx, mailbox) = loop_ctx(vec![cover_mailbox()]);
        let blob = vec![0x77u8; 256];

        ctx.pending.enqueue(
            "cover-test",
            PendingItem {
                priority: AbsorptionPriority::DummySelfDeposit,
                msg_id: None,
                payload: PendingPayload::Blob {
                    deposit_cap: [0x41; 32],
                    blob: blob.clone(),
                },
            },
        );

        service_deposit_slot(&ctx, mailbox.as_ref()).await;

        let deposits = mailbox.deposits.lock().unwrap();
        assert_eq!(deposits.len(), 1, "the blob item must be deposited");
        assert_eq!(deposits[0].0, [0x41; 32]);
        assert_eq!(deposits[0].1, blob);
        assert_eq!(
            ctx.stats.dummy_self_deposits.load(Ordering::Relaxed),
            1,
            "tier-7 dummy self-deposit counted"
        );
    }

    /// Delivery never depends on cover being healthy (§6 invariant): a cover
    /// deposit failure is swallowed — no panic, the slot is spent, the loop
    /// keeps running.
    #[tokio::test]
    async fn inv_cover_deposit_failure_does_not_stall_the_loop() {
        let (ctx, mailbox) = loop_ctx(vec![cover_mailbox()]);
        *mailbox.fail.lock().unwrap() = true;

        ctx.pending.enqueue(
            "cover-test",
            PendingItem {
                priority: AbsorptionPriority::DummySelfDeposit,
                msg_id: None,
                payload: PendingPayload::Blob {
                    deposit_cap: [0x41; 32],
                    blob: vec![0x77; 64],
                },
            },
        );

        // Must return cleanly on a failing transport.
        service_deposit_slot(&ctx, mailbox.as_ref()).await;

        assert_eq!(
            mailbox.deposits.lock().unwrap().len(),
            0,
            "failed deposits are not counted as sent"
        );
    }
}