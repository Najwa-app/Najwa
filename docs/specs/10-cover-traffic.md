---
id: S10
title: Cover Traffic System
crates: [najwa-core, najwa-ffi]
depends-on: [S04, S07, S08, S16]
---

# S10 — Cover Traffic System

## Overview

Encryption hides what a message says. It does not hide when it was sent. A mailbox
operator, or someone watching a user's Tor traffic, can see deposits arrive and
fetches happen. Cover traffic makes the client send a steady, random stream of
dummy deposits and fetches to its own mailboxes whether or not the user is doing
anything, so real activity is harder to pick out.

The native service runs one cover scheduler per process. The scheduler fires
*poll slots* and *deposit slots* at random times. The gaps follow an exponential
distribution, so knowing when the last slot fired does not tell an observer when
the next one will. A poll slot fetches from the user's own cover capability on one
of the user's mailboxes. A deposit slot either carries real work that is waiting
for it, or, when nothing is waiting, deposits a dummy blob to the user's own cover
capability. Dummy blobs are encrypted like real ones and padded to the same sizes,
so a mailbox operator cannot tell them apart by content.

Whether real work waits for a slot depends on the user's **delivery mode** (§14):

- **Responsive** (the default) sends real work immediately. Cover still runs in the
  background, but real deposits are not hidden inside it, and send timing is
  exposed.
- **Timing privacy** makes real messages, acknowledgements, read receipts,
  registrations and prekey publications wait for the next deposit slot. The real
  item takes the slot's place instead of adding traffic ("absorption"). When a
  user message waits, the slot rate speeds up for a while (a *boost*); identical
  boosts also fire at random as decoys. Delivery is slower.

Cover keeps running while the profile is locked, so locking does not switch the
cover stream off. It stops when the native process exits, when the profile is
erased, or when the bridge settings change, and it starts again after the next
unlock. The supplied mailbox configuration releases deposits immediately (zero
hold and zero jitter), so the mailbox adds no timing protection of its own.

Cover traffic does not hide content (encryption does), does not help against a
compromised device, and gives no global traffic-analysis guarantee. §15 states its
limits.

## 1. Scope

This specification defines:

- The cover-traffic configuration and its level parameters.
- Cover blob construction.
- The scheduler: exponential slot timing, poll slots, deposit slots and mailbox
  eligibility.
- Dedicated cover capabilities, dummy queues, their provisioning and
  registration pacing.
- The slot-queue absorption model, priority tiers and the slot-acquisition API.
- Acknowledgement, read-receipt and typing-indicator absorption.
- Boost windows and decoy boosts.
- File-part pacing and circuit policy.
- Cover statistics and the scheduler lifecycle, including lock behavior.
- The Responsive and Timing privacy delivery modes.

## 2. Configuration

```rust
struct CoverTrafficConfig {
    enabled: bool,              // default true
    level: CoverLevel,          // default High
    poll_interval: Duration,    // mean poll interval, from level
    deposit_interval: Duration, // mean deposit interval, from level
    jitter_percent: u32,        // default 25 — secondary ±jitter (§3)
    burst_mode: BurstMode,      // default SpeedPriority (§8.1)
}

enum CoverLevel { Low, Medium, High }
```

- The native service MUST run the scheduler with `CoverTrafficConfig::default()`:
  level `High`, 25 % jitter, Speed-Priority boosts. The level is not a user
  setting. The user setting is the delivery mode (§14).
- The slot rate MUST NOT depend on UI state (for example an open conversation). A
  rate tied to the screen would turn the cover capability into a live activity
  signal for the mailbox operator. The only rate changes are boost windows (§8.1).
- With `enabled = false`, `start` does nothing.

### 2.1 Level Parameters

| Level | Poll interval (mean) | Deposit interval (mean) | Jitter |
|-------|----------------------|-------------------------|--------|
| Low | 60 s | 120 s | ±25 % |
| Medium | 30 s | 60 s | ±25 % |
| **High (used by the application)** | 10 s | 30 s | ±25 % |

In Timing privacy, the deposit interval is the floor on send latency. At `High`, a
first message after an idle period waits about 30 s on average, and later
messages wait about 7.5 s on average while a boost window is open (§8.1).

### 2.2 Constants

| Constant | Value | Use |
|----------|-------|-----|
| `MIN_JITTERED_INTERVAL_MS` | 1000 | Floor on every sampled interval (§3) |
| `COVER_DEPOSIT_SIZES` | 256, 512, 1024, 2048, 4096 | Cover blob sizes in bytes (§2.3) |
| `SPEED_BOOST_FACTOR` | 4 | Deposit mean divisor inside a boost window |
| `SPEED_BOOST_WINDOW_SECS` | 120 | Fixed boost window length, counted from the trigger that opened it |
| `DECOY_BOOST_MEAN_INTERVAL_SECS` | 3600 | Mean interval between decoy boosts |
| Cover fetch limit | 100 | `limit` of a cover poll |
| Slot lease | 1 s | Time a granted sender has to begin its deposit (§6.2) |
| Slot job deadline | 120 s | Bound on one poll or deposit job (§4.1) |
| Mailbox failure threshold | 5 | `failure_count` at which a mailbox stops being eligible |
| Provisioning interval | 5 s | Cover-registration loop period (§5) |
| Registration attempt deadline | 180 s | Bound on one cover registration attempt (§5) |

### 2.3 Cover Blob Construction and Bucket Rationale

A cover deposit MUST be an envelope-wrapped CSPRNG payload whose final deposited
size equals a padding bucket exactly. It MUST NOT be a raw random byte string.

```
func build_cover_blob(cover_envelope_secret, cover_deposit_cap) → bytes:
    bucket = uniform choice from COVER_DEPOSIT_SIZES
    inner  = CSPRNG(bucket − ENVELOPE_OVERHEAD)            // ENVELOPE_OVERHEAD = 40
    return envelope_encrypt(cover_envelope_secret, cover_deposit_cap, inner)
           // = nonce(24) ‖ AEAD ciphertext ‖ tag(16); length == bucket
```

`envelope_encrypt` is the deposit envelope of [S07 §3](07-message-format.md): the
outer key is `HKDF-SHA256(IKM = envelope secret, salt = "najwa/v1/deposit-envelope",
info = "outer-key", L = 32)` and the AAD is the capability hint
`SHA-256(deposit capability)[0..8]`. A real deposit is the same construction over a
WireMessage. Because the AEAD output looks uniformly random, a cover blob is
indistinguishable by content from a real deposit of the same bucket to anyone
without the envelope secret, including the mailbox operator.

- The cover envelope secret is self-generated and never sent to the server (§5).
- Every size in `COVER_DEPOSIT_SIZES` MUST be one of the padding buckets of
  [S07 §5.1](07-message-format.md). A size that only cover could produce would
  identify cover.
- Text messages, acknowledgements, receipts and control messages land in these
  buckets. File parts land in larger buckets (up to 262,144 bytes), which cover
  never produces (§15).

## 3. Scheduling Algorithm

Every slot interval is sampled from an exponential distribution, then perturbed:

```
func jittered_duration(mean, jitter_percent) → Duration:
    u  = 1 − uniform[0, 1)                    // u ∈ (0, 1], so ln(u) is finite
    ms = −mean_ms × ln(u)                     // exponential with mean mean_ms
    r  = ms × jitter_percent / 100
    if r > 0: ms = ms + uniform[−r, r)        // secondary ±jitter
    ms = max(ms, MIN_JITTERED_INTERVAL_MS)
    return floor(ms) milliseconds
```

- The sampler MUST NOT have an upper cutoff. A cutoff creates a point mass that an
  observer can key on.
- Random values come from the thread-local CSPRNG.
- Slot timers use the monotonic clock, so wall-clock changes do not move them.
  After a process suspend, each overdue timer fires once and is re-sampled from
  the moment it fires. Missed slots MUST NOT be replayed as a burst.
- The exponential model is idealized. The 1 s floor, the secondary jitter,
  scheduler wake-up latency and network duration mean the observable trace is not
  strictly memoryless.

## 4. Cover Traffic Scheduler

```rust
struct CoverTrafficScheduler {
    config: CoverTrafficConfig,
    running: Arc<AtomicBool>,
    stats: Arc<CoverStats>,                              // §10
    pending: Arc<PendingQueues>,                         // §6.1 — the only absorption state
    boost: Arc<BoostState>,                              // §8.1
    mailboxes: Arc<RwLock<Vec<CoverMailboxSnapshot>>>,   // eligible cover mailboxes (§4.3)
    slot_source: Arc<SlotSource>,                        // send-path handle (§6.2)
}

struct CoverMailboxSnapshot {
    onion_address: String,
    cover_deposit_capability: [u8; 32],
    cover_fetch_capability: [u8; 32],
    cover_envelope_secret: [u8; 32],
    dummy_deposit_capabilities: Vec<[u8; 32]>,   // active dummy queues (§5.1)
}
```

The snapshot holds only cover material: no real capability, no message or
identity key, and no database handle. It is therefore safe to keep in memory
while the profile is locked (§11).

There are no absorption flags. Absorption state is the per-mailbox pending queue
of §6.1 and nothing else. A global flag would let a real deposit on mailbox A
suppress cover on mailbox B, which colluding operators could correlate.

### 4.1 Main Loop

```
async func run_cover_loop():
    poll    = timer(jittered_duration(poll_interval, jitter))
    deposit = timer(jittered_duration(effective_deposit_interval(), jitter))
    decoy   = timer(jittered_duration(DECOY_BOOST_MEAN_INTERVAL_SECS, jitter))
    while running and this run's generation is current:
        select:
            poll fires:
                poll.reset(now + jittered_duration(poll_interval, jitter))
                spawn job: service_poll_slot()                  // §4.2
            deposit fires:
                deposit.reset(now + jittered_duration(effective_deposit_interval(), jitter))
                spawn job: service_deposit_slot()               // §6.1
            decoy fires:
                open_boost_window()                             // §8.1; deposit timer untouched
                decoy.reset(now + jittered_duration(DECOY_BOOST_MEAN_INTERVAL_SECS, jitter))
            a job finishes: continue

effective_deposit_interval() = deposit_interval / SPEED_BOOST_FACTOR  if a boost window is open
                               deposit_interval                       otherwise
```

- Each slot runs as a separate job, bounded by 120 s, so a slow network operation
  never delays the next slot.
- Jobs started by an earlier run (before a stop and restart) do nothing.
- Real mailbox polls ([S08 §6.1](08-messaging-service.md)) run on their own schedule
  and never suppress poll slots.

### 4.2 Poll Slots

```
func service_poll_slot():
    mb = uniform choice from the eligible snapshot          // none → nothing happens
    msgs = fetch_cover(mb.onion, mb.cover_fetch_capability, limit = 100)
           over CircuitIsolation::CoverTraffic(mb.onion)    // S04 §4.1.1
    on error: return                                        // not counted
    if msgs is not empty:
        acknowledge_cover(mb.onion, mb.cover_fetch_capability, ids(msgs))
            over CircuitIsolation::CoverTraffic(mb.onion)   // failure deferred to the next poll
    stats.cover_polls += 1
```

The acknowledgement deletes the user's own cover blobs from the mailbox, so cover
does not fill the quota.

**Circuit isolation (normative).** Cover polls and cover acknowledgements MUST use
`CircuitIsolation::CoverTraffic(mailbox_onion)`, one circuit per own mailbox, as
real fetches use one `ByMailbox` circuit per mailbox. A single shared cover
circuit would route streams to every mailbox the user owns over one guard-side
circuit and let an observer group the user's mailbox set. Cover deposits use a
new `OneShot` circuit each (§4.3).

### 4.3 Cover Deposits

A cover deposit is the "nothing pending" outcome of §6.1:

```
func do_cover_deposit():
    mb = uniform choice from the eligible snapshot          // none → nothing happens
    target = uniform choice from [mb.cover_deposit_capability] ‖ mb.dummy_deposit_capabilities   // §5.1
    blob = build_cover_blob(mb.cover_envelope_secret, target)   // §2.3
    deposit(mb.onion, target, blob, pow = None)
        over CircuitIsolation::OneShot                      // new circuit; single attempt
    on error: return                                        // not counted
    stats.cover_deposits += 1
    stats.cover_bytes_sent += len(blob)
```

A cover deposit never solves proof of work. A rate-limited cover deposit is
dropped.

**Cover deposit circuits (normative).** Every cover deposit MUST use a new
`OneShot` circuit, exactly as a real deposit does
([S04 §4.1.1](04-transport.md)). Building a circuit is visible to the user's
guard. If cover reused a circuit while real deposits built new ones, the build
would mark each real deposit. The cost is one onion-service circuit build per
cover deposit: about 2 per minute in total at `High` (one per deposit slot),
spread over the user's mailboxes, and about 8 per minute inside a boost window.

**Eligibility filter.** The scheduler MUST NOT use a disabled or failing mailbox.
A mailbox is eligible when all of these hold:

- `enabled` is true;
- `failure_count < 5`;
- the server has accepted its cover registration (`cover_registered_at` is set);
- all three cover values are present and 32 bytes long.

The native service rebuilds the snapshot from the database when the messaging
service is installed after unlock, on every provisioning-loop iteration (every
5 s while unlocked), after each successful cover registration, and once more just
before the database closes on lock. While locked, the snapshot is frozen. With an
empty snapshot, poll and deposit slots do nothing, and the scheduler logs that
cover is paused.

## 5. Dedicated Cover Capabilities

Cover traffic MUST use capability pairs that are separate from every real
capability:

```
For each mailbox M the user owns:
    cover_deposit_capability = CSPRNG(32)
    cover_fetch_capability   = CSPRNG(32)
    cover_envelope_secret    = CSPRNG(32)     // self-generated; never sent to the server
    register (cover_fetch_capability, cover_deposit_capability) on M
```

- The values are generated when the mailbox row is created, or by the provisioning
  loop if they are missing.
- They are stored in the `mailboxes` table ([S03](03-encrypted-storage.md)) as
  `cover_deposit_capability`, `cover_fetch_capability` and
  `cover_envelope_secret`, with `cover_registered_at` set once the server accepts
  the registration.
- The pair is registered as an ordinary type-2 capability (no expiry, default
  settings) with a proof-of-work solution ([S16 §7](16-mailbox-server.md)), so the
  server cannot tell a cover pair from a contact pair by its type.
- They are never shared with any contact and are used only for cover deposits,
  cover polls and cover acknowledgements.

**Provisioning loop.** While the profile is unlocked, every 5 s:

1. If the previous registration succeeded but recording `cover_registered_at`
   failed, record it now, provided the mailbox and its cover values are unchanged.
2. Pick the next enabled mailbox with `failure_count < 5` and either no
   `cover_registered_at` or an unregistered dummy pair (§5.1), round-robin after
   the last mailbox attempted. Generate cover values if they are missing; once the
   cover pair is registered, generate any missing dummy pairs. The cover pair is
   registered before the dummies.
3. Refresh the scheduler snapshot (§4.3) and the fetch plan
   ([S08 §6.1.1](08-messaging-service.md)).
4. If a pair was picked, within 180 s: solve the registration proof of work,
   wait for a tier-6 slot (§5.2), check that the mailbox is still enabled, healthy
   and has the same cover values, and for a dummy that the same dummy pair is
   still stored (otherwise abandon; the unused slot becomes cover), then register
   on its own `OneShot` circuit. On success, record `cover_registered_at` and add
   the mailbox to the snapshot, or record the dummy's `registered_at`; a dummy
   joins the snapshot and the fetch plan at the next refresh.

Registering the exact same pair again is idempotent at the server, so a lost local
record is recovered by resubmitting. A conflict (409) means a different mapping
and is a failure.

### 5.1 Dummy Queues

Real polls pad their choice of receive queues with dummy queues
([S08 §6.1.1](08-messaging-service.md)). A dummy queue is a self-owned type-2
pair that receives modelled self-deposits, so the operator cannot tell it from a
contact's queue by its fetches or its deposits.

```
For each mailbox M the user owns, after its cover pair is registered:
    repeat until M has DUMMY_CAPS_PER_MAILBOX = 9 dummy pairs:
        dummy_fetch_capability   = CSPRNG(32)
        dummy_deposit_capability = CSPRNG(32)
    register each pair on M exactly as a cover pair (§5, §5.2)
```

- The pairs are stored in the `dummy_capabilities` table
  ([S03 §5.26](03-encrypted-storage.md)) with `registered_at` set once the server
  accepts the registration. A dummy has no envelope secret of its own and is
  never shared with anyone.
- The cover pair itself is not a dummy. It is polled on its own schedule (§4.2),
  so reading it from the real poll as well would make it the only queue read
  from two schedules, and would leave too few dummies to fill a pool.
- **Self-deposits.** The *active* dummies of a mailbox (the first
  `max(0, 10 − real receive queues)` registered ones, the same entries the poll
  pool uses) are listed in its snapshot entry. Each cover deposit to that mailbox
  picks its target uniformly from the cover pair and these dummies, and wraps a
  CSPRNG payload under the mailbox's cover envelope secret (§2.3). Like every cover
  deposit it uses a new `OneShot` circuit, as a contact's deposits do.
- **Fetching.** Dummies are fetched only by the real poll, on its `ByMailbox`
  circuit, and their blobs are acknowledged there. They are never fetched by
  cover polls.
- Idle dummies (beyond the pool) receive no deposits and are not fetched.
- Erasure deactivates dummy queues together with every other receive queue
  ([S13 §10](13-privacy-hardening.md)).

### 5.2 Capability-Registration Pacing

Capability registrations are observable, dated events. Registrations sent in one
burst over one circuit let the operator group them as one user.

- Every capability registration (primary mailbox pair, per-contact pair, invitation
  pair, cover pair) and every prekey publication MUST wait for a deposit slot at
  tier 6 (§6.1) for its destination mailbox when Timing privacy is active.
- Each registration MUST use its own `OneShot` circuit
  ([S04 §4.1.1](04-transport.md)) and its own slot.
- The proof of work is solved before waiting, so solving never delays a granted
  slot. Its challenge is fetched on its own `OneShot` circuit, never on the
  user's `ByMailbox` circuit ([S04 §4.1.1](04-transport.md)).
- In Responsive mode the slot wait is skipped (§14).

## 6. Absorption Model

In Timing privacy, real protocol events take the place of scheduled cover slots
instead of adding traffic. There is exactly one absorption algorithm: the slot
queue of §6.1.

### 6.1 Slot Queue (normative algorithm)

**State.** The scheduler keeps a pending queue per destination mailbox onion. A
sender that wants a slot is queued under the onion of the mailbox it will deposit
to. A multi-mailbox delivery ([S08 §9](08-messaging-service.md)) queues each target
separately, one after another in randomized order, so N mailboxes cost N slots and
never a burst.

```
func service_deposit_slot():
    nonempty = onions with pending items
    if nonempty is empty:
        do_cover_deposit(); return                      // §4.3
    onion = uniform choice from nonempty
    item  = pop_highest(onion)                          // lowest tier; FIFO within a tier
    if item is None:                                    // lost a race
        do_cover_deposit(); return
    permit = new SlotPermit with a lease ending 1 s from now
    if item.waiter accepts permit:
        wait up to 1 s for the sender to begin (§6.2)
    if the lease was not claimed (atomic 0 → 2):
        do_cover_deposit(); return                      // replacement cover
    stats.real_sends_absorbed += 1                      // the sender deposits itself
```

The scheduler never deposits real content itself. The sender owns the deposit,
its durable outbox row and its retry. A dropped, cancelled or late sender MUST NOT
leave the slot empty: the slot emits replacement cover instead. A lease claimed by
the sender cannot also emit cover, so a slot never produces two deposits.

**Priority tiers.**

| Tier | Work |
|------|------|
| 1 | User content: text messages, file parts, and any outbox frame that carries a user message |
| 2 | `SessionRepairInit` (control subtype `0x31`), and outbox retries of `Initial` (`0x01`) frames that carry no user message |
| 3 | `CumulativeAck` (message type `0x12`) |
| 4 | `ReadReceipt` (message type `0x11`) |
| 5 | `TypingIndicator` (control subtype `0x02`) |
| 6 | All other control messages, capability registrations (§5.2) and prekey publications |
| — | Cover deposit when nothing is pending (§4.3) |

A received control subtype the client does not know is handled by the receiver
rules of [S07](07-message-format.md) and has no effect on priorities.

### 6.2 Slot Acquisition API

```rust
impl SlotSource {
    fn set_bypass(&self, on: bool);   // true = Responsive (§14)
    fn bypass(&self) -> bool;
    async fn await_slot(&self, mailbox_onion: &str, priority: AbsorptionPriority,
                        msg_id: Option<[u8; 16]>) -> SlotPermit;
}

impl SlotPermit {
    fn was_paced(&self) -> bool;      // true only for Granted
    fn begin(self) -> bool;           // claim the lease; see below
}

enum SlotGrant { Granted, Bypassed, SchedulerIdle, SchedulerStopped }
```

```
async func await_slot(onion, priority, msg_id) → SlotPermit:
    if bypass:              return unpaced(Bypassed)
    if scheduler stopped:   return unpaced(SchedulerIdle)
    if priority is tier 1:  open_boost_window()                       // §8.1
    under the queue lock, if still running: queue a waiter under onion
    await the grant
    if the queue was dropped (scheduler stopped): return unpaced(SchedulerStopped)
    return the granted permit

func begin(permit) → bool:
    false if the lease has expired (1 s after grant) or the scheduler already used the slot for cover
    true otherwise; the caller MUST start its deposit at once
```

Requirements:

- Every Timing-privacy deposit of real work MUST go through `await_slot`. There is
  no "send now and suppress the next slot" path.
- Delivery MUST NOT depend on cover health. Every outcome other than `Granted`
  means "deposit now".
- A caller MUST finish its local checks before calling `begin`, and MUST NOT wait
  on anything else between `begin` and its request. If `begin` returns false, the
  caller MUST wait for a new slot. A proof-of-work re-submission after a 429 also
  waits for a new slot.
- Dropping a permit without calling `begin` produces replacement cover.
- Stopping the scheduler releases all waiting senders with `SchedulerStopped`.

### 6.3 Result — Scoped Constant-Rate Claim

- In Timing privacy, outside boost windows, the deposit-slot rate does not depend on
  user activity. Real messages, acknowledgements and receipts replace cover in
  slots and add no deposits.
- Inside a boost window the rate is higher. A boost is evidence of a boost, not
  proof of activity, because decoys fire too. §8.1 and §15 state what boosts still
  reveal.
- In Responsive mode, real deposits are added to the cover stream. The total
  deposit rate rises with activity.
- A single mailbox operator sees only the deposits that arrive at their mailbox.
  When a slot carries real work to a contact's mailbox, the user's own mailboxes
  receive one cover deposit fewer. The global slot rate is unchanged, but each
  operator's share moves.

## 7. ACK / Receipt / Typing Absorption

### 7.1 ACK Absorption

After processing received messages, the client sends a `CumulativeAck`
([S07 §8.1](07-message-format.md)) as a durable outbox frame at tier 3. The first
attempt goes to the contact's primary mailbox; retries follow
[S08](08-messaging-service.md).

- In Timing privacy, the acknowledgement waits for a slot and takes its place.
- In Responsive mode, a poll stores acknowledgement intents together with the
  received frames and sends cumulative ranges at the end of the batch, without
  waiting for slots.

### 7.2 Read Receipt Absorption

A read receipt is sent only for a received message whose sender asked for one
([S08](08-messaging-service.md)). Display events are converted to durable outbox
frames (checked every second while unlocked) and sent at tier 4. In Timing
privacy they wait for a slot.

### 7.3 Typing Indicator Absorption

Typing indicators are tier 5. The application does not send typing indicators. A
received typing indicator is handled per [S08](08-messaging-service.md).

## 8. Burst Handling

### 8.1 Speed-Priority Boost

The scheduler raises the slot rate for a bounded window so that queued work drains
faster:

```
SPEED_BOOST_FACTOR             = 4
SPEED_BOOST_WINDOW_SECS        = 120
DECOY_BOOST_MEAN_INTERVAL_SECS = 3600

func open_boost_window() → bool:
    if boost_until > now: return false          // a window is open: no effect
    boost_until = now + SPEED_BOOST_WINDOW_SECS
    stats.boost_windows += 1
    return true
```

**Window rule (normative).** Real and decoy triggers both go through
`open_boost_window`. A trigger opens a window only when none is open. The window
lasts exactly `SPEED_BOOST_WINDOW_SECS` from that trigger and is never extended,
whatever triggers arrive while it is open. Every window, real or decoy, therefore
has the same length. Work still queued when a window closes drains through
ordinary slots. A later tier-1 wait, after the window has closed, opens a new
window under the same rule, as a decoy firing then would.

- **Real trigger.** A tier-1 item that starts waiting for a slot while no window
  is open opens one. This happens only in Timing privacy, because Responsive
  never waits. Acknowledgements, receipts and control traffic never trigger a
  boost.
- **Decoys (normative).** The scheduler MUST also open windows as decoys, on an
  independent timer with mean `DECOY_BOOST_MEAN_INTERVAL_SECS` (§4.1). Decoys fire
  in both delivery modes. Real and decoy windows MUST be identical: same factor,
  same fixed length, same start. An observer who sees a rate change therefore
  cannot tell from the change alone whether the user was active.
- Inside a window, the deposit mean is `deposit_interval / SPEED_BOOST_FACTOR`
  (7.5 s at `High`). For real and decoy windows alike, the new mean applies from
  the next deposit-timer reset. Opening a window MUST NOT reset the deposit timer.
  If only decoys reset it, their boosted rate would start sooner than a real
  window's.

How often boosts occur still bounds how much real activity occurred (§15).

## 9. File Transfer Traffic

File parts ([S11](11-file-transfer-sanitization.md)) are tier-1 outbox frames sent
through the same deposit path as messages.

| | Timing privacy | Responsive |
|-|----------------|------------|
| Pacing | Each part waits for its own deposit slot; a part that starts waiting while no window is open opens one (§8.1) | Parts are deposited without waiting |
| Circuit | A fresh `OneShot` circuit per attempt | `FileTransfer(key)`: one isolated circuit per file, contact, destination capability and mailbox, subject to [S04 §4.4](04-transport.md) rotation |

The mode is read immediately before each attempt, so switching to Timing privacy
also affects parts already queued.

**File-transfer isolation key.** For a part of an outgoing file sent in Responsive
mode:

```
key = SHA-256( "najwa-responsive-file-circuit-v1" ‖ 0x00
             ‖ contact_id                   // u64, big-endian
             ‖ session_id                   // 16 bytes: first 16 bytes of the stored file message content
             ‖ their_deposit_capability     // 32 bytes
             ‖ their_envelope_secret        // 32 bytes
             ‖ mailbox_onion )              // ASCII onion label, without ".onion"
```

The key applies only to frames of an outgoing file message (content types 10 and
11) with no disappearing timer. If any input is missing, the attempt uses
`OneShot`. Reusing one circuit per file speeds up large transfers. The trade-off is
that the mailbox operator sees all parts of one file arrive on one circuit.

## 10. Statistics

```rust
struct CoverStats {
    cover_polls: AtomicU64,                  // successful cover polls
    cover_deposits: AtomicU64,               // successful cover deposits
    cover_bytes_sent: AtomicU64,             // bytes of successful cover deposits
    real_sends_absorbed: AtomicU64,          // slots claimed by real senders
    dummy_self_deposits: AtomicU64,          // never incremented in this release
    boost_windows: AtomicU64,                // real + decoy windows opened, combined
    receive_maintenance_deposits: AtomicU64, // never incremented in this release
}
```

- Counters are internal. They MUST NOT be exposed to any server or external party.
- `boost_windows` MUST NOT be split into real and decoy counts in any export.
- A failed poll or deposit is not counted.

The status the native service reports to the UI includes only whether the
scheduler is running.

## 11. Lifecycle

```
start:  on installing the messaging service after a successful Tor bootstrap
        (first unlock in the process), with CoverTrafficConfig::default();
        restarted on a later unlock if it is not running
stop:   process exit; profile erase; a change of bridge settings (S04 §11.1)
```

**Cover continues under lock (normative).** Locking the profile
([S13 §8.2](13-privacy-hardening.md)) MUST NOT stop the cover scheduler. The Tor
client, the scheduler and the cover snapshot survive the lock in memory. They hold
no message or identity keys. Stopping cover on lock would switch the cover stream
on and off in step with the user's presence.

While locked:

- Cover polls and cover deposits continue on the frozen snapshot.
- No real work is sent. The messaging service is removed and in-flight operations
  are drained. Any slot a drained sender had been granted becomes replacement cover.
- The provisioning loop stops. Real mailbox polling continues fetch-only on the
  frozen fetch plan, with the same schedule and selection
  ([S13 §8.3](13-privacy-hardening.md)).

On unlock, the existing Tor client and scheduler are reused. Nothing restarts.

Cover does not run before the first unlock of a process, because no Tor client
exists yet. If bootstrap fails, cover starts once a later bootstrap succeeds.
After a bridge change, cover resumes after the next unlock and bootstrap.

## 12. Reserved

## 13. Reserved

## 14. Delivery Modes

| Mode | Wire value | Stored setting `desktop:responsive` |
|------|------------|-------------------------------------|
| Responsive (default) | `"responsive"` | `true` |
| Timing privacy | `"privacy"` | `false` |

- The setting is a boolean in the encrypted profile settings
  ([S03](03-encrypted-storage.md)).
- On unlock, if the setting is absent, the native service MUST set it to `true`, so
  new profiles start in Responsive mode. An embedder that uses the C ABI without
  the desktop client treats an absent setting as Timing privacy
  ([S17](17-ffi-bindings.md)).
- The local service operation is
  `{"kind": "set_delivery_mode", "mode": "responsive" | "privacy"}`. Any other
  value MUST be rejected with `invalid_request`. The profile MUST be unlocked. The
  new mode is saved and applied immediately through `SlotSource::set_bypass`,
  including to queued work.
- The network status reports the mode as `deliveryMode`.

| Behavior | Responsive | Timing privacy |
|----------|------------|----------------|
| Real messages, control messages, ACKs, receipts | Deposited immediately | Wait for a deposit slot (§6.1) |
| Registrations and prekey publication | Immediate | Wait for a tier-6 slot (§5.2) |
| Boosts from real sends | None | Yes (§8.1) |
| Decoy boosts | Yes | Yes |
| File-part circuits | `FileTransfer` per file (§9) | `OneShot` per attempt |
| ACKs after a poll | Sent at the end of the batch, no slot | Each waits for a slot |
| Cover polls and deposits | Run | Run |
| Send-timing exposure | Send time is visible | Hidden at slot granularity outside boosts |

**Mailbox release timing.** The supplied mailbox configurations
(`scripts/deployment/config/mailbox.toml` and `mailbox-test.toml`) set
`min_hold_secs = 0`, `max_hold_secs = 0` and `jitter_secs = 0` in `[batching]`. A
deposit is fetchable as soon as it is stored. An operator may configure a hold
([S16](16-mailbox-server.md)). The client does not depend on one.

## 15. Security Considerations

Cover traffic and Timing privacy reduce some timing and volume signals under the
conditions stated here. Neither mode provides a global traffic-analysis guarantee,
and there is no numerical bound on how quickly an observer could link activity.

- **Global observers.** An adversary who watches many mailboxes, or both the user's
  guard and the mailboxes, can still correlate deposits with fetches. With the
  supplied zero-hold mailbox configuration, a deposit becomes fetchable
  immediately, so the server adds no delay that would blur that correlation.
- **Responsive exposes send timing.** Real deposits happen when the user sends, in
  addition to cover.
- **Boosts.** In Timing privacy, a burst of user messages raises the slot rate.
  Every window lasts exactly 120 s, real or decoy (§8.1), so a single window's
  length says nothing. Decoys fire about once an hour, though. Sustained activity,
  such as a file transfer, opens a new window soon after each one closes, so
  windows that follow one another closely, or many windows in an hour, still
  point to real activity.
- **Circuit construction.** Every deposit, real or cover, builds a fresh
  onion-service circuit, so an observer at the user's guard cannot separate real
  deposits from cover by the circuit build. Cover polls reuse one circuit per own
  mailbox, as real fetches do. A deposit to a contact's mailbox is still real
  (see Destinations).
- **Sizes.** Cover uses only buckets up to 4,096 bytes. File parts use larger
  buckets, so a file transfer is visible by blob size in both modes. There is no
  same-bucket cover during transfers, and dummy queues (§5.1) receive only cover
  sizes.
- **Destinations.** Cover goes only to the user's own mailboxes. Every deposit the
  user makes to a contact's mailbox is real, and that mailbox's operator sees each
  one.
- **Lock and process state.** Cover and real polling continue under lock with the
  same schedule and selection, but a locked poll acknowledges nothing, so blobs
  waiting on a real queue are fetched again and again until unlock
  ([S13 §20](13-privacy-hardening.md)). Continuing cover also shows that Najwa is
  running. Exiting the
  native service, or a sleeping or powered-off computer, stops cover and polling,
  and that on/off pattern is visible.
- **Linkage through proof of work.** A proof-of-work challenge uses the isolation
  of the request it gates, so a cover registration's challenge rides its own
  `OneShot` circuit and does not link the registration to the user's real
  traffic ([S04 §13](04-transport.md)). The operator still sees the challenge and
  the registration arrive close together.
- **Records.** A mailbox operator who keeps or is compelled to hand over records
  can provide deposit and fetch timing and capability metadata for the retention
  window (at most 90 days per capability, [S16](16-mailbox-server.md)). The blobs
  remain opaque ciphertext.
- **What cover does not do.** It does not protect content (end-to-end encryption
  does) and does not help against an adversary who controls the user's device.

See the [threat model](../understanding/threat-model.md) and
[security properties](../security/properties.md).

## 16. Conformance Checklist

- `CoverTrafficConfig` levels Low/Medium/High; the application runs `High`, ±25 %
  jitter, Speed-Priority boosts; no UI-state rate coupling (§2).
- Exponential slot sampling with a 1 s floor, secondary jitter and no upper cutoff;
  monotonic timers with no replay of missed slots (§3).
- Separate poll, deposit and decoy timers; each slot runs as a job bounded by
  120 s (§4.1).
- Cover poll on a random eligible mailbox's cover fetch capability with
  `limit = 100`, followed by acknowledgement of returned blobs (§4.2).
- Cover deposit built per §2.3: envelope-wrapped CSPRNG inner of `bucket − 40`
  bytes, final size exactly one of 256–4,096; no proof of work (§4.3).
- `CoverTraffic(onion)` isolation for cover polls and acknowledgements (§4.2); a
  new `OneShot` circuit for every cover deposit (§4.3).
- Eligibility: enabled, `failure_count < 5`, cover registration accepted, cover
  values present; snapshot holds cover material only (§4.3).
- Dedicated cover capabilities and self-generated cover envelope secret per
  mailbox, registered as type 2 with proof of work by the provisioning loop (§5).
- Nine dummy pairs per mailbox, provisioned after the cover pair and registered
  the same way; cover deposits pick their target uniformly from the cover pair and
  the active dummies; dummies fetched only by the real poll (§5.1).
- Registrations and prekey publications wait for a tier-6 slot in Timing privacy,
  each on its own `OneShot` circuit; proof of work solved before the wait, with
  its challenge on its own `OneShot` circuit (§5.2).
- Per-mailbox pending queues, uniform choice among non-empty queues, tier order
  with FIFO within a tier, 1 s slot lease, replacement cover for unclaimed slots,
  no double deposit per slot (§6.1).
- `await_slot` returns immediately when bypassed or when the scheduler is not
  running; stopping releases waiters (§6.2).
- ACKs at tier 3 and read receipts at tier 4 as durable outbox frames (§7).
- Boost window of exactly 120 s, opened by a tier-1 wait or a decoy (mean
  3,600 s) only when no window is open, and never extended; opening does not
  reset the deposit timer; deposit mean divided by 4 inside a window; windows
  counted once (§8.1).
- File parts: one slot and one `OneShot` circuit per attempt in Timing privacy;
  `FileTransfer` key per §9 in Responsive (§9).
- Internal-only `CoverStats` (§10).
- Cover survives lock and stops on process exit, erase and bridge change (§11).
- Delivery-mode values `"responsive"` and `"privacy"`, Responsive default on
  unlock, immediate effect (§14).
