---
id: S12
title: Disappearing Messages
crates: [najwa-core, najwa-storage]
depends-on: [S03, S07, S08, S13]
---

# S12 — Disappearing Messages

## Overview

A conversation can carry a timer. While it is on, every new message in that conversation
is deleted from this app's storage a fixed time after a trigger: on the sender's device after
the recipient confirms delivery, on the recipient's device after the message was displayed.
Each device enforces the timer on its own copy. The timer limits how long this application
keeps messages; it cannot force a recipient, or anything outside the application, to forget
what was shown.

The design rests on four rules:

- **Either side may change the setting, and both converge.** A change carries the time it
  was made (`set_at`). The latest change wins on both devices; equal times are broken by
  identity key (§2.2).
- **The countdown starts at a trigger, with a bound.** Each message gets a deadline when it
  is stored: a long fallback. Delivery (sender) or display (recipient) pulls the deadline
  in to `trigger + timer`. A message never disappears before it could be read, and a message
  that is never delivered or never opened still disappears (§3).
- **Destroying a key destroys the content.** The stored content of a disappearing message
  is encrypted under its own random key, held in memory. Expiry discards that key before
  anything else, so the ciphertext left behind is useless even if overwriting it on disk
  fails (§4, §5).
- **The timer survives lock and restart.** At lock the per-message keys are written to the
  encrypted database under the database key. At unlock, expired keys are discarded before
  anything else runs (§4.3).

Timer changes travel as the encrypted `TimerChange` control message (subtype `0x01`,
[S07](07-message-format.md)). Message handling is in [S08](08-messaging-service.md); the
tables are in [S03](03-encrypted-storage.md).

## 1. Scope

This specification defines:

- timer values, the per-conversation setting and its last-writer-wins merge;
- the `TimerChange` control message and the rules around sending one;
- sender and recipient deadlines, triggers and fallbacks;
- per-message key sealing and opening;
- key persistence across lock and the unlock-time purge;
- the deletion flow, secure file deletion and the background cleanup task;
- the `DisappearingStorage` trait and the cleanup manager;
- interaction with search, backup, notifications and files.

## 2. Timer Configuration

### 2.1 Timer Options

A timer is a `u32` number of seconds.

```
MIN_TIMER_SECS = 30
valid values   = 0 (off) | 30 ..= 4,294,967,295
default        = off (no stored setting)
```

```
enum DisappearTimer {
  Off,          // 0
  Seconds30,    // 30
  Minutes5,     // 300
  Hour1,        // 3,600
  Hours24,      // 86,400
  Days7,        // 604,800
  Days30,       // 2,592,000
  Custom(u32),  // any other valid value
}
```

The desktop app offers Off, 30 seconds, 5 minutes, 1 hour, 1 day, 7 days, 30 days, and a
custom whole number of seconds of at least 30.

**Validation (normative).** A value in `1..=29` MUST be rejected at every input boundary:

| Boundary | Behaviour on `1..=29` |
|---|---|
| Local web API (`set_timer` operation) | `invalid_request` |
| Desktop client `set_timer` | `invalid_timer` |
| `MessagingService::enqueue_timer_change` | error, nothing committed |
| Storage (`set_conversation_timer_setting`, `commit_outgoing_timer`) | `InvalidData`, transaction rolled back |
| Received `TimerChange` | ignored; the frame is still committed and acknowledged |

### 2.2 Per-Conversation Setting — last-writer-wins (normative)

The setting of a conversation is the triple `(timer_secs | off, set_at, setter_ik)`:
`set_at` is the Unix-seconds time the setting was made and `setter_ik` the Ed25519 identity
public key of the party that made it. "Off" is a setting with its own `set_at`, not the
absence of one: deleting it would let an older timer win the next exchange.

```
func timer_setting_wins(current, incoming) → bool:
  if current is None:                 return true
  if incoming.set_at > current.set_at: return true
  if incoming.set_at < current.set_at: return false
  return incoming.setter_ik < current.setter_ik    // unsigned bytewise over 32 bytes
```

An incoming setting replaces the current one only if `timer_setting_wins` returns true.
Equal `set_at` and equal setter keep the stored setting. Because `set_at` travels on the
wire (§2.3) and the tie-break is deterministic, both devices reach the same setting whatever
order the changes arrive in.

**Future bound (normative).** A received setting whose `set_at` is greater than
`now + MAX_FUTURE_SKEW_SECS` (300 s, [S07 §7.1](07-message-format.md)) is ignored and never
enters the merge; `now` is the same corrected clock S07 §7.1 uses. Accepted, such a value
would beat every later change, and `2^64 − 1` would make the local `previous_set_at + 1`
step (§2.3) overflow, so the user could never change the timer again. Every stored remote
`set_at` is therefore at most 300 s ahead of the time it was received, and a local change,
stamped `max(now, previous_set_at + 1)`, always supersedes it. There is no lower bound: a change
retransmitted after a long outage keeps its original `set_at`.

A change applies to future messages only. Each message row captures the timer value in
effect when it was committed (§3) and keeps it.

### 2.3 Timer Change Control Message

```
TimerChange (control subtype 0x01), body 12 bytes:
  timer_secs : u32 BE    // 0 = off; otherwise ≥ MIN_TIMER_SECS
  set_at     : u64 BE    // Unix seconds, the §2.2 merge key
```

It travels as `content_type = 0x20` in a Normal frame ([S07 §4](07-message-format.md),
[S08 §5.1](08-messaging-service.md)).

**Sending (normative).**

1. The desktop client accepts a change only when the contact is ready (a session and a
   long-term target exist), no earlier local change awaits acknowledgement, and — when
   turning the timer on — no file transfer or attachment preparation for that contact is in
   progress (`file_preparing`).
2. `set_at = max(now, previous_set_at + 1)`, so a local change always supersedes the stored
   setting. `now` is the corrected clock that stamps Payload timestamps
   ([S07 §7.1](07-message-format.md)), so the peer's future bound (§2.2) accepts the change
   even when the system clock runs fast. If `previous_set_at + 1` overflows, the change is
   refused; the §2.2 future bound keeps any received value far from that limit.
3. One `commit_outgoing_timer` transaction commits the encrypted frame to the outbox, applies
   the new setting locally with `setter_ik` = own identity key, and records the pending
   marker `pending_timer:<contact_id>` naming the frame.
4. The outbox delivers the frame and re-deposits it byte-identically until a `CumulativeAck`
   covers it ([S08 §10.1.1](08-messaging-service.md)). That ACK deletes the frame and ends
   the pending state.
5. While the change is pending, the client refuses to send text or files to the contact and
   to make another timer change (`timer_pending`). The app shows the pending state.

The ACK proves the peer committed the change before any further content is sent, so both
devices store the following messages under the same setting unless both change it at the
same time.

**Receiving (normative).** A body shorter than 12 bytes is rejected; bytes after the twelfth
are ignored. A `timer_secs` in `1..=29`, or a `set_at` beyond the §2.2 future bound, is
ignored; the frame is still committed and acknowledged. Otherwise the receiver merges
`(timer_secs, set_at, sender IK_pub)` by §2.2 and stores the winning setting in the same
transaction that commits the frame ([S08 §6.4](08-messaging-service.md)). A `TimerChange`
never appears as a message in the conversation.

### 2.4 Stored Setting

```
struct TimerSetting {
  timer_secs: Option<u32>,   // None = off
  set_at:     u64,           // Unix seconds
  setter_ik:  [u8; 32],      // Ed25519 IK_pub of the setter
}
```

Stored in the settings table under `disappear_timer:<contact_id>` as a 44-byte value
`timer_secs(u32 BE, 0 = off) ‖ set_at(u64 BE) ‖ setter_ik(32)`. A 4-byte value holding only
`timer_secs` reads as `set_at = 0` with an all-zero setter, so any timestamped setting
supersedes it. A stored remote `set_at` passed the §2.2 future bound when it was received.

Each message row stores its timer in the `messages.disappear_timer` column
([S03](03-encrypted-storage.md)) as an unsigned 32-bit value: every valid timer up to
`4,294,967,295` is written and read back unchanged. Implementations MUST NOT narrow it to a
signed 32-bit integer; a value that does not fit would make the row, and so the
conversation, fail to load.

## 3. Timer Behaviour

**Deadline model (normative).** A disappearing message row stores `disappear_timer` (the
timer in seconds) and `disappear_at` (the deadline, in local milliseconds). The row is
committed with a fallback deadline. When its trigger fires, the deadline becomes
`min(disappear_at, trigger_time + timer)`. A deadline is never extended. A message has
expired when `disappear_at ≤ now`.

The fallback guarantees expiry when a trigger never fires; the trigger makes the countdown
start when the message was actually delivered or seen.

### 3.1 Sender Side

```
SENDER_FALLBACK_SECS = 86,400   // 24 hours
```

| Event | Deadline |
|---|---|
| The message is committed | `sent_at + (SENDER_FALLBACK_SECS + timer) × 1000` |
| A `CumulativeAck` covers the message ([S08 §6.6](08-messaging-service.md)) | `min(deadline, ack_at + timer × 1000)` |
| A `ReadReceipt` names the message before any ACK | `min(deadline, receipt_at + timer × 1000)` |

ACK coverage is exact: a covered message was decrypted and durably stored by the recipient,
so the sender's copy never starts its countdown before delivery.

### 3.2 Recipient Side

```
RECIPIENT_FALLBACK_SECS = 604,800   // 7 days
```

| Sender's `ReadReceiptRequested` flag (bit 2) | Deadline at commit | When displayed |
|---|---|---|
| set | `decrypted_at + (RECIPIENT_FALLBACK_SECS + timer) × 1000` | `min(deadline, displayed_at + timer × 1000)` |
| clear | `decrypted_at + timer × 1000` | `min(deadline, displayed_at + timer × 1000)` |

"Displayed" means the message was visible in the focused conversation
([S08 §6.6](08-messaging-service.md)). A release peer requests receipts on every text and
reply, so their countdown starts on display, bounded by the 7-day fallback. Display of an
expired message has no effect.

A row that carries a timer but no deadline is given the deadline its trigger or fallback
implies by the cleanup task (§6): `read_at + timer` if it was displayed, otherwise the
fallback of this section or §3.1.

## 4. Ephemeral Key Storage

### 4.1 Store Flow

When the conversation timer is on at commit time, the content stored at rest is sealed:

```
func seal_content(cache, msg_id, plaintext) → bytes:
  K_msg = CSPRNG(32)                      // one key per message
  cache.insert(msg_id, K_msg)             // volatile memory only, zeroised on removal
  nonce = CSPRNG(24)
  return nonce(24) || XChaCha20-Poly1305-Encrypt(K_msg, nonce, plaintext, aad = msg_id(16))
```

The AAD is the 16-byte transport `msg_id` ([S07 §6.1](07-message-format.md)), binding the
ciphertext to its message. The sealed blob, `disappear_timer` and the fallback deadline
commit in the same transaction as the message row ([S08 §3](08-messaging-service.md)).

Sealing applies to every row committed while the timer is on: sent and received user
content, items recovered by gap repair, hidden control rows and introduction notices. The
local decision uses the receiving device's own conversation setting.

The sender sets payload flag bit 0 (`Ephemeral`, [S07 §4.2](07-message-format.md)) on new
content sent while the timer is on. The ratchet-encrypted wire copy is not sealed. The
gap-repair record of a sealed message holds the sealed blob, never the plaintext
([S08 §5](08-messaging-service.md)).

### 4.2 Read Flow

```
func open_sealed_content(cache, msg_id, blob) → Plaintext(bytes) | Expired:
  K_msg = cache.get(msg_id)
  if K_msg is None: return Expired
  if len(blob) < 24: error
  return Plaintext(XChaCha20-Poly1305-Decrypt(K_msg, blob[0..24], blob[24..], aad = msg_id))
       // authentication failure is an error, not expiry
```

Every reader — the conversation view, history, attachments, the gap-repair responder and the
re-send responder ([S08 §6.5, §10.2](08-messaging-service.md)) — MUST:

- skip a row whose deadline has passed, evicting its key;
- treat `Expired` as "no content": the row is not shown and its content is not re-sent;
- never show or send the sealed bytes.

### 4.3 Lock Persistence and Unlock Cleanup

The desktop client locks on user request, after the inactivity timeout and at shutdown
([S13 §8](13-privacy-hardening.md)). Every lock persists the keys:

```
func on_lock(db_key):
  stop the cleanup task
  run_cleanup_once()                                    // §6
  in one transaction:
    delete every volatile_keys row
    for (msg_id, K_msg) in cache:
      if the message exists, has a timer and is unexpired:
        nonce = CSPRNG(24)
        insert volatile_keys(msg_id,
               encrypted_key = nonce(24) || XChaCha20-Poly1305-Encrypt(db_key, nonce, K_msg,
                                                                      aad = "volatile-key"),
               expires_at = message.disappear_at)
  wal_checkpoint(TRUNCATE)
  cache.zeroize_all()
  // on any failure: the lock fails, keys stay in memory, the cleanup task restarts
```

The persisted key is 72 bytes (`24 + 32 + 16`). A storage trigger keeps `expires_at` equal
to the message's `disappear_at`, and deleting a message deletes its key row.

**Unlock-time cleanup — normative MUST.** On unlock, before the storage handle is published
to any other code, before any message is rendered and before network bootstrap:

```
func on_unlock(db_key):
  // STEP 1 (MUST be first), one transaction:
  delete volatile_keys rows with expires_at ≤ now
  live = rows whose message still has a timer and is unexpired
  delete every volatile_keys row
  // STEP 2: restore
  for row in live: cache.insert(row.msg_id, Decrypt(db_key, row.encrypted_key, "volatile-key"))
                   // a row that fails to decrypt is dropped
  // STEP 3
  run_cleanup_once()                                    // §6
  start the cleanup task (every 10 s)
```

Keys are on disk only while the profile is locked or closed. By the time the UI can show
anything, no key exists for a message whose deadline has passed.

### 4.4 Invariant

**After a message's deadline passes and the next cleanup pass or reader runs, its key exists
nowhere: not in memory and not in storage.** The invariant is approximate, not
instantaneous:

- While unlocked, cleanup runs every 10 seconds and every reader checks deadlines.
- While locked or closed nothing runs. An expired message's row and encrypted key remain on
  disk, protected by the database key, until the next unlock removes them first.

Immediate "no-trace" deletion MUST NOT be claimed to users.

## 5. Deletion Flow

### 5.1 Delete Expired Messages

```
func delete_expired_messages(storage, cache):
  expired = storage.get_expired_disappearing_messages(now_ms)    // disappear_at ≤ now
  for msg in expired: cache.remove(msg.msg_id)                   // 1. keys first, all of them
  storage.purge_expired_volatile_keys(now_ms)                    // 2. persisted keys
  for msg in expired:
    storage.overwrite_message_content(msg.id, empty)             // 3. content
    if msg.file_path exists: secure_delete_file(msg.file_path)   // 4. media, failure logged
    storage.delete_message(msg.id)                               // 5. row
  if expired is non-empty: storage.wal_checkpoint()              // 6. PRAGMA wal_checkpoint(TRUNCATE)
```

Keys are evicted before any fallible storage or file operation: even if a later step fails,
the remaining ciphertext cannot be opened. Storage triggers complete the removal:
overwriting the content deletes the message's queued outbox frames, outbound history and
gap-repair record; deleting the row deletes its key row and any remaining repair record.
The database runs with `PRAGMA secure_delete = ON`, so freed pages are overwritten.

### 5.2 Secure File Deletion

```
func secure_delete_file(path):
  overwrite the file with random bytes of its size
  fsync(file)
  remove(path)
  fsync(parent directory)    // best-effort: a platform that refuses (Windows) is not an error
```

Overwriting is best-effort on SSDs, flash and copy-on-write filesystems. The key deletion of
§5.1 is the primary defence.

## 6. Background Cleanup Task

```
DEFAULT_CLEANUP_INTERVAL_SECS = 10
FALLBACK_TIMEOUT_MS           = 86,400,000

func run_cleanup_once():
  r1 = assign missing deadlines (§3; legacy cutoff now_ms − FALLBACK_TIMEOUT_MS for sent rows)
  r2 = delete_expired_messages()          // runs even if r1 failed
  r3 = wal_checkpoint()                   // also flushes purged key rows
  return first error of (r1, r2, r3)
```

| When | Cleanup |
|---|---|
| Unlocked | every 10 s, independent of Tor connectivity |
| Unlock | once, before anything else (§4.3) |
| Lock | once, before keys are persisted (§4.3) |
| Locked or closed | none |

The `najwa-ffi` cleaner task also runs the storage retention pass
([S03 §6.4](03-encrypted-storage.md)) after its cleanup: on the first tick after
unlock and then once an hour. It stops with the cleaner at lock.

## 7. `DisappearingStorage` Trait

The cleanup task works through this trait. The production implementation is
`Arc<SqliteStorage>`; all deadlines are local milliseconds.

```
trait DisappearingStorage {
  set_conversation_timer(contact_id, Option<u32>)
  get_conversation_timer(contact_id) → Option<u32>
  set_conversation_timer_setting(contact_id, Option<u32>, set_at, setter_ik)
  get_conversation_timer_setting(contact_id) → Option<(Option<u32>, u64, [u8; 32])>
  set_message_disappear_pending(id, timer_secs)
  get_message_disappear_pending(id) → Option<u32>
  set_message_disappear_at(id, disappear_at)
  apply_fallback_disappear_timers(cutoff) → u32
  get_expired_disappearing_messages(now) → Vec<ExpiredMessage>
  overwrite_message_content(id, bytes)
  delete_message(id)
  purge_expired_volatile_keys(now) → u32
  wal_checkpoint()
  search_messages_excluding_disappearing(query, now) → Vec<Message>
  get_messages_for_backup(now) → Vec<Message>
}

struct ExpiredMessage { id: i64, msg_id: [u8; 16], file_path: Option<String> }
```

## 8. `DisappearingMessageManager`

`DisappearingMessageManager<S: DisappearingStorage>` wraps the storage for the cleanup task,
which calls `apply_fallback_timers()` (cutoff `now_ms − FALLBACK_TIMEOUT_MS`) and the deletion
of §5.1. Timer changes do not go through the manager: local changes use
`MessagingService::enqueue_timer_change` (§2.3, [S08 §5.1](08-messaging-service.md)) and
received changes are merged in the receive commit ([S08 §6.4](08-messaging-service.md)). Both
use `timer_setting_wins` (§2.2).

```
enum DisappearError {
  StorageError(String),
  IoError(io::Error),       // secure file deletion
  InvalidTimer(String),     // 1..=29 seconds
  CryptoError(String),      // malformed sealed blob or failed authentication
}
```

## 9. Integration with Other Features

### 9.1 Search

Conversation search MUST NOT return disappearing messages. The release excludes every row
with payload flag bit 0, a timer or a deadline from search results, whether or not it has
expired. Expired rows are also excluded from every message listing.

### 9.2 Backup

The release has no message-history backup or export. Any backup or export of the message
store MUST exclude disappearing messages, their keys and their repair copies, selected by
the `Ephemeral` flag or a stored timer, regardless of whether a deadline is set.

### 9.3 Notifications

The desktop client shows no operating-system notifications, so no message content or
disappearing status reaches the notification system.

### 9.4 Files

Sending a file requires the conversation timer off:

- the desktop client refuses a file send while the timer is on or a timer change is pending
  (`file_timer_unsupported`), and the service refuses to queue file metadata or chunks
  (content types `0x10`, `0x11`) while the timer is on;
- turning the timer on is refused while a file transfer or attachment preparation for that
  contact is in progress (§2.3).

A file announced by a peer while the timer is on is stored sealed like any other row, but
the client does not reassemble disappearing file parts or offer the file for download.

## 10. Constraints

- Disappearing messages MUST NOT appear in search (§9.1).
- Media files MUST be securely deleted on expiry (best-effort on flash, §5.2).
- Backups MUST NOT include disappearing messages (§9.2).
- `TimerChange` frames are kept only as hidden control rows and are not shown in the
  conversation.
- The minimum non-zero timer is `MIN_TIMER_SECS = 30`; smaller values are rejected (§2.1).
- The `volatile_keys` table ([S03 §5.13](03-encrypted-storage.md)) holds keys only while the
  profile is locked or closed (§4.3).
- On unlock, expired key rows MUST be purged before any other work (§4.3).
- **No resurrection.** A deleted message cannot be re-created by a replayed or late-released
  copy of its blob: dedup entries are kept for at least 90 days, the mailbox's hard retention
  cap ([S08 §9.4](08-messaging-service.md)). Responders MUST NOT re-send expired content in
  gap repair or in answer to `ReSendRequest` ([S08 §6.5, §10.2](08-messaging-service.md)).

## Limitations

- **Retention control, not erasure.** The timer does not remove screenshots, copied text,
  exported or downloaded files, the peer's copy on a device that ignores timers, operating
  system swap, hibernation or crash dumps, or older blocks kept by SSD wear-levelling,
  filesystem snapshots or backups of the profile directory.
- **Nothing runs while locked or closed.** Expiry is enforced when the profile is next
  unlocked (§4.4). A computer that is off deletes nothing.
- **A crash loses keys.** Keys reach disk only at lock. After a crash or forced termination,
  every disappearing message stored before it becomes unreadable at once and is deleted at its
  deadline.
- **Not a synchronised remote wipe.** The sender's trigger (delivery) and the recipient's
  (display) are independent, and a timer change reaches the peer only when it next fetches.
- **Each device applies its own setting.** If both parties change the timer at the same time,
  messages sent before the changes converge can be kept by one side and timed on the other.
- **A peer with a clock more than 5 minutes fast cannot change the timer.** Its changes carry
  a `set_at` beyond the §2.2 future bound and are ignored, though acknowledged, so the two
  devices can hold different settings until that clock is corrected. A local change made
  meanwhile reaches the peer with an older `set_at` than the peer's own setting and loses
  there.
- **Transport metadata is unaffected.** Mailbox operators still see deposits and fetches, and
  a mailbox keeps the encrypted blob until it is acknowledged or its retention expires
  ([S16 §10](16-mailbox-server.md)).

## 11. Conformance Checklist

- Timer values `0` or `30..=4,294,967,295`; `1..=29` rejected at the web API, desktop client,
  service and storage; ignored on receive.
- `DisappearTimer` presets and `to_secs` / `from_secs`.
- Setting `(timer_secs | off, set_at, setter_ik)` stored as a 44-byte value; off stored with
  its own `set_at`; 4-byte values read with `set_at = 0`.
- `messages.disappear_timer` written and read as `u32`; `4,294,967,295` round-trips and the
  conversation still lists.
- Last-writer-wins merge on `set_at` with lex-smaller `IK_pub` tie-break, unsigned bytewise.
- Received `set_at` greater than `now + MAX_FUTURE_SKEW_SECS` ignored (frame still committed
  and acknowledged); a later local change always wins over any accepted remote value.
- `TimerChange` body `timer_secs(u32 BE) ‖ set_at(u64 BE)`; short bodies rejected.
- Local change: `set_at = max(now, previous + 1)` on the corrected clock; frame, local
  setting and pending marker in one transaction; retransmitted until ACKed; text, file and
  timer sends refused while pending; enabling refused during file preparation.
- Deadline model: fallback at commit, `min(deadline, trigger + timer)` on trigger, never
  extended.
- Sender fallback `SENDER_FALLBACK_SECS = 86,400`; ACK and read-receipt triggers.
- Recipient fallback `RECIPIENT_FALLBACK_SECS = 604,800` when receipts are requested; decrypt
  time otherwise; display trigger for focused, visible messages.
- Per-message CSPRNG key; sealed blob `nonce(24) ‖ XChaCha20-Poly1305(K_msg, nonce, pt,
  aad = msg_id)`; seal, timer and deadline committed with the row; repair records sealed.
- Readers skip expired rows, evict their keys and treat a missing key as expired.
- Lock: cleanup, atomic replacement of `volatile_keys` with
  `nonce ‖ XChaCha20-Poly1305(db_key, nonce, K_msg, "volatile-key")` for live messages, WAL
  checkpoint, cache zeroised; failed lock keeps keys and restarts cleanup.
- Unlock: purge expired rows and take live keys in one transaction before publishing storage,
  rendering or bootstrap; restore; cleanup; start the 10 s task.
- Deletion: evict all expired keys first; purge persisted keys; overwrite content; secure-delete
  media; delete row; WAL checkpoint; `secure_delete = ON`; triggers remove outbox frames,
  history, repair records and key rows.
- `secure_delete_file`: random overwrite, fsync, remove, best-effort parent fsync.
- Cleanup task every 10 s while unlocked, independent of Tor; fallback assignment, deletion and
  checkpoint each attempted.
- Search excludes every disappearing row; expired rows excluded from all listings.
- File sends refused while the timer is on; disappearing file parts never reassembled.
- Dedup retention of at least 90 days; responders never re-send expired content.
