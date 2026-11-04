---
id: S13
title: Privacy Hardening & Account Lifecycle
crates: [najwa-privacy, najwa-ffi, najwa-web]
depends-on: [S02, S03, S04, S08, S10, S12, S17]
---

# S13 — Privacy Hardening & Account Lifecycle

## Overview

This part covers what Najwa does to limit what someone with access to the
computer can learn from a profile, and how a profile ends.

The native local service (`najwa-web`) holds the identity and the database key
only while the profile is unlocked. Locking destroys those keys in memory, saves
the few keys that disappearing messages need in encrypted form, and empties the
database's write-ahead log. The profile locks when the user presses Lock, when
the page closes, when the service stops, when the operating system locks the
session, switches user or goes to sleep, and after a period without user
activity: five minutes by default, adjustable from one minute to one hour. A
per-page "Keep unlocked" option pauses the inactivity timer for long transfers
and switches itself off at the next lock.

Locking is not going offline. The Tor connection, cover traffic and mailbox
polling continue while the profile is locked, on the same schedule and with the
same choice of receive queues, so a lock does not mark the moment the user walked
away ([S10 §11](10-cover-traffic.md), §8.3). A locked poll only fetches: nothing
is decrypted or acknowledged, and waiting messages are processed after unlock.

Local erasure removes a profile from this computer. It first records its intent
on disk. If the profile is unlocked, it then asks each of the user's mailboxes,
over Tor and within 20 seconds, to deactivate the user's receive queues, and
reports which mailboxes it reached. It then deletes the profile's device key
from the OS key store and overwrites and removes every file in the profile
directory, whatever the mailboxes answered. A locked profile is erased locally
only. If anything fails, the profile stays in an erasing state that cannot be
unlocked, and erasure can be retried after a restart. Messages already waiting
at mailboxes, contacts' copies and the user's recovery kit are outside its
reach.

The browser is an untrusted renderer on the same machine. The service listens
only on loopback, accepts API calls only with a per-process token in a custom
header, checks `Host`, `Origin` and `Sec-Fetch-Site`, sends strict response
headers, and never puts secrets in browser storage (§19).

Najwa cannot protect a profile against malware running as the same user.

## 1. Scope

This specification defines:

- receive handling of typing indicators and the link-preview policy (§5, §6);
- inactivity auto-lock, lock triggers, the lock procedure and the
  "Keep unlocked" option (§8);
- local profile erasure and its limits (§10);
- the error codes of these operations (§15);
- memory zeroization (§17) and log hygiene (§18);
- the protections at the browser–service boundary (§19).

Identity unlock, passphrases and the device key are specified in
[S02](02-identity-key-protection.md). Database encryption and the profile layout
are in [S03](03-encrypted-storage.md). Disappearing-message keys are in
[S12](12-disappearing-messages.md). The native lifecycle and drain contract is in
[S17 §4.1](17-ffi-bindings.md).

## 2. Reserved

## 3. Reserved

## 4. Reserved

## 5. Typing Indicators

The release never sends a typing indicator.

A received `TypingIndicator` control (control type `0x02`, empty body,
[S08 §6.4](08-messaging-service.md)) goes through the normal receive transaction
for ratchet, dedup and acknowledgement ([S03 §6.1](03-encrypted-storage.md)).
It is then dropped: it is not stored as a message and produces no UI event.

## 6. Link Previews

The release does not generate, request or display link previews. Received text
is displayed as plain text, and the page's Content-Security-Policy (§19) blocks
loads from any origin other than the local service.

A client MUST NOT fetch a URL found in received content. Fetching it would reveal
the recipient's network location and that the message was opened.

## 7. Reserved

## 8. Inactivity Auto-Lock and Related Lock Settings

### 8.1 Constants

| Constant | Value | Source |
|----------|-------|--------|
| Default inactivity timeout | 300 s | `LocalPreferences::default` |
| Minimum timeout | 60 s | `LocalPreferences::normalized` |
| Maximum timeout | 3600 s | same |
| Choices offered by the UI | 60, 300, 900, 1800, 3600 s | `Preferences.svelte` |
| Idle check interval | 5 s | `apps/local-web/src/main.rs` |
| Minimum spacing of page activity reports | 30 s | `LocalWeb.svelte` |
| "Keep unlocked" report interval | 15 s (subject to the 30 s spacing) | same |
| Lock drain deadline (`LOCK_DRAIN_DEADLINE_MS`) | 5000 ms | `crates/najwa-ffi/src/state.rs` |
| macOS session lock check interval (§8.5) | 2 s | `apps/local-web/src/os_lock.rs` |

The timeout is stored in the encrypted `settings` table under
`desktop:local-preferences` ([S03 §5.16](03-encrypted-storage.md)) and loaded at
every unlock.

- Saving a timeout outside 60–3600 s MUST fail with `invalid_preferences`.
- A stored value that does not parse or is out of range MUST fail the unlock
  with `invalid_preferences`. It MUST NOT fall back to a default or disable
  locking.
- There is no setting that disables the inactivity lock.

The profile locks when it has been unlocked with no activity (§8.6) for at least
the timeout. The idle worker checks every 5 s, so the lock begins within 5 s of
the deadline.

### 8.2 Auto-Lock

Every lock trigger (§8.5) runs this procedure:

```
func lock():
    // Fence (Owner::begin_lock)
    if phase in {wiping, erased}: return        // erasure owns the profile (§10)
    generation += 1
    phase = "locking"
    signal cancellation to in-flight messaging operations

    // Drain and destroy (Owner::finish_lock → DesktopClient::lock → najwa_lock)
    close admission of key-using operations
    wait up to LOCK_DRAIN_DEADLINE_MS for in-flight operations
    if not drained: fail lock_failed
    stop the disappearing-message cleaner
    clear native callbacks
    run one disappearing-message cleanup pass                  // S12 §6
    save the volatile key cache to volatile_keys under db_key  // S03 §5.13
    wal_checkpoint(TRUNCATE)                                   // S03 §6.3
    if any of the last three steps fails:
        restart the cleaner; fail lock_failed
    zeroize the volatile key cache
    refresh cover mailboxes and the fetch plan from storage    // §8.3
    drop db_key, the identity keys, both storage handles and the messaging service
    lock the identity manager; drop displayed recovery words

    // Publish
    if a transport reset is pending (§8.5): destroy and re-create the messaging runtime
    phase = "locked"   (or "absent" if no identity record exists)
    on any failure: phase = "error"
```

Requirements:

- The fence MUST come first. Advancing `generation` makes every in-flight browser
  request stale, and every operation re-validates its session and generation
  after it runs, so a result that straddles a lock is discarded with
  `stale_operation`.
- Keys MUST NOT be zeroized while a key-using operation is still running
  ([S17 §4.1](17-ffi-bindings.md)).
- A lock that fails MUST NOT be reported as locked. Keys stay in memory, the
  phase becomes `error`, the API returns `lock_failed`, and the user retries.
- Disappearing-message keys are saved at every lock, whatever the trigger, and
  taken back at unlock ([S12 §4.3](12-disappearing-messages.md)).

A lock leaves running: the local HTTP service, the profile lease, the browser's
API token, the Tor client, cover traffic with its cover capabilities and
envelope secrets ([S10 §11](10-cover-traffic.md)), and the receive worker with
its fetch plan (§8.3). It destroys every key that can decrypt identity, sessions,
history or the database.

### 8.3 Polling While Locked

The receive worker that an unlock starts keeps running through the lock that
follows, on the same exponential schedule ([S08 §10.1](08-messaging-service.md)).
It stops when the next unlock starts its own worker, or when the messaging runtime
is destroyed.

```
func receive_tick():                      // after each exponential gap
    if unlocked: sync()                   // S08 §6.1 poll, setup and announcements
    else:        fetch_plan.poll_locked() // same selection, S08 §6.1.1
```

While locked, the native service keeps in memory only what fetching needs: the
onion address of each enabled mailbox and the fetch capabilities of its receive
queues and registered dummy queues, as captured by the last refresh before the
database closed. It keeps no envelope secret of a real queue, no identity, ratchet
or database key, and no database handle. A locked poll MUST:

- select queues exactly as an unlocked poll does (`k` from `[4, 10]`, the same
  round-robin rotation and dummies), over the same `ByMailbox` circuit;
- fetch each selected queue once with `limit = 10`, and nothing else: it MUST NOT
  decrypt, process or acknowledge any blob, so every blob stays on the mailbox
  until the first poll after unlock processes it.

The fetch plan is zeroized when the messaging runtime is destroyed: on profile
erase, on a bridge change and when the service quits (it tears the runtime down
after its final lock).

### 8.5 Relationship Between Settings

All lock triggers converge on §8.2:

| Trigger | Path |
|---------|------|
| Lock button | `POST /api/lock` |
| Page closed or navigated away | `pagehide` → `POST /api/lock` with `keepalive` (best effort) |
| Inactivity | The idle worker (§8.1) |
| Session locked, user switched, system going to sleep | The OS lock listener (below) |
| Quit | `POST /api/quit`: lock, then stop the service |
| Ctrl+C or service shutdown | Graceful shutdown locks before exit; the process exits with an error if the lock fails |
| Bridge setting changed | Lock, then destroy and re-create the messaging runtime so the old Tor connection is never reused; the new routing applies at the next unlock ([S04 §11](04-transport.md)) |
| Failed identity operation | Lock; a failed mutation never leaves messaging unlocked |
| Passphrase change, recovery, recovery-kit replacement | Messaging locks before the change and attaches again after it |

`POST /api/lock` requires the current session but accepts any generation, so a
lock can overtake an operation that has already advanced the generation.

The service runs an OS lock listener (`apps/local-web/src/os_lock.rs`). Each
event below runs `begin_lock` then `finish_lock`, exactly as `POST /api/lock`
does, whatever activity the page has reported:

| Platform | Events |
|----------|--------|
| Windows | A message-only window receives `WM_WTSSESSION_CHANGE` with `WTS_SESSION_LOCK`, `WTS_CONSOLE_DISCONNECT` or `WTS_REMOTE_DISCONNECT` (`WTSRegisterSessionNotification`), and `WM_POWERBROADCAST` with `PBT_APMSUSPEND` (`RegisterSuspendResumeNotification`). The lock runs before the window procedure returns. |
| Linux | System bus: logind `PrepareForSleep(true)`, and `Lock` on the session that `GetSession("auto")` returns. Session bus: `ActiveChanged(true)` on `org.freedesktop.ScreenSaver` or `org.gnome.ScreenSaver`. |
| macOS | IOKit `kIOMessageSystemWillSleep` (`IORegisterForSystemPower`); the system may sleep only after the lock returns. Every 2 s, the current session dictionary is read: the change to screen locked (`CGSSessionScreenIsLocked`) or off the console (`kCGSSessionOnConsoleKey` false, another user switched in) locks. |

- Unlock, wake and screen-saver-off events do nothing. Unlocking still requires
  the passphrase.
- A listener that cannot start (no window, no D-Bus bus, no logind session)
  prints one line to standard error (§18), and the service runs without that
  trigger.

The release has no lock-on-minimize.

### 8.6 Activity and Keep Unlocked

The idle deadline restarts when:

- the page sends `POST /api/activity` with the current session and generation
  while unlocked;
- an identity operation completes;
- preferences are saved.

The page reports activity on `pointerdown` and `keydown`, at most once every
30 s. Status polling, messaging calls, file transfers and network events are not
activity.

"Keep unlocked" is a checkbox shown on the page while the profile is unlocked.
It is off by default. While it is checked, the page reports activity every 15 s
(subject to the 30 s spacing), which keeps the inactivity lock from firing. The
service has no matching setting; the option exists only in that page's memory.
It switches off whenever the session, generation or phase changes: any lock, any
service restart, any identity operation. It does not prevent the Lock button,
the lock on page close, the OS lock listener (§8.5), or quitting.

### 8.7 Unlock

After the identity unlocks ([S02 §9](02-identity-key-protection.md)), messaging
attaches to it:

1. Derive `db_key` and open the database ([S03 §3–§4](03-encrypted-storage.md)).
2. Run the one-time route re-enable step and set the default delivery mode if
   absent ([S03 §5.11, §5.16](03-encrypted-storage.md)).
3. Take the saved disappearing-message keys back into memory, discarding expired
   ones, and run one cleanup pass, before storage is published to any other
   operation or the transport starts ([S12 §4.3](12-disappearing-messages.md)).
   Expired content is never shown after an unlock.
4. Publish the identity and storage, re-open operation admission, start the
   transport.
5. Load the lock timeout (§8.1). On failure, lock again (§8.5).

## 9. Reserved

## 10. Account Deletion

The release deletes accounts locally: local profile erasure removes one profile
from this computer. While the profile is unlocked it also asks the user's
mailboxes, best effort, to stop accepting deposits for it.

### 10.1 Procedure

```
func erase(session, generation, confirmed, confirmation):
    // Admission
    require confirmed == true and confirmation == "ERASE"     else invalid_confirmation
    require no identity, preference or erase operation running else busy
    require session and generation current, not busy,
            phase in {unlocked, locked, absent, wiping, error} else stale_operation

    // Step 1: durable intent
    begin(profile):
        if wipe.pending exists: validate it; keep it unchanged
        else: atomically write wipe.pending = copy of identity.najwa
              (at most 192 bytes, parsed and validated), or empty if there is none
    generation += 1; phase = "wiping"

    // Step 2: destroy key owners
    lock the identity manager; drop displayed recovery words
    prepare_wipe():
        close admission; drain up to LOCK_DRAIN_DEADLINE_MS   else wipe_incomplete
        clear callbacks
        take the whole messaging state
        if unlocked: copy every receive fetch capability (primary, cover,
                     invitation, per-contact, dummy) with its mailbox, and the
                     saved Tor settings including bridges
        stop the disappearing-message cleaner
        drop cover traffic and the messaging service
        zeroize the volatile key cache WITHOUT saving it
        drop db_key, identity keys and storage handles
        shut down the messaging runtime (2 s bound)

    // Step 3: best-effort deactivation (unlocked only)
    if capabilities were copied:
        within DEACTIVATION_BUDGET (20 s) for everything below:
            start a fresh Tor client with the saved settings
            // unreadable settings: no client; never direct Tor
            in parallel, POST /v1/capability/deactivate once per capability
                (ByMailbox(onion), no retry, no PoW; 404 counts as done)
            stop the client; zeroize the copied capabilities
        report each mailbox as deactivated (every capability on it done)
               or unreachable (anything else)
    // never fails; Step 4 runs whatever the result

    // Step 4: local erase
    erase_files(profile):
        if wipe.pending is not empty:
            delete this record's device key from the OS key store or TPM
            // a key that provably no longer exists counts as deleted (S02 §17.6)
            // a failure is recorded; the files are still erased
        for every entry in the profile except owner.lock and wipe.pending:
            erase_entry(entry)             // continue past failures
        if anything failed: keep wipe.pending; fail wipe_incomplete
        remove wipe.pending
        sync the profile directory (Unix)

    // Step 5: outcome
    phase = "erased"; return the snapshot with the Step 3 report; stop the service
```

`erase_entry`:

- **Regular file:** open it without following links, verify it is still a
  regular file (on Unix: one hard link, same device and inode as observed
  before opening), overwrite its full length with CSPRNG output in 64 KiB chunks,
  sync it, unlink it, and sync the parent directory (Unix).
- **Symbolic link or reparse point:** unlink the link; never touch its target.
- **Directory:** erase each entry, then remove the directory and sync its parent
  (Unix).
- Any other file type fails.

Requirements:

- The intent marker MUST be durable before any key or byte is removed.
- The device key MUST be deleted before the files, so the identity record and
  every copy of it, including `wipe.pending`, become undecryptable even if file
  removal fails.
- Local erasure MUST NOT depend on the network. Deactivation MUST be bounded
  by one overall deadline and MUST NOT stop or skip Step 4, whatever its
  outcome.
- Deactivation runs before the files are removed, so the Tor state it writes is
  erased with the rest of the profile. It MUST use the saved bridges; when
  they cannot be read, no mailbox is contacted.
- A locked profile's capabilities are inside the encrypted database. Erasing a
  locked, absent or interrupted profile MUST NOT contact any mailbox.
- Erasure MUST touch only the exclusively owned profile directory. Files outside
  it and other profiles' device keys MUST NOT be affected.
- Erasure MUST continue past a failed entry so that one locked file does not
  leave the rest in place.

Erasure does not require the passphrase. It is available while the profile is
unlocked, locked, absent or in the `error` phase. The UI asks for a confirmation
checkbox and the typed word `ERASE`, says that only an unlocked profile's
mailboxes are asked to deactivate it, and afterwards lists the mailboxes that
were deactivated and those that could not be reached.

### 10.2 Effect

After success:

- The identity record, recovery record, unlock counters, database, WAL, browser
  grant, instance record, Tor state and any other file in the profile are
  overwritten and removed.
- This identity's device key is deleted from the OS key store. Neither the
  passphrase nor a recovered copy of `identity.najwa` can decrypt the identity.
- The service reports phase `erased`, with `mailboxes.deactivated` and
  `mailboxes.unreachable` (both empty for a locked profile), and stops. The
  next start finds an absent profile.
- On each deactivated mailbox the profile's receive queues and their waiting
  blobs are gone; contacts' deposits to them are silently discarded
  ([S16 §3.9](16-mailbox-server.md)).
- `owner.lock` and the empty profile directory remain.

### 10.3 Limitations

Erasure cannot reach:

- **Unreached mailboxes.** On a mailbox reported `unreachable`, and on every
  mailbox when the profile was locked, the profile's queues stay registered.
  Contacts can keep depositing to them, and each deposit refreshes the queue,
  so it expires only after 30 days without deposits or fetches
  ([S16 §10](16-mailbox-server.md)). Blobs already there stay until their
  retention ends. To deactivate them, unlock before erasing.
- **Contacts.** Contacts keep their copies of the conversation.
- **The recovery kit.** The 24 words and the recovery file restore the identity.
  Because the database key derives from the identity seed
  ([S03 §3](03-encrypted-storage.md)), the kit together with any surviving copy
  of `najwa.db` decrypts the history.
- **Copies outside the profile.** Downloaded attachments, the exported recovery
  file, backups, snapshots and file-sync copies.
- **The browser.** History, the downloads list and any cache entries.
- **The operating system.** Swap, hibernation files and crash dumps.
- **Storage media.** SSD wear levelling, copy-on-write file systems and
  file-system journals can keep overwritten blocks. On Windows the service
  cannot sync directory entries.

### 10.4 Interrupted Erasure

If erasure fails, `wipe.pending` stays, the phase stays `wiping`, and the status
reports `unavailableReason = "wipe_incomplete"`.

When the service starts and finds `wipe.pending`:

1. It validates the marker. An invalid marker stops the service with an error.
2. It does not open `identity.najwa`: the identity manager is pointed at a
   random path that does not exist.
3. It does not read `browser-access.json`; a fresh grant exists in memory only.
4. The phase is `wiping`. Lock is a no-op and identity operations fail with
   `stale_operation`.
5. Erasure can be retried. It reads the record copy from the marker, deletes the
   device key again and removes the remaining files. Deleting a key that is
   provably gone succeeds: a missing key, or on Windows a key whose TPM was
   cleared (S02 §17.6). A key that may still exist but cannot be deleted keeps
   the erasure incomplete. On Windows that includes a TPM that is absent,
   disabled in firmware, or not ready: retry after enabling it.

## 11. Reserved

## 12. Reserved

## 13. Reserved

## 14. Reserved

## 15. Error Types

The local API answers `{"ok": value}` or `{"error": {"code": string}}`; a
rate-limited unlock adds `"retryAfterMs"`. Codes for the operations in this
specification:

| Code | Meaning |
|------|---------|
| `stale_operation` | Session or generation is not current, or the phase does not allow the operation |
| `busy` | Another identity, preference or erase operation is running |
| `lock_failed` | The drain timed out or saving volatile keys or the checkpoint failed; keys stay in memory |
| `invalid_preferences` | Timeout outside 60–3600 s, more than 8 bridge lines or more than 16384 bridge bytes, or a stored value that does not parse |
| `invalid_bridges` | A bridge line is malformed or of an unsupported type |
| `bridge_helper_unavailable` | The bundled pluggable-transport helper is missing or does not match its pinned SHA-256 |
| `locked` | The profile is not unlocked |
| `invalid_confirmation` | Erase without `confirmed = true` and `confirmation = "ERASE"` |
| `wipe_incomplete` | Erasure did not finish; retry |
| `operation_failed` | Internal failure of the request worker |
| `forbidden` (HTTP 403) | The request failed the boundary checks of §19 |

## 16. Rust Crate Dependencies

| Crate | Purpose |
|-------|---------|
| `najwa-privacy` | `lifecycle::emergency` (erasure marker and file erasure) and the overwrite helpers in `lifecycle::deletion` |
| `najwa-identity` | Identity manager lock, atomic writes, device-key deletion |
| `najwa-ffi` | `DesktopClient` lock, drain and `prepare_wipe`; `WipeTargets::deactivate_best_effort` and `WipeReport`; `LocalPreferences` |
| `axum` | Local HTTP service |
| `fs2` | `owner.lock` exclusive lease |
| `directories` | Default profile path |
| `zeroize` | Credential and key buffers |
| `windows-sys` (Windows), `dbus` (Linux), `core-foundation` (macOS) | OS lock listener (§8.5) |

## 17. Memory Zeroization

The release clears secrets from memory as follows:

| Secret | Handling |
|--------|----------|
| `db_key` and its hex form | `db_key`: one copy in locked memory shared by every database handle, zeroed when dropped at lock and erase ([S01 §6.2](01-crypto-primitives.md)); the hex form: a zeroizing buffer ([S03 §3](03-encrypted-storage.md)) |
| SQLCipher key schedule and page buffers | `cipher_memory_security = ON` ([S03 §4.2](03-encrypted-storage.md)) |
| Unlocked identity key | One copy in locked memory, shared with the messaging service ([S01 §6.2](01-crypto-primitives.md)); destroyed by the identity manager's `lock`, before any disk or key-store I/O; seed copies are zeroizing |
| Ratchet, skipped and prekey secrets read from storage | Decrypted into zeroizing buffers; the record types zeroize on drop |
| Disappearing-message keys | Zeroizing entries; the cache is zeroized at lock (after saving) and at erase (without saving) |
| Passphrases and recovery words in API requests | `/api/identity` reads the body into one zeroizing buffer reserved at the 32 KiB limit, so it never reallocates, and zeroizes it right after JSON parsing, including when parsing fails; passphrase and word fields are zeroizing strings, so a partly parsed operation is wiped too |
| Recovery words and message content in API replies | `/api/identity` and `/api/invoke` replies are serialized into a zeroizing buffer sized before writing; the HTTP library frees it (zeroized) after sending, and the reply value's strings are zeroized once serialized. Message rows read for a reply are zeroized after conversion, and the returned messages zeroize their text on drop ([S17 §5.6.2](17-ffi-bindings.md)) |
| Displayed recovery words | Zeroizing; dropped when acknowledged and at lock |
| Browser grant, launch record | Read and written through zeroizing buffers; the grant zeroizes on drop |
| Capabilities gathered during erasure | Zeroized |
| Fetch plan kept while locked (§8.3) | Zeroizing entries; zeroized when the messaging runtime is destroyed (erase, bridge change, quit) |
| Browser page | Passphrase and word fields are cleared after submit, at lock, at page hide and on a session change |

The native service and the mailbox server install a zeroizing global allocator
([S01 §6.1](01-crypto-primitives.md)): every heap block is zeroed when it is
freed, and a reallocation zeroes the old block. That covers freed copies these
measures cannot reach directly: the HTTP library's receive and send buffers,
the JSON parser's scratch copies, Rust reallocations and message rows dropped
when a read fails partway. Copies that are still live (in a buffer not yet
freed, or on the stack), JavaScript strings, browser process memory, swap
(except the locked identity seed and `db_key`, [S01 §6.2](01-crypto-primitives.md)),
hibernation and crash dumps are not covered.

## 18. Log Hygiene

- Passphrases, recovery words, keys, capabilities, envelope secrets, message
  content, the API token and the browser grant MUST NOT be logged, printed or
  returned in an error.
- The local service installs no `tracing` subscriber. Diagnostics emitted by the
  libraries are discarded.
- Standard output carries only the readiness line (local origin and profile
  path), `--help` text and `--build-info` JSON. A startup failure prints one line,
  `Najwa: <message>`, to standard error and, in the Windows release build (which
  has no console), shows it in a message box. An OS lock listener that cannot
  start (§8.5) prints one fixed line, `Najwa: <trigger> will not lock Najwa`, to
  standard error, and the service keeps running.
- API errors carry only a fixed code (§15), never internal error text.
- Credential-carrying request types have no `Debug` implementation. Key and
  secret record types print redacted `Debug` output.

## 19. Browser-Side Protections

The browser UI is served by the service itself and talks to it over loopback.

**Listener.** The service binds `127.0.0.1:<port>` (default 1421, `--port`) only
after it holds the profile lease, so it never trusts another process already on
that port.

**Request checks.** Every request MUST pass all of these, or it gets HTTP 403
`{"error":{"code":"forbidden"}}`:

| Check | Rule |
|-------|------|
| `Host` | Exactly `127.0.0.1:<port>` (defeats DNS rebinding) |
| `Origin` | Absent, or exactly `http://127.0.0.1:<port>` |
| `Sec-Fetch-Site` | Absent, `same-origin` or `none`; not checked on a `GET /` with `Sec-Fetch-Mode: navigate` and `Sec-Fetch-Dest: document`, the cross-site navigation from the Unix launch page |
| API token | Every `/api/*` request except `/api/bootstrap` and `/api/download/*` carries `X-Najwa-Session: <token>` |
| Bootstrap | `/api/bootstrap` carries `X-Najwa-Launch: <token>` or a valid launch cookie |
| `Content-Type` on POST | `application/octet-stream` for `/api/attachment` and `/api/transfer-part/*`; `application/json` otherwise |

The token is 32 random bytes in lowercase hex (64 characters), new for every
service process. A custom header cannot be sent cross-origin without a CORS
preflight, which the service does not grant. The token and the launch cookie's
grant are compared in constant time.

**Launch and pairing.**

- The service opens the browser at `http://127.0.0.1:<port>/#<token>`. The page
  sends the fragment as `X-Najwa-Launch` to `/api/bootstrap`, receives
  `{"token", "session"}`, and removes the fragment from the address bar with
  `history.replaceState`.
- The token MUST NOT appear in a child process's arguments, which other local
  users can read on Linux (`/proc/<pid>/cmdline`) and macOS (`ps`). On Linux
  and macOS the service writes `web-launch.html` in the profile directory,
  created with mode `0600` before any content is written, holding only a
  `<meta http-equiv="refresh">` redirect and a link to the URL, and passes the
  file's path to `xdg-open` or `open`. Each launch replaces the file; the running
  service removes it at exit. On Windows the URL goes to `ShellExecute`; the
  browser's command line is readable only by the same user, SYSTEM and
  administrators.
- Bootstrap also sets the launch cookie
  `Najwa-Launch-<port>=<grant>; HttpOnly; SameSite=Strict; Path=/api/bootstrap; Max-Age=<remaining lifetime>`.
  The grant is 32 random bytes in hex, stored per profile in
  `browser-access.json` (mode `0600` on Unix), valid for 30 days and replaced
  when it expires. It lets the same browser reconnect after a restart. It never
  unlocks a profile.
- `session` is 16 random bytes in hex, new for every process. Every mutating
  request carries `session` and `generation`.
- A second launch for a profile that is already open reads `web-instance.json`,
  checks that the running service answers bootstrap with the recorded session
  and token, and opens that instance.

**Body limits.** 32 KiB by default; 8 MiB for `/api/attachment`; 1 MiB for
`/api/transfer-part/*`.

**Downloads.** `/api/download/{ticket}` needs no API header because the browser
fetches it natively. The ticket is 32 random bytes in hex; the database stores
only its SHA-256 for one hour ([S03 §5.24](03-encrypted-storage.md)), and every
streamed part re-checks the lock epoch.

**Static files.** `GET` only. Paths containing `%`, `\` or `:`, or a `..` or
dot-prefixed segment, are refused. Only `index.html`, `.js`, `.css`, `.png`,
`.svg` and `.woff2` are served.

**Response headers.** Every response carries:

```
Cache-Control: no-store
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
Cross-Origin-Resource-Policy: same-origin
Cross-Origin-Opener-Policy: same-origin
X-Frame-Options: DENY
Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; media-src 'self' blob:; font-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'; object-src 'none'
```

**Secrets in the page.**

- Passphrases and recovery words travel only in request bodies to
  `/api/identity`. They are never written to `localStorage`, `sessionStorage`,
  IndexedDB or a script-readable cookie.
- The page never retries a mutation or a passphrase submission after the
  service restarts; only reads retry, once.
- Recovery-word inputs set `autocomplete="off"` and `spellcheck="false"`.
  Passphrase inputs are `type="password"` with `autocomplete="current-password"`
  or `"new-password"`.

## 20. Security Considerations

- **Same-user malware** can read browser memory, capture the passphrase and read
  the launch token. It is out of scope.
- **Launch token exposure.** The token in the launch URL is the API token for the
  life of the service process. Browser history may record the launch URL. It is
  also stored in `web-instance.json` and, on Linux and macOS, `web-launch.html`,
  both inside the owner-only profile directory. A party holding the token can
  reach the API at `127.0.0.1` and act as the page, including on an unlocked
  profile.
- **Unix launch page.** A sandboxed browser (for example a Snap or Flatpak
  build) may be unable to read `web-launch.html` from a hidden profile directory.
  The user can then open the address printed at start and use a browser that
  was paired before, or start the service with `--profile` in a directory the
  browser can read.
- **Erasure without passphrase.** Whoever controls the paired page can erase the
  local profile. This is deliberate: erasure works while locked and offline.
- **Deactivation is visible to the mailbox.** Erasing an unlocked profile tells
  each reached mailbox, at one moment, that its queues end together, so the
  operator can link them, cover queue included. Contacts see their deposits
  silently dropped rather than an error. Erasing while locked avoids this but
  leaves the queues registered (§10.3).
- **OS lock is best effort.** The fence (§8.2) is immediate, but Windows waits
  only about two seconds for suspend handlers and logind does not wait at all,
  so keys can stay in memory until the lock finishes after wake. macOS sees a
  screen lock or user switch up to 2 s late. A Linux desktop that sends none of
  the §8.5 signals is not observed; the inactivity lock still applies.
- **Keep unlocked** disables the inactivity lock while the page stays open.
- **Page-close lock is best effort.** If the browser crashes, the keepalive
  request may never arrive; the inactivity lock still applies.
- **Online while locked.** Tor, cover traffic and fetch-only polling keep running
  after a lock (§8.3).
- **Fetch capabilities in memory while locked.** Someone who reads the locked
  service's memory obtains the fetch capabilities of the user's receive queues.
  They cannot read messages (no envelope secret or ratchet key is held), but they
  can fetch, acknowledge (delete) and deactivate those queues at the mailbox.
- **A locked poll does not acknowledge.** The poll schedule and the queues read
  are the same as unlocked, but a queue with waiting blobs keeps returning them
  until unlock, and a full page is not followed by a further fetch. An operator
  who sees blobs fetched repeatedly without acknowledgement can infer that the
  profile is locked or that the client cannot process them.
- **Password managers.** The passphrase fields invite the browser's password
  manager to save the passphrase.

## 21. Conformance Checklist

- Inactivity timeout default 300 s, bounds 60–3600 s enforced on save and on
  load; no setting disables it; idle check every 5 s.
- Activity counted only from `/api/activity`, identity operations and preference
  saves; polling is not activity.
- "Keep unlocked" is page-local, off by default, and reset by any session,
  generation or phase change.
- Lock fences first (generation, phase `locking`), drains within 5000 ms, saves
  volatile keys, checkpoints the WAL, then destroys keys; a failed lock is
  reported as `lock_failed` and never as locked.
- Lock on button, page hide, inactivity, OS session lock, user switch and sleep
  (§8.5), quit, shutdown, bridge change and failed identity operation; cover
  traffic continues after lock. Keep unlocked never holds off the OS lock.
- Polling continues after lock on the same schedule and selection, fetch-only:
  no decryption, processing or acknowledgement; only onions and fetch
  capabilities kept in memory, zeroized with the runtime (§8.3).
- Unlock takes disappearing-message keys back and cleans expired content before
  storage or transport is published.
- Erasure: `ERASE` confirmation; durable `wipe.pending` before deletion; when
  unlocked, one parallel deactivation attempt per receive capability over Tor
  with the saved bridges, within 20 s overall, before any file is removed, and a
  `mailboxes` report of deactivated and unreachable mailboxes; when locked, no
  network; device key deleted before files; random overwrite, sync and unlink of
  every profile entry except `owner.lock` and the marker, whatever deactivation
  returned; marker removed last; interrupted erasure blocks unlock and is
  retryable after restart.
- Typing indicators never sent; received ones dropped after the receive
  transaction.
- No link previews; no fetch of URLs from received content.
- Request checks, token handling, pairing cookie, body limits and response
  headers of §19.
- Launch token never in a child process's arguments; the Unix launch page is
  created `0600`, replaced on each launch and removed at exit; token and grant
  compared in constant time (§19).
- Zeroization of §17, including the credential body buffer (reserved at the
  limit, wiped after parsing on every path), zeroizing credential fields, and
  identity and messaging replies built and sent from zeroizing buffers; no
  logging of secrets, no log subscriber, code-only API errors (§18).
