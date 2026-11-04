# Typed desktop boundary

`najwa_ffi::desktop::DesktopClient` is the Rust API the desktop service
(`apps/local-web`) uses to run messaging. It sits beside the C ABI of
[S17](../../docs/specs/17-ffi-bindings.md) and shares its process-wide state:
the SQLCipher store, the embedded Arti transport, the cover runtime, the
volatile disappearing-message keys, the operation gate and the callback
dispatcher. It adds no C symbols.

The browser never calls this API directly. The local HTTP API
([API reference](../../docs/reference/api-reference.md)) validates each request
and forwards it here. The other callers are the `desktop_peer` and
`browser_peer` examples.

## Ownership and lifecycle

There is one client per process.

| Method | Effect |
|--------|--------|
| `DesktopClient::init(directory)` | Runs process security initialization and creates the shared state for `directory`. Fails with `already_initialized` if the C ABI or another client initialized first, or `security_initialization_failed`. No identity, storage or network yet. |
| `attach_identity(&Identity)` | Attaches an identity the native owner has already authenticated. See below. |
| `lock()` | Calls `najwa_lock` (S17 §4.1). Any failure returns `lock_failed` and keeps every key. |
| `cancel()` | Closes admission and signals in-flight operations without waiting. Used to invalidate work before a lock. |
| `reconnect()` | Starts the Tor bootstrap again if none is running. |
| `prepare_wipe()` | Destroys the messaging runtime for profile erasure (see [Wipe](#wipe)). |

The native owner authenticates the identity and passes the unlocked `Identity`.
Passwords and private-key exports never pass through this API.

**`attach_identity`:**

1. Close admission and drain in-flight work (up to 5 000 ms); on timeout return
   `lock_failed`. Fails with `unavailable` before `init` and `already_unlocked`
   if an identity is attached.
2. Derive the database key from the identity seed (S17 §5.7) and open
   `<directory>/najwa.db`.
3. Once per profile (marker `desktop:auto-retry-v1`), re-enable contacts'
   mailboxes paused after five or more failures. If no delivery mode is stored,
   store Responsive (see [Delivery mode](#status-and-delivery-mode)).
4. Restore persisted volatile keys and run one disappearing-message cleanup;
   start the periodic cleaner.
5. Publish the unlocked state, increment the lifecycle generation, reopen
   admission, resume callback delivery and start the Tor bootstrap.
6. Start three background loops bound to this generation. The first two stop
   when the identity is detached or the generation changes; the receive loop
   runs through the following lock and stops at the next attach:

   | Interval | Work |
   |----------|------|
   | 1 s | Queue read receipts; prepare uploaded files; feed staged attachments into the outbox |
   | 1 s | Drive the outbox (one run at a time, 600 s timeout per run) |
   | Exponential, mean 3 s, 1 s floor | Unlocked: reconnect if the connection is `offline`, then `sync`. Locked: fetch-only poll from the fetch plan ([S13 §8.3](../../docs/specs/13-privacy-hardening.md)) |

**Lock** first closes admission and cancels operations. It then saves the
volatile keys encrypted in storage and drops every unlocked key. A failed drain
or save keeps the keys and reports failure; the caller MUST NOT report the
profile as locked. The cover runtime, its schedule and its fetch plan (onions
and fetch capabilities, [S08 §6.1.1](../../docs/specs/08-messaging-service.md))
survive a successful lock; they hold no identity or database key and no envelope
secret of a real queue. `prepare_wipe` zeroizes them; the local service calls it
after its final lock at quit.

## Calling rules

- Every method blocks. Call it from a blocking worker thread
  (`spawn_blocking`), never from inside an async runtime.
- Key-using methods acquire the shared operation gate. When the gate is closed
  they return `locked`.
- Network setup (`add_mailbox`, `invitation`, `sync`, `forget_mailbox`) takes a
  single network admission slot. A second concurrent call returns `busy`.
  Sending, reading and local contact actions do not take this slot, so they run
  while a long sync owns the network.
- Errors are fixed lowercase codes (`DesktopError { code }`). They never carry
  secrets, capabilities or message text.
- Contact and row ids are decimal strings of positive 64-bit integers (1–19
  ASCII digits), so JavaScript never rounds them. Message ids (`msgId`) are 32
  lowercase hex characters.
- Onion addresses are 56 characters of `a–z2–7`, with or without `.onion`.
- Names are non-blank, at most 128 bytes, with no control characters.

## Operations

### Status and delivery mode

**`status()`** needs no admission and returns:

| Field | Value |
|-------|-------|
| `unlocked` | an identity is attached |
| `connection` | `locked`, `connecting` (bootstrap running, including while no saved bridge is reachable), `connected` (messaging service installed after Tor reached its first hop, S04 §10.1) or `offline` |
| `coverRunning` | the cover scheduler is running |
| `mailboxes` | every configured own mailbox, as `<56 chars>.onion` |
| `pausedMailboxes` | contacts' mailboxes paused after repeated delivery failures |
| `retryingMailboxes` | own or contacts' mailboxes that are enabled but have recent failures |
| `mailboxDetails` | `[{onion, registered, primary}]` per own mailbox |
| `deliveryMode` | `responsive` or `privacy` |
| `pendingDeposits` | outbox frames not yet deposited, plus setup work still being prepared (staged attachments, unfinished uploads, queued introductions, contacts whose receive paths are not yet registered or announced); `null` if unreadable |

The primary mailbox is the saved choice if it is enabled, otherwise the first
enabled mailbox.

**`prekey_recovery_pending()`** is true while a recovered identity's fresh
prekeys are not yet published: the recovery marker names a generation that the
encrypted store has not recorded as complete
([S02 §13.2](../../docs/specs/02-identity-key-protection.md)). Without an attached
identity it returns `locked` or `unavailable`.

**`set_delivery_mode(mode)`** takes `responsive` or `privacy` (otherwise
`invalid_request`). It stores the choice and applies it to the live cover
scheduler at once. Responsive sends queued frames without waiting for a cover
slot. Privacy sends them in cover slots ([S10](../../docs/specs/10-cover-traffic.md)).
`attach_identity` stores Responsive when no choice exists. The C ABI reads the
same setting and treats a missing value as Privacy.

### Mailboxes

**`add_mailbox(onion)`**

1. Validate the address; take network admission.
2. If the mailbox is new, refuse a ninth (`mailbox_limit`). Save fresh random
   capabilities with the mailbox disabled, before any network request, so an
   unreachable mailbox cannot stall working conversations. A retry reuses the
   saved capabilities.
3. Register: request a proof-of-work challenge, wait for a cover slot at
   control priority, submit the registration
   ([S16](../../docs/specs/16-mailbox-server.md) §3.1), and record success.
4. Enable the mailbox, publish prekeys, and create a per-contact receive
   capability (type 2) on it for every unblocked contact that lacks one. These
   are registered and announced by the next `sync`.

Registration failures return a classified code: `registration_transport`,
`registration_pow`, `registration_limited`, `registration_conflict`,
`registration_server`, `registration_rejected` or `registration_failed`. Only
the classification and HTTP status are logged, never capabilities, tokens or
responses.

**`select_mailbox(onion)`** makes an enabled, registered mailbox primary
(`mailbox_required`, `mailbox_unregistered`). The next `sync` announces the new
order to every contact.

**`forget_mailbox(onion)`** deletes an unused, incomplete mailbox record. It
returns `mailbox_in_use` if the mailbox is enabled, registered, or holds any
contact or invitation capability.

**`retry_mailbox(onion)`** re-enables a contact's paused mailbox
(`mailbox_not_paused` otherwise). Automatic reconnects never clear a pause.

### Contacts and invitations

**`invitation(name)`** creates a signed invitation
([S05](../../docs/specs/05-contact-establishment.md)) and returns its URI.

1. Take network admission. Require at least one enabled, registered mailbox
   (`mailbox_required`); order them primary first.
2. For each mailbox, reuse its saved invitation slot if the slot is unaccepted,
   active, carries the type-1 marker, was created with the full 48-hour
   lifetime, and has more than 600 s left. Otherwise create a new single-use
   handshake capability: random 32-byte deposit capability, fetch capability
   and envelope secret, type 1, expiring 48 hours (`EPHEMERAL_CAP_TTL_SECS`)
   after creation.
3. Register an unregistered slot with its type and absolute expiry, so the
   mailbox enforces the expiry and its quotas (S16). Publish prekeys.
4. Refuse with `invitation_expiring` if 600 s or less remain. The invitation
   expires at the earliest slot expiry and is signed by the identity key.

The receiving side consumes a slot after the first valid introduction. A retry
reuses a saved slot for as long as it qualifies under step 2.

**`invitation_details(invitation)`** verifies a URI invitation (at most 4 096
bytes) and returns `{qrText, qrSvg, expiresAt}` for display. A payload too
large for a QR code returns `qr_too_large`.

**`accept_invitation(invitation, name, confirmed)`** accepts a URI or a `NAJWA:`
QR string (at most 4 096 bytes) and returns the new contact id.

1. Parse and verify the signature; reject any malformed onion address
   (`invalid_invitation`, `invalid_mailbox`).
2. Reject the user's own identity (`self_contact`).
3. If a contact with the same identity key exists, succeed only when this is the
   exact signed invitation that created it; otherwise `contact_exists`.
4. If 10 or more contacts were created in the last 24 hours (by `created_at`,
   including contacts from the user's own invitations) and `confirmed` is
   false, return `contact_limit_confirm` and store nothing. The caller warns the
   user and retries with `confirmed` true ([S05 §8.1](../../docs/specs/05-contact-establishment.md)).
5. Store the contact and its credentials, and record that a reciprocal
   introduction is owed.

Acceptance needs only the unlocked store, not the network. `sync` registers the
receive paths and sends the introduction.

**`sync()`** takes network admission and runs for at most 600 s:

1. Poll every mailbox through the core ([S08](../../docs/specs/08-messaging-service.md)).
2. Register any enabled mailbox not yet registered.
3. For every unblocked contact whose setup has not failed or expired: register
   its unregistered receive capabilities and publish prekeys.
4. If a reciprocal introduction is owed and no session exists, send it once,
   signed, listing the registered long-term receive paths (type 2). If a
   session exists and the ordered set of receive paths differs from the last
   one announced, send a `MailboxUpdate` control message. A lost result never
   produces a second introduction.

Expired setups are retired: an undeposited introduction is withdrawn and the
obligation removed.

**`contacts()`** returns, per contact:

| Field | Value |
|-------|-------|
| `id`, `name` | decimal id; display name (`Contact` if none) |
| `verified`, `blocked` | flags |
| `unread` | unread received messages |
| `ready` | a session exists and the peer advertised a long-term receive path |
| `setupState` | `ready`, `queued`, `waiting`, `unconfirmed`, `expired` or `failed` |
| `setupExpiresAt` | invitation expiry in Unix seconds, or `null` |
| `safetyNumber` | eight groups of four hex digits (39 characters) over both identity keys |
| `timerSeconds`, `timerPending` | disappearing timer; whether a change awaits confirmation |
| `preview` | latest visible text, at most 160 characters; `null` for disappearing messages |
| `lastMessageAt` | Unix seconds, or `null` |
| `repairStatus` | `repairing`, `failed` or `null` |

Setup states: `queued` (introduction saved, not yet deposited), `waiting`
(deposited, invitation still valid), `unconfirmed` (deposited, invitation
expired without a reply), `expired` (never deposited before expiry), `failed`
(introduction permanently failed).

**`verify(contact, safety, verified)`** recomputes the safety number and
returns `stale_operation` if it differs from the one the user compared. On a
match it sets the verified flag bound to the contact's current identity key.

**`manage_contact(contact, action, name)`** performs `block`, `unblock`,
`rename` (requires a valid `name`) or `delete`. Blocking keeps history and
pauses setup and file work. Deleting removes the contact, its messages and
their volatile keys.

### Messages

**`messages(contact)`** returns the latest page: up to 200 text, reply and
file rows, newest first. Expired rows are omitted; disappearing content is
opened from the volatile key cache. It does not mark anything read or start any
timer.

**`message_history(contact, before, query)`** pages and searches the same
rows. `before` is `(timestamp, id)` with `timestamp >= 0` and returns rows
strictly older than that cursor. `query` is non-blank, at most 512 bytes, and
matches text case-insensitively; disappearing rows are excluded from search.
It returns up to 200 rows and marks nothing read.

Each message has:

| Field | Value |
|-------|-------|
| `id` | decimal row id |
| `msgId` | 32-hex message id |
| `text` | text, or `""` for a file |
| `outgoing` | sent by this profile |
| `timestamp` | Unix seconds |
| `status` | `queued`, `deposited`, `delivered`, `read`, `retrying` or `failed` |
| `expiresAt` | disappearing deadline in Unix milliseconds, or `null` |
| `replyTo` | 32-hex id of the quoted message, or `null` |
| `attachment` | `{filename, size, chunks, availableChunks, depositedChunks, complete, supported, failed}` or `null`; `failed`: an incoming file whose missing-part requests ran out ([S11 §4.1](../../docs/specs/11-file-transfer-sanitization.md)) |

Both calls wipe the content of each stored row they convert, and a `Message`
wipes its `text` when dropped ([S17 §5.6.2](../../docs/specs/17-ffi-bindings.md)).

**`displayed(contact, ids)`** takes at most 200 row ids. It marks those received
rows read, starts their disappearing timers
([S12](../../docs/specs/12-disappearing-messages.md)) and records read-receipt
intents. The renderer calls it only for rows visible in a focused window.

**`send(contact, text)`** and **`send_reply(contact, text, reply_to)`** return
the new `msgId`.

- `text` is non-blank, at most 16 000 bytes, with no NUL (`invalid_message`).
  `reply_to` is 32 hex characters.
- The contact must be `ready` (`contact_pending`) with no unconfirmed timer
  change (`timer_pending`).
- The message is committed atomically to the durable outbox with a read-receipt
  request (15 s limit, `timeout`). No mailbox request and no cover-slot wait
  happen in the call. The outbox loop delivers it.

**`set_timer(contact, seconds)`** sets the disappearing timer for future
messages. `0` turns it off; 1–29 is `invalid_timer`. The contact must be
`ready`. A non-zero timer is refused while a file for that contact is still
being prepared (`file_preparing`). The setting and the encrypted notification
to the peer are committed together.

### Files

Files are sanitized before they are sent
([S11](../../docs/specs/11-file-transfer-sanitization.md)). Sending a file
requires the conversation timer to be off (`file_timer_unsupported`) and the
contact to be `ready`. At most four files are prepared at a time; when the
queue is full, a new file is refused with `storage_unavailable`.

**Resumable uploads** (up to 256 MiB):

| Method | Effect |
|--------|--------|
| `begin_upload(contact, {name, size, hashes})` | `size` 1 B–256 MiB; `name` at most 255 bytes; `hashes` holds one 64-hex SHA-256 per 1 MiB part. The same contact and manifest resume the existing transfer. Returns a transfer view. |
| `upload_part(id, part, bytes)` | `bytes` MUST hash to `hashes[part]` and have the exact part length. Re-sending an identical part is accepted; different bytes are `invalid_file`. |
| `seal_upload(id)` | Requires every byte. Hands the file to preparation. |
| `list_transfers(contact)` | Up to 8 unfinished transfers. |
| `cancel_upload(id, contact)` | Only while uploading or failed. |

A transfer view is `{id, filename, size, uploaded, phase, parts, error}`.
`phase` is `uploading`, `preparing`, `queued` or `failed`. `parts` lists
received part indexes while uploading. `error` holds the failure code.

The preparation loop sanitizes each sealed upload with the streaming sanitizer,
writes the output in 245 760-byte chunks inside SQLCipher, hashes it, and then
queues the metadata frame and up to 16 chunk frames per tick while fewer than
64 deposits are pending. Decodable images become WebP and their filename takes
a `.webp` extension. Unsupported input fails the transfer with
`unsupported_file`.

**Small files** (up to 8 MiB) can go in one call: `queue_file(contact, bytes,
name)` sanitizes in memory and stages a durable job that survives restarts.

**Downloads:**

| Method | Effect |
|--------|--------|
| `download_file(contact, message)` | Files up to 8 MiB: verifies every chunk and the SHA-256, returns `{filename, data}` with `data` in base64. |
| `create_file_download(contact, message)` | Verifies the whole file and checks it for metadata (S11 §8), then creates a grant: a random 32-byte token (64 hex) stored only as its SHA-256, valid for 3 600 s. Returns `{url: "/api/download/<token>", filename, size, metadataWarning}`; a `true` warning does not refuse the grant. |
| `file_download_info(token)` | `{filename, size, sha256}` |
| `file_download_part(token, offset)` | The bytes from `offset` to the end of its chunk; empty at or past the end. |

Downloads are refused for disappearing messages and expired rows
(`file_unavailable`). Filenames are reduced to their last path component, with
control characters and `<>:"|?*` removed, at most 120 characters, and
`attachment` when nothing remains.

### Preferences and Tor bridges

`local_preferences()` and `save_local_preferences(prefs)` read and write
`{lockTimeoutSeconds, bridges}` in encrypted storage.

- `lockTimeoutSeconds`: 60–3 600, default 300.
- `bridges`: at most 8 lines, at most 16 384 bytes in total, each at most 4 096
  bytes with no CR, LF or NUL. A line may start with `Bridge `. Accepted types
  are `obfs4`, `snowflake` and plain `IP:port` bridges.
- Saving builds and validates the complete Arti configuration before anything
  is stored. Pluggable transports use the bundled `lyrebird` helper from the
  `transports` directory next to the executable; its SHA-256 must match the
  pinned value in `tor-transports.json`, or the save fails with
  `bridge_helper_unavailable`.
- A stored value that cannot be read or validated is an error. It never falls
  back to a direct Tor connection.

The local service locks the profile and rebuilds the Tor client when the bridge
list changes.

### Wipe

`prepare_wipe()` drains admission (`wipe_incomplete` on timeout), clears
callbacks, and takes the whole shared state. It collects every mailbox fetch
capability (own, cover, invitation, per-contact and dummy) and the saved Tor settings,
bridges included, into `WipeTargets` and wipes the other copied capability
material. A locked owner has no storage, so its targets are empty. It then drops the cover runtime, the
messaging service, the volatile keys, the identity and the storage handle
without saving volatile keys, and shuts the runtime down within 2 s. The native
owner erases the files. `DesktopClient::init` may be called again afterwards.

`WipeTargets::deactivate_best_effort(budget)` asks each mailbox to deactivate
those capabilities over a fresh Tor client built from the saved settings (none
if they cannot be read: never direct Tor). It sends one parallel
`deactivate_emergency` request per capability on the `ByMailbox` circuit, and
`budget` bounds bootstrap, requests and shutdown. It never fails and returns a
`WipeReport {deactivated, unreachable}` of `<onion>.onion` names; a mailbox is
deactivated only when every capability on it was. Empty targets return an empty
report without starting Tor. The local service calls it with 20 s before erasing
the files.

## Error codes

| Group | Codes |
|-------|-------|
| State | `unavailable`, `already_initialized`, `security_initialization_failed`, `already_unlocked`, `locked`, `lock_failed`, `busy`, `timeout`, `operation_failed`, `storage_unavailable`, `wipe_incomplete` |
| Network | `not_connected`, `sync_failed`, `mailbox_unavailable`, `registration_transport`, `registration_pow`, `registration_limited`, `registration_conflict`, `registration_server`, `registration_rejected`, `registration_failed` |
| Input | `invalid_request`, `invalid_mailbox`, `invalid_name`, `invalid_message`, `invalid_timer`, `invalid_invitation`, `invalid_preferences`, `invalid_bridges`, `bridge_helper_unavailable` |
| Contacts | `contact_missing`, `contact_blocked`, `contact_exists`, `contact_limit_confirm`, `contact_pending`, `self_contact`, `stale_operation`, `timer_pending` |
| Mailboxes and invitations | `mailbox_required`, `mailbox_unregistered`, `mailbox_limit`, `mailbox_in_use`, `mailbox_not_paused`, `invitation_expiring`, `qr_too_large` |
| Files | `file_too_large`, `file_timer_unsupported`, `unsupported_file`, `invalid_file`, `file_unavailable`, `file_preparing` |

Core errors map to `contact_blocked`, `contact_missing`, `mailbox_unavailable`
(no mailbox capability) or `sync_failed`. Shared-state errors map to `locked`,
`not_connected`, `storage_unavailable` or `operation_failed` (which includes
cancellation).

## Two-peer test harness

The `desktop_peer` example runs one peer over this API with its own embedded
Arti client and a disposable in-memory identity; it exports no secrets.
`scripts/test-desktop-messaging.py` drives two of them against a development
mailbox. It checks Tor bootstrap, mailbox registration and prekey publication,
signed invitation acceptance, reciprocal setup until both contacts are ready,
matching safety numbers, non-ASCII text in both directions, that cover keeps
running while a peer is locked, and that a text sent to the locked peer arrives
after it unlocks. It does not exercise the browser UI or hardware
authentication.

With Python 3, from the repository root in an initialized MSVC developer shell
on Windows (see [ONION-DEVELOPMENT](../../scripts/deployment/ONION-DEVELOPMENT.md)
for the development mailbox):

```powershell
cargo +stable-x86_64-pc-windows-msvc build --manifest-path Cargo.toml --locked -p najwa-ffi --example desktop_peer
$onion = (docker compose -f scripts/deployment/docker-compose.onion-dev.yml exec -T tor cat /var/lib/najwa-onion/hostname).Trim()
python scripts/test-desktop-messaging.py target/debug/examples/desktop_peer.exe $onion target/desktop-messaging-e2e
```

Use a fresh output directory for every run. Allow time for Tor bootstrap,
registration proof-of-work, reciprocal setup and batched release.
