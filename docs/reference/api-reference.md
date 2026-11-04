# API reference

Najwa has three programming interfaces:

| Interface | Who uses it | Where it is reachable |
|-----------|-------------|-----------------------|
| [Local HTTP API](#1-local-http-api) | the browser UI of the desktop app | loopback only, `127.0.0.1:<port>` |
| [C ABI](#2-c-abi) | native hosts linking `najwa-ffi` as a C library | in-process |
| [Mailbox HTTP API](#3-mailbox-http-api) | Najwa clients | a mailbox's Tor onion service |

## 1. Local HTTP API

The desktop service (`apps/local-web`) owns the profile, the identity and every
key. It serves the bundled UI and this API on loopback. The UI is the only
intended client. The API is private to one running service: it is not a hosted
API, and it MUST NOT be exposed on another interface or behind a reverse proxy.

Messaging requests go to `najwa_ffi::desktop::DesktopClient`; see
[DESKTOP.md](../../crates/najwa-ffi/DESKTOP.md) for what each operation does.

### 1.1 Launch and discovery

- The service binds `127.0.0.1:<port>` only. The port defaults to 1421
  (`--port N`, non-zero). Other options: `--profile DIR`, `--assets DIR`,
  `--no-browser`, `--help`, `--build-info`.
- One service owns a profile at a time through an exclusive lock on
  `<profile>/owner.lock`. The service refuses to start when the
  `NAJWA_DKM_FILE` test override is set.
- At start the service creates a **launch token** (§1.3), writes
  `<profile>/web-instance.json` = `{"port", "session", "token"}`, and opens the
  default browser at `http://127.0.0.1:<port>/#<token>`. The file is removed
  when the service exits.
- The token never appears in a process's arguments, which other local users
  can read on Linux and macOS. On Windows the URL goes to `ShellExecute`. On
  Linux and macOS the service writes `<profile>/web-launch.html`, created with
  mode `0600` in the `0700` profile directory, a page that redirects to the URL
  by `<meta http-equiv="refresh">` and loads nothing else. It then runs
  `xdg-open` or `open` with the file's path. Each launch replaces the file; the
  running service removes it when it exits.
- A second start on the same profile reads `web-instance.json`, calls
  `GET /api/bootstrap` with `X-Najwa-Launch: <token>`, checks that the reply
  carries the same session and token, and opens the browser at the same URL in
  the same way.
- The UI reads the token from the URL fragment, calls `/api/bootstrap`, then
  removes the fragment from the address bar.

### 1.2 Request checks

Every request, including static files, passes one boundary check. A request
that fails it gets `403` with `{"error":{"code":"forbidden"}}`.

| Check | Rule |
|-------|------|
| `Host` | MUST equal `127.0.0.1:<port>` exactly. `localhost` is rejected. This blocks DNS rebinding. |
| `Origin` | If present, MUST equal `http://127.0.0.1:<port>`. |
| `Sec-Fetch-Site` | If present, MUST be `same-origin` or `none`. Not checked on a `GET /` with `Sec-Fetch-Mode: navigate` and `Sec-Fetch-Dest: document`: the Linux and macOS launch page (§1.1) is a `file://` page, so its redirect arrives as `cross-site`. That page load carries no credential. |
| `X-Najwa-Session` | MUST equal the launch token on every `/api/*` path except `/api/bootstrap` and `/api/download/*`. |
| `/api/bootstrap` | MUST carry `X-Najwa-Launch: <token>` or the browser-permission cookie (§1.3). |
| `/api/download/*` | Needs no header; the path carries a download grant (§1.6). |
| `Content-Type` on `POST` | MUST be exactly `application/json`, or exactly `application/octet-stream` for `/api/attachment` and `/api/transfer-part/*`. Parameters such as `; charset=utf-8` are rejected. |

Every response, including a `403` refusal, carries these headers:

```
Cache-Control: no-store
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
Cross-Origin-Resource-Policy: same-origin
Cross-Origin-Opener-Policy: same-origin
X-Frame-Options: DENY
Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; media-src 'self' blob:; font-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'; object-src 'none'
```

Request body limits: 32 768 bytes for JSON endpoints, 8 MiB for
`/api/attachment`, 1 MiB for `/api/transfer-part/*`.

### 1.3 Tokens and identity epochs

| Value | Form | Lifetime | Use |
|-------|------|----------|-----|
| Launch token | 32 random bytes, 64 lowercase hex | one service run | URL fragment, `X-Najwa-Launch`, and `X-Najwa-Session` on every API call |
| Browser permission | 32 random bytes, 64 hex, in `<profile>/browser-access.json` (mode 0600 on Unix) | 30 days, replaced when expired | Cookie `Najwa-Launch-<port>`; `HttpOnly; SameSite=Strict; Path=/api/bootstrap; Max-Age=<remaining seconds>`. Lets a browser that was launched once get the token again after a restart. It reaches only the locked profile. |
| Identity session | 16 random bytes, 32 hex | one service run | `session` field in request bodies; `X-Najwa-Identity` on uploads |
| Identity generation | unsigned integer, starts at 1 | increments on every identity operation, lock, bridge change and erase | `generation` field in request bodies; `X-Najwa-Generation` on uploads |

Note the naming: the `X-Najwa-Session` header carries the launch token, while
the `session` body field carries the identity session.

The service compares the launch token and the browser permission in constant
time.

An operation that needs the unlocked identity is **validated** against the
current snapshot: `session` and `generation` MUST match, the phase MUST be
`unlocked`, and no identity operation may be running. Otherwise the result is
`stale_operation`. Messaging and transfer requests are validated before and
after they run. A request that loses its epoch while running returns
`stale_operation` even though its effect may already be committed.

The service locks the profile when no activity is reported for
`lockTimeoutSeconds` (checked every 5 s), and when the operating system locks
the session, switches user or goes to sleep
([S13 §8.5](../specs/13-privacy-hardening.md)). Neither lock reports a reason: the
page sees the raised `generation` and the phase `locked`.

### 1.4 Responses and HTTP status codes

Every handled JSON request returns `200` with one of:

```json
{"ok": <result>}
{"error": {"code": "<code>"}}
{"error": {"code": "rate_limited", "retryAfterMs": 4000}}
{"error": {"code": "weak_passphrase", "hint": "This is a very common password."}}
```

`retryAfterMs` appears only with `rate_limited`. `hint` appears only with
`weak_passphrase`, and only when the strength estimator has a warning; it is one
of the estimator's fixed English sentences and never contains the input.
`/api/bootstrap` and `/api/download/*` do not use this envelope.

| Status | When |
|-------:|------|
| 200 | Handled request (success or application error); full download |
| 206 | Partial download (`Range`) |
| 400 | Malformed JSON body, or an unparsable path parameter |
| 403 | Boundary check failed (§1.2) |
| 404 | Unknown static path; download not available |
| 405 | Wrong method for a route; non-`GET` static request |
| 413 | Body over the limit |
| 416 | Unsatisfiable `Range` |
| 422 | JSON body with unknown or missing fields on endpoints that parse a typed body (`/api/lock`, `/api/quit`, `/api/activity`, `POST /api/preferences`, `/api/erase`, `/api/invoke`, `/api/transfers`) |
| 503 | `/api/bootstrap` could not save a renewed browser permission |

`/api/identity` parses its own body and returns `invalid_request` in the
envelope instead of 400 or 422. Error bodies for 400, 405, 413 and 422 are
plain text from the HTTP framework.

### 1.5 Endpoints

| Method | Path | Request | `ok` result |
|--------|------|---------|-------------|
| `GET` | `/api/bootstrap` | — | not enveloped: `{"token", "session"}` |
| `GET` | `/api/status` | — | identity snapshot |
| `POST` | `/api/identity` | `{session, generation, operation}` | `{"identity": snapshot, "value": …}` |
| `POST` | `/api/lock` | `{session, generation}` | identity snapshot |
| `POST` | `/api/quit` | `{session, generation}` | `null` |
| `POST` | `/api/activity` | `{session, generation}` | `null` |
| `GET` | `/api/preferences` | — | preferences |
| `POST` | `/api/preferences` | `{session, generation, preferences}` | `{"preferences", "identity"}` |
| `POST` | `/api/erase` | `{session, generation, confirmed, confirmation}` | identity snapshot with `mailboxes` |
| `POST` | `/api/invoke` | `{command, args}` | §1.7 |
| `POST` | `/api/transfers` | `{session, generation, action}` | §1.6 |
| `POST` | `/api/attachment` | raw file bytes | `null` |
| `POST` | `/api/transfer-part/{id}/{part}` | raw part bytes | `null` |
| `GET` | `/api/download/{ticket}` | — | file stream |
| `GET` | any other path | — | static UI asset |

All JSON request objects reject unknown fields.

### 1.6 Endpoint details

**`GET /api/bootstrap`.** Returns `{"token": "<64 hex>", "session": "<32 hex>"}`
and sets the browser-permission cookie. A permission past its 30 days is
replaced first; if that cannot be saved the reply is `503`.

**`GET /api/status`.** Returns the identity snapshot (§1.8). No body fields;
no epoch check.

**`POST /api/identity`.** Runs one identity operation. The request buffer is
wiped after parsing, including when parsing fails.

1. The operation is checked first, before any state changes: a failed field
   check returns `invalid_password`, a new passphrase that is too easy to guess
   returns `weak_passphrase`, and `approve_software_storage` without
   `confirmed: true` returns `software_approval_required`.
2. Only one identity operation runs at a time (`busy`).
3. `session` and `generation` MUST match, and the phase MUST NOT be `locking`,
   `error`, `wiping` or `erased` (`stale_operation`).
4. The generation increments, including for read-only operations, so a stale
   tab cannot act. Mutating operations set the phase to `locking` while they
   run.
5. If a lock lands while the operation runs, the result is `stale_operation`
   and the identity is locked again.
6. After a successful `create`, `unlock`, `recover`, `restore`,
   `change_password` or `replace_recovery`, the identity is attached to
   messaging and the lock timeout is loaded. If any of that fails, the profile
   is locked again.

Operations (`operation.kind`):

| `kind` | Fields and checks | Effect | `value` |
|--------|-------------------|--------|---------|
| `create` | `password`, `confirmation`: at least 12 characters, at most 1 024 bytes, equal; strong enough ([S02 §11.1](../specs/02-identity-key-protection.md)) | Creates the identity and a 24-word recovery record; holds the words until acknowledged or locked. `already_exists` if a record exists. | `null` |
| `unlock` | `password`: 1–1 024 bytes | Rate-limited unlock ([S02](../specs/02-identity-key-protection.md)). `already_unlocked` if unlocked. | `null` |
| `change_password` | `current` (1–1 024 bytes), `password`, `confirmation` (as for create) | Locks messaging, re-encrypts the identity under the new password, re-attaches. | `null` |
| `recover` | `words` (1–1 024 bytes), `password`, `confirmation` | Recovers this profile's identity from its recovery record and words with a new password. `recovery_invalid` if the record does not match the identity. | `null` |
| `restore` | `record` (base64, at most 256 characters), `words`, `password`, `confirmation` | Imports a recovery record into an empty profile and recovers from it. `already_exists` if a record exists. | `null` |
| `replace_recovery` | `password`: 1–1 024 bytes | Re-authenticates and replaces the recovery record with a new 24-word one. | `null` |
| `recovery_words` | — | Returns the pending words. Requires unlocked; `recovery_missing` if none are pending. | `{"words": "<24 words>"}` |
| `export_recovery` | — | Returns the recovery record. Requires unlocked with pending words. | `{"record": "<base64>"}` |
| `acknowledge_recovery` | — | Forgets the pending words. | `null` |
| `approve_software_storage` | `confirmed`: MUST be `true` | Allows the OS key store for this identity after hardware protection failed. `software_approval_not_available` unless `softwareFallbackAvailable` is true and the identity is locked. | `null` |

**`POST /api/lock`.** `session` MUST match (`stale_operation`); `generation`
is not checked, so a lock always wins over a running operation. The service
raises the generation, sets the phase to `locking`, cancels messaging work,
locks messaging and the identity, and forgets pending recovery words. Returns
the new snapshot, or `lock_failed` with the phase set to `error`. While wiping
or erased, it returns the current snapshot unchanged.

**`POST /api/quit`.** As lock, then shuts the service down. Returns `null`.

**`POST /api/activity`.** Validated (§1.3). Resets the idle timer.

**`GET /api/preferences`.** Validated against the current snapshot. Returns
`{"lockTimeoutSeconds": 300, "bridges": []}`.

**`POST /api/preferences`.** `preferences` is
`{lockTimeoutSeconds, bridges}` with the bounds in
[DESKTOP.md](../../crates/najwa-ffi/DESKTOP.md#preferences-and-tor-bridges).
The request takes the identity-operation slot (`busy`) and is validated. If the
bridge list is unchanged, it returns `{"preferences", "identity"}`. If it
changed, the service also raises the generation, locks the profile and
rebuilds the Tor client; the returned identity is then `locked`, or the result
is `lock_failed` with the phase `error`. Errors: `invalid_preferences`,
`invalid_bridges`, `bridge_helper_unavailable`.

**`POST /api/erase`.** Requires `confirmed: true` and `confirmation: "ERASE"`
(`invalid_confirmation`), the identity-operation slot (`busy`), a matching
session and generation, no running operation, and a phase of `unlocked`,
`locked`, `absent`, `wiping` or `error`. The service writes a durable erase
marker before removing anything, sets the phase to `wiping` and destroys the
messaging runtime. If the profile was unlocked, it then asks each mailbox over
Tor, with the saved bridges and within 20 s overall, to deactivate the
profile's receive capabilities; a locked profile contacts no mailbox. It then
erases the profile whatever the mailboxes answered
([S13 §10](../specs/13-privacy-hardening.md)). On success it returns the
snapshot with phase `erased` plus
`"mailboxes": {"deactivated": ["<onion>.onion", …], "unreachable": […]}`
(both empty when locked), and shuts down. A mailbox is `deactivated` only when
every capability on it was. On failure it returns `wipe_incomplete`, without
the mailbox report; the next start opens the profile in phase `wiping`, where
only erase is possible, and that retry contacts no mailbox.

**`POST /api/transfers`.** Validated. `action` is one of:

| `action.kind` | Fields | `ok` result |
|---------------|--------|-------------|
| `begin` | `contact`, `manifest: {name, size, hashes}` | transfer view |
| `list` | `contact` | transfer view array |
| `finish` | `id` | `null` |
| `cancel` | `contact`, `id` | `null` |
| `download` | `contact`, `message` | `{"url": "/api/download/<64 hex>", "filename", "size", "metadataWarning"}`; `metadataWarning` is `true` when the received file may still contain metadata (S11 §8) |

Bounds and behavior are those of `begin_upload`, `list_transfers`,
`seal_upload`, `cancel_upload` and `create_file_download` in DESKTOP.md.

**`POST /api/transfer-part/{id}/{part}`.** Uploads part `part` (0-based) of
transfer `id`. Headers: `X-Najwa-Identity: <session>`,
`X-Najwa-Generation: <generation>`. Validated before and after. The body MUST
be exactly the part (1 MiB, or the remainder for the last part) and MUST hash
to the manifest entry (`invalid_file`). A missing or non-numeric generation
header returns `invalid_request`.

**`POST /api/attachment`.** Sends a file of at most 8 MiB in one request.
Headers: `X-Najwa-Identity`, `X-Najwa-Generation`, `X-Najwa-Contact` (contact
id), `X-Najwa-Filename` (base64 of the UTF-8 name). Validated before and after;
runs `queue_file`. The bundled UI uses the resumable transfer endpoints.

**`GET /api/download/{ticket}`.** Streams a file for a grant created by the
`download` transfer action. A grant is valid for 3 600 s and can be used more
than once; the service stores only its SHA-256.

- The profile MUST be unlocked with no identity operation running; otherwise
  `404`. An unknown or expired ticket is also `404`.
- Each streamed piece re-checks that the session and generation are unchanged;
  a lock ends the stream with an error.
- One range is supported: `bytes=a-b`, `bytes=a-` or `bytes=-n`. Multiple
  ranges, `bytes=-0` and starts past the end return `416` with
  `Content-Range: bytes */<size>`. `If-Range` is honored against the ETag.
- Headers: `Content-Type: application/octet-stream`, `Content-Length`,
  `Accept-Ranges: bytes`, `ETag: "<sha256 hex>"`,
  `Content-Disposition: attachment; filename="attachment"; filename*=UTF-8''<percent-encoded name>`,
  and `Content-Range` on `206`.

**Static files.** `GET` only. `/` serves `index.html`. Paths containing `%`,
`\`, `:`, `..` or a segment starting with `.` return `404`. Allowed types:
`index.html`, `.js`, `.css`, `.png`, `.svg`, `.woff2`. Assets come from the
embedded bundle or, with `--assets`, from a directory (files up to 4 MiB,
confined to that directory).

### 1.7 `/api/invoke` operations

`/api/invoke` takes `{"command": <string>, "args": <object>}`. Two commands
exist; any other returns `invalid_request`.

**`messaging_status`** with `args` = `{}`. Requires phase `unlocked`
(`locked` otherwise). Returns the network status (§1.8) with
`"enabled": true` added, then checks that the epoch did not change
(`stale_operation`).

**`messaging_request`** with
`args` = `{"request": {"session", "generation", "operation"}}`. Malformed
`args` return `invalid_request`. The request is validated (§1.3), the
operation's bounds are checked, the operation runs, and the epoch is validated
again. `operation.kind` selects the operation:

| `kind` | Fields | Bounds checked first | `ok` result |
|--------|--------|----------------------|-------------|
| `status` | — | — | network status (without `enabled`) |
| `contacts` | — | — | contact array |
| `messages` | `contact`, `before?: [timestamp, id]`, `query?` | `contact` is an id; `timestamp >= 0` and `id` is an id; `query` non-blank, at most 512 bytes | message array (at most 200) |
| `displayed` | `contact`, `ids` | ids; at most 200 `ids` | `null` |
| `send` | `contact`, `text`, `reply_to?` | id; `text` non-blank, at most 16 000 bytes; `reply_to` 32 hex | message id (32 hex) |
| `manage_contact` | `contact`, `action`, `name?` | id; `action` is `block`, `unblock`, `delete` or `rename`; `name` at most 128 bytes and non-blank for `rename` | `null` |
| `invitation_details` | `invitation` | at most 4 096 bytes | `{"qrText", "qrSvg", "expiresAt"}` |
| `download_file` | `contact`, `message` | ids | `{"filename", "data"}` (base64) |
| `set_timer` | `contact`, `seconds` | id; `seconds` is 0 or at least 30 | `null` |
| `add_mailbox` | `onion` | at most 62 bytes | `null` |
| `select_mailbox` | `onion` | at most 62 bytes | `null` |
| `forget_mailbox` | `onion` | at most 62 bytes | `null` |
| `set_delivery_mode` | `mode` | `responsive` or `privacy` | `null` |
| `retry_mailbox` | `onion` | at most 62 bytes | `null` |
| `invitation` | `name` | non-blank, at most 128 bytes | invitation URI |
| `accept_invitation` | `invitation`, `name`, optional `confirmed` (default `false`) | invitation at most 4 096 bytes; name non-blank, at most 128 bytes. After 10 contacts in 24 hours a new contact needs `confirmed: true`, otherwise `contact_limit_confirm` ([S05 §8.1](../specs/05-contact-establishment.md)) | contact id |
| `verify` | `contact`, `safety`, `verified` | id; `safety` exactly 39 bytes | `null` |
| `sync` | — | — | `null` |
| `reconnect` | — | — | `null` |

An "id" is 1–19 ASCII digits. A failed bound returns `invalid_request`.
`DesktopClient` then applies its own checks (positive 64-bit ids, onion syntax,
names without control characters) and the behavior described in DESKTOP.md.
`messages` without `before` and `query` returns the latest page; with either,
it pages or searches history. Neither marks anything read; `displayed` does.

### 1.8 Data shapes

All keys are camelCase. Ids are decimal strings; message ids are 32 hex.

**Identity snapshot:**

| Field | Values |
|-------|--------|
| `enabled` | always `true` |
| `session` | 32 hex |
| `generation` | integer |
| `phase` | `absent`, `locked`, `unlocked`, `locking`, `wiping`, `erased`, `error` |
| `hardware` | `unverified`, `protected`, `unavailable` |
| `protection` | `hardware` or `os-keystore` |
| `fingerprint` | 64-hex identity public key, or `null` |
| `recoveryAvailable` | a recovery record exists |
| `recoveryPending` | recovery words are waiting to be saved |
| `prekeyRefreshRequired` | after a recovery, fresh prekeys are not yet published; messaging refuses Initials until they are. Cleared once publication is recorded (checked while unlocked) |
| `unavailableReason` | `null` or `wipe_incomplete` |
| `busy` | an identity operation is running |
| `softwareFallbackAvailable` | the OS key store can be approved now |
| `softwareFallbackApproved` | it was approved |
| `lockTimeoutSeconds` | idle lock timeout |

**Network status, contact, message, attachment and transfer view** are defined
in [DESKTOP.md](../../crates/najwa-ffi/DESKTOP.md#operations).

### 1.9 Error codes

| Code | Meaning |
|------|---------|
| `forbidden` | Boundary check failed (403). |
| `invalid_request` | Malformed request, unknown command, or a bound check failed. |
| `stale_operation` | Session or generation changed, the profile is not unlocked, an identity operation is running, or a compared safety number is out of date. |
| `busy` | Another identity operation or network setup is running. |
| `locked` | The profile is locked or messaging admission is closed. |
| `operation_failed` | Internal failure or cancellation. |
| `lock_failed` | Lock could not complete; keys may still be held. The phase is `error`. |
| `invalid_password` | An identity operation failed its field checks. |
| `weak_passphrase` | A new passphrase (create, change, recover, restore) is too easy to guess ([S02 §11.1](../specs/02-identity-key-protection.md)); may carry `hint`. Unlock never returns it. |
| `authentication_failed` | Wrong password. |
| `rate_limited` | Too many unlock attempts; wait `retryAfterMs`. |
| `locked_out` | Unlock is locked out (S02). |
| `already_exists`, `already_unlocked`, `identity_missing` | Identity state does not allow the operation. |
| `recovery_missing`, `recovery_invalid` | No pending words or record; record or words do not match. |
| `keystore_unavailable` | Hardware or OS key store failed. |
| `software_approval_not_available`, `software_approval_required` | OS key-store approval is not offered now, or `confirmed` was not `true`. |
| `storage_unavailable` | Encrypted storage failed. |
| `invalid_preferences`, `invalid_bridges`, `bridge_helper_unavailable` | Preferences rejected. |
| `invalid_confirmation`, `wipe_incomplete` | Erase not confirmed, or erasure did not finish. |
| Messaging codes | `unavailable`, `not_connected`, `timeout`, `sync_failed`, `contact_missing`, `contact_blocked`, `contact_pending`, `contact_exists`, `self_contact`, `timer_pending`, `invalid_timer`, `invalid_message`, `invalid_name`, `invalid_mailbox`, `mailbox_required`, `mailbox_unregistered`, `mailbox_unavailable`, `mailbox_limit`, `mailbox_in_use`, `mailbox_not_paused`, `invalid_invitation`, `contact_limit_confirm`, `invitation_expiring`, `qr_too_large`, `registration_transport`, `registration_pow`, `registration_limited`, `registration_conflict`, `registration_server`, `registration_rejected`, `registration_failed`, `file_too_large`, `file_timer_unsupported`, `unsupported_file`, `invalid_file`, `file_unavailable`, `file_preparing`; see [DESKTOP.md](../../crates/najwa-ffi/DESKTOP.md#error-codes) |

## 2. C ABI

The exact interface is `crates/najwa-ffi/include/najwa.h`, specified by
[S17](../specs/17-ffi-bindings.md). The library builds as a `cdylib`.

### 2.1 Rules for every symbol

- **Panics.** No panic crosses the boundary. A caught panic returns
  `NAJWA_PANIC` (-99) or NULL; treat it as fatal.
- **Strings in.** Arguments are NUL-terminated UTF-8, borrowed only for the
  call. NULL returns `NAJWA_NULL_POINTER`; invalid UTF-8 returns
  `NAJWA_INVALID_UTF8`.
- **Strings out.** `char*` results are owned by the caller and MUST be freed
  exactly once with `najwa_free_string`, which wipes them first. They contain
  plaintext. `najwa_version` is static and MUST NOT be freed.
- **Threads.** Every symbol is thread-safe. Lifecycle calls are serialized
  internally. Create, unlock, lock, send and poll block; do not call them on a
  UI thread.
- **Callbacks.** All callbacks run on one library thread, in order. They MUST
  NOT call any `najwa_*` function, MUST NOT free their arguments, and MUST
  catch their own exceptions. Once a setter or clear returns, the old callback
  is not running and never runs again.
- **Lock.** `najwa_lock` clears every callback and suspends delivery until the
  next create or unlock. Register again after every lock.
- **Lifetime.** `najwa_init` is permanent for the process; one process serves
  one data directory.

### 2.2 Symbols

| Symbol | Returns | Notes |
|--------|---------|-------|
| `int32_t najwa_init(const char* data_dir)` | code | First caller wins (`NAJWA_ALREADY_INITIALIZED`); empty path is `NAJWA_NULL_POINTER`; security init failure is `NAJWA_CRYPTO_ERROR`. |
| `int32_t najwa_identity_exists(void)` | 1, 0 or code | Whether `<data_dir>/identity.najwa` exists. |
| `int32_t najwa_create_identity(const char* password)` | code | Creates and unlocks; password copied into wiped memory; starts Tor in the background. A password that fails the S02 §11.1 rule returns `NAJWA_WEAK_PASSPHRASE`. |
| `int32_t najwa_unlock(const char* password)` | code | Rate-limited; returns before Tor is ready (send and poll return `NAJWA_TRANSPORT_ERROR` until then). |
| `int32_t najwa_lock(void)` | code | Drains up to 5 s, clears callbacks, saves volatile keys, drops keys. Failure keeps keys. |
| `int32_t najwa_cancel_operations(int32_t deadline_ms)` | code | Closes admission until the next unlock; `deadline_ms <= 0` does not wait. `NAJWA_INTERNAL_ERROR` if work is still running. |
| `char* najwa_list_contacts(void)` | JSON array | `[{"id","name","verified","blocked"}]`; `"[]"` on any error or while locked. |
| `char* najwa_list_messages(const char* contact_id)` | JSON array | Up to 200, newest first: `[{"msg_id","direction","timestamp","status","content_type","content"}]`. Marks received rows read and starts disappearing timers. |
| `int32_t najwa_send_message(const char* contact_id, const char* content)` | code | Blocks until the core accepts the text; one status callback. Closed admission is `NAJWA_RATE_LIMIT_EXCEEDED`. |
| `int32_t najwa_poll_messages(void)` | code | Blocks while polling; received UTF-8 text goes to the message-received callback. |
| `int32_t najwa_update_battery(int32_t level, int32_t is_charging)` | code | `level` 0–100 or `NAJWA_NULL_POINTER`; stored, unused in this release. |
| `void najwa_free_string(char* ptr)` | — | Wipes then frees; NULL is a no-op. |
| `const char* najwa_version(void)` | static string | `"najwa-ffi <version>"`. |
| `void najwa_set_message_received_callback(NajwaMessageReceivedCallback cb)` | — | `(contact_id, content)`; NULL clears. |
| `void najwa_set_message_status_callback(NajwaMessageStatusCallback cb)` | — | `(msg_id, status)`; status 0 queued, 1 deposited, 2 delivered, 3 read, 4 failed (retries exhausted), 5 retrying. |
| `void najwa_set_connection_status_callback(NajwaConnectionStatusCallback cb)` | — | `(connected)`: 1 or 0 after a Tor bootstrap. |
| `void najwa_set_error_callback(NajwaErrorCallback cb)` | — | `(code, message)`; not emitted in this release. |
| `void najwa_set_feature_toggle_callback(NajwaFeatureToggleCallback cb)` | — | `(feature, enabled)`; not emitted in this release. |
| `void najwa_set_event_callback(NajwaEventCallback cb)` | — | `(event_json)`; not emitted in this release. |
| `void najwa_clear_all_callbacks(void)` | — | Clears all slots and discards queued events; callbacks registered afterwards receive later events at once. |

### 2.3 Error codes

| Value | Macro | Value | Macro |
|------:|-------|------:|-------|
| 0 | `NAJWA_SUCCESS` | 9 | `NAJWA_TIMESTAMP_OUT_OF_RANGE` |
| -1 | `NAJWA_NULL_POINTER` | 10 | `NAJWA_RATE_LIMIT_EXCEEDED` |
| -2 | `NAJWA_INVALID_UTF8` | 11 | `NAJWA_RATCHET_ERROR` |
| -3 | `NAJWA_NOT_INITIALIZED` | 12 | `NAJWA_MESSAGE_ERROR` |
| -4 | `NAJWA_ALREADY_INITIALIZED` | 13 | `NAJWA_X3DH_ERROR` |
| -5 | `NAJWA_INTERNAL_ERROR` | 14 | `NAJWA_MAILBOX_ERROR` |
| -99 | `NAJWA_PANIC` | 15 | `NAJWA_STORAGE_ERROR` |
| 1 | `NAJWA_CONTACT_NOT_FOUND` | 16 | `NAJWA_SERIALIZATION_ERROR` |
| 2 | `NAJWA_CONTACT_BLOCKED` | 17 | `NAJWA_TRANSPORT_ERROR` |
| 3 | `NAJWA_NO_MAILBOX_CAPABILITY` | 18 | `NAJWA_IDENTITY_ERROR` |
| 4 | `NAJWA_NO_SIGNED_PREKEY` | 19 | `NAJWA_CRYPTO_ERROR` |
| 5 | `NAJWA_PSEUDONYM_MISMATCH` | 20 | `NAJWA_FILE_TRANSFER_ERROR` (reserved) |
| 6 | `NAJWA_UNKNOWN_PSEUDONYM` | 21 | `NAJWA_SANITIZE_ERROR` (reserved) |
| 7 | `NAJWA_DUPLICATE_MESSAGE` | 22 | `NAJWA_GROUP_ERROR` (reserved) |
| 8 | `NAJWA_NO_MATCHING_SESSION` | 23 | `NAJWA_WEAK_PASSPHRASE` |

When each code is returned is listed in [S17 §2](../specs/17-ffi-bindings.md#2-error-codes).

## 3. Mailbox HTTP API

The mailbox server (`najwa-mailbox`) serves this router on
`listen_addr:listen_port` (default `127.0.0.1:8080`), published as a Tor onion
service. [S16](../specs/16-mailbox-server.md) defines every request and
response body.

| Method | Path | Purpose | Spec |
|--------|------|---------|------|
| `POST` | `/v1/capability/register` | Register a capability pair (proof-of-work gated) | S16 §3.1 |
| `POST` | `/v1/challenge` | Get a proof-of-work challenge | S16 §3.2 |
| `POST` | `/v1/deposit` | Store an encrypted blob | S16 §3.3 |
| `POST` | `/v1/fetch` | Fetch released, unacknowledged blobs | S16 §3.4 |
| `POST` | `/v1/acknowledge` | Acknowledge and delete fetched blobs | S16 §3.5 |
| `POST` | `/v1/prekey/upload` | Publish a signed prekey bundle (queue owner only) | S16 §3.6 |
| `POST` | `/v1/prekey/fetch` | Fetch a contact's prekey bundle | S16 §3.7 |
| `POST` | `/v1/status` | Read capability status | S16 §3.8 |
| `POST` | `/v1/capability/deactivate` | Deactivate a capability | S16 §3.9 |
| `GET`, `POST` | `/v1/attestation` | Operator attestation | S16 §3.10 |
| `GET` | `/v1/health` | Liveness probe, on a separate listener | S16 §3.11 |

`/v1/health` is served only on `127.0.0.1:<health_port>` (default 9090) and is
never published through Tor.

Every `/v1` request on the main listener:

- has a body of at most 1 MiB (`413` otherwise);
- if it has a body, MUST be JSON with nesting depth at most 4, arrays of at
  most 200 elements and no duplicate keys (`400` otherwise);
- gets its response no earlier than 100 ms after arrival, so timing does not
  reveal whether a capability exists.

Errors are JSON `{"error": "<message>"}`. A `429` that demands proof of work
adds `"pow_challenge": {"challenge", "difficulty", "algorithm", "expires_at"}`.
Statuses used: 400, 404, 409, 410, 413, 429, 500, 503 and 507.
