---
id: S17
title: FFI Bindings
crates: [najwa-ffi]
depends-on: [S02, S03, S04, S08, S10, S12, S13]
---

# S17 — FFI Bindings

## Overview

`najwa-ffi` is the boundary between Najwa's Rust core and the program that
drives it. It has two front ends over one process-wide runtime:

- **A thin C ABI.** Twenty `extern "C"` symbols declared in
  `crates/najwa-ffi/include/najwa.h`: 13 operation functions and 7 callback
  registration functions. A native host can initialize a data directory,
  create or unlock a password-protected identity, list contacts and messages
  as JSON, send text, poll mailboxes, and receive events through callbacks.
- **A typed Rust API**, `najwa_ffi::desktop::DesktopClient`. The desktop
  service (`apps/local-web`) uses it. The service authenticates the identity
  itself and attaches the unlocked identity; passwords never pass through this
  crate on that path. [DESKTOP.md](../../crates/najwa-ffi/DESKTOP.md) lists its
  operations.

Both front ends share one global state: one data directory, one Tokio runtime,
one SQLCipher store ([S03](03-encrypted-storage.md)), one embedded Arti
transport ([S04](04-transport.md)), one cover-traffic runtime
([S10](10-cover-traffic.md)), one volatile disappearing-message key cache
([S12](12-disappearing-messages.md)), one operation gate and one callback
dispatcher. Below them sits the messaging service of
[S08](08-messaging-service.md).

This spec defines the contracts that keep that shared state safe at the
boundary:

- No panic crosses the boundary, and every input is validated before use.
- Every returned string has one owner and is wiped before it is freed.
- Callbacks run on one dedicated thread. Once a clear returns, the old callback
  is not running and never runs again.
- Lock stops admission and drains in-flight work before any key is dropped. A
  lock that cannot finish keeps the keys and reports failure; it never claims
  to have locked.

The application request path is: browser UI → local HTTP API
([API reference](../reference/api-reference.md)) → `DesktopClient` →
`najwa-core`. The C ABI is a second, smaller entry into the same state.

---

## 1. Scope

This specification defines:

- C ABI error codes (§2);
- panic safety, input validation and interior-NUL handling (§3);
- the exported C functions and their ownership rules (§4);
- callbacks, the event channel, threading, zeroization, the shared operation
  gate and the typed desktop boundary (§5);
- the C header and its generator configuration (§6);
- crate dependencies (§10).

Mobile bindings and mobile platform constants (§7–§9) are reserved.

The committed header `crates/najwa-ffi/include/najwa.h` and the enum in
`crates/najwa-ffi/src/error.rs` are the exact ABI. This specification and the
header MUST agree on every symbol, signature and discriminant.

---

## 2. Error Codes

Every `int32_t`-returning operation returns one of the following values.
Negative values are argument and lifecycle errors. Positive values are domain
errors. The header exposes them as `#define` macros; Rust exposes them as
`FfiErrorCode`.

```rust
#[repr(i32)]
pub enum FfiErrorCode {
    Success = 0,
    NullPointer = -1,
    InvalidUtf8 = -2,
    NotInitialized = -3,
    AlreadyInitialized = -4,
    InternalError = -5,
    Panic = -99,

    ContactNotFound = 1,
    ContactBlocked = 2,
    NoMailboxCapability = 3,
    NoSignedPrekey = 4,
    PseudonymMismatch = 5,
    UnknownPseudonym = 6,
    DuplicateMessage = 7,
    NoMatchingSession = 8,
    TimestampOutOfRange = 9,
    RateLimitExceeded = 10,
    RatchetError = 11,
    MessageError = 12,
    X3DHError = 13,
    MailboxError = 14,
    StorageError = 15,
    SerializationError = 16,
    TransportError = 17,
    IdentityError = 18,
    CryptoError = 19,
    FileTransferError = 20,
    SanitizeError = 21,
    GroupError = 22,
    WeakPassphrase = 23,
}
```

30 variants: 7 general, 23 domain. Discriminants are fixed and MUST NOT change.

| Value | C macro | Returned when |
|------:|---------|---------------|
| 0 | `NAJWA_SUCCESS` | The operation succeeded. |
| -1 | `NAJWA_NULL_POINTER` | A required pointer is NULL, or an argument is invalid: empty `data_dir`, empty password, empty message content, battery level outside 0–100. |
| -2 | `NAJWA_INVALID_UTF8` | A string argument is not valid UTF-8. |
| -3 | `NAJWA_NOT_INITIALIZED` | `najwa_init` has not succeeded in this process. |
| -4 | `NAJWA_ALREADY_INITIALIZED` | `najwa_init` was already done (by either front end), or `najwa_create_identity` was called while an identity is unlocked. |
| -5 | `NAJWA_INTERNAL_ERROR` | A drain missed its deadline, an operation was cancelled, the runtime could not start, or the core reported an internal error. |
| -99 | `NAJWA_PANIC` | A Rust panic was caught at the boundary (§3). |
| 1–14 | `NAJWA_CONTACT_NOT_FOUND` … `NAJWA_MAILBOX_ERROR` | Mapped from the core's `MessagingError` (table below). |
| 10 | `NAJWA_RATE_LIMIT_EXCEEDED` | Also returned by `najwa_send_message` and `najwa_poll_messages` when admission is closed (§5.7). |
| 15 | `NAJWA_STORAGE_ERROR` | The database could not be opened or written, or lock could not persist volatile keys. |
| 16 | `NAJWA_SERIALIZATION_ERROR` | Mapped from the core; also an invalid `contact_id` in `najwa_send_message`. |
| 17 | `NAJWA_TRANSPORT_ERROR` | The Tor transport and messaging service are not ready yet. |
| 18 | `NAJWA_IDENTITY_ERROR` | Identity creation or unlock failed (wrong password, lockout, missing record, unavailable keystore). |
| 19 | `NAJWA_CRYPTO_ERROR` | Process security initialization failed in `najwa_init`. |
| 20–22 | `NAJWA_FILE_TRANSFER_ERROR`, `NAJWA_SANITIZE_ERROR`, `NAJWA_GROUP_ERROR` | Reserved values. No function returns them. |
| 23 | `NAJWA_WEAK_PASSPHRASE` | `najwa_create_identity` was given a password that fails the new-passphrase rule of [S02 §11.1](02-identity-key-protection.md): shorter than 12 characters, longer than 1024 bytes, or too easy to guess. |

Core errors map through one shared function (`code_from_messaging`), which
`najwa_core::error_to_ffi_code` delegates to:

| `MessagingError` | Code |
|------------------|------|
| `ContactNotFound` | 1 |
| `ContactBlocked` | 2 |
| `NoMailboxCapability` | 3 |
| `NoSignedPrekey` | 4 |
| `PseudonymMismatch` | 5 |
| `UnknownPseudonym` | 6 |
| `DuplicateMessage` | 7 |
| `NoMatchingSession` | 8 |
| `TimestampOutOfRange` | 9 |
| `RateLimitExceeded { .. }` | 10 |
| `RatchetError(_)` | 11 |
| `MessageError(_)` | 12 |
| `X3DHError(_)` | 13 |
| `MailboxError(_)`, `AllMailboxesFailed(_)`, `MailboxDisabled(_)` | 14 |
| `StorageError(_)` | 15 |
| `SerializationError(_)` | 16 |
| `IntroducerMismatch`, `InvalidIntroduction(_)`, `KeepLocalSession`, `InternalError(_)` | -5 |

---

## 3. Panic Safety Macros

A Rust panic MUST NOT unwind across the C ABI. Every value-returning export
runs its body inside one of these guards:

```rust
#[macro_export]
macro_rules! ffi_guard {
    ($body:expr) => {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| $body)) {
            Ok(result) => result,
            Err(_) => $crate::error::FfiErrorCode::Panic.as_i32(),
        }
    };
}

#[macro_export]
macro_rules! ffi_guard_ptr {
    ($body:expr) => {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| $body)) {
            Ok(result) => result,
            Err(_) => std::ptr::null_mut(),
        }
    };
}
```

- `int32_t` functions use `ffi_guard!` and return `NAJWA_PANIC` (-99).
- `char*` functions use `ffi_guard_ptr!` and return NULL.
- The six setters and `najwa_clear_all_callbacks` wrap their bodies in
  `catch_unwind` and discard the panic.
- `najwa_free_string` and `najwa_version` contain no panicking path.

The release profile MUST build with `panic = "unwind"`; with `abort`, these
guards do nothing and `Drop`-based zeroization does not run.

The shared state lock, the lifecycle mutex and the operation gate do not
recover from poisoning. A panic while one of them is held makes every later
call that needs it return `NAJWA_PANIC` (or NULL). Callback slots do recover.
The host MUST treat `NAJWA_PANIC` as fatal for the process.

### 3.1 Input Validation Helpers

Every string argument passes through one validator before use:

```rust
pub(crate) fn cstr_to_str(ptr: *const c_char) -> Result<&'static str, i32> {
    if ptr.is_null() {
        return Err(FfiErrorCode::NullPointer.as_i32());
    }
    unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .map_err(|_| FfiErrorCode::InvalidUtf8.as_i32())
}
```

1. A NULL pointer MUST yield `NAJWA_NULL_POINTER`.
2. Bytes that are not valid UTF-8 MUST yield `NAJWA_INVALID_UTF8`.
3. The caller MUST pass a NUL-terminated buffer that stays valid and unchanged
   for the duration of the call. The library reads it only during the call and
   copies what it keeps; it never stores the caller's pointer.

The `'static` lifetime in the Rust signature is an internal convenience; no
borrowed string outlives the call.

Returned strings are built with a fallible constructor:

```rust
pub(crate) fn str_to_cstring_ptr(s: String) -> *mut c_char {
    match CString::new(s) {
        Ok(c) => c.into_raw(),
        Err(e) => {
            let mut bytes = e.into_vec();
            bytes.zeroize();
            std::ptr::null_mut()
        }
    }
}
```

### 3.2 Interior-NUL Handling (normative)

Message content comes from remote peers and MAY contain `0x00` bytes. A C
string cannot.

1. **Returned values.** Contact and message lists are JSON. The JSON encoder
   writes U+0000 as the escape `\u0000`, so the returned C string contains no
   interior NUL and is never truncated. If any returned string did contain an
   interior NUL, the library MUST return NULL after wiping the bytes, not panic.
2. **No infallible construction.** `CString::new(..).unwrap()` and equivalents
   are forbidden in non-test code. Every C string the crate builds MUST handle
   the NUL case.
3. **Callback arguments.** Callback strings are built in a wiped-on-drop buffer
   with every `0x00` byte removed and one terminator appended. Text delivered to
   `NajwaMessageReceivedCallback` therefore omits any NUL bytes the sender
   included. The full content stays in storage and appears, escaped, in
   `najwa_list_messages`.
4. **Panics in callback paths.** The dispatcher wraps the entire
   marshal-and-invoke sequence in `catch_unwind`. Callback pointer types are
   `extern "C"`; a foreign exception that tries to unwind out of a callback
   aborts the process. The host MUST catch its own exceptions inside every
   callback.

---

## 4. Exported Functions

Operation functions return `int32_t` (§2) unless they return a string. String
results are owned by the caller and MUST be released with `najwa_free_string`
exactly once.

### 4.1 Lifecycle (6)

```c
int32_t najwa_init(const char* data_dir);
int32_t najwa_identity_exists(void);
int32_t najwa_create_identity(const char* password);
int32_t najwa_unlock(const char* password);
int32_t najwa_lock(void);
int32_t najwa_cancel_operations(int32_t deadline_ms);
```

`najwa_init`, `najwa_create_identity`, `najwa_unlock`, `najwa_lock` and
`najwa_cancel_operations` are serialized by one process-wide lifecycle mutex
(§5.7).

**`najwa_init(data_dir)`.**

1. Validate `data_dir` (§3.1). An empty string yields `NAJWA_NULL_POINTER`.
2. If the process is already initialized, by the C ABI or by
   `DesktopClient::init`, return `NAJWA_ALREADY_INITIALIZED`. The first caller
   wins. The library never tears this state down; one process serves one data
   directory.
3. Run process security initialization (`najwa_crypto::initialize`): suppress
   process crash dumps as far as the platform allows (on Linux, mark the process
   non-dumpable and set the core-size limit to 0), then verify the CSPRNG. On
   failure return `NAJWA_CRYPTO_ERROR` and stay uninitialized.
4. Start the callback dispatcher thread (§5.5) and the library's multi-thread
   Tokio runtime. If the runtime cannot start, return `NAJWA_INTERNAL_ERROR`.

`najwa_init` does not create the directory, read the identity or touch the
network.

**`najwa_identity_exists()`.** Returns 1 if `<data_dir>/identity.najwa`
exists, 0 if it does not, `NAJWA_NOT_INITIALIZED` before init. It does not
validate the record.

**`najwa_create_identity(password)`.**

1. Validate `password` (§3.1); an empty password yields `NAJWA_NULL_POINTER`.
   Copy it into a wiped-on-drop buffer immediately (§5.6.1).
2. If an identity is already unlocked, return `NAJWA_ALREADY_INITIALIZED`.
3. Close admission and drain in-flight operations with the 5 000 ms lock
   deadline (§5.7). If the drain misses the deadline, return
   `NAJWA_INTERNAL_ERROR`.
4. If not initialized, return `NAJWA_NOT_INITIALIZED`.
5. Create the data directory (`NAJWA_STORAGE_ERROR` on failure) and create the
   identity record through the identity manager of
   [S02](02-identity-key-protection.md). A password that fails the S02 §11.1
   rule returns `NAJWA_WEAK_PASSPHRASE`; any other identity failure, including
   an existing record, returns `NAJWA_IDENTITY_ERROR`.
6. Derive the database key (§5.7) and open `<data_dir>/najwa.db`
   (`NAJWA_STORAGE_ERROR` on failure).
7. Restore persisted volatile keys, run one disappearing-message cleanup and
   start the periodic cleaner ([S12](12-disappearing-messages.md)), which also
   runs the storage retention pass ([S03 §6.4](03-encrypted-storage.md)).
8. Publish the unlocked state, increment the lifecycle generation, reopen
   admission, resume callback delivery, and start the Tor bootstrap in the
   background (§5.7).

On success the new identity is unlocked. A failure after step 3 leaves
admission closed until a later successful create or unlock.

**`najwa_unlock(password)`.**

1. Validate and copy `password` as for create.
2. Close admission and drain with the 5 000 ms deadline; on timeout return
   `NAJWA_INTERNAL_ERROR`.
3. If not initialized, return `NAJWA_NOT_INITIALIZED`.
4. Unlock the identity record through the rate-limited unlock of S02. Any
   failure returns `NAJWA_IDENTITY_ERROR`.
5. If an identity is already unlocked in this process (for example after
   `najwa_cancel_operations`), reopen admission, resume callback delivery and
   return. The unlocked state is not rebuilt.
6. Otherwise derive the database key, open storage, restore and clean volatile
   keys, publish the state, increment the generation, reopen admission, resume
   callback delivery and start the Tor bootstrap.

`najwa_unlock` returns before Tor is ready. Until the bootstrap installs the
messaging service, `najwa_send_message` and `najwa_poll_messages` return
`NAJWA_TRANSPORT_ERROR`. The connection-status callback reports the outcome.

**`najwa_lock()` (normative order).**

1. Close admission and cancel in-flight operations. Wait for them to finish for
   at least 2 s; this implementation waits up to 5 000 ms
   (`LOCK_DRAIN_DEADLINE_MS`). If any are still running, return
   `NAJWA_INTERNAL_ERROR` and drop nothing.
2. Stop the disappearing-message cleaner.
3. Clear all callbacks and quiesce the dispatcher (§5.3). Queued events are
   wiped and discarded.
4. Run one disappearing-message cleanup, store the volatile key cache encrypted
   under the database key, and checkpoint the WAL. On failure, restart the
   cleaner, keep every key and return the error (`NAJWA_STORAGE_ERROR`).
5. Wipe the volatile key cache, refresh the cover runtime's mailbox list and
   fetch plan, increment the lifecycle generation, then drop the database key,
   the identity keys, the storage handle and the messaging service, and lock the
   identity manager.

Zeroizing keys while an operation is still running is forbidden. The cover
runtime (its Tor client, cover-capability coordinates and the fetch plan of
[S08 §6.1.1](08-messaging-service.md): onions and fetch capabilities) survives a
lock; it holds no identity or database key and no envelope secret of a real
queue. The C ABI itself never polls while locked; the desktop receive worker
does, fetch-only (§5.8, [S13 §8.3](13-privacy-hardening.md)). Before `najwa_init`, `najwa_lock` returns
`NAJWA_SUCCESS`. After a lock, admission stays closed and callbacks stay
cleared until the next successful create or unlock.

**`najwa_cancel_operations(deadline_ms)`.** Close admission, signal
cancellation to every in-flight operation, and wait up to `deadline_ms` for
them to finish. `deadline_ms <= 0` signals without waiting. Returns
`NAJWA_SUCCESS` if nothing is in flight at return, otherwise
`NAJWA_INTERNAL_ERROR`. Operations are never killed. An operation waiting on
core work through the cancellable wrapper (§5.7) returns `NAJWA_INTERNAL_ERROR`
to its own caller; a synchronous storage read finishes normally. Admission
stays closed until the next successful `najwa_unlock` or
`najwa_create_identity`. Callbacks stay registered.

**Interrupted polls lose nothing.** The core acknowledges a fetched blob only
after it reaches a durable terminal outcome ([S08](08-messaging-service.md)).
Blobs from a cancelled or killed poll stay on the mailbox and are fetched again
by the next poll.

### 4.2 Contacts & Messages (4)

```c
char*   najwa_list_contacts(void);
char*   najwa_list_messages(const char* contact_id);
int32_t najwa_send_message(const char* contact_id, const char* content);
int32_t najwa_poll_messages(void);
```

**`najwa_list_contacts()`.** Returns a new NUL-terminated UTF-8 JSON array.
Each element is:

```json
{"id": 7, "name": "Alice", "verified": false, "blocked": false}
```

`id` is a JSON integer (positive, fits in `int64`). `name` is a string or
`null`. The result is `"[]"` before init, while locked, while admission is
closed, or on a storage error; these cases are indistinguishable from an empty
list. NULL is returned only after a caught panic.

**`najwa_list_messages(contact_id)`.** `contact_id` is the decimal string of a
positive `int64`; any other value returns `"[]"`. The result holds up to 200
messages for that contact, newest first (by timestamp, then row id), across all
stored content types. Each element is:

```json
{"msg_id": "00112233445566778899aabbccddeeff", "direction": 0,
 "timestamp": 1767225600, "status": 2, "content_type": 0, "content": "hi"}
```

| Field | Meaning |
|-------|---------|
| `msg_id` | 16-byte message id, 32 lowercase hex characters |
| `direction` | 0 received, 1 sent |
| `timestamp` | Unix seconds |
| `status` | §5.1 status value (0–5) |
| `content_type` | stored content-type code ([S03](03-encrypted-storage.md)): 0 text, 8 text reply, 10 file metadata, 11 file chunk |
| `content` | the content as a UTF-8 string, or `null` if the bytes are not UTF-8 |

Expired disappearing messages are omitted. Sealed disappearing content is
opened from the volatile key cache; a row whose key is gone is omitted.

**Side effect:** every returned received message that was unread is marked
read, and its disappearing timer starts (the display trigger of S12). The C ABI
has no read-only listing.

The empty-result and NULL rules of `najwa_list_contacts` apply.

**`najwa_send_message(contact_id, content)`.**

1. Validate both strings (§3.1). Empty `content` yields `NAJWA_NULL_POINTER`.
2. `contact_id` MUST be the decimal string of an integer in 1 ..= 2⁶³−1;
   otherwise return `NAJWA_SERIALIZATION_ERROR`.
3. Acquire admission; if closed, return `NAJWA_RATE_LIMIT_EXCEEDED`.
4. If not initialized, return `NAJWA_NOT_INITIALIZED`. If the messaging service
   is not installed yet, return `NAJWA_TRANSPORT_ERROR`.
5. Block on the library runtime while the core sends the text
   (`MessagingService::send_message`, S08). Cancellation returns
   `NAJWA_INTERNAL_ERROR`; core errors map through §2.
6. Read the stored status of the new message and queue one message-status event
   with its 32-hex `msg_id` (`QUEUED` if the row cannot be read). Return
   `NAJWA_SUCCESS`.

Size limits are those of the core ([S07](07-message-format.md), S08). Later
status changes are not reported through the callback; read them with
`najwa_list_messages`.

**`najwa_poll_messages()`.** Acquire admission (`NAJWA_RATE_LIMIT_EXCEEDED` if
closed), require init and the messaging service as for send, then block while
the core polls every mailbox (S08), reading this poll's selection of each
mailbox's receive queues ([S08 §6.1.1](08-messaging-service.md)). Each received message whose content is
valid UTF-8 is queued to the message-received callback with the contact id as a
decimal string. Content that is not UTF-8 is stored but not delivered by
callback. Returns `NAJWA_SUCCESS`, `NAJWA_INTERNAL_ERROR` on cancellation, or a
mapped core error.

### 4.3 Battery State (1)

```c
int32_t najwa_update_battery(int32_t level, int32_t is_charging);
```

- `level` MUST be in 0 ..= 100. Any other value returns `NAJWA_NULL_POINTER`;
  the value is not clamped.
- `is_charging` is 0 or 1. Any other non-zero value is treated as 1, and a
  warning is logged once per process.
- Returns `NAJWA_NOT_INITIALIZED` before init, otherwise `NAJWA_SUCCESS`.

The function is not admission-gated and works while locked. The values are
stored; no feature consumes them in this release.

### 4.4 Utility (2)

```c
void        najwa_free_string(char* ptr);
const char* najwa_version(void);
```

**`najwa_free_string(ptr)`.** NULL is a no-op. Otherwise `ptr` MUST be a
pointer returned by `najwa_list_contacts` or `najwa_list_messages` that has not
been freed. The function overwrites the whole allocation with zeros, then frees
it (§5.6.2). Passing any other pointer, including the result of
`najwa_version`, is undefined behavior.

**`najwa_version()`.** Returns a static, NUL-terminated string
`"najwa-ffi <crate version>"`. It lives for the whole program and MUST NOT be
freed. It never fails and needs no init.

### 4.5 Symbol Inventory

| Section | Count | Symbols |
|---------|------:|---------|
| §4.1 Lifecycle | 6 | `najwa_init`, `najwa_identity_exists`, `najwa_create_identity`, `najwa_unlock`, `najwa_lock`, `najwa_cancel_operations` |
| §4.2 Contacts & Messages | 4 | `najwa_list_contacts`, `najwa_list_messages`, `najwa_send_message`, `najwa_poll_messages` |
| §4.3 Battery State | 1 | `najwa_update_battery` |
| §4.4 Utility | 2 | `najwa_free_string`, `najwa_version` |
| §5.2 Callback registration | 7 | six `najwa_set_*_callback`, `najwa_clear_all_callbacks` |
| **Total** | **20** | |

Adding or changing a symbol requires updating, together: the Rust export, the
header (§6.1), the `[export] include` list in `cbindgen.toml`, and this table.

---

## 5. Callback Types (6)

Callbacks are registered by the host and invoked by the library on its own
dedicated thread (§5.5). This section also defines the runtime contracts that
both front ends share.

### 5.1 Callback Signatures

```c
typedef void (*NajwaMessageReceivedCallback)(const char* contact_id, const char* content);
typedef void (*NajwaMessageStatusCallback)(const char* msg_id, int32_t status);
typedef void (*NajwaConnectionStatusCallback)(int32_t connected);
typedef void (*NajwaErrorCallback)(int32_t code, const char* message);
typedef void (*NajwaFeatureToggleCallback)(const char* feature, int32_t enabled);
typedef void (*NajwaEventCallback)(const char* event_json); // §5.4
```

String arguments are borrowed for the duration of the call. They are
NUL-terminated UTF-8 with any `0x00` bytes removed (§3.2). The callback MUST
copy what it keeps and MUST NOT free them; the library wipes them after the
call.

| Callback | Arguments | Produced by |
|----------|-----------|-------------|
| MessageReceived | contact id as a decimal string; message text | `najwa_poll_messages` |
| MessageStatus | 32-hex `msg_id`; status value | `najwa_send_message`, once, at acceptance |
| ConnectionStatus | 1 connected, 0 not connected | Tor bootstrap after create, unlock, `DesktopClient::attach_identity` or reconnect: 1 when the messaging service is installed; 0 when the saved Tor settings are unusable or bootstrap fails |
| Error | `FfiErrorCode`; message | no producer in this release |
| FeatureToggle | feature name; 0 or 1 | no producer in this release |
| Event | JSON object (§5.4) | no producer in this release |

**`NajwaMessageStatusCallback` status values (normative, closed set):**

| `status` | Name | Stored status mapped to it |
|---------:|------|----------------------------|
| 0 | Queued | `Pending`: accepted locally, not yet deposited |
| 1 | Deposited | `Sent`: accepted by a mailbox |
| 2 | Delivered | `Delivered`: acknowledged by the recipient (S07) |
| 3 | Read | `Read`: read receipt received |
| 4 | Failed | `PermanentlyFailed`: retries exhausted; the user must send again |
| 5 | Retrying | `Failed`: the send failed and the core retries it |

Implementations MUST NOT emit other values. Value 5 was appended after 4; the
values 0–4 keep their numbers. Before it, `Failed` also reported 4, so a host
written for 0–4 sees 5 for a message the core is still retrying.

**`NajwaFeatureToggleCallback` feature names (closed set).** `"cover_traffic"`
is the only feature name defined for this release. The names `"vpn_mode"`,
`"post_poll_burst"` and `"background_poll"` are reserved and never emitted.
`enabled` is 0 or 1. Hosts MUST ignore names they do not recognize.

### 5.2 Registration Functions

```c
void najwa_set_message_received_callback(NajwaMessageReceivedCallback cb);
void najwa_set_message_status_callback(NajwaMessageStatusCallback cb);
void najwa_set_connection_status_callback(NajwaConnectionStatusCallback cb);
void najwa_set_error_callback(NajwaErrorCallback cb);
void najwa_set_feature_toggle_callback(NajwaFeatureToggleCallback cb);
void najwa_set_event_callback(NajwaEventCallback cb);
void najwa_clear_all_callbacks(void);
```

- Each setter replaces one slot. NULL clears it. Setters never fail, need no
  init and are not admission-gated.
- `najwa_clear_all_callbacks` clears all six slots and discards (and wipes)
  every queued event. A callback registered after it receives later events at
  once; an event queued before the clear never reaches it (§5.3).
- `najwa_lock` and `DesktopClient::prepare_wipe` do the same clear and also
  suspend event delivery. Delivery resumes at the next successful
  `najwa_create_identity`, `najwa_unlock` or `DesktopClient::attach_identity`;
  events produced before then are dropped, even if a host registers callbacks
  in between. A host MUST register its callbacks again after every lock.

### 5.3 Thread-Safe Registration and Teardown Quiescence (normative)

Registration MUST provide this guarantee:

> When `najwa_clear_all_callbacks`, or a `najwa_set_*_callback` that replaces
> or clears a callback, **returns**, the callback it removed is not executing
> on any thread and will never be invoked again.

The implementation:

1. Each slot is a `Mutex<Option<fn>>`. The dispatcher holds the slot's mutex
   across the entire marshal-and-invoke sequence. A setter takes the same mutex,
   so it blocks until an in-flight invocation of that slot returns.
2. `najwa_clear_all_callbacks` first takes the dispatcher lock, so it waits for
   any in-flight invocation of any slot. It then increments the delivery
   generation, discards queued events, and clears all slots. The lock and wipe
   teardown (§5.2) does the same and also marks the queue quiesced.
3. Every queued event carries the delivery generation current when it was
   queued. The dispatcher invokes a callback only if the queue is not quiesced
   and the event's generation is current. An event queued before a clear never
   reaches a callback registered after it.

A lock-free "load the pointer, then call it" scheme is forbidden: a host could
unload the callback's code between the load and the call.

```rust
fn invoke<T: Copy>(slot: &Mutex<Option<T>>, generation: u64, call: impl FnOnce(T)) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let registered = slot.lock().unwrap_or_else(|e| e.into_inner());
        let valid = {
            let events = queue().0.lock().unwrap_or_else(|e| e.into_inner());
            !events.quiesced && generation == events.generation
        };
        if valid {
            if let Some(cb) = *registered {
                call(cb); // marshals wiped C strings, then invokes
            }
        }
    }));
}
```

Because callbacks run only on the dispatcher thread and MUST NOT re-enter the
ABI (§5.5), holding a slot mutex across the call cannot deadlock against a
setter on another thread. A setter called from inside a callback deadlocks.

### 5.4 Event Channel

`NajwaEventCallback` carries core events that have no dedicated callback.
`event_json` is a UTF-8 JSON object whose `"event"` member names the event.
These events and payloads are defined:

| `event` | Payload fields | Source |
|---------|----------------|--------|
| `"file_transfer_interrupted"` | `session_id` (hex string), `direction` (string), `reason` (`"session_repair"` or `"timeout"`), `resumable` (bool) | [S11](11-file-transfer-sanitization.md) |
| `"file_transfer_progress"` | `session_id` (hex string), `chunks_done` (integer), `chunks_total` (integer) | S11 |
| `"repair_state_changed"` | `contact_id` (integer), `state` (string) | [S06](06-key-agreement-ratchet.md) session repair |

Payloads MUST be built with a JSON encoder so that untrusted strings are
escaped. An implementation that reports one of these conditions MUST use these
names and fields. Hosts MUST ignore event names they do not recognize.

No operation emits events on this channel in this release (§5.9).

### 5.5 Threading Contract (normative)

1. **Thread safety.** Every exported function is safe to call from any thread
   at any time. The host need not serialize calls. Lifecycle functions are
   serialized internally (§4.1); other calls run concurrently.
2. **Blocking.** Create, unlock and lock can block for up to the 5 000 ms drain
   plus identity unlock or key persistence. Send and poll block until the core
   finishes; the C ABI adds no timeout. Hosts MUST NOT call them on a UI thread. A host that needs a
   bound calls `najwa_cancel_operations` from another thread.
3. **Runtime.** Asynchronous core work runs on the library's multi-thread Tokio
   runtime. C ABI calls block on that runtime. Core work never runs on the
   callback thread.
4. **Dedicated callback thread.** All callbacks run on one library-owned thread
   named `najwa-ffi-callbacks`, started by `najwa_init` or the first queued
   event. A callback never runs on the thread of a `najwa_*` caller or on a
   runtime worker. Events go through one FIFO queue and are delivered in the
   order they were produced.
5. **No re-entry.** A callback MUST NOT call any `najwa_*` function, including
   the setters. The host hands the work to its own executor.

### 5.6 Zeroization Contract (normative)

#### 5.6.1 Password paths

`najwa_create_identity` and `najwa_unlock` MUST copy the password into a
wiped-on-drop buffer (`Zeroizing<String>`) immediately after validation. The
boundary MUST NOT make other copies (no `format!`, no logging). The identity
manager's own handling is specified by S02.

#### 5.6.2 Zeroize before free

1. `najwa_free_string` MUST overwrite the entire allocation with zeros before
   releasing it. Returned JSON contains plaintext messages, so building it MUST
   NOT leave other unwiped copies: `najwa_list_messages` serializes the message
   text by reference (no intermediate JSON values) into a buffer sized before
   writing, so it never reallocates, copies that buffer into a returned string
   of exactly its length plus the terminator, then wipes the buffer and the
   message rows it read. A returned string is never built by growing or
   shrinking a buffer that holds the JSON.
2. Queued callback payloads (message content, message id, error message, event
   JSON) MUST be wiped when the event is dropped, including events discarded by
   a clear.
3. Callback argument buffers MUST be wiped after the call.
4. Internal buffers that hold plaintext or key material MUST be wiped when
   dropped. The database key is held in a `Zeroizing` buffer; lock wipes the
   volatile key cache and drops every key holder (§4.1). On the typed desktop
   boundary (§5.8), `messages` and `message_history` wipe each stored row once
   its text is copied out, and `Message` wipes its text on drop. A row dropped
   because a read fails partway is zeroed by the native service's zeroizing
   allocator ([S01 §6.1](01-crypto-primitives.md)); a C ABI host that installs
   no such allocator does not get that backstop.

#### 5.6.3 Caller buffers

The host owns every buffer it passes in. The library reads input strings only
during the call. Hosts SHOULD hold passwords in memory they can overwrite and
SHOULD overwrite it after the call returns. Hosts SHOULD free returned JSON as
soon as it is parsed.

### 5.7 Operation Admission and Cancellation (normative)

Both front ends use one process-wide **operation gate**: an `allowed` flag, an
in-flight counter and a cancellation signal, all under one mutex.

1. **Admission.** Every key-using operation acquires a guard before touching
   state. Acquisition fails when the gate is closed. The C ABI then returns
   `"[]"` (lists) or `NAJWA_RATE_LIMIT_EXCEEDED` (send, poll); `DesktopClient`
   returns the code `locked`.
2. **Closing.** Lock, cancel, create, unlock, `attach_identity` and
   `prepare_wipe` close the gate: set `allowed = false`, raise the cancellation
   signal, then wait until the in-flight counter is zero or the deadline
   passes. Closing and counting happen under the same mutex, so no operation can
   enter after the drain has observed zero.
3. **Cancellation.** An operation that awaits core work through the guard's
   `cancellable` wrapper stops at its next await point and reports
   `InternalError` (C ABI) or `operation_failed` (desktop). Threads are never
   killed.
4. **Reopening.** Only a successful create, unlock or `attach_identity` reopens
   the gate, and only when nothing is in flight. If something is, the call
   fails (`NAJWA_INTERNAL_ERROR`, or `lock_failed` on the desktop).
5. **Lifecycle mutex.** `najwa_init`, create, unlock, lock, cancel,
   `DesktopClient::init`, `attach_identity` and `prepare_wipe` hold one
   lifecycle mutex for their whole duration.
6. **Lifecycle generation.** A counter incremented each time an unlocked state
   is published or cleared. Background work (Tor bootstrap completion, desktop
   workers) records the generation it started under and discards its result if
   the generation has changed.
7. **Deadline.** `LOCK_DRAIN_DEADLINE_MS = 5000`.

**Tor bootstrap.** After an unlock the library reads the saved Tor bridge
preferences from encrypted storage and builds the Arti configuration
(DESKTOP.md). If the preferences cannot be read or are invalid, the connection
stops and the connection-status callback receives 0; the library MUST NOT fall
back to a direct Tor connection. If a cover runtime already exists, its Tor
client is reused; otherwise a new Arti client bootstraps with state under
`<data_dir>/tor`. Bridge lines MUST NOT be logged.

**Database key.** Both front ends derive the SQLCipher key from the identity
signing seed:

```
db_key = HKDF-SHA256(IKM  = Ed25519 seed (32 bytes),
                     salt = "najwa-sqlcipher-key",
                     info = "najwa/v1/sqlcipher-key",
                     L    = 32)
```

**Files** under the data directory: `identity.najwa` (identity record, S02),
`najwa.db` (SQLCipher store, S03), `tor/` (Arti state).

### 5.8 Typed Desktop Boundary

`najwa_ffi::desktop::DesktopClient` is a Rust API. It adds no C symbols.

1. One client per process. `DesktopClient::init(directory)` fails with
   `already_initialized` if the C ABI or another client initialized first. It
   runs the same security initialization as `najwa_init`
   (`security_initialization_failed` on failure).
2. The native owner authenticates the identity and passes the unlocked
   `Identity` to `attach_identity`. This crate never receives the password on
   this path.
3. It shares the operation gate, lifecycle mutex, generation and dispatcher of
   §5.7. `DesktopClient::lock` calls `najwa_lock` and reports `lock_failed` on
   any non-zero result; a failed lock keeps the keys. The receive worker that
   `attach_identity` starts polls after exponential gaps (mean 3 s,
   [S08 §10.1](08-messaging-service.md)) and keeps polling fetch-only from the
   cover runtime's fetch plan through the following lock, until the next
   attach starts its own worker ([S13 §8.3](13-privacy-hardening.md)).
4. Errors are fixed lowercase codes (for example `locked`, `not_connected`,
   `stale_operation`). They never contain secrets, capabilities or message
   content.
5. Row ids cross the boundary as decimal strings; message ids as 32 lowercase
   hex characters.
6. Methods block. They MUST be called from a blocking worker thread, never from
   inside an async runtime.
7. `prepare_wipe` closes and drains the gate (`wipe_incomplete` on timeout),
   clears callbacks, takes the whole state, collects mailbox fetch capabilities
   (dummy queues included) for optional remote deactivation, wipes copied
   capability material, drops the cover runtime (zeroizing its fetch plan),
   service, keys and storage without persisting volatile keys, and shuts the
   runtime down. `DesktopClient::init` may then be called again. The local
   service also calls it after its final lock at quit.

[DESKTOP.md](../../crates/najwa-ffi/DESKTOP.md) defines each operation, its
bounds and its error codes.

### 5.9 Security Considerations and Limitations

- The C ABI covers one-to-one text only. File transfer, contact establishment,
  mailbox registration and preferences are available only through
  `DesktopClient`.
- No operation produces the error, feature-toggle or event callbacks. Message
  status is reported once per send; later transitions are visible only through
  `najwa_list_messages`.
- `najwa_list_messages` marks received rows read and starts their disappearing
  timers. A host that lists messages it does not display shortens their visible
  lifetime.
- List functions return `"[]"` for errors, locked state and closed admission.
  Hosts cannot tell these apart from an empty result.
- Message-received callbacks drop NUL bytes from the text (§3.2).
- `najwa_init` cannot be undone. The data directory is fixed for the life of
  the process.

---

## 6. cbindgen Configuration

The committed header is the reference and the build input; it is maintained by
hand and no build step runs cbindgen. CI compiles it as C and C++ and links the
C smoke test (`crates/najwa-ffi/tests/c_abi_smoke.c`) against the cdylib, which
fails if a declared function is not exported; signatures are not compared. The
generator configuration lives in `cbindgen.toml` at the repository root:

```toml
language = "C"
include_guard = "NAJWA_CORE_H"
autogen_warning = "/* Maintained by hand to match the najwa-ffi exports (S17 §6). */"
include_version = true
header = """/* Najwa thin C ABI (S17 §1–§6). ... */"""

[export]
include = [
    "najwa_init", "najwa_identity_exists", "najwa_create_identity",
    "najwa_unlock", "najwa_lock", "najwa_cancel_operations",
    "najwa_list_contacts", "najwa_list_messages", "najwa_send_message",
    "najwa_poll_messages", "najwa_update_battery", "najwa_free_string",
    "najwa_version",
    "najwa_set_message_received_callback", "najwa_set_message_status_callback",
    "najwa_set_connection_status_callback", "najwa_set_error_callback",
    "najwa_set_feature_toggle_callback", "najwa_set_event_callback",
    "najwa_clear_all_callbacks",
]

[parse]
parse_deps = false
```

- No `[export] prefix` is set: the symbols already carry the `najwa_` prefix.
- Error codes are written as `NAJWA_*` macros (§2), not as a C enum.

After changing an exported signature, regenerate the function declarations:

```sh
cbindgen --config cbindgen.toml --crate najwa-ffi --output crates/najwa-ffi/include/najwa.h
```

Then reconcile the error-code macros with `error.rs` and the inventory in §4.5.

### 6.1 Generated Header

`crates/najwa-ffi/include/najwa.h` uses the include guard `NAJWA_CORE_H`,
includes only `<stdint.h>`, and wraps its declarations in `extern "C"` for C++.
Its declarations, without comments, are:

```c
#ifndef NAJWA_CORE_H
#define NAJWA_CORE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*NajwaMessageReceivedCallback)(const char* contact_id, const char* content);
typedef void (*NajwaMessageStatusCallback)(const char* msg_id, int32_t status);
typedef void (*NajwaConnectionStatusCallback)(int32_t connected);
typedef void (*NajwaErrorCallback)(int32_t code, const char* message);
typedef void (*NajwaFeatureToggleCallback)(const char* feature, int32_t enabled);
typedef void (*NajwaEventCallback)(const char* event_json);

void najwa_set_message_received_callback(NajwaMessageReceivedCallback cb);
void najwa_set_message_status_callback(NajwaMessageStatusCallback cb);
void najwa_set_connection_status_callback(NajwaConnectionStatusCallback cb);
void najwa_set_error_callback(NajwaErrorCallback cb);
void najwa_set_feature_toggle_callback(NajwaFeatureToggleCallback cb);
void najwa_set_event_callback(NajwaEventCallback cb);
void najwa_clear_all_callbacks(void);

int32_t najwa_init(const char* data_dir);
int32_t najwa_identity_exists(void);
int32_t najwa_create_identity(const char* password);
int32_t najwa_unlock(const char* password);
int32_t najwa_lock(void);
int32_t najwa_cancel_operations(int32_t deadline_ms);

char* najwa_list_contacts(void);
char* najwa_list_messages(const char* contact_id);
int32_t najwa_send_message(const char* contact_id, const char* content);
int32_t najwa_poll_messages(void);

int32_t najwa_update_battery(int32_t level, int32_t is_charging);

void najwa_free_string(char* ptr);
const char* najwa_version(void);

#define NAJWA_SUCCESS 0
#define NAJWA_NULL_POINTER (-1)
#define NAJWA_INVALID_UTF8 (-2)
#define NAJWA_NOT_INITIALIZED (-3)
#define NAJWA_ALREADY_INITIALIZED (-4)
#define NAJWA_INTERNAL_ERROR (-5)
#define NAJWA_PANIC (-99)
#define NAJWA_CONTACT_NOT_FOUND 1
#define NAJWA_CONTACT_BLOCKED 2
#define NAJWA_NO_MAILBOX_CAPABILITY 3
#define NAJWA_NO_SIGNED_PREKEY 4
#define NAJWA_PSEUDONYM_MISMATCH 5
#define NAJWA_UNKNOWN_PSEUDONYM 6
#define NAJWA_DUPLICATE_MESSAGE 7
#define NAJWA_NO_MATCHING_SESSION 8
#define NAJWA_TIMESTAMP_OUT_OF_RANGE 9
#define NAJWA_RATE_LIMIT_EXCEEDED 10
#define NAJWA_RATCHET_ERROR 11
#define NAJWA_MESSAGE_ERROR 12
#define NAJWA_X3DH_ERROR 13
#define NAJWA_MAILBOX_ERROR 14
#define NAJWA_STORAGE_ERROR 15
#define NAJWA_SERIALIZATION_ERROR 16
#define NAJWA_TRANSPORT_ERROR 17
#define NAJWA_IDENTITY_ERROR 18
#define NAJWA_CRYPTO_ERROR 19
#define NAJWA_FILE_TRANSFER_ERROR 20
#define NAJWA_SANITIZE_ERROR 21
#define NAJWA_GROUP_ERROR 22
#define NAJWA_WEAK_PASSPHRASE 23

#ifdef __cplusplus
}
#endif

#endif /* NAJWA_CORE_H */
```

In Rust, the setters take `Option<extern "C" fn(..)>`, which has the same
representation as a nullable C function pointer.

---

## 7. Reserved

---

## 8. Reserved

---

## 9. Reserved

---

## 10. Rust Crate Dependencies

`najwa-ffi` builds as both `rlib` (for `apps/local-web`) and `cdylib` (for C
hosts).

| Crate | Purpose |
|-------|---------|
| `najwa-core` | `MessagingService`, cover scheduler, disappearing-message cache and cleaner, file-transfer session |
| `najwa-crypto` | process security initialization, HKDF, Ed25519, hashing, CSPRNG |
| `najwa-identity` | identity record, unlock, `Identity` |
| `najwa-storage` | SQLCipher store |
| `najwa-protocol` | mailbox HTTP client, invitations, wire types |
| `najwa-transport` | embedded Arti transport and bridge configuration |
| `najwa-sanitize` | streaming file sanitization for desktop uploads |
| `tokio` | async runtime |
| `zeroize` | wiping secrets and plaintext |
| `serde`, `serde_json` | JSON results and desktop types |
| `base64`, `sha2` | desktop file payloads and transport-helper pinning |
| `tracing` | logging (no secrets) |

Cargo features `windows-tpm`, `linux-tpm`, `macos-secure-enclave` and
`hardware-keystore` pass through to `najwa-identity`.

---

## 11. Conformance Checklist

- `FfiErrorCode` has 30 variants with the fixed discriminants of §2, and the
  header macros match them.
- `najwa_create_identity` returns `NAJWA_WEAK_PASSPHRASE` for a password that
  fails S02 §11.1.
- One shared `MessagingError` mapping (`code_from_messaging`).
- Every value-returning export runs under `ffi_guard!` or `ffi_guard_ptr!`;
  setters and clear-all catch panics; the release profile uses
  `panic = "unwind"`.
- Every string input passes `cstr_to_str` (NULL → -1, bad UTF-8 → -2).
- No infallible `CString` construction in non-test code; an interior NUL in a
  return value yields NULL after wiping; callback strings drop NUL bytes.
- `najwa_init`: first caller wins across both front ends; security
  initialization fails closed with `NAJWA_CRYPTO_ERROR`.
- Create and unlock copy the password into `Zeroizing` immediately, drain
  before publishing state, and use the rate-limited S02 unlock.
- `najwa_lock`: drain (5 000 ms) → quiesce callbacks → persist volatile keys →
  wipe and drop keys; any failure keeps keys and returns an error.
- `najwa_cancel_operations(deadline_ms)` is exported; admission and drain are
  atomic.
- `najwa_update_battery` rejects levels outside 0–100 and normalizes
  `is_charging` with a once-per-process warning.
- `najwa_free_string` wipes the full allocation and ignores NULL;
  `najwa_version` is static and NUL-terminated.
- `najwa_list_messages` builds its JSON by reference in a buffer sized before
  writing, copies it into an exact-size returned string, then wipes the buffer
  and the rows it read; desktop history rows and `Message` text are wiped
  (§5.6.2).
- Callback slots hold their mutex across invocation; clear-all waits for the
  in-flight callback, discards queued events, and fences stale events by
  generation.
- One dedicated callback thread with a FIFO queue; `catch_unwind` around
  marshal and invoke.
- Message status is the closed set 0–5; `PermanentlyFailed` maps to 4 and
  `Failed` (retrying) to 5.
- Callbacks registered after `najwa_clear_all_callbacks` receive later events
  without an unlock; after `najwa_lock` delivery waits for the next unlock.
- Event payload builders escape untrusted strings through a JSON encoder.
- Queued event payloads and callback argument buffers are wiped.
- Header uses include guard `NAJWA_CORE_H` and declares exactly the 20 symbols
  of §4.5.
- Tests cover: NULL inputs, invalid UTF-8, static version string, NULL free,
  lists before init, operations before init, the init → create → exists → lock
  → unlock → wrong-password lifecycle, battery validation, concurrent
  registration, crash-dump suppression at init (Linux), dispatcher delivery,
  quiescence after clear, registration after clear and after lock,
  stale-event fencing, contained marshalling panics,
  clear waiting for an in-flight callback, cancellation waking a pending
  operation, drain deadlines, atomic admission under contention, invalid
  contact ids, the `PermanentlyFailed` and retrying mappings, cancel with
  contact listing,
  interior NUL in return values, zeroize-before-free, and a wiped
  `najwa_list_messages` JSON build buffer.
