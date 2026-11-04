//! Najwa thin C ABI (S17 §1–§6).
//!
//! A deliberately SMALL surface: 13 operation functions (S17 §4.1–§4.4) + 7
//! callback functions (S17 §5.2, including `najwa_clear_all_callbacks`).
//! Everything else (contact setup, mailboxes, files, preferences, backup, Tor
//! control) is NOT in the C ABI; the desktop service uses the typed Rust API
//! in `desktop` (S17 §5.8), and other Rust consumers use the crates directly.
//! S17 §7–§9 (platform bindings and constants) are reserved.
//!
//! Safety contracts implemented here: S17 §3 panic guard + input validation +
//! fallible `CString` (interior-NUL handling); §4.1 `najwa_lock` drain-then-
//! zeroize; §5.3 callback quiescence (mutex held across invocation, never a
//! lock-free load-then-call); §5.4 event channel; §5.5 dedicated callback
//! thread; §5.6 zeroize-before-free and `Zeroizing` password paths; §5.7
//! shared operation gate.
//!
//! Threading (S17 §5.5): every export is thread-safe; callbacks fire ONLY on
//! the dedicated dispatcher thread and MUST NOT re-enter `najwa_*`.

pub mod callback;
mod cover;
pub mod desktop;
mod desktop_wipe;
mod disappearing;
pub mod error;
pub mod hardening;
pub mod state;

use std::os::raw::c_char;
use std::sync::atomic::Ordering;

use najwa_protocol::mailbox::http::HttpMailboxClient;

use najwa_core::types::{ContactId, MessageContent};
use najwa_identity::manager::IdentityManager;
use najwa_identity::record::Identity;
use najwa_storage::database::SqliteStorage;
use zeroize::{Zeroize, Zeroizing};

use crate::callback::message_status;
use crate::error::{code_from_messaging, FfiErrorCode};
use crate::state::{state_cell, AppState, OperationGuard};

/// Library version (§4.4: statically allocated, MUST NOT be freed).
pub const VERSION: &str = concat!("najwa-ffi ", env!("CARGO_PKG_VERSION"));

/// The static storage behind `najwa_version`. Two contract requirements in
/// one: program-lifetime storage AND an explicit trailing NUL — Rust `&str`
/// is NOT NUL-terminated, so `.as_ptr()` on a plain string static hands C a
/// unterminated buffer (CStr would read past the version into adjacent
/// rodata; caught by the contract test against the workspace build).
static VERSION_C: &[u8] =
    concat!(env!("CARGO_PKG_NAME"), " ", env!("CARGO_PKG_VERSION"), "\0").as_bytes();

// ---------------------------------------------------------------------------
// §4.1 Lifecycle (6)
// ---------------------------------------------------------------------------

/// Initialize the library with a data directory. First caller wins; later
/// calls are `AlreadyInitialized`.
#[no_mangle]
pub extern "C" fn najwa_init(data_dir: *const c_char) -> i32 {
    ffi_guard!({
        let _lifecycle = state::LIFECYCLE.lock().unwrap();
        let dir = match hardening::cstr_to_str(data_dir) {
            Ok(s) if !s.is_empty() => s.to_string(),
            Ok(_) => return FfiErrorCode::NullPointer.as_i32(),
            Err(code) => return code,
        };
        let cell = state_cell();
        let mut guard = cell.write().unwrap();
        if guard.is_some() {
            return FfiErrorCode::AlreadyInitialized.as_i32();
        }
        if let Err(error) = najwa_crypto::initialize() {
            tracing::error!(%error, "security initialization failed");
            return FfiErrorCode::CryptoError.as_i32();
        }
        callback::ensure_dispatcher();
        match AppState::new(std::path::PathBuf::from(dir)) {
            Ok(s) => {
                *guard = Some(s);
                FfiErrorCode::Success.as_i32()
            }
            Err(code) => code.as_i32(),
        }
    })
}

/// 1 if an identity record exists, 0 if not, negative on error (§4.1).
#[no_mangle]
pub extern "C" fn najwa_identity_exists() -> i32 {
    ffi_guard!({
        let cell = state_cell();
        let guard = cell.read().unwrap();
        match guard.as_ref() {
            None => FfiErrorCode::NotInitialized.as_i32(),
            Some(s) => i32::from(s.identity_path().exists()),
        }
    })
}

/// Create a new identity protected by `password` (§4.1). The password is
/// copied into a `Zeroizing` buffer immediately (§5.6.1).
#[no_mangle]
pub extern "C" fn najwa_create_identity(password: *const c_char) -> i32 {
    ffi_guard!({
        let _lifecycle = state::LIFECYCLE.lock().unwrap();
        let password = match read_password(password) {
            Ok(p) => p,
            Err(code) => return code,
        };
        // Lifecycle (not key-using): exempt from the §4.1 operation guard —
        // unlock is the path that re-enables operations after a lock.
        if state_cell()
            .read()
            .unwrap()
            .as_ref()
            .is_some_and(|s| s.identity.is_some())
        {
            return FfiErrorCode::AlreadyInitialized.as_i32();
        }
        // Close admission before publishing/reopening storage; otherwise a list
        // call can enter between publication and the new operation generation.
        if !state::cancel_operations(state::LOCK_DRAIN_DEADLINE_MS) {
            return FfiErrorCode::InternalError.as_i32();
        }
        let cell = state_cell();
        let mut state = cell.write().unwrap();
        let Some(s) = state.as_mut() else {
            return FfiErrorCode::NotInitialized.as_i32();
        };

        if std::fs::create_dir_all(&s.data_dir).is_err() {
            return FfiErrorCode::StorageError.as_i32();
        }
        let mut manager = match IdentityManager::new(s.identity_path()) {
            Ok(m) => m,
            Err(_) => return FfiErrorCode::IdentityError.as_i32(),
        };
        if let Err(error) = manager.create(&password) {
            use najwa_identity::IdentityError as E;
            return match error {
                E::WeakPassphrase { .. } | E::PasswordTooShort(_) | E::PasswordTooLong(_) => {
                    FfiErrorCode::WeakPassphrase
                }
                _ => FfiErrorCode::IdentityError,
            }
            .as_i32();
        }
        let identity = match manager.identity() {
            Some(id) => Identity {
                // Shares the manager's guarded key; copies nothing (S01 §6.2).
                keypair: id.keypair.clone(),
                created_at: id.created_at,
                version: id.version,
            },
            None => return FfiErrorCode::IdentityError.as_i32(),
        };
        let db_key = derive_sqlcipher_key(&Zeroizing::new(identity.keypair.private().to_bytes()));
        match state::open_storage(&s.data_dir, &db_key) {
            Ok(storage) => {
                if let Err(code) = s.prepare_disappearing(&storage, &db_key) {
                    return code.as_i32();
                }
                s.db_key = Some(db_key);
                s.identity = Some(identity);
                s.identity_manager = Some(manager);
                s.storage = Some(storage);
                s.lifecycle_generation += 1;
                drop(state);
                if !state::allow_operations() {
                    return FfiErrorCode::InternalError.as_i32();
                }
                callback::unquiesce();
                bootstrap_transport_in_background();
                FfiErrorCode::Success.as_i32()
            }
            Err(code) => code.as_i32(),
        }
    })
}

/// Unlock an existing identity (§4.1). Uses the rate-limited production
/// unlock (`IdentityManager::unlock`, S02 §10 lockout binds). On success the
/// transport bootstrap starts in the background; `send`/`poll` report the
/// not-connected error until it completes.
#[no_mangle]
pub extern "C" fn najwa_unlock(password: *const c_char) -> i32 {
    ffi_guard!({
        let _lifecycle = state::LIFECYCLE.lock().unwrap();
        let password = match read_password(password) {
            Ok(p) => p,
            Err(code) => return code,
        };
        // Lifecycle: exempt from the operation guard (it re-enables ops).
        // Close admission before publishing/reopening storage; otherwise a list
        // call can enter between publication and the new operation generation.
        if !state::cancel_operations(state::LOCK_DRAIN_DEADLINE_MS) {
            return FfiErrorCode::InternalError.as_i32();
        }
        let cell = state_cell();
        let mut state = cell.write().unwrap();
        let Some(s) = state.as_mut() else {
            return FfiErrorCode::NotInitialized.as_i32();
        };
        let mut manager = match IdentityManager::new(s.identity_path()) {
            Ok(m) => m,
            Err(_) => return FfiErrorCode::IdentityError.as_i32(),
        };
        if manager.unlock(&password).is_err() {
            return FfiErrorCode::IdentityError.as_i32();
        }
        // A cancelled but still unlocked session retains its cache and service.
        // Never rebuild those while an older operation is still draining.
        if s.identity.is_some() {
            if !state::allow_operations() {
                return FfiErrorCode::InternalError.as_i32();
            }
            callback::unquiesce();
            return FfiErrorCode::Success.as_i32();
        }
        let identity = match manager.identity() {
            Some(id) => Identity {
                // Shares the manager's guarded key; copies nothing (S01 §6.2).
                keypair: id.keypair.clone(),
                created_at: id.created_at,
                version: id.version,
            },
            None => return FfiErrorCode::IdentityError.as_i32(),
        };
        let db_key = derive_sqlcipher_key(&Zeroizing::new(identity.keypair.private().to_bytes()));
        let storage = match state::open_storage(&s.data_dir, &db_key) {
            Ok(st) => st,
            Err(code) => return code.as_i32(),
        };
        if let Err(code) = s.prepare_disappearing(&storage, &db_key) {
            return code.as_i32();
        }
        s.identity = Some(identity);
        s.db_key = Some(db_key);
        s.identity_manager = Some(manager);
        s.storage = Some(storage);
        s.lifecycle_generation += 1;
        s.bootstrapping = false;
        drop(state);
        if !state::allow_operations() {
            return FfiErrorCode::InternalError.as_i32();
        }
        callback::unquiesce();
        bootstrap_transport_in_background();
        FfiErrorCode::Success.as_i32()
    })
}

/// Lock (§4.1, normative order): (1) reject new key-using entry,
/// (2) drain/cancel in-flight operations (deadline ≥ 2 s — this implementation uses 5 s),
/// (3) quiesce callbacks and only then zeroize key material. Zeroizing keys
/// under a live operation is FORBIDDEN.
#[no_mangle]
pub extern "C" fn najwa_lock() -> i32 {
    ffi_guard!({
        let _lifecycle = state::LIFECYCLE.lock().unwrap();
        if !state::cancel_operations(state::LOCK_DRAIN_DEADLINE_MS) {
            return FfiErrorCode::InternalError.as_i32();
        }
        // A runtime worker may be waiting for the state lock (cover upkeep).
        // Release that lock before joining the aborted cleaner, so even a
        // single-worker runtime can finish cancellation without deadlocking.
        let cleanup = {
            let mut state = state_cell().write().unwrap();
            state.as_mut().and_then(|s| {
                s.disappearing_cleanup
                    .take()
                    .map(|task| (s.runtime.handle().clone(), task))
            })
        };
        if let Some((runtime, task)) = cleanup {
            task.abort();
            let _ = runtime.block_on(task);
        }
        callback::quiesce_callbacks();
        let cell = state_cell();
        let mut state = cell.write().unwrap();
        if let Some(s) = state.as_mut() {
            if let Err(code) = s.clear_unlocked() {
                return code.as_i32();
            }
        }
        FfiErrorCode::Success.as_i32()
    })
}

/// Cancel in-flight operations within `deadline_ms` and refuse new ones
/// until the next unlock (§4.1). Returns Success when drained, InternalError on deadline.
#[no_mangle]
pub extern "C" fn najwa_cancel_operations(deadline_ms: i32) -> i32 {
    ffi_guard!({
        let _lifecycle = state::LIFECYCLE.lock().unwrap();
        if state::cancel_operations(deadline_ms) {
            FfiErrorCode::Success.as_i32()
        } else {
            FfiErrorCode::InternalError.as_i32()
        }
    })
}

// ---------------------------------------------------------------------------
// §4.2 Contacts & Messages (4)
// ---------------------------------------------------------------------------

/// List contacts as a JSON array (caller frees with `najwa_free_string`).
#[no_mangle]
pub extern "C" fn najwa_list_contacts() -> *mut c_char {
    ffi_guard_ptr!({
        let Some(_guard) = OperationGuard::acquire() else {
            return hardening::str_to_cstring_ptr("[]".to_string());
        };
        let json = with_storage(|storage| {
            let contacts = storage
                .list_contacts()
                .map_err(|_| FfiErrorCode::StorageError)?;
            let items: Vec<serde_json::Value> = contacts
                .iter()
                .map(|c| {
                    serde_json::json!({
                        "id": c.id,
                        "name": c.display_name,
                        "verified": c.verified,
                        "blocked": c.blocked,
                    })
                })
                .collect();
            serde_json::to_string(&items).map_err(|_| FfiErrorCode::SerializationError)
        });
        match json {
            Ok(json) => hardening::str_to_cstring_ptr(json),
            Err(_) => hardening::str_to_cstring_ptr("[]".to_string()),
        }
    })
}

/// List a contact's messages as a JSON array (≤ 200, stored order). Sealed
/// disappearing content is opened using the unlocked session's shared cache;
/// non-UTF-8 payloads surface as `null` content (§3.2: the FFI never
/// marshal-panics on attacker bytes).
#[no_mangle]
pub extern "C" fn najwa_list_messages(contact_id: *const c_char) -> *mut c_char {
    ffi_guard_ptr!({
        let Some(_guard) = OperationGuard::acquire() else {
            return hardening::str_to_cstring_ptr("[]".to_string());
        };
        // Storage ContactId (i64) — the core's own alias is u64 (seam note above).
        let parse: fn(*const c_char) -> Option<i64> = |ptr| {
            hardening::cstr_to_str(ptr)
                .ok()?
                .parse::<i64>()
                .ok()
                .filter(|id| *id > 0)
        };
        let Some(id) = parse(contact_id) else {
            return hardening::str_to_cstring_ptr("[]".to_string());
        };
        let json = (|| {
            let state = state_cell().read().unwrap();
            let s = state.as_ref().ok_or(FfiErrorCode::NotInitialized)?;
            let storage = s.storage.as_ref().ok_or(FfiErrorCode::IdentityError)?;
            let mut messages =
                disappearing::displayed_messages(storage, &s.disappearing_keys, id)?;
            // §5.6.2: items borrow the text, so the only copy left is the
            // wiped JSON buffer; the rows are wiped after it is built.
            #[derive(serde::Serialize)]
            struct Item<'a> {
                content: Option<&'a str>,
                content_type: u8,
                direction: i32,
                msg_id: String,
                status: i32,
                timestamp: i64,
            }
            let items: Vec<Item> = messages
                .iter()
                .map(|m| Item {
                    content: std::str::from_utf8(&m.content).ok(),
                    content_type: m.content_type as u8,
                    direction: m.direction as i32,
                    msg_id: hex_encode(&m.msg_id),
                    status: abi_message_status(m.status),
                    timestamp: m.timestamp,
                })
                .collect();
            let json = hardening::json_to_cstring_ptr(&items);
            drop(items);
            messages.iter_mut().for_each(|m| m.content.zeroize());
            json
        })();
        match json {
            Ok(json) => json,
            Err(_) => hardening::str_to_cstring_ptr("[]".to_string()),
        }
    })
}

/// Send a text message to a contact (§4.2). Returns 0 on accept; the status
/// callback carries the persisted status (queued, deposited, or acknowledged).
#[no_mangle]
pub extern "C" fn najwa_send_message(contact_id: *const c_char, content: *const c_char) -> i32 {
    ffi_guard!({
        let id_str = match hardening::cstr_to_str(contact_id) {
            Ok(s) => s.to_string(),
            Err(code) => return code,
        };
        let content = match hardening::cstr_to_str(content) {
            Ok(s) if !s.is_empty() => s.to_string(),
            Ok(_) => return FfiErrorCode::NullPointer.as_i32(),
            Err(code) => return code,
        };
        let id: ContactId = match id_str.parse() {
            Ok(v) if v > 0 && v <= i64::MAX as u64 => v,
            _ => return FfiErrorCode::SerializationError.as_i32(),
        };
        let Some(mut operation) = OperationGuard::acquire() else {
            return FfiErrorCode::RateLimitExceeded.as_i32();
        };
        // §5.1 status lifecycle: accepted by the core → QUEUED. Runs on the
        // state's runtime (blocking this caller — §5.5: never on the callback
        // thread); the borrow of `service` lives only for the call.
        let result = (|| -> Result<(), i32> {
            let cell = state_cell();
            let state = cell.read().unwrap();
            let Some(s) = state.as_ref() else {
                return Err(FfiErrorCode::NotInitialized.as_i32());
            };
            let service = s.service.lock().unwrap().clone();
            let Some(service) = service else {
                return Err(FfiErrorCode::TransportError.as_i32());
            };
            let runtime = s.runtime.handle().clone();
            drop(state);
            let sent = runtime
                .block_on(
                    operation.cancellable(service.send_message(id, MessageContent::Text(content))),
                )
                .map_err(|e| e.as_i32())?
                .map_err(|e| code_from_messaging(&e))?;
            let status = with_storage(|storage| {
                storage
                    .get_message(sent.id)
                    .map_err(|_| FfiErrorCode::StorageError)
            })
            .ok()
            .flatten()
            .map(|msg| abi_message_status(msg.status))
            .unwrap_or(message_status::QUEUED);
            callback::emit_message_status(hex_encode(&sent.msg_id), status);
            Ok(())
        })();
        match result {
            Ok(()) => FfiErrorCode::Success.as_i32(),
            Err(code) => code,
        }
    })
}

/// Poll all mailboxes for new messages (§4.2). Delivered messages fire the
/// `MessageReceived` callback from the dispatcher thread (§5.5).
#[no_mangle]
pub extern "C" fn najwa_poll_messages() -> i32 {
    ffi_guard!({
        let Some(mut operation) = OperationGuard::acquire() else {
            return FfiErrorCode::RateLimitExceeded.as_i32();
        };
        let result = (|| -> Result<(), i32> {
            let cell = state_cell();
            let state = cell.read().unwrap();
            let Some(s) = state.as_ref() else {
                return Err(FfiErrorCode::NotInitialized.as_i32());
            };
            let service = s.service.lock().unwrap().clone();
            let Some(service) = service else {
                return Err(FfiErrorCode::TransportError.as_i32());
            };
            let runtime = s.runtime.handle().clone();
            drop(state);
            let received = runtime
                .block_on(operation.cancellable(service.poll_messages()))
                .map_err(|e| e.as_i32())?
                .map_err(|e| code_from_messaging(&e))?;
            for msg in received {
                if let Ok(content) = String::from_utf8(msg.content) {
                    // Core ContactId (u64) → ABI contract (i64); see the seam
                    // note in najwa_list_messages.
                    callback::emit_message_received(msg.contact_id as i64, content);
                }
            }
            Ok(())
        })();
        match result {
            Ok(()) => FfiErrorCode::Success.as_i32(),
            Err(code) => code,
        }
    })
}

// ---------------------------------------------------------------------------
// S17 §4.3 Battery State (1)
// ---------------------------------------------------------------------------

/// Report battery state (S17 §4.3). The value is stored in the shared state;
/// no feature reads it.
#[no_mangle]
pub extern "C" fn najwa_update_battery(level: i32, is_charging: i32) -> i32 {
    ffi_guard!({
        // §4.3: level MUST be in [0, 100] — the boundary REJECTS a violation
        // (negative code), it does not clamp. The closed §2 table has no
        // InvalidArgument variant; NullPointer is this crate's established
        // bad-argument carrier (empty password precedent).
        if !(0..=100).contains(&level) {
            return FfiErrorCode::NullPointer.as_i32();
        }
        // "Any non-zero value is treated as 1, with a warning logged once
        // per session."
        static CHARGING_WARNED: std::sync::atomic::AtomicBool =
            std::sync::atomic::AtomicBool::new(false);
        if is_charging != 0 && is_charging != 1 && !CHARGING_WARNED.swap(true, Ordering::SeqCst) {
            tracing::warn!("najwa_update_battery: is_charging normalized to 1");
        }
        let cell = state_cell();
        let mut state = cell.write().unwrap();
        match state.as_mut() {
            Some(s) => {
                s.battery_level = level;
                s.battery_charging = is_charging != 0;
                FfiErrorCode::Success.as_i32()
            }
            None => FfiErrorCode::NotInitialized.as_i32(),
        }
    })
}

// ---------------------------------------------------------------------------
// §4.4 Utility (2)
// ---------------------------------------------------------------------------

/// §5.6.2: zeroize the buffer, then free. No-op on NULL.
///
/// Not marked `unsafe` despite the raw pointer: the C ABI cannot express
/// safety requirements, and every najwa_* symbol is equally raw — the
/// contract lives in the header (§4.4).
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn najwa_free_string(ptr: *mut c_char) {
    unsafe { hardening::zeroize_and_free_string(ptr) }
}

/// Static version string — MUST NOT be passed to `najwa_free_string` (§4.4).
#[no_mangle]
pub extern "C" fn najwa_version() -> *const c_char {
    VERSION_C.as_ptr() as *const c_char
}

// ---------------------------------------------------------------------------
// §5.2 registration functions + clear (implemented in callback.rs)
// ---------------------------------------------------------------------------

pub use crate::callback::{
    najwa_clear_all_callbacks, najwa_set_connection_status_callback, najwa_set_error_callback,
    najwa_set_event_callback, najwa_set_feature_toggle_callback,
    najwa_set_message_received_callback, najwa_set_message_status_callback,
};

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

/// S17 §5.6.1: password bytes into `Zeroizing` immediately; an empty password
/// is rejected as `NullPointer` (S17 §2).
fn read_password(ptr: *const c_char) -> Result<Zeroizing<String>, i32> {
    let s = hardening::cstr_to_str(ptr)?;
    if s.is_empty() {
        return Err(FfiErrorCode::NullPointer.as_i32());
    }
    Ok(Zeroizing::new(s.to_string()))
}

/// Database-key derivation (S17 §5.7): HKDF-SHA256 over the identity seed with
/// salt `najwa-sqlcipher-key` and info `najwa/v1/sqlcipher-key`. These bytes
/// are fixed; changing them makes every existing profile unreadable. The key is
/// written straight into locked memory (S01 §6.2).
fn derive_sqlcipher_key(identity_seed: &[u8; 32]) -> state::DbKey {
    let derived = Zeroizing::new(
        najwa_crypto::kdf::hkdf_sha256(
            identity_seed,
            b"najwa-sqlcipher-key",
            b"najwa/v1/sqlcipher-key",
            32,
        )
        .expect("HKDF-SHA256 should not fail for 32-byte output"),
    );
    let mut key = najwa_crypto::memory::GuardedMemory::new([0u8; 32]);
    key.copy_from_slice(&derived);
    std::sync::Arc::new(key)
}

fn abi_message_status(status: najwa_storage::types::MessageStatus) -> i32 {
    use najwa_storage::types::MessageStatus;
    match status {
        MessageStatus::Pending => message_status::QUEUED,
        MessageStatus::Sent => message_status::DEPOSITED,
        MessageStatus::Delivered => message_status::DELIVERED,
        MessageStatus::Read => message_status::READ,
        MessageStatus::Failed => message_status::RETRYING,
        MessageStatus::PermanentlyFailed => message_status::FAILED,
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Run `f` with the unlocked storage.
fn with_storage<F, R>(f: F) -> Result<R, FfiErrorCode>
where
    F: FnOnce(&najwa_storage::database::SqliteStorage) -> Result<R, FfiErrorCode>,
{
    let cell = state_cell();
    let state = cell.read().unwrap();
    let Some(s) = state.as_ref() else {
        return Err(FfiErrorCode::NotInitialized);
    };
    let Some(storage) = &s.storage else {
        return Err(FfiErrorCode::IdentityError);
    };
    f(storage)
}

/// §5.5-friendly background bootstrap: build the Tor transport on the
/// runtime, then construct the service and emit connection status. Failures
/// emit `connection_status(0)` and leave the service absent (send/poll then
/// return `TransportError`).
fn bootstrap_transport_in_background() {
    use najwa_transport::tor::TorTransport;
    use std::sync::Arc;
    let (runtime, generation, existing_client, config) = {
        let mut state = state_cell().write().unwrap();
        let Some(s) = state.as_mut() else { return };
        if s.bootstrapping {
            return;
        }
        s.bootstrapping = true;
        (
            s.runtime.handle().clone(),
            s.lifecycle_generation,
            s.cover.as_ref().map(|c| c.client.clone()),
            s.storage.as_ref().ok_or(desktop::DesktopError { code: "locked" })
                .and_then(|db| desktop::preferences::read(db))
                .and_then(|prefs| desktop::preferences::tor_config(&s.data_dir, &prefs)),
        )
    };
    runtime.spawn(async move {
        let config = match config {
            Ok(config) => config,
            Err(_) => {
                // Bridge addresses and options must never be included in logs.
                tracing::warn!("saved Tor settings unavailable; connection stopped");
                let mut state = state_cell().write().unwrap();
                if let Some(s) = state.as_mut().filter(|s| s.lifecycle_generation == generation) {
                    s.bootstrapping = false;
                    callback::emit_connection_status(false);
                }
                return;
            }
        };
        let client = match existing_client {
            Some(client) => client,
            None => {
                let mut transport = TorTransport::new(config);
                if transport.bootstrap().await.is_err() {
                    tracing::warn!("transport bootstrap failed");
                    let mut state = state_cell().write().unwrap();
                    if let Some(s) = state
                        .as_mut()
                        .filter(|s| s.lifecycle_generation == generation)
                    {
                        s.bootstrapping = false;
                        callback::emit_connection_status(false);
                    }
                    return;
                }
                Arc::new(HttpMailboxClient::new(Arc::new(transport)))
            }
        };
        let mut state = state_cell().write().unwrap();
        let Some(s) = state
            .as_mut()
            .filter(|s| s.lifecycle_generation == generation)
        else {
            return;
        };
        s.bootstrapping = false;
        if install_connected_service(s, client).is_err() {
            return;
        }
        callback::emit_connection_status(true);
        drop(state);
    });
}

/// The single installation path used after bootstrap and after re-unlock.
fn install_connected_service(
    s: &mut AppState,
    client: std::sync::Arc<HttpMailboxClient>,
) -> Result<(), FfiErrorCode> {
    use std::sync::Arc;
    let (Some(db_key), Some(identity)) = (&s.db_key, &s.identity) else {
        return Err(FfiErrorCode::IdentityError);
    };
    let service_storage = SqliteStorage::open_shared(&s.data_dir.join("najwa.db"), db_key.clone())
        .map_err(|_| FfiErrorCode::StorageError)?;
    let keypair = identity.keypair.clone();
    let cover = s.cover.get_or_insert_with(|| {
        crate::cover::CoverRuntime::start(client.clone(), Default::default())
    });
    cover.refresh(&service_storage);
    if !cover.scheduler.is_running() {
        cover.scheduler.start(client.clone());
    }
    let mut service =
        najwa_core::service::MessagingService::new(keypair, service_storage, (*client).clone());
    service.set_volatile_cache(s.disappearing_keys.clone());
    cover.scheduler.slot_source().set_bypass(
        s.storage
            .as_ref()
            .ok_or(FfiErrorCode::StorageError)?
            .get_setting::<bool>("desktop:responsive")
            .map_err(|_| FfiErrorCode::StorageError)?
            == Some(true),
    );
    service.set_slot_source(cover.scheduler.slot_source());
    service.set_fetch_plan(cover.fetch_plan.clone());
    *s.service.lock().unwrap() = Some(Arc::new(service));
    Ok(())
}

#[cfg(test)]
mod row14_tests {
    use super::*;
    #[test]
    fn cancel_export_codes_and_contact_gating_follow_contract() {
        let _callbacks = callback::tests::test_lock().lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut state = AppState::new(dir.path().into()).unwrap();
        let storage = state::open_storage(dir.path(), &crate::state::test_key(14)).unwrap();
        storage
            .create_contact(&najwa_storage::types::NewContact {
                pseudonym: [1; 32],
                their_ik_pub: [2; 32],
                their_device_pub: [3; 32],
                our_pseudonym: [4; 32],
                display_name: Some("private contact".into()),
            })
            .unwrap();
        state.storage = Some(storage);
        *state_cell().write().unwrap() = Some(state);
        assert!(state::allow_operations());
        let guard = OperationGuard::acquire().unwrap();
        assert_eq!(
            najwa_cancel_operations(0),
            FfiErrorCode::InternalError.as_i32()
        );
        let contacts = najwa_list_contacts();
        assert_eq!(
            unsafe { std::ffi::CStr::from_ptr(contacts) }.to_bytes(),
            b"[]"
        );
        najwa_free_string(contacts);
        drop(guard);
        assert_eq!(najwa_cancel_operations(0), FfiErrorCode::Success.as_i32());
        assert!(state::allow_operations());
        let contacts = najwa_list_contacts();
        assert!(unsafe { std::ffi::CStr::from_ptr(contacts) }
            .to_str()
            .unwrap()
            .contains("private contact"));
        najwa_free_string(contacts);
        let state = state_cell().write().unwrap().take();
        drop(state);
    }

    /// §5.6.2: the buffer the message JSON was built in is zeroed by the time
    /// `najwa_list_messages` returns. It was sized exactly, so it never grew.
    #[test]
    fn listed_message_json_build_buffer_is_wiped() {
        let _callbacks = callback::tests::test_lock().lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut state = AppState::new(dir.path().into()).unwrap();
        let storage = state::open_storage(dir.path(), &crate::state::test_key(15)).unwrap();
        let cid = storage
            .create_contact(&najwa_storage::types::NewContact {
                pseudonym: [5; 32],
                their_ik_pub: [6; 32],
                their_device_pub: [7; 32],
                our_pseudonym: [8; 32],
                display_name: None,
            })
            .unwrap();
        state
            .runtime
            .block_on(najwa_core::storage::CoreStorage::save_message(
                &*storage,
                &najwa_core::types::Message {
                    id: 0,
                    contact_id: cid as u64,
                    msg_id: [9; 16],
                    direction: najwa_core::types::Direction::Received,
                    content_type: 0,
                    flags: 0,
                    content: b"plaintext to wipe".to_vec(),
                    timestamp: najwa_crypto::time::now(),
                    status: najwa_core::types::MessageStatus::Delivered,
                    ratchet_index: None,
                },
            ))
            .unwrap();
        state.storage = Some(storage);
        *state_cell().write().unwrap() = Some(state);
        assert!(state::allow_operations());
        let contact = std::ffi::CString::new(cid.to_string()).unwrap();
        let listed = najwa_list_messages(contact.as_ptr());
        let text = unsafe { std::ffi::CStr::from_ptr(listed) }.to_str().unwrap();
        assert!(text.contains("plaintext to wipe"));
        let length = text.len();
        najwa_free_string(listed);
        let built = hardening::tests::LAST_JSON.with(|last| last.take());
        assert_eq!(built.capacity(), length);
        // SAFETY: zeroize wrote every byte of the capacity before release.
        let bytes = unsafe { std::slice::from_raw_parts(built.as_ptr(), built.capacity()) };
        assert!(bytes.iter().all(|&b| b == 0));
        let state = state_cell().write().unwrap().take();
        drop(state);
    }

    /// S01 §6.2: the unlocked profile's database key is derived straight into
    /// GuardedMemory (the type is the assertion), with the unchanged derivation.
    #[test]
    fn database_key_is_derived_into_guarded_memory() {
        let key: state::DbKey = derive_sqlcipher_key(&[3; 32]);
        let expected = najwa_crypto::kdf::hkdf_sha256(
            &[3; 32],
            b"najwa-sqlcipher-key",
            b"najwa/v1/sqlcipher-key",
            32,
        )
        .unwrap();
        assert_eq!(&key[..], &expected[..]);
    }

    #[test]
    fn permanent_failure_maps_to_closed_abi_status_set() {
        assert_eq!(
            abi_message_status(najwa_storage::types::MessageStatus::PermanentlyFailed),
            message_status::FAILED
        );
    }

    #[test]
    fn retried_failure_is_distinct_from_permanent_failure() {
        assert_eq!(
            abi_message_status(najwa_storage::types::MessageStatus::Failed),
            message_status::RETRYING
        );
    }

    #[test]
    fn invalid_contact_ids_are_rejected_before_operation_gate() {
        let content = std::ffi::CString::new("text").unwrap();
        for id in ["0", "-1", "9223372036854775808", "18446744073709551615"] {
            let id = std::ffi::CString::new(id).unwrap();
            assert_eq!(
                najwa_send_message(id.as_ptr(), content.as_ptr()),
                FfiErrorCode::SerializationError.as_i32()
            );
        }
    }
}
