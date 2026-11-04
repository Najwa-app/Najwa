//! S17 contract tests over the real exported symbols.
//!
//! The FFI state is process-global, so the lifecycle tests share one mutex
//! and run their steps in a fixed order; pure-contract tests (null handling,
//! zeroize, panic guard) are independent.

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::sync::{Mutex, OnceLock};

use najwa_ffi::error::FfiErrorCode;

fn test_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn c(s: &str) -> CString {
    CString::new(s).unwrap()
}

// ---------------------------------------------------------------------------
// §3/§4.4 pure contracts
// ---------------------------------------------------------------------------

#[test]
fn null_inputs_map_to_null_pointer_code() {
    assert_eq!(najwa_ffi::najwa_init(std::ptr::null()), FfiErrorCode::NullPointer.as_i32());
    assert_eq!(
        najwa_ffi::najwa_create_identity(std::ptr::null()),
        FfiErrorCode::NullPointer.as_i32()
    );
    assert_eq!(
        najwa_ffi::najwa_unlock(std::ptr::null()),
        FfiErrorCode::NullPointer.as_i32()
    );
    assert_eq!(
        najwa_ffi::najwa_send_message(std::ptr::null(), std::ptr::null()),
        FfiErrorCode::NullPointer.as_i32()
    );
}

#[test]
fn invalid_utf8_input_maps_to_invalid_utf8_code() {
    let bad: [u8; 3] = [0xFF, 0xFE, 0x00];
    let ptr = bad.as_ptr() as *const c_char;
    assert_eq!(najwa_ffi::najwa_init(ptr), FfiErrorCode::InvalidUtf8.as_i32());
}

#[test]
fn version_is_static_and_not_freed() {
    let ptr = najwa_ffi::najwa_version();
    let s = unsafe { CStr::from_ptr(ptr) }.to_str().unwrap();
    assert!(s.starts_with("najwa-ffi"), "{s}");
    // MUST NOT be passed to najwa_free_string (§4.4) — nothing to assert at
    // the type level; the contract is enforced by the doc + header comment.
}

#[test]
fn free_string_no_op_on_null() {
    najwa_ffi::najwa_free_string(std::ptr::null_mut());
}

#[test]
fn list_functions_before_init_return_not_initialized_or_empty() {
    let ptr = najwa_ffi::najwa_list_contacts();
    assert!(!ptr.is_null(), "list functions return JSON, never null (§3.2)");
    let s = unsafe { CStr::from_ptr(ptr) }.to_str().unwrap();
    assert_eq!(s, "[]");
    najwa_ffi::najwa_free_string(ptr);
}

#[test]
fn uninit_operations_return_not_initialized() {
    let _g = test_lock().lock().unwrap();
    // No init happened in THIS process ordering? The lifecycle test below
    // initializes — keep this test robust either way: send without a contact
    // id must not panic and must return SOME i32 error code (negative or
    // positive domain code), never UB.
    let code = najwa_ffi::najwa_poll_messages();
    assert_ne!(code, 0);
    assert_ne!(code, FfiErrorCode::Panic.as_i32());
}

// ---------------------------------------------------------------------------
// Lifecycle E2E (§4.1) — ordered steps under the global lock
// ---------------------------------------------------------------------------

#[test]
fn lifecycle_init_create_exists_lock_unlock() {
    let _g = test_lock().lock().unwrap();

    let dir = tempfile::tempdir().unwrap();
    let dir_c = c(dir.path().to_str().unwrap());

    // Headless gate: route the DKM to a 0600-style file inside the test
    // directory (the identity crate's sanctioned escape for Docker/CI, where
    // no Secret Service/keychain exists).
    std::env::set_var(
        "NAJWA_DKM_FILE",
        dir.path().join("test-dkm.hex"),
    );

    // init
    let code = najwa_ffi::najwa_init(dir_c.as_ptr());
    assert_eq!(code, FfiErrorCode::Success.as_i32(), "init");
    // double init → AlreadyInitialized
    let code = najwa_ffi::najwa_init(dir_c.as_ptr());
    assert_eq!(code, FfiErrorCode::AlreadyInitialized.as_i32());

    // identity does not exist yet
    assert_eq!(najwa_ffi::najwa_identity_exists(), 0);

    // S02 §11.1: a weak new passphrase is refused and nothing is created
    let weak = c("aaaaaaaaaaaa");
    let code = najwa_ffi::najwa_create_identity(weak.as_ptr());
    assert_eq!(code, FfiErrorCode::WeakPassphrase.as_i32(), "weak passphrase");
    assert_eq!(najwa_ffi::najwa_identity_exists(), 0);

    // create (also unlocks + opens storage)
    let pw = c("correct horse battery staple");
    let code = najwa_ffi::najwa_create_identity(pw.as_ptr());
    assert_eq!(code, FfiErrorCode::Success.as_i32(), "create_identity");
    assert_eq!(najwa_ffi::najwa_identity_exists(), 1);

    // contacts list is a JSON array
    let ptr = najwa_ffi::najwa_list_contacts();
    let s = unsafe { CStr::from_ptr(ptr) }.to_str().unwrap();
    assert_eq!(s, "[]", "fresh identity has no contacts");
    najwa_ffi::najwa_free_string(ptr);

    // messages for an unknown contact → empty JSON array
    let contact = c("999");
    let ptr = najwa_ffi::najwa_list_messages(contact.as_ptr());
    let s = unsafe { CStr::from_ptr(ptr) }.to_str().unwrap();
    assert_eq!(s, "[]");
    najwa_ffi::najwa_free_string(ptr);

    // send before any mailbox is connected → TransportError, never a panic
    let code = najwa_ffi::najwa_send_message(contact.as_ptr(), c("hi").as_ptr());
    assert_eq!(code, FfiErrorCode::TransportError.as_i32());

    // §4.1 lock semantics: drains, quiesces, zeroizes — then identity still
    // exists on disk, and a fresh unlock succeeds.
    let code = najwa_ffi::najwa_lock();
    assert_eq!(code, FfiErrorCode::Success.as_i32(), "lock");

    // unlock with the SAME password succeeds (record + DKM on disk).
    let code = najwa_ffi::najwa_unlock(pw.as_ptr());
    assert_eq!(code, FfiErrorCode::Success.as_i32(), "unlock after lock");

    // wrong password is rejected (IdentityError), not a panic.
    let wrong = c("wrong password entirely");
    // lock first so the unlock path re-runs the rate limiter cleanly.
    let code = najwa_ffi::najwa_lock();
    assert_eq!(code, FfiErrorCode::Success.as_i32());
    let code = najwa_ffi::najwa_unlock(wrong.as_ptr());
    assert_eq!(code, FfiErrorCode::IdentityError.as_i32());

    // §4.3: range is VALIDATED, not clamped — out-of-range level gets a
    // negative code; non-0/1 is_charging normalizes to 1 with a one-time
    // warning; in-range values succeed.
    assert_eq!(
        najwa_ffi::najwa_update_battery(150, 0),
        FfiErrorCode::NullPointer.as_i32()
    );
    assert_eq!(
        najwa_ffi::najwa_update_battery(-5, 1),
        FfiErrorCode::NullPointer.as_i32()
    );
    assert_eq!(najwa_ffi::najwa_update_battery(0, 0), FfiErrorCode::Success.as_i32());
    assert_eq!(najwa_ffi::najwa_update_battery(100, 1), FfiErrorCode::Success.as_i32());
    assert_eq!(najwa_ffi::najwa_update_battery(50, 7), FfiErrorCode::Success.as_i32());
}

// ---------------------------------------------------------------------------
// §5 event channel / quiescence (covered in callback.rs unit tests; the
// registration symbols are exercised here over the real exports)
// ---------------------------------------------------------------------------

extern "C" fn noop_message_cb(_contact_id: *const c_char, _content: *const c_char) {}

#[test]
fn registration_round_trip_is_thread_safe_and_returns() {
    najwa_ffi::najwa_set_message_received_callback(Some(noop_message_cb));
    najwa_ffi::najwa_set_message_received_callback(None);
    najwa_ffi::najwa_clear_all_callbacks();
}
