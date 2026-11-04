//! Integration tests for the Task 11 `NajwaCore` lift.
//!
//! These tests verify the `NajwaCore` façade in `najwa_core::najwa_core`
//! correctly delegates `send_message` / `poll_messages` to its installed
//! `NajwaCoreHooks` implementation and preserves the legacy FFI contract
//! on both the success and error paths.
//!
//! This is the non-regression gate for Task 11 since there are no Kotlin
//! unit tests. A real end-to-end send/poll across Tor is out of scope
//! here (covered by the Android instrumented suite); these tests use a
//! mock hook impl so the lift surface can be exercised deterministically.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use najwa_core::error::{MessagingError, Result as CoreResult};
use najwa_core::najwa_core::{NajwaCore, NajwaCoreHooks, PollResult, SendResult};

/// A deterministic mock hook implementation that captures call parameters
/// and returns pre-seeded results. Lets tests assert both the forward
/// arguments and the backward result propagation through `NajwaCore`.
struct MockHooks {
    send_calls: AtomicU32,
    poll_calls: AtomicU32,
    captured_contact_id: Mutex<Option<i64>>,
    captured_text: Mutex<Option<String>>,
    captured_reply_info: Mutex<Option<String>>,
    send_result: Mutex<CoreResult<SendResult>>,
    poll_result: Mutex<CoreResult<PollResult>>,
}

impl MockHooks {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            send_calls: AtomicU32::new(0),
            poll_calls: AtomicU32::new(0),
            captured_contact_id: Mutex::new(None),
            captured_text: Mutex::new(None),
            captured_reply_info: Mutex::new(None),
            send_result: Mutex::new(Ok(SendResult {
                msg_id_hex: "0".to_string(),
            })),
            poll_result: Mutex::new(Ok(PollResult { new_count: 0 })),
        })
    }

    fn set_send_ok(&self, msg_id_hex: &str) {
        *self.send_result.lock().unwrap() = Ok(SendResult {
            msg_id_hex: msg_id_hex.to_string(),
        });
    }

    fn set_send_err(&self, message: &str) {
        *self.send_result.lock().unwrap() = Err(MessagingError::InternalError(message.to_string()));
    }

    fn set_poll_ok(&self, count: i32) {
        *self.poll_result.lock().unwrap() = Ok(PollResult { new_count: count });
    }

    fn set_poll_err(&self, message: &str) {
        *self.poll_result.lock().unwrap() = Err(MessagingError::InternalError(message.to_string()));
    }
}

impl NajwaCoreHooks for MockHooks {
    fn send_message_impl(
        &self,
        contact_id: i64,
        text: &str,
        reply_info_json: Option<&str>,
    ) -> CoreResult<SendResult> {
        self.send_calls.fetch_add(1, Ordering::SeqCst);
        *self.captured_contact_id.lock().unwrap() = Some(contact_id);
        *self.captured_text.lock().unwrap() = Some(text.to_string());
        *self.captured_reply_info.lock().unwrap() = reply_info_json.map(String::from);
        match &*self.send_result.lock().unwrap() {
            Ok(r) => Ok(r.clone()),
            Err(e) => Err(MessagingError::InternalError(e.to_string())),
        }
    }

    fn poll_messages_impl(&self) -> CoreResult<PollResult> {
        self.poll_calls.fetch_add(1, Ordering::SeqCst);
        match &*self.poll_result.lock().unwrap() {
            Ok(r) => Ok(r.clone()),
            Err(e) => Err(MessagingError::InternalError(e.to_string())),
        }
    }
}

// ---------------------------------------------------------------------------
// send_message success path (Task 11 acceptance criterion — test (a))
// ---------------------------------------------------------------------------

#[test]
fn send_message_success_path_returns_msg_id_and_invokes_hook_once() {
    let hooks = MockHooks::new();
    hooks.set_send_ok("cafebabe00112233");
    let core = NajwaCore::new(hooks.clone());

    let result = core
        .send_message(7, "hello task 11", None)
        .expect("send_message success path must return Ok");

    assert_eq!(result.msg_id_hex, "cafebabe00112233");
    assert_eq!(hooks.send_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        *hooks.captured_contact_id.lock().unwrap(),
        Some(7),
        "contact_id must be threaded through unchanged"
    );
    assert_eq!(
        hooks.captured_text.lock().unwrap().as_deref(),
        Some("hello task 11"),
        "message text must be threaded through unchanged"
    );
    assert!(
        hooks.captured_reply_info.lock().unwrap().is_none(),
        "reply_info_json None must remain None through the facade"
    );
}

#[test]
fn send_message_success_path_preserves_reply_info_json() {
    let hooks = MockHooks::new();
    hooks.set_send_ok("aa");
    let core = NajwaCore::new(hooks.clone());

    let reply_json = r#"{"ts":1700000000000,"text":"original","sender":"Bob"}"#;
    let _ = core
        .send_message(42, "re: hi", Some(reply_json))
        .expect("success path");

    assert_eq!(
        hooks.captured_reply_info.lock().unwrap().as_deref(),
        Some(reply_json),
        "reply_info_json must be threaded verbatim for Task 14a disappearing-msg parity"
    );
}

#[test]
fn send_message_error_path_maps_to_core_error() {
    let hooks = MockHooks::new();
    hooks.set_send_err("simulated deposit failure");
    let core = NajwaCore::new(hooks.clone());

    let err = core
        .send_message(1, "test", None)
        .expect_err("error path must propagate as Err");
    match err {
        MessagingError::InternalError(msg) => {
            assert!(
                msg.contains("simulated deposit failure"),
                "error message must be preserved for logcat triage; got: {msg}"
            );
        }
        other => panic!("expected InternalError, got {other:?}"),
    }
    assert_eq!(hooks.send_calls.load(Ordering::SeqCst), 1);
}

// ---------------------------------------------------------------------------
// poll_messages success path (Task 11 acceptance criterion — test (b))
// ---------------------------------------------------------------------------

#[test]
fn poll_messages_success_path_returns_new_count_from_hook() {
    let hooks = MockHooks::new();
    hooks.set_poll_ok(5);
    let core = NajwaCore::new(hooks.clone());

    let result = core
        .poll_messages()
        .expect("poll_messages success path must return Ok");
    assert_eq!(
        result.new_count, 5,
        "new_count must reflect the hook-returned count verbatim"
    );
    assert_eq!(hooks.poll_calls.load(Ordering::SeqCst), 1);
}

#[test]
fn poll_messages_success_path_returns_zero_when_no_new_messages() {
    let hooks = MockHooks::new();
    hooks.set_poll_ok(0);
    let core = NajwaCore::new(hooks.clone());

    let result = core.poll_messages().expect("idle poll must still be Ok");
    assert_eq!(result.new_count, 0);
}

#[test]
fn poll_messages_error_path_maps_to_core_error() {
    let hooks = MockHooks::new();
    hooks.set_poll_err("mailbox unreachable");
    let core = NajwaCore::new(hooks.clone());

    let err = core
        .poll_messages()
        .expect_err("error path must propagate as Err");
    match err {
        MessagingError::InternalError(msg) => {
            assert!(msg.contains("mailbox unreachable"), "got: {msg}");
        }
        other => panic!("expected InternalError, got {other:?}"),
    }
    assert_eq!(hooks.poll_calls.load(Ordering::SeqCst), 1);
}

// ---------------------------------------------------------------------------
// Multi-call ordering (regression guard against the POLL_LOCK / guard
// ordering rules in the lifted body — make sure the facade itself does
// not drop hook calls under repeated invocation).
// ---------------------------------------------------------------------------

#[test]
fn facade_invokes_hook_on_every_call_no_caching() {
    let hooks = MockHooks::new();
    let core = NajwaCore::new(hooks.clone());

    hooks.set_send_ok("first");
    let r1 = core.send_message(1, "a", None).unwrap();
    hooks.set_send_ok("second");
    let r2 = core.send_message(1, "b", None).unwrap();
    hooks.set_send_ok("third");
    let r3 = core.send_message(1, "c", None).unwrap();

    assert_eq!(r1.msg_id_hex, "first");
    assert_eq!(r2.msg_id_hex, "second");
    assert_eq!(r3.msg_id_hex, "third");
    assert_eq!(
        hooks.send_calls.load(Ordering::SeqCst),
        3,
        "facade must not deduplicate or cache — every call must hit the hook"
    );
}
