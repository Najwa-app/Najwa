//! Callbacks, the event channel, and the dedicated callback thread
//! (S17 §5.1–§5.5).
//!
//! Design, per the normative contracts:
//! - **S17 §5.3 (quiescence).** No lock-free load-then-call: a host could
//!   unload the callback between the load and the call. Each callback lives
//!   in its own `Mutex<Option<Fn>>`, and the dispatcher holds that mutex across
//!   the ENTIRE invocation, so a `najwa_set_*_callback` / `najwa_clear_all_callbacks`
//!   that has returned can never observe the old callback executing or starting.
//! - **S17 §5.5 (threading).** All callbacks fire from ONE dedicated thread
//!   owned by this crate (spawned by `najwa_init` or the first queued event).
//!   Events go through one FIFO queue and are delivered in production order.
//!   Callbacks MUST NOT re-enter `najwa_*` (documented in the header).
//! - **S17 §3.2/§3 (panic + NUL).** Every invocation is wrapped in
//!   `catch_unwind`; argument C strings are built fallibly with interior NULs
//!   stripped (never `.unwrap()`ed).
//! - **S17 §5.4 (event channel).** `NajwaEventCallback` carries
//!   `{"event": "<name>", ...}` JSON. Defined events:
//!   `file_transfer_interrupted`, `file_transfer_progress` (S11 defines no
//!   file-transfer events: repair does not interrupt a transfer, S11 §2.6, and
//!   progress is persisted state, S11 §3), `repair_state_changed`
//!   (S06 §3.7). Nothing emits them, the
//!   error callback or the feature-toggle callback in this release; only
//!   message-received, message-status and connection-status fire (S17 §5.1).

use std::collections::VecDeque;
use std::sync::{Condvar, Mutex, OnceLock};
use zeroize::{Zeroize, Zeroizing};

// ---------------------------------------------------------------------------
// Callback pointer types (§5.1) — `extern "C"`, closed sets documented.
// ---------------------------------------------------------------------------

pub type MessageReceivedCallback =
    extern "C" fn(contact_id: *const std::os::raw::c_char, content: *const std::os::raw::c_char);
pub type MessageStatusCallback = extern "C" fn(msg_id: *const std::os::raw::c_char, status: i32);
pub type ConnectionStatusCallback = extern "C" fn(connected: i32);
pub type ErrorCallback = extern "C" fn(code: i32, message: *const std::os::raw::c_char);
pub type FeatureToggleCallback = extern "C" fn(feature: *const std::os::raw::c_char, enabled: i32);
pub type EventCallback = extern "C" fn(event_json: *const std::os::raw::c_char);

/// `NajwaMessageStatusCallback` status values (§5.1, normative closed set).
pub mod message_status {
    pub const QUEUED: i32 = 0;
    pub const DEPOSITED: i32 = 1;
    pub const DELIVERED: i32 = 2;
    pub const READ: i32 = 3;
    /// Retries exhausted (`PermanentlyFailed`).
    pub const FAILED: i32 = 4;
    /// Send failed; the core retries it (`Failed`). Appended after 4.
    pub const RETRYING: i32 = 5;
}

/// `NajwaFeatureToggleCallback` feature strings (S17 §5.1, closed set).
/// `cover_traffic` is the only defined feature; `vpn_mode`, `post_poll_burst`
/// and `background_poll` are reserved names that are never emitted.
pub mod feature_names {
    pub const COVER_TRAFFIC: &str = "cover_traffic";
    pub const VPN_MODE: &str = "vpn_mode";
    pub const POST_POLL_BURST: &str = "post_poll_burst";
    pub const BACKGROUND_POLL: &str = "background_poll";
    pub const ALL: [&str; 4] = [COVER_TRAFFIC, VPN_MODE, POST_POLL_BURST, BACKGROUND_POLL];
}

// ---------------------------------------------------------------------------
// The registration table — one mutex per callback (§5.3 reference shape).
// ---------------------------------------------------------------------------

static MESSAGE_RECEIVED_CB: Mutex<Option<MessageReceivedCallback>> = Mutex::new(None);
static MESSAGE_STATUS_CB: Mutex<Option<MessageStatusCallback>> = Mutex::new(None);
static CONNECTION_STATUS_CB: Mutex<Option<ConnectionStatusCallback>> = Mutex::new(None);
static ERROR_CB: Mutex<Option<ErrorCallback>> = Mutex::new(None);
static FEATURE_TOGGLE_CB: Mutex<Option<FeatureToggleCallback>> = Mutex::new(None);
static EVENT_CB: Mutex<Option<EventCallback>> = Mutex::new(None);

// ---------------------------------------------------------------------------
// Event queue + the dedicated dispatcher thread.
// ---------------------------------------------------------------------------

/// Internal event envelope. Payload strings are pre-encoded JSON/value bytes;
/// the dispatcher does the marshal-and-invoke.
///
/// `Error`, `FeatureToggle` and `Event` (and the S17 §5.4 builders below)
/// have no producer in this release (session repair does not interrupt a
/// file transfer, S11 §2.6; S06 §3.7 repair transitions are not reported
/// here); the channel itself is live and
/// contract-tested here.
#[derive(Debug)]
#[allow(dead_code)]
pub(crate) enum FfiEvent {
    /// §5.1: the callback signature carries the contact id as a STRING —
    /// the numeric core id never crosses the ABI.
    MessageReceived {
        contact_id: i64,
        content: String,
    },
    MessageStatus {
        msg_id: String,
        status: i32,
    },
    ConnectionStatus {
        connected: bool,
    },
    Error {
        code: i32,
        message: String,
    },
    FeatureToggle {
        feature: &'static str,
        enabled: bool,
    },
    Event {
        json: String,
    },
}

impl Drop for FfiEvent {
    fn drop(&mut self) {
        match self {
            Self::MessageReceived { content, .. } => content.zeroize(),
            Self::MessageStatus { msg_id, .. } => msg_id.zeroize(),
            Self::Error { message, .. } => message.zeroize(),
            Self::Event { json } => json.zeroize(),
            _ => {}
        }
    }
}

struct QueuedEvent {
    generation: u64,
    event: FfiEvent,
}

#[derive(Default)]
struct EventQueue {
    events: VecDeque<QueuedEvent>,
    generation: u64,
    quiesced: bool,
}

static QUEUE: OnceLock<(Mutex<EventQueue>, Condvar)> = OnceLock::new();
// Own this before removing plaintext from the queue. Clearing callbacks waits
// for the current invocation and zeroizes every remaining queued event.
static DISPATCH: Mutex<()> = Mutex::new(());

fn queue() -> &'static (Mutex<EventQueue>, Condvar) {
    QUEUE.get_or_init(|| (Mutex::new(EventQueue::default()), Condvar::new()))
}

pub(crate) fn ensure_dispatcher() {
    static STARTED: OnceLock<()> = OnceLock::new();
    STARTED.get_or_init(|| {
        std::thread::Builder::new()
            .name("najwa-ffi-callbacks".into())
            .spawn(|| loop {
                let (events, available) = queue();
                let waiting = events.lock().unwrap_or_else(|e| e.into_inner());
                drop(
                    available
                        .wait_while(waiting, |q| q.events.is_empty())
                        .unwrap_or_else(|e| e.into_inner()),
                );
                let _dispatch = DISPATCH.lock().unwrap_or_else(|e| e.into_inner());
                let event = events
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .events
                    .pop_front();
                if let Some(event) = event {
                    dispatch(event);
                }
            })
            .expect("spawn dedicated callback thread");
    });
}

fn enqueue(event: FfiEvent) {
    ensure_dispatcher();
    let (events, available) = queue();
    let mut events = events.lock().unwrap_or_else(|e| e.into_inner());
    if events.quiesced {
        return;
    }
    let generation = events.generation;
    events.events.push_back(QueuedEvent { generation, event });
    available.notify_one();
}

fn invoke<T: Copy>(slot: &Mutex<Option<T>>, generation: u64, call: impl FnOnce(T)) {
    // Cover marshalling as well as invocation. Foreign callbacks must catch
    // their own exceptions and must not re-enter this ABI.
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let registered = slot.lock().unwrap_or_else(|e| e.into_inner());
        let valid = {
            let events = queue().0.lock().unwrap_or_else(|e| e.into_inner());
            !events.quiesced && generation == events.generation
        };
        if valid {
            if let Some(cb) = *registered {
                call(cb);
            }
        }
    }));
}

fn dispatch(queued: QueuedEvent) {
    let generation = queued.generation;
    match &queued.event {
        FfiEvent::MessageReceived {
            contact_id,
            content,
        } => {
            invoke(&MESSAGE_RECEIVED_CB, generation, |cb| {
                let contact = cstring_lossy(&contact_id.to_string());
                let content = cstring_lossy(content);
                cb(contact.as_ptr(), content.as_ptr());
            });
        }
        FfiEvent::MessageStatus { msg_id, status } => {
            invoke(&MESSAGE_STATUS_CB, generation, |cb| {
                cb(cstring_lossy(msg_id).as_ptr(), *status)
            });
        }
        FfiEvent::ConnectionStatus { connected } => {
            invoke(&CONNECTION_STATUS_CB, generation, |cb| {
                cb(i32::from(*connected))
            });
        }
        FfiEvent::Error { code, message } => {
            invoke(&ERROR_CB, generation, |cb| {
                cb(*code, cstring_lossy(message).as_ptr())
            });
        }
        FfiEvent::FeatureToggle { feature, enabled } => {
            invoke(&FEATURE_TOGGLE_CB, generation, |cb| {
                cb(cstring_lossy(feature).as_ptr(), i32::from(*enabled))
            });
        }
        FfiEvent::Event { json } => {
            invoke(&EVENT_CB, generation, |cb| cb(cstring_lossy(json).as_ptr()));
        }
    }
}

// ---------------------------------------------------------------------------
// Registration (§5.2) — setters hold the mutex, so on return the previous
// callback is quiescent (§5.3 guarantee).
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn najwa_set_message_received_callback(cb: Option<MessageReceivedCallback>) {
    let _ = std::panic::catch_unwind(|| {
        *MESSAGE_RECEIVED_CB
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = cb;
    });
}

#[no_mangle]
pub extern "C" fn najwa_set_message_status_callback(cb: Option<MessageStatusCallback>) {
    let _ = std::panic::catch_unwind(|| {
        *MESSAGE_STATUS_CB.lock().unwrap_or_else(|e| e.into_inner()) = cb;
    });
}

#[no_mangle]
pub extern "C" fn najwa_set_connection_status_callback(cb: Option<ConnectionStatusCallback>) {
    let _ = std::panic::catch_unwind(|| {
        *CONNECTION_STATUS_CB
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = cb;
    });
}

#[no_mangle]
pub extern "C" fn najwa_set_error_callback(cb: Option<ErrorCallback>) {
    let _ = std::panic::catch_unwind(|| {
        *ERROR_CB.lock().unwrap_or_else(|e| e.into_inner()) = cb;
    });
}

#[no_mangle]
pub extern "C" fn najwa_set_feature_toggle_callback(cb: Option<FeatureToggleCallback>) {
    let _ = std::panic::catch_unwind(|| {
        *FEATURE_TOGGLE_CB.lock().unwrap_or_else(|e| e.into_inner()) = cb;
    });
}

#[no_mangle]
pub extern "C" fn najwa_set_event_callback(cb: Option<EventCallback>) {
    let _ = std::panic::catch_unwind(|| {
        *EVENT_CB.lock().unwrap_or_else(|e| e.into_inner()) = cb;
    });
}

/// Clear every callback. On return, no registered callback is executing or
/// will ever execute again (S17 §5.3), and queued events are dropped. A
/// callback registered afterwards receives events produced after it
/// (S17 §5.2).
#[no_mangle]
pub extern "C" fn najwa_clear_all_callbacks() {
    clear_all(false);
}

/// Lock and wipe teardown: clear like `najwa_clear_all_callbacks`, then drop
/// every new event until the next successful create, unlock or attach
/// (S17 §4.1 step 3), even if the host registers callbacks in between.
pub(crate) fn quiesce_callbacks() {
    clear_all(true);
}

fn clear_all(quiesce: bool) {
    let _ = std::panic::catch_unwind(|| {
        let _dispatch = DISPATCH.lock().unwrap_or_else(|e| e.into_inner());
        {
            let mut events = queue().0.lock().unwrap_or_else(|e| e.into_inner());
            events.quiesced |= quiesce;
            events.generation = events.generation.wrapping_add(1);
            events.events.clear();
        }
        *MESSAGE_RECEIVED_CB
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = None;
        *MESSAGE_STATUS_CB.lock().unwrap_or_else(|e| e.into_inner()) = None;
        *CONNECTION_STATUS_CB
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = None;
        *ERROR_CB.lock().unwrap_or_else(|e| e.into_inner()) = None;
        *FEATURE_TOGGLE_CB.lock().unwrap_or_else(|e| e.into_inner()) = None;
        *EVENT_CB.lock().unwrap_or_else(|e| e.into_inner()) = None;
    });
}

/// Resume event delivery without making pre-lock envelopes valid again.
pub(crate) fn unquiesce() {
    queue().0.lock().unwrap_or_else(|e| e.into_inner()).quiesced = false;
}

// ---------------------------------------------------------------------------
// Emit helpers (crate-internal) — enqueue onto the dispatcher thread.
// ---------------------------------------------------------------------------

pub(crate) fn emit_message_received(contact_id: i64, content: impl Into<String>) {
    enqueue(FfiEvent::MessageReceived {
        contact_id,
        content: content.into(),
    });
}

pub(crate) fn emit_message_status(msg_id: impl Into<String>, status: i32) {
    enqueue(FfiEvent::MessageStatus {
        msg_id: msg_id.into(),
        status,
    });
}

#[allow(dead_code)] // called by the Tor bootstrap in lib.rs (S17 §5.1)
pub(crate) fn emit_connection_status(connected: bool) {
    enqueue(FfiEvent::ConnectionStatus { connected });
}

#[allow(dead_code)] // no producer in this release (S17 §5.1)
pub(crate) fn emit_error(code: i32, message: impl Into<String>) {
    enqueue(FfiEvent::Error {
        code,
        message: message.into(),
    });
}

#[allow(dead_code)] // no producer in this release (S17 §5.1)
pub(crate) fn emit_feature_toggle(feature: &'static str, enabled: bool) {
    debug_assert!(feature_names::ALL.contains(&feature), "closed set");
    enqueue(FfiEvent::FeatureToggle { feature, enabled });
}

/// S17 §5.4: the generic event channel. `json` MUST be a UTF-8 JSON object
/// with at least `{"event": "<name>", ...}`.
#[allow(dead_code)] // no producer in this release (S17 §5.4)
pub(crate) fn emit_event_json(json: String) {
    enqueue(FfiEvent::Event { json });
}

/// S17 §5.4 defined event payloads. No call site emits them in this release.
#[allow(dead_code)] // see emit_event_json
pub(crate) mod events {
    /// `file_transfer_interrupted` event payload. Unused: session repair does
    /// not interrupt a file transfer (S11 §2.6).
    pub fn file_transfer_interrupted(
        session_id_hex: &str,
        direction: &str,
        reason: &str,
        resumable: bool,
    ) -> String {
        serde_json::json!({"event": "file_transfer_interrupted", "session_id": session_id_hex,
            "direction": direction, "reason": reason, "resumable": resumable})
        .to_string()
    }

    /// `file_transfer_progress` event payload. Unused: transfer progress is
    /// persisted state that the UI reads (S11 §3).
    pub fn file_transfer_progress(
        session_id_hex: &str,
        chunks_done: u32,
        chunks_total: u32,
    ) -> String {
        serde_json::json!({"event": "file_transfer_progress", "session_id": session_id_hex,
            "chunks_done": chunks_done, "chunks_total": chunks_total})
        .to_string()
    }

    /// S06 §3.7.
    pub fn repair_state_changed(contact_id: i64, state: &str) -> String {
        serde_json::json!({"event": "repair_state_changed", "contact_id": contact_id,
            "state": state})
        .to_string()
    }
}

// ---------------------------------------------------------------------------
// §3.2: fallible CString with NUL stripping — never `.unwrap()`ed.
// ---------------------------------------------------------------------------

/// Build a C string for a callback argument: interior NULs are STRIPPED
/// (S17 §3.2 item 3) rather than panicking — the affected argument is
/// re-encoded without them and nothing is logged.
pub(crate) struct CallbackString(Zeroizing<Vec<u8>>);

impl CallbackString {
    fn as_ptr(&self) -> *const std::os::raw::c_char {
        self.0.as_ptr().cast()
    }

    #[cfg(test)]
    fn to_bytes(&self) -> &[u8] {
        &self.0[..self.0.len() - 1]
    }
}

pub(crate) fn cstring_lossy(s: &str) -> CallbackString {
    let mut bytes = Zeroizing::new(Vec::with_capacity(s.len() + 1));
    bytes.extend(s.bytes().filter(|b| *b != 0));
    bytes.push(0);
    CallbackString(bytes)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::os::raw::c_char;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Mutex, OnceLock};
    use std::time::Duration;

    /// The quiesce flag + callback table are process-global: serialize the
    /// callback tests (they otherwise race on QUIESCED).
    pub(crate) fn test_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    extern "C" fn counting_cb(_contact_id: *const c_char, _content: *const c_char) {
        COUNT.fetch_add(1, Ordering::SeqCst);
    }

    static COUNT: AtomicU32 = AtomicU32::new(0);

    #[test]
    fn event_reaches_registered_callback_on_dispatcher_thread() {
        let _g = test_lock().lock().unwrap();
        COUNT.store(0, Ordering::SeqCst);
        unquiesce();
        ensure_dispatcher();
        najwa_set_message_received_callback(Some(counting_cb));
        emit_message_received(1, "hello");
        // Dispatcher is asynchronous: poll for delivery.
        for _ in 0..100 {
            if COUNT.load(Ordering::SeqCst) == 1 {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(COUNT.load(Ordering::SeqCst), 1);
        najwa_set_message_received_callback(None);
    }

    #[test]
    fn cstring_lossy_strips_interior_nuls() {
        let dirty = "a\0b";
        let c = cstring_lossy(dirty);
        assert_eq!(c.to_bytes(), b"ab");
        // Clean strings pass through unchanged.
        assert_eq!(cstring_lossy("ok").to_bytes(), b"ok");
    }

    #[test]
    fn clear_all_quiesces_delivery() {
        let _g = test_lock().lock().unwrap();
        ensure_dispatcher();
        najwa_set_message_received_callback(Some(counting_cb));
        najwa_clear_all_callbacks();
        let before = COUNT.load(Ordering::SeqCst);
        emit_message_received(2, "after quiesce");
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(
            COUNT.load(Ordering::SeqCst),
            before,
            "no delivery after clear"
        );
        unquiesce();
    }

    #[test]
    fn registration_after_clear_takes_effect_immediately() {
        let _g = test_lock().lock().unwrap();
        unquiesce();
        najwa_clear_all_callbacks();
        COUNT.store(0, Ordering::SeqCst);
        najwa_set_message_received_callback(Some(counting_cb));
        emit_message_received(3, "after re-registration");
        for _ in 0..100 {
            if COUNT.load(Ordering::SeqCst) == 1 {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(COUNT.load(Ordering::SeqCst), 1, "delivered without unlock");
        // Lock teardown still suspends delivery until the next unlock.
        quiesce_callbacks();
        najwa_set_message_received_callback(Some(counting_cb));
        emit_message_received(4, "while locked");
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(COUNT.load(Ordering::SeqCst), 1, "no delivery while locked");
        najwa_set_message_received_callback(None);
        unquiesce();
    }
}

#[cfg(test)]
mod row14_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    static CALLS: AtomicUsize = AtomicUsize::new(0);
    extern "C" fn counted(_: *const std::os::raw::c_char) {
        CALLS.fetch_add(1, Ordering::SeqCst);
    }

    #[test]
    fn pre_lock_event_never_reaches_replacement_callback() {
        let _test = tests::test_lock().lock().unwrap();
        unquiesce();
        let stale = QueuedEvent {
            generation: queue().0.lock().unwrap().generation,
            event: FfiEvent::Event {
                json: "private old session".into(),
            },
        };
        najwa_clear_all_callbacks();
        assert!(queue().0.lock().unwrap().events.is_empty());
        unquiesce();
        CALLS.store(0, Ordering::SeqCst);
        najwa_set_event_callback(Some(counted));
        dispatch(stale);
        assert_eq!(CALLS.load(Ordering::SeqCst), 0);
        let current = QueuedEvent {
            generation: queue().0.lock().unwrap().generation,
            event: FfiEvent::Event {
                json: "current".into(),
            },
        };
        dispatch(current);
        assert_eq!(CALLS.load(Ordering::SeqCst), 1);
        najwa_clear_all_callbacks();
    }

    #[test]
    fn event_builders_escape_untrusted_strings() {
        let dirty = "quote\" newline\n nul\0";
        let interruption: serde_json::Value = serde_json::from_str(
            &events::file_transfer_interrupted(dirty, dirty, dirty, true),
        )
        .unwrap();
        assert_eq!(interruption["reason"], dirty);
        let progress: serde_json::Value =
            serde_json::from_str(&events::file_transfer_progress(dirty, 1, 2)).unwrap();
        assert_eq!(progress["session_id"], dirty);
        let repair: serde_json::Value =
            serde_json::from_str(&events::repair_state_changed(1, dirty)).unwrap();
        assert_eq!(repair["state"], dirty);
    }

    #[test]
    fn marshalling_panic_is_contained_and_registration_recovers() {
        let _test = tests::test_lock().lock().unwrap();
        unquiesce();
        najwa_set_event_callback(Some(counted));
        let generation = queue().0.lock().unwrap().generation;
        invoke(&EVENT_CB, generation, |_| panic!("marshal failure"));
        najwa_set_event_callback(None);
        najwa_clear_all_callbacks();
    }

    type Blocking = (std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>);
    static BLOCKING: Mutex<Option<Blocking>> = Mutex::new(None);
    extern "C" fn blocked(_: *const std::os::raw::c_char) {
        let blocking = BLOCKING.lock().unwrap();
        let (started, release) = blocking.as_ref().unwrap();
        started.send(()).unwrap();
        release.recv().unwrap();
    }

    #[test]
    fn clear_waits_for_inflight_callback_and_discards_queued_plaintext() {
        let _test = tests::test_lock().lock().unwrap();
        let (started, ready) = std::sync::mpsc::channel();
        let (release, wait) = std::sync::mpsc::channel();
        *BLOCKING.lock().unwrap() = Some((started, wait));
        unquiesce();
        najwa_set_event_callback(Some(blocked));
        emit_event_json("current invocation".into());
        ready
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        emit_message_received(1, "queued plaintext");
        let (done, completed) = std::sync::mpsc::channel();
        let clearing = std::thread::spawn(move || {
            najwa_clear_all_callbacks();
            done.send(()).unwrap();
        });
        assert!(completed
            .recv_timeout(std::time::Duration::from_millis(30))
            .is_err());
        release.send(()).unwrap();
        completed
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        clearing.join().unwrap();
        assert!(queue().0.lock().unwrap().events.is_empty());
        *BLOCKING.lock().unwrap() = None;
    }
}
