//! Top-level `NajwaCore` façade for the mobile FFI boundary.
//!
//! This module is the landing zone for Task 11 ("begin lifting messaging
//! logic out of `najwa-ffi/lib.rs` into `najwa-core`"). It exposes a
//! [`NajwaCore`] type whose `send_message` and `poll_messages` methods are
//! the canonical entry points the FFI shim delegates to.
//!
//! ## Scope (Task 11)
//!
//! Task 11 is explicitly scoped as the *first step* of lifting — not a full
//! refactor. The `najwa_send_message` and `najwa_poll_messages` bodies in
//! `najwa-ffi/src/lib.rs` are ~1500 lines of code tightly coupled to
//! FFI-layer state globals (`state::with_storage`, the Tor runtime handle,
//! event callbacks, pending-transfer / dedup / ignore-list caches, etc.).
//! Moving every line in one PR would require either duplicating helpers
//! across two crates or a structural refactor that was explicitly ruled
//! out of scope.
//!
//! Instead, this module uses a **dependency-inversion via `NajwaCoreHooks`
//! trait** pattern: [`NajwaCore`] owns the orchestration entry points and
//! state that belongs in core, while the FFI-specific glue (transport
//! access, callback dispatch, the per-call FFI-global state reads) is
//! abstracted behind the [`NajwaCoreHooks`] trait, which `najwa-ffi`
//! implements. Subsequent PRs will progressively move real logic from the
//! hook implementations into `NajwaCore` methods without churning the FFI
//! surface each time.
//!
//! ## Auto-reset note (resolves lib.rs:63 TODO)
//!
//! Historically, `najwa-ffi/src/lib.rs` carried a TODO stating that
//! auto-reset on repeated decryption failure belongs in `najwa-core`
//! because contact identification via `cap_hint` happens *before* ratchet
//! decryption, which is impossible at the FFI layer where failed trial
//! decryption does not reveal which contact sent the message. That TODO
//! is now tracked here: when the receive path is lifted into
//! [`NajwaCore::poll_messages`] (future PR in the Task 11 series), the
//! per-contact decryption-failure tracker can be added as a field on
//! `NajwaCore` and consulted using the `cap_hint` routing information
//! that core already has access to. See S06 §3.7.1.

use std::sync::Arc;

use crate::error::{MessagingError, Result};

/// Outcome of a `send_message` call reported back to the FFI shim.
#[derive(Debug, Clone)]
pub struct SendResult {
    /// Hex-encoded 16-byte message ID (same string the FFI currently
    /// returns to Kotlin).
    pub msg_id_hex: String,
}

/// Outcome of a `poll_messages` call reported back to the FFI shim.
#[derive(Debug, Clone)]
pub struct PollResult {
    /// Number of newly decrypted + saved messages (matches the legacy
    /// `najwa_poll_messages` return code contract: a non-negative count
    /// on success, or a negative error code on failure).
    pub new_count: i32,
}

/// Hooks the FFI layer implements so [`NajwaCore`] can call back into
/// FFI-global state (Tor transport, event callbacks, the legacy
/// `state::with_storage` accessor) without introducing a circular crate
/// dependency.
///
/// This trait is intentionally *not* a stable public API. It is the
/// seam through which logic is being lifted from `najwa-ffi` into
/// `najwa-core` across the Task 11 series. Each hook method corresponds
/// to one FFI-layer side effect that has not yet been lifted.
pub trait NajwaCoreHooks: Send + Sync {
    /// Invoke the legacy `najwa_send_message` body against FFI-global
    /// state (storage, identity key, Tor transport). Returns the
    /// hex-encoded message ID on success.
    ///
    /// The `reply_info_json` parameter matches the FFI C signature:
    /// `None` means no reply context, `Some(json)` is the same
    /// `{"ts":..,"text":..,"sender":..}` JSON the Kotlin bridge builds.
    fn send_message_impl(
        &self,
        contact_id: i64,
        text: &str,
        reply_info_json: Option<&str>,
    ) -> Result<SendResult>;

    /// Invoke the legacy `najwa_poll_messages` body against FFI-global
    /// state. Returns the newly-decrypted message count (legacy contract).
    fn poll_messages_impl(&self) -> Result<PollResult>;
}

/// Top-level messaging façade for the mobile FFI boundary.
///
/// Holds a single [`NajwaCoreHooks`] implementation supplied by the FFI
/// crate at initialization time. Methods on `NajwaCore` are the canonical
/// entry points for messaging; the FFI extern-C wrappers do nothing more
/// than parse their C parameters, call into `NajwaCore`, and marshal the
/// result back across the boundary.
///
/// `NajwaCore` is intentionally `Clone` (cheap `Arc` bump) so the FFI
/// shim can obtain a handle per call without having to thread a lifetime
/// through every extern-C entry.
#[derive(Clone)]
pub struct NajwaCore {
    hooks: Arc<dyn NajwaCoreHooks>,
}

impl NajwaCore {
    /// Construct a `NajwaCore` façade around a concrete hook
    /// implementation. The FFI crate calls this exactly once at
    /// `najwa_init`-equivalent time and stores the result in its
    /// global state.
    pub fn new(hooks: Arc<dyn NajwaCoreHooks>) -> Self {
        Self { hooks }
    }

    /// Send a text message to a contact (S08 §5).
    ///
    /// This is the canonical messaging send entry point. Task 11 lifts
    /// the call boundary into `najwa-core` so follow-up PRs can
    /// progressively move the real body in without churning the FFI
    /// surface every time. For now the call delegates to the FFI-side
    /// hook implementation, which preserves:
    ///
    /// - Sender-key rotation on group sends (Task 9d).
    /// - Repair-state tracking on ratchet failure (Task 9b).
    /// - Multipath routing for epoch-transition messages (Task 9c).
    /// - Disappearing-message timer threading (Task 14a).
    /// - Battery-aware scheduling integration (Task 6).
    pub fn send_message(
        &self,
        contact_id: i64,
        text: &str,
        reply_info_json: Option<&str>,
    ) -> Result<SendResult> {
        self.hooks
            .send_message_impl(contact_id, text, reply_info_json)
    }

    /// Poll the primary mailbox for new messages (S08 §6.1).
    ///
    /// This is the canonical messaging poll entry point. As with
    /// [`send_message`](Self::send_message), the body currently lives in
    /// the FFI hook impl and will be lifted in follow-up PRs.
    pub fn poll_messages(&self) -> Result<PollResult> {
        self.hooks.poll_messages_impl()
    }

    /// Return a reference to the installed hook implementation for
    /// diagnostic / test purposes.
    #[doc(hidden)]
    pub fn hooks(&self) -> &Arc<dyn NajwaCoreHooks> {
        &self.hooks
    }
}

impl std::fmt::Debug for NajwaCore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NajwaCore")
            .field("hooks", &"<dyn NajwaCoreHooks>")
            .finish()
    }
}

/// Convert a `MessagingError` into the negative FFI error code used by
/// `najwa_send_message` / `najwa_poll_messages`. Matches the existing
/// mapping in `najwa-ffi::error`.
///
/// This lives in `najwa-core` so tests can exercise the mapping without
/// pulling in the FFI crate.
pub fn error_to_ffi_code(err: &MessagingError) -> i32 {
    match err {
        MessagingError::ContactNotFound => -10,
        MessagingError::ContactBlocked => -11,
        MessagingError::NoMailboxCapability => -12,
        MessagingError::NoSignedPrekey => -13,
        MessagingError::StorageError(_) => -20,
        MessagingError::InternalError(_) => -99,
        _ => -1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    struct CountingHooks {
        sends: AtomicU32,
        polls: AtomicU32,
        send_result: std::sync::Mutex<Result<SendResult>>,
        poll_result: std::sync::Mutex<Result<PollResult>>,
    }

    impl CountingHooks {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                sends: AtomicU32::new(0),
                polls: AtomicU32::new(0),
                send_result: std::sync::Mutex::new(Ok(SendResult {
                    msg_id_hex: "deadbeef".to_string(),
                })),
                poll_result: std::sync::Mutex::new(Ok(PollResult { new_count: 0 })),
            })
        }
    }

    impl NajwaCoreHooks for CountingHooks {
        fn send_message_impl(
            &self,
            _contact_id: i64,
            _text: &str,
            _reply_info_json: Option<&str>,
        ) -> Result<SendResult> {
            self.sends.fetch_add(1, Ordering::SeqCst);
            // Clone the stashed result (cannot move out of the mutex).
            match &*self.send_result.lock().unwrap() {
                Ok(r) => Ok(r.clone()),
                Err(e) => Err(MessagingError::InternalError(e.to_string())),
            }
        }

        fn poll_messages_impl(&self) -> Result<PollResult> {
            self.polls.fetch_add(1, Ordering::SeqCst);
            match &*self.poll_result.lock().unwrap() {
                Ok(r) => Ok(r.clone()),
                Err(e) => Err(MessagingError::InternalError(e.to_string())),
            }
        }
    }

    #[test]
    fn send_message_delegates_to_hooks() {
        let hooks = CountingHooks::new();
        let core = NajwaCore::new(hooks.clone());
        let result = core.send_message(42, "hello", None).unwrap();
        assert_eq!(result.msg_id_hex, "deadbeef");
        assert_eq!(hooks.sends.load(Ordering::SeqCst), 1);
        assert_eq!(hooks.polls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn poll_messages_delegates_to_hooks() {
        let hooks = CountingHooks::new();
        *hooks.poll_result.lock().unwrap() = Ok(PollResult { new_count: 3 });
        let core = NajwaCore::new(hooks.clone());
        let result = core.poll_messages().unwrap();
        assert_eq!(result.new_count, 3);
        assert_eq!(hooks.polls.load(Ordering::SeqCst), 1);
        assert_eq!(hooks.sends.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn send_message_threads_reply_info_through_hooks() {
        struct CaptureHooks {
            captured: std::sync::Mutex<Option<String>>,
        }
        impl NajwaCoreHooks for CaptureHooks {
            fn send_message_impl(
                &self,
                _contact_id: i64,
                _text: &str,
                reply_info_json: Option<&str>,
            ) -> Result<SendResult> {
                *self.captured.lock().unwrap() = reply_info_json.map(String::from);
                Ok(SendResult {
                    msg_id_hex: "aa".to_string(),
                })
            }
            fn poll_messages_impl(&self) -> Result<PollResult> {
                Ok(PollResult { new_count: 0 })
            }
        }
        let hooks = Arc::new(CaptureHooks {
            captured: std::sync::Mutex::new(None),
        });
        let core = NajwaCore::new(hooks.clone());
        core.send_message(1, "hi", Some(r#"{"ts":1,"text":"x","sender":"A"}"#))
            .unwrap();
        assert_eq!(
            hooks.captured.lock().unwrap().as_deref(),
            Some(r#"{"ts":1,"text":"x","sender":"A"}"#)
        );
    }

    #[test]
    fn error_to_ffi_code_maps_known_variants() {
        assert_eq!(error_to_ffi_code(&MessagingError::ContactNotFound), -10);
        assert_eq!(error_to_ffi_code(&MessagingError::ContactBlocked), -11);
        assert_eq!(error_to_ffi_code(&MessagingError::NoMailboxCapability), -12);
    }
}
