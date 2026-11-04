//! Multi-path delivery constants and the epoch-redundancy helper (S08 §9.1).
//!
//! The multi-path *sender* logic is inlined in `send.rs`: the `MessagingService`
//! owns target selection and per-target D3 deposit-envelope encryption. What
//! remains here are the shared tuning constants and the epoch-transition
//! predicate that path consumes. (The former `MultiPathSender` struct was
//! removed — it had no callers and, unlike the inlined `send.rs` loop, applied no
//! D3 envelope, so it was a latent anonymity trap.)

use najwa_protocol::ratchet::state::RatchetState;

/// Default stagger delay range in milliseconds (S08 §9.1).
pub const STAGGER_DELAY_MIN_MS: u64 = 500;
/// Maximum stagger delay in milliseconds.
pub const STAGGER_DELAY_MAX_MS: u64 = 3000;

/// Default threshold of consecutive failures before auto-disabling a mailbox.
pub const DEFAULT_FAILURE_THRESHOLD: u32 = 5;

/// S08 §9.1: number of messages at the start of a new sending epoch
/// that should be routed with redundant multi-path delivery.
///
/// The first `EPOCH_REDUNDANCY_WINDOW` messages after a DH ratchet step are
/// the most critical for keeping the receiver in sync: losing any of them
/// can trigger a full `MissedEpochBoundary` recovery. Routing them over
/// extra paths (`Adaptive`) reduces that probability without imposing the
/// full `Paranoid` fan-out on steady-state traffic.
pub const EPOCH_REDUNDANCY_WINDOW: u32 = 3;

/// Returns `true` if this outgoing message is within the
/// `EPOCH_REDUNDANCY_WINDOW` of the current sending epoch — i.e. one of the
/// first `EPOCH_REDUNDANCY_WINDOW` messages the sender emits after a DH
/// ratchet step (S08 §9.1).
///
/// Call this **before** `ratchet_encrypt` — `state.ns` is the index of the
/// message about to be sent (0, 1, 2, ...) and is incremented by
/// `ratchet_encrypt` after the header is built.
pub fn is_epoch_transition_message(state: &RatchetState) -> bool {
    state.ns < EPOCH_REDUNDANCY_WINDOW
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{DeliveryReport, DeliveryStrategy};

    // DeliveryStrategy default is Adaptive
    #[test]
    fn default_strategy_is_adaptive() {
        assert_eq!(DeliveryStrategy::default(), DeliveryStrategy::Adaptive);
    }

    // DeliveryReport tracks successes and failures correctly
    #[test]
    fn delivery_report_tracking() {
        let mut report = DeliveryReport::new();
        assert!(!report.any_success());
        assert_eq!(report.success_count(), 0);

        report.record_success(1, Some("id1".into()));
        report.record_failure(2, "err".into());
        report.record_success(3, None);

        assert!(report.any_success());
        assert_eq!(report.success_count(), 2);
        assert_eq!(report.failure_count(), 1);
        assert_eq!(report.results.len(), 3);
    }

    // S08 §9.1: the first 3 messages of a new epoch are "transition"
    #[test]
    fn epoch_transition_first_three_messages() {
        use najwa_crypto::keys::x25519::X25519KeyPair;
        let mut rng = rand::thread_rng();
        let dhs = X25519KeyPair::generate(&mut rng);
        let mut state = RatchetState {
            dhs,
            dhr: None,
            rk: [0u8; 32],
            cks: Some([0u8; 32]),
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            prev_dhs_pub: None,
            skipped: std::collections::HashMap::new(),
        };
        assert!(is_epoch_transition_message(&state));
        state.ns = 1;
        assert!(is_epoch_transition_message(&state));
        state.ns = 2;
        assert!(is_epoch_transition_message(&state));
        state.ns = 3;
        assert!(!is_epoch_transition_message(&state));
        state.ns = 100;
        assert!(!is_epoch_transition_message(&state));
    }

    #[test]
    fn epoch_redundancy_window_is_three() {
        assert_eq!(EPOCH_REDUNDANCY_WINDOW, 3);
    }
}
