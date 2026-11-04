//! Disappearing message timer configuration (S12 §2).

use crate::types::ContactId;

/// Minimum custom disappearing-message timer (S12 §2.1): 30 seconds. A custom
/// value in `1..MIN_TIMER_SECS` MUST be rejected at input boundaries (UI +
/// control receive) rather than applied — a shorter timer could be used to
/// force near-instant message expiry.
pub const MIN_TIMER_SECS: u32 = 30;

/// True for a below-minimum custom timer (`1..MIN_TIMER_SECS`). `0` (off) and
/// values `>= MIN_TIMER_SECS` are valid.
pub fn timer_below_minimum(secs: u32) -> bool {
    (1..MIN_TIMER_SECS).contains(&secs)
}

/// True when a received `set_at` is further ahead of `now` than the S07 §7.1
/// future bound. Such a setting is ignored (S12 §2.2): accepted, it would win
/// every later merge, and `2^64 − 1` would make the local `previous + 1` step
/// overflow, so the user could never change the timer again.
pub fn set_at_too_far_ahead(set_at: u64, now: u64) -> bool {
    set_at > now.saturating_add(najwa_protocol::message::MAX_FUTURE_SKEW_SECS)
}

/// Recipient never-read fallback window (S12 §3.2): 7 days. A received
/// disappearing message's timer normally starts on DISPLAY (`read_at`), but a
/// decrypted-but-never-opened message MUST still expire — at
/// `decrypted_at + RECIPIENT_FALLBACK_SECS + timer_secs`. We realise this by
/// scheduling the fallback deadline at receive time and moving it earlier (to
/// `read_at + timer_secs`) when the message is displayed, so a short-timer
/// message can never vanish before it is read.
pub const RECIPIENT_FALLBACK_SECS: u64 = 604_800;

/// Sender no-ACK fallback window (S12 §3.1): 24 hours. A sent disappearing
/// message's timer normally starts on the delivery ACK (`sent → Delivered`),
/// but if no ACK arrives it MUST still expire — at
/// `sent_at + SENDER_FALLBACK_SECS + timer_secs`. Realised the same way as the
/// recipient fallback: the deadline is scheduled at send and moved earlier (to
/// `ack_at + timer_secs`) when the ACK lands, so the sender's own copy never
/// vanishes before delivery is confirmed.
pub const SENDER_FALLBACK_SECS: u64 = 86_400;

/// S12 §3.2: no read receipts means the countdown starts at decryption.
/// Opted-in messages keep a bounded fallback until they are displayed.
pub fn recipient_deadline(now_ms: u64, timer_secs: u32, flags: u8) -> u64 {
    let fallback = if flags & 4 != 0 { RECIPIENT_FALLBACK_SECS } else { 0 };
    now_ms.saturating_add((fallback + u64::from(timer_secs)) * 1000)
}

/// Disappearing message timer presets (S12 §2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DisappearTimer {
    /// Timer disabled.
    #[default]
    Off,
    /// 30 seconds.
    Seconds30,
    /// 5 minutes.
    Minutes5,
    /// 1 hour.
    Hour1,
    /// 24 hours.
    Hours24,
    /// 7 days.
    Days7,
    /// 30 days.
    Days30,
    /// Arbitrary duration in seconds.
    Custom(u32),
}

impl DisappearTimer {
    /// Convert to seconds, or `None` if timer is off.
    pub fn to_secs(&self) -> Option<u32> {
        match self {
            Self::Off => None,
            Self::Seconds30 => Some(30),
            Self::Minutes5 => Some(300),
            Self::Hour1 => Some(3600),
            Self::Hours24 => Some(86400),
            Self::Days7 => Some(604800),
            Self::Days30 => Some(2592000),
            Self::Custom(s) => Some(*s),
        }
    }

    /// Parse from a seconds value.
    pub fn from_secs(secs: u32) -> Self {
        match secs {
            0 => Self::Off,
            30 => Self::Seconds30,
            300 => Self::Minutes5,
            3600 => Self::Hour1,
            86400 => Self::Hours24,
            604800 => Self::Days7,
            2592000 => Self::Days30,
            s => Self::Custom(s),
        }
    }
}

/// Who set the timer for this conversation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerSetBy {
    /// We set the timer.
    Me,
    /// The contact set the timer.
    Them,
}

/// Per-conversation timer setting (S12 §2.2).
#[derive(Debug, Clone)]
pub struct ConversationTimerSetting {
    /// Contact this setting applies to.
    pub contact_id: ContactId,
    /// Timer duration in seconds, or `None` if off.
    pub timer_secs: Option<u32>,
    /// Who set this timer.
    pub set_by: TimerSetBy,
    /// When this setting was changed (unix timestamp).
    pub set_at: u64,
}

/// A timer setting as it participates in the S12 §2.2 merge.
///
/// Note `timer_secs: None` ("off") is a real *setting* carrying its own
/// `set_at`, not the absence of one — "off, set at T" must beat "5 minutes,
/// set at T−1". Storing "off" as a deleted row would drop `set_at` and let the
/// older setting win on the next exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimerSetting {
    /// Timer duration in seconds, or `None` if off.
    pub timer_secs: Option<u32>,
    /// Unix-seconds time the setter's user changed it — the merge key.
    pub set_at: u64,
    /// Ed25519 `IK_pub` of whoever set it — the deterministic tiebreak key.
    pub setter_ik: [u8; 32],
}

/// S12 §2.2 last-writer-wins merge: does `incoming` supersede `current`?
///
/// Later `set_at` wins; on an exact tie the setting from the party with the
/// **lex-smaller** `IK_pub` wins (unsigned bytewise over the 32-byte Ed25519
/// keys). Because `set_at` travels on the wire (§2.3) and the tiebreak is
/// deterministic, both sides converge on the same setting regardless of
/// delivery order.
///
/// This replaces the old "shorter timer always wins" rule, which did **not**
/// converge: a stale short timer permanently overrode a deliberate later
/// lengthening.
pub fn timer_setting_wins(current: Option<&TimerSetting>, incoming: &TimerSetting) -> bool {
    match current {
        None => true,
        Some(current) => match incoming.set_at.cmp(&current.set_at) {
            std::cmp::Ordering::Greater => true,
            std::cmp::Ordering::Less => false,
            // Tie → lex-smaller IK_pub wins. Equal keys (same setter, same
            // second) keep the stored setting rather than flapping.
            std::cmp::Ordering::Equal => incoming.setter_ik < current.setter_ik,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timer_presets_to_secs() {
        assert_eq!(DisappearTimer::Off.to_secs(), None);
        assert_eq!(DisappearTimer::Seconds30.to_secs(), Some(30));
        assert_eq!(DisappearTimer::Minutes5.to_secs(), Some(300));
        assert_eq!(DisappearTimer::Hour1.to_secs(), Some(3600));
        assert_eq!(DisappearTimer::Hours24.to_secs(), Some(86400));
        assert_eq!(DisappearTimer::Days7.to_secs(), Some(604800));
        assert_eq!(DisappearTimer::Days30.to_secs(), Some(2592000));
        assert_eq!(DisappearTimer::Custom(42).to_secs(), Some(42));
    }

    // S12 §2.1: a below-minimum custom timer (1..30s) is detected; 0 (off) and
    // >= 30 are valid.
    #[test]
    fn below_minimum_timer_detection() {
        assert!(!timer_below_minimum(0));
        assert!(timer_below_minimum(1));
        assert!(timer_below_minimum(29));
        assert!(!timer_below_minimum(MIN_TIMER_SECS)); // 30
        assert!(!timer_below_minimum(3600));
    }

    #[test]
    fn timer_from_secs_roundtrip() {
        assert_eq!(DisappearTimer::from_secs(0), DisappearTimer::Off);
        assert_eq!(DisappearTimer::from_secs(30), DisappearTimer::Seconds30);
        assert_eq!(DisappearTimer::from_secs(300), DisappearTimer::Minutes5);
        assert_eq!(DisappearTimer::from_secs(3600), DisappearTimer::Hour1);
        assert_eq!(DisappearTimer::from_secs(86400), DisappearTimer::Hours24);
        assert_eq!(DisappearTimer::from_secs(604800), DisappearTimer::Days7);
        assert_eq!(DisappearTimer::from_secs(2592000), DisappearTimer::Days30);
        assert_eq!(DisappearTimer::from_secs(42), DisappearTimer::Custom(42));
    }

    #[test]
    fn timer_default_is_off() {
        assert_eq!(DisappearTimer::default(), DisappearTimer::Off);
    }

    // -- S12 §2.2 last-writer-wins merge ---------------------------------

    fn setting(timer_secs: Option<u32>, set_at: u64, ik: u8) -> TimerSetting {
        TimerSetting {
            timer_secs,
            set_at,
            setter_ik: [ik; 32],
        }
    }

    #[test]
    fn merge_first_setting_always_wins() {
        assert!(timer_setting_wins(None, &setting(Some(300), 100, 0x01)));
    }

    #[test]
    fn merge_later_set_at_wins() {
        let current = setting(Some(300), 100, 0x01);
        assert!(timer_setting_wins(
            Some(&current),
            &setting(Some(30), 101, 0x02)
        ));
        assert!(!timer_setting_wins(
            Some(&current),
            &setting(Some(30), 99, 0x02)
        ));
    }

    // The regression the LWW rule exists to prevent: under the old
    // "shorter timer always wins" rule a stale 30s setting permanently
    // overrode a deliberate later lengthening to 7 days.
    #[test]
    fn merge_later_lengthening_beats_stale_shorter_timer() {
        let stale_short = setting(Some(30), 100, 0x01);
        let later_long = setting(Some(604_800), 200, 0x02);
        assert!(timer_setting_wins(Some(&stale_short), &later_long));
    }

    // "Off" is a setting, not the absence of one — a later "off" wins.
    #[test]
    fn merge_later_off_beats_earlier_timer() {
        let current = setting(Some(300), 100, 0x01);
        assert!(timer_setting_wins(
            Some(&current),
            &setting(None, 150, 0x02)
        ));
        // ...and an earlier "off" loses to a later timer.
        let off = setting(None, 100, 0x01);
        assert!(timer_setting_wins(
            Some(&off),
            &setting(Some(300), 150, 0x02)
        ));
    }

    // Tie → lex-smaller IK_pub wins (unsigned bytewise).
    #[test]
    fn merge_tie_breaks_on_lex_smaller_ik() {
        let current = setting(Some(300), 100, 0x05);
        assert!(timer_setting_wins(
            Some(&current),
            &setting(Some(30), 100, 0x04)
        ));
        assert!(!timer_setting_wins(
            Some(&current),
            &setting(Some(30), 100, 0x06)
        ));
        // Same setter at the same second: keep what is stored, don't flap.
        assert!(!timer_setting_wins(
            Some(&current),
            &setting(Some(30), 100, 0x05)
        ));
    }

    // Comparison is UNSIGNED bytewise: 0x80.. must sort above 0x7F.., which a
    // signed-byte comparison would invert.
    #[test]
    fn merge_tiebreak_is_unsigned_bytewise() {
        let high = setting(Some(300), 100, 0x80);
        let low = setting(Some(30), 100, 0x7F);
        assert!(
            timer_setting_wins(Some(&high), &low),
            "0x7F < 0x80 unsigned"
        );
        assert!(!timer_setting_wins(Some(&low), &high));
    }

    // Convergence: both sides merge the same pair of settings in EITHER
    // delivery order and end up with the same result.
    #[test]
    fn merge_converges_regardless_of_delivery_order() {
        let a = setting(Some(300), 100, 0x01);
        let b = setting(Some(30), 100, 0x02); // tie → a wins (lex-smaller)
        let c = setting(Some(86_400), 250, 0x09);

        // Order 1: a, b, c
        let mut s1: Option<TimerSetting> = None;
        for incoming in [a, b, c] {
            if timer_setting_wins(s1.as_ref(), &incoming) {
                s1 = Some(incoming);
            }
        }
        // Order 2: c, b, a
        let mut s2: Option<TimerSetting> = None;
        for incoming in [c, b, a] {
            if timer_setting_wins(s2.as_ref(), &incoming) {
                s2 = Some(incoming);
            }
        }
        assert_eq!(s1, s2);
        assert_eq!(s1.unwrap(), c, "latest set_at must win in both orders");
    }
}
