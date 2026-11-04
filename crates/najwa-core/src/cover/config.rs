//! Cover traffic configuration (S10 §2).

use std::time::Duration;

/// Cover traffic intensity level (S10 §2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CoverLevel {
    /// ~1 operation per minute.
    Low,
    /// ~1 operation per 30 seconds.
    Medium,
    /// ~1 operation per 10 seconds.
    ///
    /// The default. In Timing privacy outbound sends absorb deposit slots
    /// (S10 §6.2), so the deposit interval is the floor on send latency and
    /// the level is not only a bandwidth dial. At `High` a first message after
    /// an idle period waits ~30 s on average (~7.5 s inside an S10 §8.1 boost
    /// window); `Medium` doubles that to ~60 s, which reads as
    /// broken rather than private. The cost is real — the device polls three
    /// times as often as `Medium` and deposits twice as often, even with
    /// nothing to say — and that is the price of the deposit rate being
    /// independent of user activity.
    #[default]
    High,
}

impl CoverLevel {
    /// Base poll interval for this level.
    pub fn poll_interval(&self) -> Duration {
        match self {
            Self::Low => Duration::from_secs(60),
            Self::Medium => Duration::from_secs(30),
            Self::High => Duration::from_secs(10),
        }
    }

    /// Base deposit interval for this level (mean). Twice the poll mean per
    /// S10 §2.1: Low 120 s / Medium 60 s / High 30 s.
    pub fn deposit_interval(&self) -> Duration {
        match self {
            Self::Low => Duration::from_secs(120),
            Self::Medium => Duration::from_secs(60),
            Self::High => Duration::from_secs(30),
        }
    }
}

/// Configuration for cover traffic (S10 §2).
#[derive(Debug, Clone)]
pub struct CoverTrafficConfig {
    /// Whether cover traffic is enabled.
    pub enabled: bool,
    /// Cover traffic intensity level.
    pub level: CoverLevel,
    /// Base interval between cover fetches.
    pub poll_interval: Duration,
    /// Base interval between cover deposits.
    pub deposit_interval: Duration,
    /// Secondary ±jitter% applied on top of the exponential inter-arrival
    /// (S10 §2.1, §3).
    pub jitter_percent: u32,
    /// Burst handling: SpeedPriority (default) boosts the slot rate on real
    /// bursts and fires decoy boosts (S10 §8.1); PrivacyPriority never boosts
    /// and is not used by the application.
    pub burst_mode: crate::cover::absorption::BurstMode,
}

impl CoverTrafficConfig {
    /// Create a config from a cover level with sensible defaults.
    pub fn from_level(level: CoverLevel) -> Self {
        Self {
            enabled: true,
            level,
            poll_interval: level.poll_interval(),
            deposit_interval: level.deposit_interval(),
            jitter_percent: 25,
            burst_mode: crate::cover::absorption::BurstMode::default(),
        }
    }
}

impl Default for CoverTrafficConfig {
    fn default() -> Self {
        Self::from_level(CoverLevel::default())
    }
}

/// Default cover-deposit sampling set (S10 §2.2): final DEPOSITED-BLOB sizes,
/// a strict subset of the S07 §5.1 padding buckets (asserted in tests below).
/// Most real traffic (text, ACKs, control) lands in these buckets; a 262 KB
/// cover deposit per slot would multiply bandwidth for little benefit during
/// text-only periods. File parts use larger buckets, which cover never
/// produces (S10 §2.3, §15).
pub const COVER_DEPOSIT_SIZES: &[usize] = &[256, 512, 1024, 2048, 4096];

/// Minimum jittered interval in milliseconds (floor to prevent sub-second intervals).
pub const MIN_JITTERED_INTERVAL_MS: u64 = 1000;

/// S10 §8.1: deposit-interval mean divisor inside a boost window.
pub const SPEED_BOOST_FACTOR: u32 = 4;

/// S10 §8.1: boost window length in seconds.
pub const SPEED_BOOST_WINDOW_SECS: u64 = 120;

/// S10 §8.1: decoy boosts fire as an independent Poisson process with this
/// mean interval (1/h), parameter-identical to real-burst boosts.
pub const DECOY_BOOST_MEAN_INTERVAL_SECS: u64 = 3600;

#[cfg(test)]
mod tests {
    use super::*;

    // The default level also sets Timing-privacy SEND LATENCY (S10 §2.1,
    // §6.2) — a send waits for a deposit slot — so this is a product-facing constant,
    // not just a bandwidth dial. Pin it with the reason attached.
    #[test]
    fn default_config_is_high() {
        let config = CoverTrafficConfig::default();
        assert_eq!(config.level, CoverLevel::High);
        assert!(config.enabled);
        assert_eq!(config.jitter_percent, 25);
        // ~30 s mean slot spacing; ~7.5 s inside a §8.1 boost window.
        assert_eq!(config.deposit_interval, Duration::from_secs(30));
        assert_eq!(
            config.deposit_interval / SPEED_BOOST_FACTOR,
            Duration::from_millis(7_500)
        );
    }

    #[test]
    fn level_intervals() {
        // S10 §2.1: deposit mean is 2× the poll mean at every level.
        assert_eq!(CoverLevel::Low.poll_interval(), Duration::from_secs(60));
        assert_eq!(CoverLevel::Medium.poll_interval(), Duration::from_secs(30));
        assert_eq!(CoverLevel::High.poll_interval(), Duration::from_secs(10));
        assert_eq!(CoverLevel::Low.deposit_interval(), Duration::from_secs(120));
        assert_eq!(
            CoverLevel::Medium.deposit_interval(),
            Duration::from_secs(60)
        );
        assert_eq!(CoverLevel::High.deposit_interval(), Duration::from_secs(30));
    }

    #[test]
    fn from_level_sets_intervals() {
        let config = CoverTrafficConfig::from_level(CoverLevel::High);
        assert_eq!(config.poll_interval, Duration::from_secs(10));
        assert_eq!(config.deposit_interval, Duration::from_secs(30));
        assert_eq!(config.level, CoverLevel::High);
    }

    // S10 §2.2: every cover bucket MUST be a real S07 §5.1 padding bucket —
    // a size cover can hit but real traffic can't would fingerprint cover.
    #[test]
    fn cover_sizes_are_a_subset_of_padding_buckets() {
        for size in COVER_DEPOSIT_SIZES {
            assert!(
                najwa_protocol::message::BUCKETS.contains(size),
                "cover bucket {size} is not an S07 §5.1 padding bucket"
            );
        }
        // §2.2 default set is 256 B – 4 KB.
        assert_eq!(COVER_DEPOSIT_SIZES, &[256, 512, 1024, 2048, 4096]);
    }
}
