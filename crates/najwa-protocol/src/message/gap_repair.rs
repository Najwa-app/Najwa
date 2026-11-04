//! Gap-repair wire structures (S07 §8.5).

/// Delay before a skipped ratchet message number is treated as a genuine gap.
pub const GAP_DETECT_SECS: u64 = 600;

/// Maximum total ratchet message numbers accepted in one repair request.
pub const GAP_REPAIR_MAX_RANGE: usize = 100;

/// Maximum sending epochs carried by one repair request.
pub const GAP_REPAIR_MAX_EPOCHS: usize = 8;

/// Maximum ranges carried for one sending epoch.
pub const GAP_REPAIR_MAX_RANGES_PER_EPOCH: usize = 16;

/// Fixed bytes before `original_content` in a repaired item.
pub const REPAIRED_ITEM_HEADER_SIZE: usize = 70;

/// Inclusive range of missing ratchet message numbers within one sending epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GapRange {
    pub start_n: u32,
    pub end_n: u32,
}

impl GapRange {
    /// Number of ratchet message numbers represented by this inclusive range.
    pub fn len(&self) -> u64 {
        u64::from(self.end_n)
            .saturating_sub(u64::from(self.start_n))
            .saturating_add(1)
    }

    pub fn is_empty(&self) -> bool {
        self.start_n > self.end_n
    }
}

/// Missing ranges belonging to one remote sending-ratchet public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochGap {
    pub dh_pub: [u8; 32],
    pub ranges: Vec<GapRange>,
}

/// A requested range that is no longer available in the sender's durable history.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GapRepairUnavailable {
    pub dh_pub: [u8; 32],
    pub start_n: u32,
    pub end_n: u32,
}

/// Original user-content fields carried inside a gap-repair bundle.
///
/// The fixed header is exactly 70 bytes; `original_content` follows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairedItem {
    pub original_dh_pub: [u8; 32],
    pub original_n: u32,
    pub original_msg_id: [u8; 16],
    pub original_timestamp: u64,
    pub original_logical_seq: u32,
    pub original_content_type: u8,
    pub original_flags: u8,
    pub original_content: Vec<u8>,
}
