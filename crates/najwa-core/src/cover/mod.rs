//! Cover traffic module (S10).
//!
//! Provides traffic analysis resistance by generating Poisson-scheduled
//! cover polls and deposits that are indistinguishable from real messaging
//! activity. In Timing privacy mode, real outbound items absorb deposit slots
//! through per-mailbox pending queues (S10 §6.1, §14), keeping the deposit-slot
//! rate independent of user activity outside boost windows.

pub mod absorption;
pub mod config;
mod permit;
pub mod scheduler;
pub use permit::SlotPermit;

pub use absorption::{
    AbsorptionPriority, BurstMode, PendingItem, PendingPayload, PendingQueues, SlotGrant,
    SlotSource,
};
pub use config::{CoverLevel, CoverTrafficConfig};
pub use scheduler::{CoverMailboxSnapshot, CoverStats, CoverStatsSnapshot, CoverTrafficScheduler};
