//! Identity management and local key protection for Najwa (S02).
//!
//! Provides:
//! - Standard-mode identity record creation and storage
//! - Password-based unlock with Argon2id + DKM (2-of-2 scheme)
//! - Platform device key management (DKM): TPM 2.0 on Windows and Linux, the
//!   Secure Enclave on macOS, and OS key storage after explicit approval
//! - Rate-limited unlock with exponential backoff
//! - Recovery kit: recovery phrase and recovery record
//! - Atomic file writes for crash safety
//! - Detection of record mode 0x02 (hardware-wrapped); migration into that mode
//!   fails closed
//!
//! `device_cert` (device certificates and device lists) is library code that
//! neither the app nor the receive path uses.

pub mod aad;
pub mod atomic;
pub mod backup;
pub mod creation;
pub mod device_cert;
pub mod error;
pub mod hardware;
pub mod manager;
pub mod mode_migration;
pub mod password;
pub mod platform;
pub mod record;
pub mod rotation;
pub mod unlock;

// -- Public re-exports -------------------------------------------------------

pub use error::{IdentityError, Result};
pub use manager::IdentityManager;
pub mod prekey_recovery;
pub use record::{Identity, IdentityRecordHardware, IdentityRecordStandard, IdentityState};
pub use rotation::{RotationAnnouncement, RotationError, VerificationResult};
pub use unlock::UnlockRateLimiter;

/// Prelude — import everything commonly needed.
pub mod prelude {
    pub use crate::backup::{export_seed_phrase, recover_from_seed_phrase, BackupVerification};
    pub use crate::error::{IdentityError, Result};
    pub use crate::manager::IdentityManager;
    pub use crate::record::{Identity, IdentityRecordStandard, IdentityState};
    pub use crate::rotation::{
        verify_key_rotation, IdentityHistory, RotationAnnouncement, RotationError, RotationReason,
        VerificationResult,
    };
    pub use crate::unlock::UnlockRateLimiter;
}
