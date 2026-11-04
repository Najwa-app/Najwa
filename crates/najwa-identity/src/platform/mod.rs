//! Platform-specific Device Key Material (DKM) storage (S02 §17).
//!
//! Each platform module implements `store_dkm`, `retrieve_dkm`, and `delete_dkm`.
//! The active platform is re-exported at module level.
//!
//! The [`DkmStorage`] trait enables mock implementations for testing
//! without requiring real platform secure storage.

use crate::error::Result;

#[cfg(feature = "approved-software-fallback")]
mod approved_software;
#[cfg(feature = "approved-software-fallback")]
pub use approved_software::{record_uses_software_storage, with_software_fallback_approval};

mod scoped;
pub use scoped::{delete_record_dkm, retrieve_record_dkm};
pub(crate) use scoped::{has_record_dkm, record_key_id, store_record_dkm};

/// Trait abstracting the unscoped DKM storage operations (one slot, not the
/// per-record generations of S02 §17.1).
///
/// Implementations use platform-specific secure storage:
/// - **Windows:** DPAPI / Credential Manager
/// - **macOS:** Keychain Services
/// - **Linux:** Secret Service (libsecret)
/// - **Android:** Android KeyStore
/// - **iOS:** Secure Enclave / Keychain
///
/// This trait enables mock implementations for unit testing without
/// requiring real platform secure storage.
pub trait DkmStorage {
    /// Store DKM in platform secure storage.
    fn store(&self, dkm: &[u8; 32]) -> Result<()>;
    /// Retrieve DKM from platform secure storage.
    fn retrieve(&self) -> Result<[u8; 32]>;
    /// Delete DKM from platform secure storage.
    fn delete(&self) -> Result<()>;
}

/// Platform-native DKM storage using the OS secure storage.
pub struct NativeDkmStorage;

impl DkmStorage for NativeDkmStorage {
    fn store(&self, dkm: &[u8; 32]) -> Result<()> {
        store_dkm(dkm)
    }
    fn retrieve(&self) -> Result<[u8; 32]> {
        retrieve_dkm()
    }
    fn delete(&self) -> Result<()> {
        delete_dkm()
    }
}

/// In-memory DKM storage for testing (no platform dependencies).
#[cfg(test)]
pub struct MockDkmStorage {
    pub dkm: std::sync::Mutex<Option<[u8; 32]>>,
}

#[cfg(test)]
impl Default for MockDkmStorage {
    fn default() -> Self {
        Self {
            dkm: std::sync::Mutex::new(None),
        }
    }
}

#[cfg(test)]
impl MockDkmStorage {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn with_key(key: [u8; 32]) -> Self {
        Self {
            dkm: std::sync::Mutex::new(Some(key)),
        }
    }
}

#[cfg(test)]
impl DkmStorage for MockDkmStorage {
    fn store(&self, dkm: &[u8; 32]) -> Result<()> {
        *self.dkm.lock().unwrap() = Some(*dkm);
        Ok(())
    }
    fn retrieve(&self) -> Result<[u8; 32]> {
        self.dkm
            .lock()
            .unwrap()
            .ok_or_else(|| crate::error::IdentityError::DkmError("no DKM stored".into()))
    }
    fn delete(&self) -> Result<()> {
        *self.dkm.lock().unwrap() = None;
        Ok(())
    }
}

#[cfg(target_os = "windows")]
mod windows;
#[cfg(all(target_os = "windows", feature = "windows-tpm"))]
mod windows_tpm;
#[cfg(target_os = "windows")]
use windows as imp;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(all(target_os = "macos", feature = "macos-secure-enclave"))]
mod macos_enclave;
#[cfg(target_os = "macos")]
use macos as imp;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(all(target_os = "linux", feature = "linux-tpm"))]
mod linux_tpm;
#[cfg(target_os = "linux")]
use linux as imp;

// `pub mod android` (not `mod android`) so that `najwa-ffi`'s
// `JNI_OnLoad` can call `najwa_identity::platform::android::set_java_vm`
// from outside the crate. This is the only entry point the FFI layer
// needs to invoke directly — all other DKM operations go through the
// `store_dkm`/`retrieve_dkm`/`delete_dkm` re-exports below.
#[cfg(target_os = "android")]
pub mod android;
#[cfg(target_os = "android")]
use android as imp;

#[cfg(target_os = "ios")]
mod ios;
#[cfg(target_os = "ios")]
use ios as imp;

// Fallback for unsupported platforms (WASM, FreeBSD, etc.)
#[cfg(not(any(
    target_os = "windows",
    target_os = "macos",
    target_os = "linux",
    target_os = "android",
    target_os = "ios"
)))]
mod fallback;
#[cfg(not(any(
    target_os = "windows",
    target_os = "macos",
    target_os = "linux",
    target_os = "android",
    target_os = "ios"
)))]
use fallback as imp;

// Unit tests default to isolated thread-local storage and never touch a user's
// real keychain. Integration tests exercise the production backend separately.
#[cfg(test)]
thread_local! {
    static MOCK_DKM_STORAGE: std::cell::RefCell<Option<MockDkmStorage>> =
        std::cell::RefCell::new(Some(MockDkmStorage::new()));
}

/// Install an in-memory DKM backend for the current test thread (test builds
/// only). Needed by any test that exercises a full unlock on a headless gate
/// (Docker) where no Secret Service / keychain exists.
#[cfg(test)]
pub fn set_dkm_storage_for_test(mock: MockDkmStorage) {
    MOCK_DKM_STORAGE.with(|m| *m.borrow_mut() = Some(mock));
    scoped::clear_mock_keys();
}

#[cfg(test)]
fn with_mock_dkm<T>(op: impl FnOnce(&dyn DkmStorage) -> Result<T>) -> Option<Result<T>> {
    MOCK_DKM_STORAGE.with(|m| m.borrow().as_ref().map(|mock| op(mock)))
}

/// Whether this build requires a hardware-protected device factor on this OS.
pub const fn hardware_keystore_required() -> bool {
    cfg!(any(
        all(target_os = "windows", feature = "windows-tpm"),
        all(target_os = "linux", feature = "linux-tpm"),
        all(target_os = "macos", feature = "macos-secure-enclave")
    ))
}

/// Headless testing must never downgrade a build that requires hardware keys.
fn headless_dkm_file() -> Option<std::ffi::OsString> {
    if hardware_keystore_required() {
        None
    } else {
        std::env::var_os("NAJWA_DKM_FILE")
    }
}

/// Store DKM in the platform secure storage.
///
/// If `NAJWA_DKM_FILE` is set, stores the DKM as hex in that file instead
/// of the platform keychain. This is for CLI testing in headless environments
/// (Docker, CI) where no D-Bus secret service or platform keychain exists.
pub fn store_dkm(dkm: &[u8; 32]) -> Result<()> {
    #[cfg(test)]
    if let Some(r) = with_mock_dkm(|m| m.store(dkm)) {
        return r;
    }
    if let Some(path) = headless_dkm_file() {
        let hex =
            zeroize::Zeroizing::new(dkm.iter().map(|b| format!("{:02x}", b)).collect::<String>());
        std::fs::write(&path, hex.as_bytes())
            .map_err(|e| crate::error::IdentityError::DkmError(format!("write DKM file: {e}")))?;
        return Ok(());
    }
    imp::store_dkm(dkm)
}

/// Retrieve DKM from the platform secure storage.
///
/// If `NAJWA_DKM_FILE` is set, reads the DKM hex from that file.
pub fn retrieve_dkm() -> Result<[u8; 32]> {
    #[cfg(test)]
    if let Some(r) = with_mock_dkm(|m| m.retrieve()) {
        return r;
    }
    if let Some(path) = headless_dkm_file() {
        let hex =
            zeroize::Zeroizing::new(std::fs::read_to_string(&path).map_err(|e| {
                crate::error::IdentityError::DkmError(format!("read DKM file: {e}"))
            })?);
        let hex = hex.trim();
        if hex.len() != 64 {
            return Err(crate::error::IdentityError::DkmError(format!(
                "DKM file must contain 64 hex chars, got {}",
                hex.len()
            )));
        }
        let mut dkm = [0u8; 32];
        for (i, bytes) in hex.as_bytes().as_chunks::<2>().0.iter().enumerate() {
            let pair = std::str::from_utf8(bytes)
                .map_err(|_| crate::error::IdentityError::DkmError("bad hex".into()))?;
            dkm[i] = u8::from_str_radix(pair, 16)
                .map_err(|e| crate::error::IdentityError::DkmError(format!("bad hex: {}", e)))?;
        }
        return Ok(dkm);
    }
    imp::retrieve_dkm()
}

/// Delete all Najwa DKM generations from platform storage (account deletion).
///
/// If `NAJWA_DKM_FILE` is set, deletes that file.
pub fn delete_dkm() -> Result<()> {
    scoped::delete_all_record_dkms()?;
    delete_legacy_dkm()
}

pub(crate) fn delete_legacy_dkm() -> Result<()> {
    #[cfg(test)]
    if let Some(r) = with_mock_dkm(|m| m.delete()) {
        return r;
    }
    if let Some(path) = headless_dkm_file() {
        return match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        };
    }
    imp::delete_dkm()
}

/// Hardware security module status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HardwareStatus {
    /// Hardware module is available and functional.
    Available,
    /// No hardware module on this device.
    NotPresent,
    /// Module was reset, wrapped key unrecoverable.
    KeyLost,
    /// Biometric/auth required to access module.
    Locked,
    /// Other error.
    Error(String),
}

/// Detect hardware security module availability.
///
/// Desktop platforms currently return `NotPresent`.
/// Mobile platforms (future) will probe the Secure Enclave / StrongBox.
pub fn detect_hardware_availability() -> HardwareStatus {
    // Desktop platforms: no hardware wrapping available
    #[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
    {
        HardwareStatus::NotPresent
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        HardwareStatus::NotPresent
    }
}

/// Startup action based on identity record and hardware availability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartupAction {
    /// Normal password unlock.
    NormalUnlock,
    /// Offer recovery from paper key.
    OfferRecovery { reason: String },
    /// No identity exists, create one.
    CreateIdentity,
}

// ---------------------------------------------------------------------------
// Biometric unlock policy. Not used by the app; desktop unlock has no
// biometric path.
// ---------------------------------------------------------------------------

/// Periodic password re-authentication interval (72 hours).
pub const BIOMETRIC_REAUTH_INTERVAL_SECS: u64 = 72 * 3600;

/// Maximum biometric failures before requiring password.
pub const BIOMETRIC_MAX_FAILURES: u32 = 5;

/// Biometric authentication policy (not used by the app).
#[derive(Debug, Clone, Default)]
pub struct BiometricPolicy {
    /// Whether biometric unlock is enabled.
    pub enabled: bool,
    /// Unix timestamp of last successful password authentication.
    pub last_password_auth: u64,
    /// Count of consecutive biometric failures.
    pub failure_count: u32,
    /// Whether biometric enrollment has changed since setup.
    pub enrollment_changed: bool,
}

impl BiometricPolicy {
    /// Check if biometric unlock is currently allowed.
    pub fn is_biometric_allowed(&self) -> bool {
        if !self.enabled || self.enrollment_changed {
            return false;
        }
        if self.failure_count >= BIOMETRIC_MAX_FAILURES {
            return false;
        }
        let now = najwa_crypto::time::now();
        if now - self.last_password_auth > BIOMETRIC_REAUTH_INTERVAL_SECS {
            return false;
        }
        true
    }

    /// Record a biometric failure.
    pub fn record_failure(&mut self) {
        self.failure_count += 1;
    }

    /// Record a successful biometric auth (resets failure count).
    pub fn record_success(&mut self) {
        self.failure_count = 0;
    }

    /// Record a successful password auth (resets timer and failure count).
    pub fn record_password_auth(&mut self) {
        self.last_password_auth = najwa_crypto::time::now();
        self.failure_count = 0;
        self.enrollment_changed = false;
    }
}
