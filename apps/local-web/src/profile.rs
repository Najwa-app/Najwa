//! One local profile owner. Secrets never enter logs or browser storage.
use najwa_ffi::desktop::DesktopClient;
use najwa_identity::{IdentityError, IdentityManager, IdentityRecordStandard};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    fs::File,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU32, Ordering},
        Arc, Mutex, RwLock,
    },
    time::Instant,
};
use zeroize::Zeroizing;

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    pub enabled: bool,
    pub session: String,
    pub generation: u64,
    pub phase: &'static str,
    pub hardware: &'static str,
    pub protection: &'static str,
    pub fingerprint: Option<String>,
    pub recovery_available: bool,
    pub recovery_pending: bool,
    pub prekey_refresh_required: bool,
    pub unavailable_reason: Option<&'static str>,
    pub busy: bool,
    pub software_fallback_available: bool,
    pub software_fallback_approved: bool,
    pub lock_timeout_seconds: u32,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Failure {
    pub code: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
    /// zxcvbn's generic warning for `weak_passphrase`; never contains the input.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
}
impl Failure {
    pub fn new(code: &'static str) -> Self {
        Self {
            code,
            retry_after_ms: None,
            hint: None,
        }
    }
}
impl From<IdentityError> for Failure {
    fn from(error: IdentityError) -> Self {
        match error {
            IdentityError::RateLimited { delay_ms } => Self {
                retry_after_ms: Some(delay_ms),
                ..Self::new("rate_limited")
            },
            IdentityError::LockedOut(_) => Self::new("locked_out"),
            IdentityError::UnlockFailed => Self::new("authentication_failed"),
            IdentityError::EmptyPassword
            | IdentityError::PasswordTooShort(_)
            | IdentityError::PasswordTooLong(_) => Self::new("invalid_password"),
            IdentityError::WeakPassphrase { hint } => Self {
                hint,
                ..Self::new("weak_passphrase")
            },
            IdentityError::AlreadyExists => Self::new("already_exists"),
            IdentityError::NotFound => Self::new("identity_missing"),
            IdentityError::RecoveryRecordMissing => Self::new("recovery_missing"),
            IdentityError::Backup(_) | IdentityError::PaperKeyMismatch => {
                Self::new("recovery_invalid")
            }
            IdentityError::DkmError(_) | IdentityError::HardwareError(_) => {
                Self::new("keystore_unavailable")
            }
            _ => Self::new("storage_unavailable"),
        }
    }
}
impl From<najwa_identity::backup::BackupError> for Failure {
    fn from(error: najwa_identity::backup::BackupError) -> Self {
        IdentityError::from(error).into()
    }
}
pub type Result<T> = std::result::Result<T, Failure>;

/// A passphrase or recovery words from a request body (S13 §17). The string is
/// zeroizing, so it is wiped even when parsing fails after this field.
pub struct Secret(Zeroizing<String>);
impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        String::deserialize(d).map(|v| Self(Zeroizing::new(v)))
    }
}
impl std::ops::Deref for Secret {
    type Target = Zeroizing<String>;
    fn deref(&self) -> &Zeroizing<String> {
        &self.0
    }
}

// No Debug derive: these fields contain credentials.
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum IdentityOperation {
    Create {
        password: Secret,
        confirmation: Secret,
    },
    Unlock {
        password: Secret,
    },
    ChangePassword {
        current: Secret,
        password: Secret,
        confirmation: Secret,
    },
    Recover {
        words: Secret,
        password: Secret,
        confirmation: Secret,
    },
    Restore {
        record: String,
        words: Secret,
        password: Secret,
        confirmation: Secret,
    },
    ReplaceRecovery {
        password: Secret,
    },
    RecoveryWords,
    ExportRecovery,
    AcknowledgeRecovery,
    ApproveSoftwareStorage { confirmed: bool },
}
impl IdentityOperation {
    fn check(&self) -> Result<()> {
        let invalid = |ok: bool| if ok { Ok(()) } else { Err(Failure::new("invalid_password")) };
        let existing = |v: &str| invalid(!v.is_empty() && v.len() <= 1024);
        // S02 §11.1: every new passphrase (create, change, recover, restore).
        // The manager enforces the rule too; checking here refuses before the
        // operation locks the session or writes a restore sidecar.
        let new = |v: &str, confirmation: &str| {
            invalid(v == confirmation)?;
            najwa_identity::password::validate_new_passphrase(v).map_err(Failure::from)
        };
        match self {
            Self::Create {
                password,
                confirmation,
            } => new(password, confirmation),
            Self::Unlock { password } | Self::ReplaceRecovery { password } => existing(password),
            Self::ChangePassword {
                current,
                password,
                confirmation,
            } => existing(current).and_then(|_| new(password, confirmation)),
            Self::Recover {
                words,
                password,
                confirmation,
            } => existing(words).and_then(|_| new(password, confirmation)),
            Self::Restore {
                record,
                words,
                password,
                confirmation,
            } => invalid(record.len() <= 256)
                .and_then(|_| existing(words))
                .and_then(|_| new(password, confirmation)),
            Self::ApproveSoftwareStorage { confirmed: false } => {
                Err(Failure::new("software_approval_required"))
            }
            _ => Ok(()),
        }
    }
}
struct Profile {
    manager: IdentityManager,
    words: Option<Zeroizing<String>>,
    _lease: File,
    software_approved: bool,
}
pub struct Owner {
    directory: PathBuf,
    profile: Mutex<Profile>,
    view: RwLock<Snapshot>,
    pub client: DesktopClient,
    pub token: String,
    pub launch_cookie: String,
    pub browser_access: crate::browser_access::BrowserAccess,
    pub host: String,
    pub origin: String,
    pub assets: crate::assets::Assets,
    pub shutdown: tokio::sync::Notify,
    identity_busy: AtomicBool,
    pub activity: Mutex<Instant>,
    lock_timeout_seconds: AtomicU32,
    transport_reset: AtomicBool,
}
#[path = "preferences.rs"]
mod preferences;
#[path = "erasure.rs"]
mod erasure;
#[cfg(test)]
#[path = "preferences_tests.rs"]
mod preferences_tests;
/// Unit tests that open an `Owner` hold this: there is one messaging owner per
/// process, released by `prepare_wipe`.
#[cfg(test)]
pub(crate) static TEST_OWNER: Mutex<()> = Mutex::new(());
pub struct BusyGuard<'a>(&'a AtomicBool);
impl Drop for BusyGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}
impl Owner {
    pub fn open(
        directory: &Path,
        assets: crate::assets::Assets,
        port: u16,
    ) -> std::result::Result<Arc<Self>, &'static str> {
        use fs2::FileExt;
        if std::env::var_os("NAJWA_DKM_FILE").is_some() {
            return Err("test keystore override is not allowed");
        }
        std::fs::create_dir_all(directory).map_err(|_| "cannot create profile")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))
                .map_err(|_| "cannot protect profile directory")?;
        }
        let directory = directory
            .canonicalize()
            .map_err(|_| "cannot resolve profile directory")?;
        let lease = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(directory.join("owner.lock"))
            .map_err(|_| "cannot open profile lease")?;
        lease
            .try_lock_exclusive()
            .map_err(|_| "this profile is already open")?;
        // Same lease and durable erasure marker as the desktop identity owner.
        let wiping = directory
            .join("wipe.pending")
            .try_exists()
            .map_err(|_| "cannot inspect profile")?;
        if wiping {
            najwa_privacy::lifecycle::emergency::begin(&directory)
                .map_err(|_| "cannot read erasure retry marker")?;
        }
        // Partial erasure can leave an unreadable identity record. Never open it
        // or allow identity operations; retain only an absent, in-memory owner.
        let record_path = if wiping { directory.join(format!("erasing-{}.absent", random_hex::<16>())) }
            else { directory.join("identity.najwa") };
        let manager = IdentityManager::new(record_path)
            .map_err(|_| "cannot read identity profile")?;
        let fingerprint = fingerprint(&manager);
        let software_approved = uses_software_storage(&manager);
        let snapshot = Snapshot {
            enabled: true,
            session: random_hex::<16>(),
            generation: 1,
            phase: if wiping { "wiping" } else if manager.exists() { "locked" } else { "absent" },
            hardware: if software_approved { "unavailable" } else { "unverified" },
            protection: if software_approved { "os-keystore" } else { "hardware" },
            fingerprint,
            recovery_available: manager.load_recovery_record().is_ok(),
            recovery_pending: false,
            prekey_refresh_required: prekey_pending(&manager),
            unavailable_reason: wiping.then_some("wipe_incomplete"),
            busy: false,
            software_fallback_available: false,
            software_fallback_approved: software_approved,
            lock_timeout_seconds: 300,
        };
        let browser_access = if wiping { crate::browser_access::BrowserAccess::for_erasure(&directory) }
            else { crate::browser_access::BrowserAccess::open(&directory)? };
        let client =
            DesktopClient::init(&directory).map_err(|_| "cannot initialize encrypted messaging")?;
        Ok(Arc::new(Self {
            directory,
            profile: Mutex::new(Profile {
                manager,
                words: None,
                _lease: lease,
                software_approved,
            }),
            view: RwLock::new(snapshot),
            client,
            token: random_hex::<32>(),
            launch_cookie: format!("Najwa-Launch-{port}"),
            browser_access,
            host: format!("127.0.0.1:{port}"),
            origin: format!("http://127.0.0.1:{port}"),
            assets,
            shutdown: tokio::sync::Notify::new(),
            identity_busy: AtomicBool::new(false),
            activity: Mutex::new(Instant::now()),
            lock_timeout_seconds: AtomicU32::new(300),
            transport_reset: AtomicBool::new(false),
        }))
    }
    pub fn status(&self) -> Snapshot {
        let mut view = self.view.write().unwrap();
        // Fresh prekeys are published in the background after a recovery.
        if view.prekey_refresh_required && view.phase == "unlocked" && !view.busy {
            view.prekey_refresh_required = self.client.prekey_recovery_pending().unwrap_or(true);
        }
        view.clone()
    }
    pub fn validate(&self, session: &str, generation: u64, unlocked: bool) -> Result<()> {
        let view = self.view.read().unwrap();
        if view.session != session
            || view.generation != generation
            || (unlocked && (view.phase != "unlocked" || view.busy))
        {
            Err(Failure::new("stale_operation"))
        } else {
            Ok(())
        }
    }
    // Invalidate first, even if a KDF or network operation is still running.
    pub fn begin_lock(&self) -> u64 {
        let mut view = self.view.write().unwrap();
        if matches!(view.phase, "wiping" | "erased") { return view.generation; }
        view.generation += 1;
        view.phase = "locking";
        view.recovery_pending = false;
        let epoch = view.generation;
        drop(view);
        self.client.cancel();
        epoch
    }
    pub fn finish_lock(&self, epoch: u64) -> Result<Snapshot> {
        let mut profile = self.profile.lock().unwrap();
        if matches!(self.view.read().unwrap().phase, "wiping" | "erased") { return Ok(self.status()); }
        let mut result = self.client.lock().map_err(|_| Failure::new("lock_failed"));
        // On failure the messaging owner may retain key handles; never claim locked.
        if result.is_ok() {
            profile.manager.lock();
            profile.words = None;
            if self.transport_reset.load(Ordering::SeqCst) {
                result = self.reset_transport();
            }
        }
        let mut view = self.view.write().unwrap();
        if view.generation == epoch {
            view.phase = if result.is_err() {
                "error"
            } else if profile.manager.exists() {
                "locked"
            } else {
                "absent"
            };
            view.busy = false;
            view.recovery_pending = false;
        }
        result.map(|_| view.clone())
    }
    pub fn identity(
        &self,
        session: &str,
        generation: u64,
        operation: IdentityOperation,
    ) -> Result<Value> {
        operation.check()?;
        self.identity_busy
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| Failure::new("busy"))?;
        let _busy = BusyGuard(&self.identity_busy);
        let epoch = {
            let mut view = self.view.write().unwrap();
            if view.session != session
                || view.generation != generation
                || matches!(view.phase, "locking" | "error" | "wiping" | "erased")
            {
                return Err(Failure::new("stale_operation"));
            }
            // Read-only recovery access also advances the generation: stale tabs cannot act.
            view.generation += 1;
            view.busy = true;
            if !matches!(
                operation,
                IdentityOperation::RecoveryWords
                    | IdentityOperation::ExportRecovery
                    | IdentityOperation::AcknowledgeRecovery
                    | IdentityOperation::ApproveSoftwareStorage { .. }
            ) {
                view.phase = "locking";
            }
            view.generation
        };
        let mut profile = self.profile.lock().unwrap();
        let mut output = Value::Null;
        let software_approved = profile.software_approved;
        let result = najwa_identity::platform::with_software_fallback_approval(software_approved, || -> Result<()> {
            match &operation {
                // `check` refused `confirmed: false` before any state changed.
                IdentityOperation::ApproveSoftwareStorage { .. } => {
                    if !self.view.read().unwrap().software_fallback_available || profile.manager.is_unlocked() {
                        return Err(Failure::new("software_approval_not_available"));
                    }
                    profile.software_approved = true;
                }
                IdentityOperation::Create { password, .. } => {
                    if profile.manager.exists() {
                        return Err(Failure::new("already_exists"));
                    }
                    profile.words = Some(Zeroizing::new(
                        profile.manager.create_with_recovery_record(password, 24)?,
                    ));
                }
                IdentityOperation::Unlock { password } => {
                    if profile.manager.is_unlocked() {
                        return Err(Failure::new("already_unlocked"));
                    }
                    profile.manager.unlock(password)?;
                }
                IdentityOperation::ChangePassword {
                    current, password, ..
                } => {
                    self.client
                        .lock()
                        .map_err(|_| Failure::new("lock_failed"))?;
                    profile.manager.change_password(current, password)?;
                }
                IdentityOperation::Recover {
                    words, password, ..
                } => {
                    let recovery = profile.manager.load_recovery_record()?;
                    let expected: String =
                        recovery.ik_pub.iter().map(|v| format!("{v:02x}")).collect();
                    if fingerprint(&profile.manager).as_deref() != Some(expected.as_str()) {
                        return Err(Failure::new("recovery_invalid"));
                    }
                    self.client
                        .lock()
                        .map_err(|_| Failure::new("lock_failed"))?;
                    profile.manager.lock();
                    profile
                        .manager
                        .recover_from_recovery_record_at(words, password)?;
                }
                IdentityOperation::Restore {
                    record,
                    words,
                    password,
                    ..
                } => {
                    use base64::Engine;
                    if profile.manager.exists() {
                        return Err(Failure::new("already_exists"));
                    }
                    let bytes = base64::engine::general_purpose::STANDARD
                        .decode(record)
                        .map_err(|_| Failure::new("recovery_invalid"))?;
                    let recovery = najwa_identity::backup::RecoveryRecord::from_bytes(&bytes)?;
                    // Import is confined to an empty profile. The manager verifies the phrase before publishing an identity.
                    let sidecar = profile.manager.record_path().with_extension("recovery");
                    najwa_identity::atomic::atomic_write(&sidecar, &recovery.to_bytes())?;
                    let restored = profile
                        .manager
                        .recover_from_recovery_record_at(words, password);
                    if restored.is_err() && !profile.manager.exists() {
                        let _ = std::fs::remove_file(sidecar);
                    }
                    restored?;
                }
                IdentityOperation::ReplaceRecovery { password } => {
                    self.client
                        .lock()
                        .map_err(|_| Failure::new("lock_failed"))?;
                    profile.manager.lock(); // unlock must authenticate, not reuse an unlocked manager
                    profile.manager.unlock(password)?;
                    let (words, record) = najwa_identity::backup::create_recovery_record(
                        profile
                            .manager
                            .identity()
                            .ok_or_else(|| Failure::new("locked"))?,
                        24,
                    )?;
                    najwa_identity::atomic::atomic_write(
                        &profile.manager.record_path().with_extension("recovery"),
                        &record.to_bytes(),
                    )?;
                    profile.words = Some(Zeroizing::new(words));
                }
                IdentityOperation::RecoveryWords => {
                    if !profile.manager.is_unlocked() {
                        return Err(Failure::new("locked"));
                    }
                    output = json!({"words": profile.words.as_deref().ok_or_else(|| Failure::new("recovery_missing"))?.as_str()});
                }
                IdentityOperation::ExportRecovery => {
                    use base64::Engine;
                    if !profile.manager.is_unlocked() || profile.words.is_none() {
                        return Err(Failure::new("locked"));
                    }
                    output = json!({"record": base64::engine::general_purpose::STANDARD.encode(profile.manager.load_recovery_record()?.to_bytes())});
                }
                IdentityOperation::AcknowledgeRecovery => {
                    profile.words = None;
                }
            }
            Ok(())
        });
        // A missing device key also makes the authenticated attempt counter
        // unavailable. Keep that lockout, but still offer consent for recovery.
        let missing_device_key = result.is_err() && device_key_unavailable(&profile.manager);
        let mut view = self.view.write().unwrap();
        if view.generation != epoch {
            // Lock superseded this operation. Never resurrect an unlocked identity.
            profile.manager.lock();
            profile.words = None;
            return Err(Failure::new("stale_operation"));
        }
        let mut result = result;
        if missing_device_key || result.as_ref().err().is_some_and(|error| error.code == "keystore_unavailable") {
            view.software_fallback_available = !profile.software_approved;
        }
        let attach = matches!(
            operation,
            IdentityOperation::Create { .. }
                | IdentityOperation::Unlock { .. }
                | IdentityOperation::Recover { .. }
                | IdentityOperation::Restore { .. }
                | IdentityOperation::ChangePassword { .. }
                | IdentityOperation::ReplaceRecovery { .. }
        );
        if result.is_ok() && attach {
            result = self
                .client
                .attach_identity(
                    profile
                        .manager
                        .identity()
                        .ok_or_else(|| Failure::new("locked"))?,
                )
                .map_err(|_| Failure::new("storage_unavailable"));
            if result.is_ok() {
                result = self.client.local_preferences().map(|prefs| {
                    self.lock_timeout_seconds.store(prefs.lock_timeout_seconds, Ordering::SeqCst);
                    view.lock_timeout_seconds = prefs.lock_timeout_seconds;
                }).map_err(|_| Failure::new("invalid_preferences"));
            }
        }
        let keep_open = attach && result.is_ok()
            || matches!(
                operation,
                IdentityOperation::RecoveryWords
                    | IdentityOperation::ExportRecovery
                    | IdentityOperation::AcknowledgeRecovery
            );
        if !keep_open {
            // Failed mutations cannot leave the messaging owner unlocked.
            let locked = self.client.lock().map_err(|_| Failure::new("lock_failed"));
            if locked.is_ok() {
                profile.manager.lock();
            } else {
                view.phase = "error";
                view.busy = false;
                return locked.map(|_| Value::Null);
            }
        }
        view.phase = if profile.manager.is_unlocked() {
            "unlocked"
        } else if profile.manager.exists() {
            "locked"
        } else {
            "absent"
        };
        view.fingerprint = fingerprint(&profile.manager);
        // Locked: the marker alone decides. Unlocked: the store records completion.
        view.prekey_refresh_required = prekey_pending(&profile.manager)
            && self.client.prekey_recovery_pending().unwrap_or(true);
        view.recovery_available = profile.manager.load_recovery_record().is_ok();
        view.recovery_pending = profile.words.is_some();
        view.busy = false;
        view.software_fallback_approved = profile.software_approved;
        if uses_software_storage(&profile.manager) {
            view.protection = "os-keystore";
            view.hardware = "unavailable";
        } else if profile.manager.is_unlocked() {
            view.protection = "hardware";
            view.hardware = "protected";
        }
        if profile.manager.is_unlocked() {
            view.software_fallback_available = false;
        }
        *self.activity.lock().unwrap() = Instant::now();
        result.map(|_| json!({"identity": view.clone(), "value": output}))
    }
}
fn device_key_unavailable(manager: &IdentityManager) -> bool {
    std::fs::read(manager.record_path()).ok()
        .and_then(|bytes| IdentityRecordStandard::from_bytes(&bytes).ok())
        .is_some_and(|record| najwa_identity::platform::retrieve_record_dkm(&record).map(Zeroizing::new).is_err())
}
fn uses_software_storage(manager: &IdentityManager) -> bool {
    std::fs::read(manager.record_path()).ok()
        .and_then(|bytes| IdentityRecordStandard::from_bytes(&bytes).ok())
        .and_then(|record| najwa_identity::platform::record_uses_software_storage(&record).ok())
        .unwrap_or(false)
}
fn prekey_pending(manager: &IdentityManager) -> bool {
    let Ok(bytes) = std::fs::read(manager.record_path()) else {
        return false;
    };
    let Ok(record) = IdentityRecordStandard::from_bytes(&bytes) else {
        return true;
    };
    najwa_identity::prekey_recovery::generation(
        manager.record_path().parent().unwrap(),
        &record.ik_pub,
    )
    .map(|value| value.is_some())
    .unwrap_or(true)
}
fn fingerprint(manager: &IdentityManager) -> Option<String> {
    let bytes = std::fs::read(manager.record_path()).ok()?;
    let record = IdentityRecordStandard::from_bytes(&bytes).ok()?;
    Some(record.ik_pub.iter().map(|v| format!("{v:02x}")).collect())
}
pub fn random_hex<const N: usize>() -> String {
    najwa_crypto::random::random_bytes::<N>()
        .iter()
        .map(|v| format!("{v:02x}"))
        .collect()
}
#[cfg(test)]
mod passphrase_tests {
    use super::*;
    fn secret(value: &str) -> Secret {
        Secret(Zeroizing::new(value.into()))
    }
    fn code(operation: IdentityOperation) -> &'static str {
        operation.check().err().map_or("ok", |failure| failure.code)
    }
    #[test]
    fn new_passphrases_must_resist_guessing_and_unlock_is_unchanged() {
        for weak in ["aaaaaaaaaaaa", "password1234", "qwertyuiopas"] {
            let create = IdentityOperation::Create { password: secret(weak), confirmation: secret(weak) };
            let failure = create.check().unwrap_err();
            assert_eq!(failure.code, "weak_passphrase", "{weak}");
            assert!(json!(failure)["hint"].is_string(), "{weak}: zxcvbn's warning is returned");
            let change = IdentityOperation::ChangePassword { current: secret("x"), password: secret(weak), confirmation: secret(weak) };
            assert_eq!(code(change), "weak_passphrase");
            let recover = IdentityOperation::Recover { words: secret("w"), password: secret(weak), confirmation: secret(weak) };
            assert_eq!(code(recover), "weak_passphrase");
            assert_eq!(code(IdentityOperation::Unlock { password: secret(weak) }), "ok");
        }
        // Three common words pass only with their separators counted, so they fail.
        let three = "synthetic orchard lantern";
        assert_eq!(code(IdentityOperation::Create { password: secret(three), confirmation: secret(three) }), "weak_passphrase");
        let four = "reconnect orchard river lantern";
        assert_eq!(code(IdentityOperation::Create { password: secret(four), confirmation: secret(four) }), "ok");
        assert_eq!(code(IdentityOperation::Create { password: secret("short"), confirmation: secret("short") }), "invalid_password");
    }
    #[test]
    fn declined_software_storage_reports_the_missing_approval() {
        assert_eq!(code(IdentityOperation::ApproveSoftwareStorage { confirmed: false }), "software_approval_required");
        assert_eq!(code(IdentityOperation::ApproveSoftwareStorage { confirmed: true }), "ok");
    }
}
