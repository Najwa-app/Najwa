//! High-level identity manager API.
//!
//! The `IdentityManager` facade (S02 §18 lifecycle) that ties together
//! creation, unlock, lock, password change, and deletion.

use std::path::{Path, PathBuf};
use std::time::Duration;

use najwa_crypto::prelude::constant_time_eq;
use zeroize::Zeroizing;

use crate::atomic::{atomic_write, read_record_file};
use crate::backup;
use crate::creation::{create_identity, create_identity_from_seed};
use crate::error::{IdentityError, Result};
use crate::platform;
use crate::record::*;
use crate::unlock::{
    rewrap_identity, unlock_identity_with_timing, UnlockRateLimiter, INITIAL_SUCCESSFUL_ARGON_TIME,
};

/// High-level identity manager.
///
/// Owns the identity state machine and delegates to the lower-level
/// modules for creation, unlock, password change, etc.
pub struct IdentityManager {
    state: IdentityState,
    record_path: PathBuf,
    rate_limiter: UnlockRateLimiter,
    last_successful_argon_time: Duration,
    record: Option<IdentityRecordStandard>,
    counter_file: PathBuf,
    timing_file: PathBuf,
}

/// An identity recovered through S02 §13.2, with its mandatory post-recovery
/// obligation attached.
#[derive(Debug)]
pub struct RecoveredIdentity {
    /// Public key of the recovered identity (byte-for-byte the `ik_pub` from
    /// the recovery record — S02 §13.2 step 7 verified this against `IK_priv`).
    pub ik_pub: [u8; 32],
    /// Creation timestamp of the newly-installed record — S02 §13.2 step 8 builds
    /// a new record on the recovering device, so this is fresh, not the
    /// original identity's timestamp.
    pub created_at: u64,
    /// S02 §13.2 step 9 — MUST be discharged before the recovered identity accepts
    /// inbound Initials. See [`PrekeyHygieneRequired`].
    pub prekey_hygiene: PrekeyHygieneRequired,
}

/// S02 §13.2 step 9 — post-recovery prekey hygiene, not yet discharged.
///
/// Normative text: "ANY restore or recovery path MUST generate a fresh SPK and
/// a brand-new OPK pool with new ids (never re-uploading or reactivating
/// pre-restore key ids) and upload new bundles (with fresh signed manifests,
/// S06 §5.8) to all mailboxes before accepting inbound Initials ... X3DH
/// Initials referencing pre-restore SPK/OPK ids MUST fail."
///
/// The obligation is split across layers, and this marker is how the identity
/// layer hands it on without letting it be silently dropped:
///
/// - **Mint + sign + upload** the fresh SPK/OPK pool: the S06 §5.8 prekey
///   manager (`najwa-protocol::prekey`), driven by the messaging service.
/// - **Reject Initials referencing pre-restore SPK/OPK ids**: the session
///   establishment path in `najwa-core`.
///
/// There is deliberately no "discharged" flag here: the discharge is the real
/// rotation running through the prekey manager, not a boolean someone sets.
/// Until that rotation has run, a caller MUST treat the recovered identity as
/// unable to accept inbound Initials.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrekeyHygieneRequired {
    /// Private field: the type is only constructed by the recovery flow.
    _incomplete: (),
}

impl IdentityManager {
    /// Create a new manager pointed at `record_path`.
    ///
    /// Loads the record from disk if it exists.
    pub fn new(record_path: PathBuf) -> Result<Self> {
        let record = read_record_file(&record_path)?
            .map(|data| IdentityRecordStandard::from_bytes(&data))
            .transpose()?;
        let state = record
            .clone()
            .map(IdentityState::Locked)
            .unwrap_or(IdentityState::None);
        let (counter_file, timing_file) = match record.as_ref() {
            Some(record) if platform::has_record_dkm(record) => {
                metadata_paths(&record_path, record)
            }
            _ => (counter_path(&record_path), argon_timing_path(&record_path)),
        };
        let (rate_limiter, last_successful_argon_time) = match record.as_ref() {
            Some(record) => {
                let dkm =
                    Zeroizing::new(platform::retrieve_record_dkm(record).unwrap_or([0u8; 32]));
                (
                    read_counter(&counter_file, &dkm),
                    read_argon_timing(&timing_file, &dkm),
                )
            }
            None => (UnlockRateLimiter::new(), INITIAL_SUCCESSFUL_ARGON_TIME),
        };

        Ok(Self {
            state,
            record_path,
            rate_limiter,
            last_successful_argon_time,
            record,
            counter_file,
            timing_file,
        })
    }

    /// Persist the current attempt counter to its sidecar file (S02 §10.1).
    /// Failure denies password verification; it cannot silently reset attempt state.
    fn persist_counter(&self) -> Result<()> {
        let record = self.record.as_ref().ok_or(IdentityError::NotFound)?;
        let dkm = Zeroizing::new(platform::retrieve_record_dkm(record)?);
        write_counter(&self.counter_file, &self.rate_limiter, &dkm)
    }

    /// Persist the successful Argon2 reference time used by S02 §9.1 padding.
    fn persist_argon_timing(&self) {
        if let Some(record) = self.record.as_ref() {
            if let Ok(dkm) = platform::retrieve_record_dkm(record).map(Zeroizing::new) {
                write_argon_timing(&self.timing_file, self.last_successful_argon_time, &dkm);
            }
        }
    }

    /// Check if an identity record exists on disk.
    pub fn exists(&self) -> bool {
        !matches!(self.state, IdentityState::None)
    }

    /// Check if the identity is currently unlocked.
    pub fn is_unlocked(&self) -> bool {
        matches!(self.state, IdentityState::Unlocked(_))
    }

    /// Create a new identity protected by `password`.
    ///
    /// Writes the encrypted record to disk and transitions to `Unlocked`.
    pub fn create(&mut self, password: &str) -> Result<()> {
        crate::password::validate_new_passphrase(password)?;
        if self.exists() {
            return Err(IdentityError::AlreadyExists);
        }

        let (record, identity) = create_identity(password, None)?;

        self.install(record, identity, None, INITIAL_SUCCESSFUL_ARGON_TIME)
    }

    /// Create a new identity **and** its recovery record (S02 §13.1–§13.2).
    ///
    /// `create()` plus a recovery record persisted to the `<record>.recovery`
    /// sidecar and the one-time BIP-39 phrase returned for display. The phrase
    /// is the only representation of `recovery_seed` — it is never stored.
    ///
    /// Plain [`Self::create`] remains available for flows that provision
    /// recovery separately; S02 §13.2 recovery requires this sidecar to exist.
    pub fn create_with_recovery_record(
        &mut self,
        password: &str,
        phrase_length: u8,
    ) -> Result<String> {
        crate::password::validate_new_passphrase(password)?;
        if self.exists() {
            return Err(IdentityError::AlreadyExists);
        }
        if !matches!(phrase_length, 12 | 24) {
            return Err(
                backup::BackupError::Backup("phrase_length must be 12 or 24".into()).into(),
            );
        }
        let (record, identity) = create_identity(password, None)?;
        let (mnemonic, recovery) = match backup::create_recovery_record(&identity, phrase_length) {
            Ok(result) => result,
            Err(error) => {
                let _ = platform::delete_record_dkm(&record);
                return Err(error.into());
            }
        };
        let mnemonic = Zeroizing::new(mnemonic);
        self.install(
            record,
            identity,
            Some(&recovery),
            INITIAL_SUCCESSFUL_ARGON_TIME,
        )?;
        Ok(mnemonic.to_string())
    }

    /// Path of the recovery-record sidecar (`<record>.recovery`).
    fn recovery_record_path(&self) -> PathBuf {
        self.record_path.with_extension("recovery")
    }

    /// Load the persisted recovery record (S02 §13.2 step 4).
    pub fn load_recovery_record(&self) -> Result<backup::RecoveryRecord> {
        let path = self.recovery_record_path();
        let data = std::fs::read(&path).map_err(|_| IdentityError::RecoveryRecordMissing)?;
        backup::RecoveryRecord::from_bytes(&data).map_err(IdentityError::from)
    }

    /// Recover the identity from its mnemonic (S02 §13.2).
    ///
    /// Loads the persisted recovery record, decrypts `IK_priv` byte-for-byte
    /// (failing loudly on a wrong phrase, wrong length, or tampered record —
    /// never regenerating `IK_priv` from the mnemonic), and installs a NEW
    /// standard-mode record under `new_password` — new DKM, new password, per
    /// S02 §13.2 step 8. Step 9 writes the prekey-recovery marker before the
    /// commit.
    ///
    /// The fresh prekeys that the marker demands are returned as a typed
    /// obligation ([`PrekeyHygieneRequired`]) rather than produced here: minting + uploading the fresh SPK/OPK pool
    /// needs the S06 prekey manager and the mailbox client, which live above
    /// this crate.
    pub fn recover_from_recovery_record_at(
        &mut self,
        mnemonic: &str,
        new_password: &str,
    ) -> Result<RecoveredIdentity> {
        crate::password::validate_new_passphrase(new_password)?;
        let record = self.load_recovery_record()?;
        let (new_record, identity) =
            backup::recover_from_recovery_record(mnemonic, &record, new_password)
                .map_err(IdentityError::from)?;
        let recovered = RecoveredIdentity {
            ik_pub: identity.keypair.public().to_bytes(),
            created_at: identity.created_at,
            prekey_hygiene: PrekeyHygieneRequired { _incomplete: () },
        };
        self.install_recovered(new_record, identity)?;
        Ok(recovered)
    }

    /// Unlock an existing identity with `password`.
    ///
    /// Enforces rate limiting before attempting decryption.
    pub fn unlock(&mut self, password: &str) -> Result<()> {
        let record = match &self.state {
            IdentityState::Locked(r) => r.clone(),
            IdentityState::Unlocked(_) => return Ok(()), // already unlocked
            IdentityState::None => return Err(IdentityError::NotFound),
        };

        match self.authenticate(&record, password) {
            Ok((identity, argon2_duration)) => {
                self.last_successful_argon_time = argon2_duration;
                self.persist_argon_timing();
                self.state = IdentityState::Unlocked(Box::new(identity));
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    /// Re-read the stored counter so its delay and 24-hour expiry are evaluated
    /// at this attempt, not only at open or lock (S02 §10.1). A device factor that
    /// was unreadable at open (locked keyring) is used once it can be read.
    fn reload_counter(&mut self) {
        let Some(record) = self.record.as_ref() else {
            return;
        };
        // Opened while the factor was unreadable: switch to the generation's files.
        if self.counter_file == counter_path(&self.record_path) && platform::has_record_dkm(record)
        {
            (self.counter_file, self.timing_file) = metadata_paths(&self.record_path, record);
        }
        let dkm = Zeroizing::new(platform::retrieve_record_dkm(record).unwrap_or([0u8; 32]));
        self.rate_limiter = read_counter(&self.counter_file, &dkm);
    }

    // Reserve and durably count the attempt BEFORE testing the password. If
    // persistence fails, no password oracle is exposed, even across restarts.
    fn authenticate(
        &mut self,
        record: &IdentityRecordStandard,
        password: &str,
    ) -> Result<(Identity, Duration)> {
        self.reload_counter();
        self.rate_limiter.check()?;
        self.rate_limiter.record_failure();
        self.persist_counter()?;
        let result =
            match unlock_identity_with_timing(record, password, self.last_successful_argon_time) {
                Ok(result) => result,
                Err(error) => {
                    // The KDF itself must not consume the delay after a failed guess.
                    self.rate_limiter.finish_failure();
                    self.persist_counter()?;
                    return Err(error);
                }
            };
        self.rate_limiter.record_success();
        self.persist_counter()?;
        Ok(result)
    }

    /// One-shot rate-limited unlock for production clients (S02 §10).
    ///
    /// Loads the persistent attempt counter, enforces the lockout/backoff,
    /// runs the 2-of-2 unwrap, persists the updated counter, and returns the
    /// recovered identity. Production unlock paths (FFI `najwa_unlock`, CLI
    /// commands) MUST use this instead of the bare `unlock::unlock_identity`
    /// so the S02 §10 lockout binds — including across process restarts.
    pub fn unlock_once(record_path: &Path, password: &str) -> Result<Identity> {
        let mut manager = Self::new(record_path.to_path_buf())?;
        manager.unlock(password)?;
        match manager.state {
            IdentityState::Unlocked(identity) => Ok(*identity),
            // Unreachable: a successful `unlock` guarantees the Unlocked state.
            _ => Err(IdentityError::InternalError(
                "unlock succeeded but state is not Unlocked".into(),
            )),
        }
    }

    /// Lock the identity (zeroize keys in memory).
    ///
    /// Transitions from `Unlocked` back to `Locked`.
    pub fn lock(&mut self) {
        if let IdentityState::Unlocked(_) = &self.state {
            // Destroy the unlocked key before any disk or keychain I/O can block.
            self.state = IdentityState::None;
            // A different manager may have committed a new generation. Reload
            // its record AND authenticated sidecars together before unlocking.
            if let Ok(reloaded) = Self::new(self.record_path.clone()) {
                *self = reloaded;
            } else {
                self.state = IdentityState::None;
                self.record = None;
            }
        }
    }

    /// Get the unlocked identity (if available).
    pub fn identity(&self) -> Option<&Identity> {
        match &self.state {
            IdentityState::Unlocked(id) => Some(id.as_ref()),
            _ => None,
        }
    }

    /// Change the password protecting the identity.
    ///
    /// Requires the identity to be in `Locked` or `Unlocked` state.
    pub fn change_password(&mut self, old_password: &str, new_password: &str) -> Result<()> {
        // Before authenticating: a refused new passphrase costs no attempt.
        crate::password::validate_new_passphrase(new_password)?;
        let record = match &self.state {
            IdentityState::Locked(r) => r.clone(),
            IdentityState::Unlocked(_) => {
                // Re-read current record from disk
                let data = read_record_file(&self.record_path)?.ok_or(IdentityError::NotFound)?;
                IdentityRecordStandard::from_bytes(&data)?
            }
            IdentityState::None => return Err(IdentityError::NotFound),
        };

        let (identity, argon2_duration) = self.authenticate(&record, old_password)?;
        let new_record = rewrap_identity(&record, &identity, new_password, None)?;
        self.install(new_record, identity, None, argon2_duration)
    }

    /// Recover identity from a 32-byte seed and protect with `password`.
    pub fn recover_from_seed(&mut self, seed: &[u8; 32], password: &str) -> Result<()> {
        crate::password::validate_new_passphrase(password)?;
        let (record, identity) = create_identity_from_seed(seed, password, None)?;
        self.install_recovered(record, identity)
    }

    fn install_recovered(&mut self, record: IdentityRecordStandard, identity: Identity) -> Result<()> {
        let directory = self.record_path.parent().filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        if let Err(error) = crate::prekey_recovery::require(directory, &identity.keypair.public().to_bytes()) {
            let _ = platform::delete_record_dkm(&record);
            return Err(error);
        }
        self.install(record, identity, None, INITIAL_SUCCESSFUL_ARGON_TIME)
    }

    /// The main record's rename is the commit point. Credential and counter
    /// generations are independent, so interruption before it preserves the old
    /// identity; interruption after it leaves all required new state available.
    fn install(
        &mut self,
        record: IdentityRecordStandard,
        identity: Identity,
        recovery: Option<&backup::RecoveryRecord>,
        timing: Duration,
    ) -> Result<()> {
        let (counter_file, timing_file) = metadata_paths(&self.record_path, &record);
        let result = (|| {
            let dkm = Zeroizing::new(platform::retrieve_record_dkm(&record)?);
            write_counter(&counter_file, &UnlockRateLimiter::new(), &dkm)?;
            write_argon_timing(&timing_file, timing, &dkm);
            let recovery_path = self.recovery_record_path();
            let previous_recovery = if recovery.is_some() {
                read_record_file(&recovery_path)?
            } else {
                None
            };
            if let Some(recovery) = recovery {
                atomic_write(&recovery_path, &recovery.to_bytes())?;
            }
            if let Err(error) = atomic_write(&self.record_path, &record.to_bytes()) {
                if recovery.is_some() {
                    let rollback = match previous_recovery {
                        Some(bytes) => atomic_write(&recovery_path, &bytes),
                        None => remove_if_present(&recovery_path),
                    };
                    if let Err(rollback) = rollback {
                        return Err(IdentityError::AtomicWriteFailed(format!(
                            "{error}; recovery rollback: {rollback}"
                        )));
                    }
                }
                return Err(error);
            }
            Ok(())
        })();
        if result.is_err() {
            // A durable replace can fail after the new record is in place. Keep
            // its generation then, as well as the old one: a power cut may leave
            // either record (S02 §12.3 step 4).
            let visible = read_record_file(&self.record_path)
                .is_ok_and(|bytes| bytes.as_deref() == Some(&record.to_bytes()[..]));
            if !visible {
                let _ = platform::delete_record_dkm(&record);
                let _ = remove_if_present(&counter_file);
                let _ = remove_if_present(&timing_file);
            }
            return result;
        }

        // `atomic_write` returned only once the new record was durable, so the
        // old generation is no longer needed.
        if let Some(old) = self.record.as_ref() {
            let cleanup = if platform::has_record_dkm(old) {
                platform::delete_record_dkm(old)
            } else {
                // Retire only the legacy slot; the just-published scoped key
                // must remain available. Full account deletion erases all slots.
                platform::delete_legacy_dkm()
            };
            if let Err(error) = cleanup {
                tracing::warn!(%error, "new identity committed; old credential cleanup failed");
            }
            let _ = remove_if_present(&self.counter_file);
            let _ = remove_if_present(&self.timing_file);
        }
        self.record = Some(record);
        self.counter_file = counter_file;
        self.timing_file = timing_file;
        self.rate_limiter = UnlockRateLimiter::new();
        self.last_successful_argon_time = timing;
        self.state = IdentityState::Unlocked(Box::new(identity));
        Ok(())
    }

    /// Delete the identity (destructive!).
    ///
    /// Removes the record file and DKM from platform storage.
    pub fn delete(&mut self) -> Result<()> {
        // Clear in-memory key material even if disk/keychain cleanup fails.
        self.state = self
            .record
            .clone()
            .map(IdentityState::Locked)
            .unwrap_or(IdentityState::None);
        // Remove the independently recoverable key before deleting the main record.
        // On failure retain the main record and report the error, allowing a retry.
        remove_if_present(&self.recovery_record_path())?;
        platform::delete_dkm()?;
        remove_if_present(&self.record_path)?;

        // Remove temp file if it exists
        let temp = self.record_path.with_extension("tmp");
        if temp.exists() {
            let _ = std::fs::remove_file(&temp);
        }

        // Remove the persisted attempt counter for the deleted identity.
        remove_if_present(&self.counter_file)?;
        remove_if_present(&self.timing_file)?;

        self.state = IdentityState::None;
        self.record = None;
        self.rate_limiter.record_success(); // reset limiter
        Ok(())
    }

    /// Get the path to the identity record file.
    pub fn record_path(&self) -> &PathBuf {
        &self.record_path
    }

    /// Get the current rate limiter state.
    pub fn rate_limiter(&self) -> &UnlockRateLimiter {
        &self.rate_limiter
    }
}

fn remove_if_present(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

fn metadata_paths(path: &Path, record: &IdentityRecordStandard) -> (PathBuf, PathBuf) {
    let generation = platform::record_key_id(record);
    (
        path.with_extension(format!("counter.{generation}")),
        path.with_extension(format!("timing.{generation}")),
    )
}

impl std::fmt::Debug for IdentityManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityManager")
            .field("state", &self.state)
            .field("record_path", &self.record_path)
            .field(
                "last_successful_argon_time",
                &self.last_successful_argon_time,
            )
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Persistent unlock-attempt counter (S02 §10.1 / §10.2)
// ---------------------------------------------------------------------------
//
// The counter is stored in a sidecar file next to the identity record and
// HMAC-tagged with the device key material (DKM) so it is tamper-evident and
// fail-secure. Persisting it defeats the "restart between guesses" bypass:
// backoff and the 10-failure lockout now survive process restart. DKM is
// injected (not read from `platform` here) so the file logic is unit-testable
// and cannot race the platform keychain in parallel tests.

/// Serialized size: `attempts(4) || timestamp(8) || tag(32)`.
const COUNTER_FILE_LEN: usize = 44;

/// Sidecar path holding the persisted attempt counter.
fn counter_path(record_path: &Path) -> PathBuf {
    record_path.with_extension("counter")
}

/// Load attempt state for an existing identity. Missing, malformed, unreadable,
/// or unauthenticated state is a lockout; only identity creation starts fresh.
fn read_counter(record_path: &Path, dkm: &[u8; 32]) -> UnlockRateLimiter {
    match std::fs::read(record_path) {
        Ok(buf) if buf.len() == COUNTER_FILE_LEN => {
            let attempts = u32::from_be_bytes(buf[0..4].try_into().unwrap());
            let timestamp = u64::from_be_bytes(buf[4..12].try_into().unwrap());
            let mut tag = [0u8; 32];
            tag.copy_from_slice(&buf[12..44]);
            UnlockRateLimiter::from_persisted(attempts, timestamp, &tag, dkm)
        }
        _ => UnlockRateLimiter::locked_out(),
    }
}

/// Atomically persist the current counter, HMAC-tagged with `dkm`.
fn write_counter(record_path: &Path, limiter: &UnlockRateLimiter, dkm: &[u8; 32]) -> Result<()> {
    let (attempts, timestamp, tag) = limiter.to_persisted(dkm);
    let mut buf = Vec::with_capacity(COUNTER_FILE_LEN);
    buf.extend_from_slice(&attempts.to_be_bytes());
    buf.extend_from_slice(&timestamp.to_be_bytes());
    buf.extend_from_slice(&tag);
    atomic_write(record_path, &buf)
}

// ---------------------------------------------------------------------------
// Persistent successful-Argon2 timing (S02 §9.1)
// ---------------------------------------------------------------------------

const ARGON_TIMING_HMAC_DOMAIN: &[u8] = b"last-successful-argon-time";
/// Serialized size: `duration_ns(8) || tag(32)`.
const ARGON_TIMING_FILE_LEN: usize = 40;

fn argon_timing_path(record_path: &Path) -> PathBuf {
    record_path.with_extension("timing")
}

fn compute_argon_timing_tag(dkm: &[u8; 32], duration_ns: u64) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(dkm).expect("HMAC key can be any size");
    mac.update(ARGON_TIMING_HMAC_DOMAIN);
    mac.update(&duration_ns.to_be_bytes());
    let mut tag = [0u8; 32];
    tag.copy_from_slice(&mac.finalize().into_bytes());
    tag
}

/// Missing or unauthenticated timing state uses the conservative creation seed,
/// preventing a first-unlock or sidecar-deletion timing downgrade.
fn read_argon_timing(record_path: &Path, dkm: &[u8; 32]) -> Duration {
    match std::fs::read(record_path) {
        Ok(buf) if buf.len() == ARGON_TIMING_FILE_LEN => {
            let duration_ns = u64::from_be_bytes(buf[0..8].try_into().unwrap());
            let expected = compute_argon_timing_tag(dkm, duration_ns);
            if constant_time_eq(&buf[8..40], &expected) {
                Duration::from_nanos(duration_ns)
            } else {
                INITIAL_SUCCESSFUL_ARGON_TIME
            }
        }
        _ => INITIAL_SUCCESSFUL_ARGON_TIME,
    }
}

fn write_argon_timing(record_path: &Path, duration: Duration, dkm: &[u8; 32]) {
    let duration_ns = u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX);
    let tag = compute_argon_timing_tag(dkm, duration_ns);
    let mut buf = Vec::with_capacity(ARGON_TIMING_FILE_LEN);
    buf.extend_from_slice(&duration_ns.to_be_bytes());
    buf.extend_from_slice(&tag);
    // A missing sidecar reloads the conservative 1000ms seed, so persistence
    // failure cannot bypass padding on the next process start.
    let _ = atomic_write(record_path, &buf);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_obligation_survives_record_install_and_reopen() {
        platform::set_dkm_storage_for_test(platform::MockDkmStorage::new());
        let dir=tempfile::tempdir().unwrap();
        let path=dir.path().join("identity.najwa");
        let mut manager=IdentityManager::new(path.clone()).unwrap();
        let (record,identity)=candidate(73);
        let public=identity.keypair.public().to_bytes();
        manager.install_recovered(record,identity).unwrap();
        let first=crate::prekey_recovery::generation(dir.path(),&public).unwrap().unwrap();
        drop(manager);
        let mut manager=IdentityManager::new(path).unwrap();
        assert_eq!(crate::prekey_recovery::generation(dir.path(),&public).unwrap(),Some(first));
        let (record,identity)=candidate(73);
        manager.install_recovered(record,identity).unwrap();
        assert_ne!(crate::prekey_recovery::generation(dir.path(),&public).unwrap(),Some(first));
    }

    fn fixture() -> (tempfile::TempDir, IdentityManager) {
        platform::set_dkm_storage_for_test(platform::MockDkmStorage::new());
        let dir = tempfile::tempdir().unwrap();
        let mut manager = IdentityManager::new(dir.path().join("identity.najwa")).unwrap();
        let (record, identity) = candidate(31);
        manager
            .install(record, identity, None, INITIAL_SUCCESSFUL_ARGON_TIME)
            .unwrap();
        manager.lock();
        (dir, manager)
    }

    fn candidate(seed: u8) -> (IdentityRecordStandard, Identity) {
        create_identity_from_seed(
            &[seed; 32],
            "original password",
            Some(najwa_crypto::kdf::Argon2Params::ABSOLUTE_MIN),
        )
        .unwrap()
    }

    #[test]
    fn failed_derivation_and_abandoned_replacement_preserve_current_dkm() {
        let (_dir, manager) = fixture();
        let old = manager.record.as_ref().unwrap();
        let old_dkm = platform::retrieve_record_dkm(old).unwrap();
        let invalid = najwa_crypto::kdf::Argon2Params {
            memory_kib: 1,
            ..najwa_crypto::kdf::Argon2Params::ABSOLUTE_MIN
        };
        assert!(create_identity_from_seed(&[32; 32], "harbor violet canyon thimble", Some(invalid)).is_err());
        let (uncommitted, _) = candidate(32);
        assert_ne!(
            platform::retrieve_record_dkm(&uncommitted).unwrap(),
            old_dkm
        );
        assert_eq!(platform::retrieve_record_dkm(old).unwrap(), old_dkm);
        assert!(IdentityManager::unlock_once(&manager.record_path, "original password").is_ok());
    }

    #[test]
    fn failed_recovery_write_preserves_previous_identity_and_cleans_candidate() {
        let (_dir, mut manager) = fixture();
        let old = manager.record.clone().unwrap();
        let bytes = std::fs::read(&manager.record_path).unwrap();
        // Deterministic real rename failure, without modifying the old credential.
        std::fs::remove_file(&manager.record_path).unwrap();
        std::fs::create_dir(&manager.record_path).unwrap();
        let (replacement, identity) = candidate(32);
        let (counter, timing) = metadata_paths(&manager.record_path, &replacement);
        assert!(manager
            .install(
                replacement.clone(),
                identity,
                None,
                INITIAL_SUCCESSFUL_ARGON_TIME
            )
            .is_err());
        assert!(!platform::has_record_dkm(&replacement));
        assert!(!counter.exists());
        assert!(!timing.exists());
        assert!(platform::has_record_dkm(&old));
        std::fs::remove_dir(&manager.record_path).unwrap();
        std::fs::write(&manager.record_path, bytes).unwrap();
        assert!(IdentityManager::unlock_once(&manager.record_path, "original password").is_ok());
    }

    #[test]
    fn failed_generation_counter_write_leaves_live_record_byte_identical() {
        let (_dir, mut manager) = fixture();
        let before = std::fs::read(&manager.record_path).unwrap();
        let (record, identity) = candidate(32);
        let (counter, _) = metadata_paths(&manager.record_path, &record);
        std::fs::create_dir(&counter).unwrap();
        assert!(manager
            .install(
                record.clone(),
                identity,
                None,
                INITIAL_SUCCESSFUL_ARGON_TIME
            )
            .is_err());
        assert_eq!(std::fs::read(&manager.record_path).unwrap(), before);
        assert!(!platform::has_record_dkm(&record));
        assert!(IdentityManager::unlock_once(&manager.record_path, "original password").is_ok());
    }

    #[test]
    fn counter_loss_corruption_and_read_errors_cannot_reset_lockout() {
        let (_dir, manager) = fixture();
        for bytes in [vec![], vec![0], vec![0; 43], vec![0; 44], vec![0; 45]] {
            std::fs::write(&manager.counter_file, bytes).unwrap();
            let mut reopened = IdentityManager::new(manager.record_path.clone()).unwrap();
            assert!(matches!(
                reopened.unlock("original password"),
                Err(IdentityError::LockedOut(10))
            ));
        }
        std::fs::remove_file(&manager.counter_file).unwrap();
        assert!(IdentityManager::new(manager.record_path.clone())
            .unwrap()
            .rate_limiter()
            .is_locked());
        std::fs::create_dir(&manager.counter_file).unwrap();
        assert!(IdentityManager::new(manager.record_path.clone())
            .unwrap()
            .rate_limiter()
            .is_locked());
    }

    #[test]
    fn counter_write_failure_denies_unlock_and_password_change() {
        let (_dir, mut manager) = fixture();
        let before = std::fs::read(&manager.record_path).unwrap();
        // The counter stays readable (each attempt re-reads it); only its write fails.
        crate::atomic::fail_durable_replace_for_test(Some(manager.counter_file.clone()));
        assert!(matches!(
            manager.unlock("original password"),
            Err(IdentityError::AtomicWriteFailed(_))
        ));
        assert!(!manager.is_unlocked());
        crate::atomic::fail_durable_replace_for_test(None);
        manager.rate_limiter = UnlockRateLimiter::new();
        manager.persist_counter().unwrap();
        crate::atomic::fail_durable_replace_for_test(Some(manager.counter_file.clone()));
        assert!(matches!(
            manager.change_password("original password", "harbor violet canyon thimble"),
            Err(IdentityError::AtomicWriteFailed(_))
        ));
        assert_eq!(std::fs::read(&manager.record_path).unwrap(), before);
    }

    #[test]
    fn password_changes_share_backoff_lockout_and_persistent_attempts() {
        let (_dir, mut manager) = fixture();
        assert!(matches!(
            manager.change_password("wrong password", "harbor violet canyon thimble"),
            Err(IdentityError::UnlockFailed)
        ));
        assert_eq!(manager.rate_limiter().attempts(), 1);
        let mut reopened = IdentityManager::new(manager.record_path.clone()).unwrap();
        assert_eq!(reopened.rate_limiter().attempts(), 1);
        assert!(matches!(
            reopened.change_password("original password", "harbor violet canyon thimble"),
            Err(IdentityError::RateLimited { .. })
        ));
        reopened.rate_limiter = UnlockRateLimiter::locked_out();
        reopened.persist_counter().unwrap();
        let mut reopened = IdentityManager::new(manager.record_path.clone()).unwrap();
        assert!(matches!(
            reopened.change_password("original password", "harbor violet canyon thimble"),
            Err(IdentityError::LockedOut(10))
        ));
        assert!(!reopened.is_unlocked());
    }

    #[test]
    fn password_change_commits_new_generation_and_retires_old_key() {
        let (_dir, mut manager) = fixture();
        let old = manager.record.clone().unwrap();
        let old_counter = manager.counter_file.clone();
        manager
            .change_password("original password", "harbor violet canyon thimble")
            .unwrap();
        assert!(manager.is_unlocked());
        assert_eq!(manager.rate_limiter().attempts(), 0);
        assert!(!platform::has_record_dkm(&old));
        assert!(!old_counter.exists());
        assert!(IdentityManager::unlock_once(&manager.record_path, "harbor violet canyon thimble").is_ok());
        assert!(IdentityManager::unlock_once(&manager.record_path, "original password").is_err());
    }

    // S02 §12.3: the old device key is deleted only once the new record is
    // durable. A replace that fails after the new record appeared keeps both keys.
    #[test]
    fn failed_durable_replace_keeps_old_and_new_generation() {
        let (_dir, mut manager) = fixture();
        let old = manager.record.clone().unwrap();
        crate::atomic::fail_durable_replace_for_test(Some(manager.record_path.clone()));
        assert!(matches!(
            manager.change_password("original password", "harbor violet canyon thimble"),
            Err(IdentityError::AtomicWriteFailed(_))
        ));
        crate::atomic::fail_durable_replace_for_test(None);
        assert!(platform::has_record_dkm(&old));
        assert!(IdentityManager::unlock_once(&manager.record_path, "harbor violet canyon thimble").is_ok());
        // A power cut that undoes the replace leaves the old record, still usable.
        std::fs::write(&manager.record_path, old.to_bytes()).unwrap();
        assert!(IdentityManager::unlock_once(&manager.record_path, "original password").is_ok());
    }

    // S02 §10.1: the stored counter is evaluated at each attempt. Neither an
    // expired lockout nor a keyring unlocked after open needs an app restart.
    #[test]
    fn stored_counter_is_evaluated_at_each_attempt() {
        let (_dir, manager) = fixture();
        let record = manager.record.clone().unwrap();
        let dkm = platform::retrieve_record_dkm(&record).unwrap();
        write_counter(&manager.counter_file, &UnlockRateLimiter::locked_out(), &dkm).unwrap();
        // The app opens the profile while the keyring is still locked.
        platform::delete_record_dkm(&record).unwrap();
        let mut open = IdentityManager::new(manager.record_path.clone()).unwrap();
        platform::store_record_dkm(&record, &dkm).unwrap();
        assert!(matches!(
            open.unlock("original password"),
            Err(IdentityError::LockedOut(10))
        ));
        // 24 hours pass with the app open. (A bad tag loads as a lockout that keeps
        // the stored time, so persisting it gives a valid day-old lockout.)
        let day_old = UnlockRateLimiter::from_persisted(
            10,
            najwa_crypto::time::now() - 86_401,
            &[0; 32],
            &dkm,
        );
        write_counter(&manager.counter_file, &day_old, &dkm).unwrap();
        open.unlock("original password").unwrap();
    }

    #[test]
    fn locking_reloads_attempt_state_after_another_manager_changes_password() {
        let (_dir, mut first) = fixture();
        first.unlock("original password").unwrap();
        let mut second = IdentityManager::new(first.record_path.clone()).unwrap();
        second
            .change_password("original password", "harbor violet canyon thimble")
            .unwrap();
        first.lock();
        assert!(matches!(
            first.unlock("wrong password"),
            Err(IdentityError::UnlockFailed)
        ));
        let reopened = IdentityManager::new(first.record_path.clone()).unwrap();
        assert_eq!(reopened.rate_limiter().attempts(), 1);
    }

    #[test]
    fn failed_recovery_provisioning_leaves_no_identity_and_allows_retry() {
        let dir = tempfile::tempdir().unwrap();
        let mut manager = IdentityManager::new(dir.path().join("identity.najwa")).unwrap();
        assert!(manager.create_with_recovery_record("maple quartz ferry lantern", 13).is_err());
        assert!(!manager.exists());
        assert!(!manager.record_path.exists());
        std::fs::create_dir(manager.recovery_record_path()).unwrap();
        assert!(manager.create_with_recovery_record("maple quartz ferry lantern", 12).is_err());
        assert!(!manager.exists());
        assert!(!manager.record_path.exists());
        std::fs::remove_dir(manager.recovery_record_path()).unwrap();
        let mnemonic = manager.create_with_recovery_record("maple quartz ferry lantern", 12).unwrap();
        assert_eq!(mnemonic.split_whitespace().count(), 12);
        assert!(manager.load_recovery_record().is_ok());
        assert!(IdentityManager::unlock_once(&manager.record_path, "maple quartz ferry lantern").is_ok());
    }

    #[test]
    fn failed_main_commit_rolls_back_recovery_sidecar() {
        let dir = tempfile::tempdir().unwrap();
        let mut manager = IdentityManager::new(dir.path().join("identity.najwa")).unwrap();
        std::fs::create_dir(&manager.record_path).unwrap();
        for prior in [None, Some(b"previous recovery record".as_slice())] {
            if let Some(bytes) = prior {
                std::fs::write(manager.recovery_record_path(), bytes).unwrap();
            }
            let (record, identity) = candidate(32);
            let (_, recovery) = backup::create_recovery_record(&identity, 12).unwrap();
            assert!(manager
                .install(
                    record.clone(),
                    identity,
                    Some(&recovery),
                    INITIAL_SUCCESSFUL_ARGON_TIME
                )
                .is_err());
            assert!(!manager.exists());
            assert!(!platform::has_record_dkm(&record));
            assert_eq!(
                read_record_file(&manager.recovery_record_path())
                    .unwrap()
                    .as_deref(),
                prior
            );
        }
    }

    #[test]
    fn delete_removes_recovery_key_and_generation_state() {
        let (_dir, mut manager) = fixture();
        manager.unlock("original password").unwrap();
        let (_, recovery) =
            backup::create_recovery_record(manager.identity().unwrap(), 12).unwrap();
        atomic_write(&manager.recovery_record_path(), &recovery.to_bytes()).unwrap();
        let record = manager.record.clone().unwrap();
        let (abandoned, _) = candidate(99);
        manager.delete().unwrap();
        for path in [
            &manager.record_path,
            &manager.recovery_record_path(),
            &manager.counter_file,
            &manager.timing_file,
        ] {
            assert!(!path.exists());
        }
        assert!(!manager.exists());
        assert!(!manager.is_unlocked());
        assert!(!platform::has_record_dkm(&record));
        assert!(!platform::has_record_dkm(&abandoned));
        assert!(manager.load_recovery_record().is_err());
        manager.delete().unwrap();
    }

    #[test]
    fn recovery_deletion_errors_are_reported_without_losing_main_record() {
        let (_dir, mut manager) = fixture();
        manager.unlock("original password").unwrap();
        std::fs::create_dir(manager.recovery_record_path()).unwrap();
        assert!(manager.delete().is_err());
        assert!(!manager.is_unlocked());
        assert!(manager.record_path.is_file());
        std::fs::remove_dir(manager.recovery_record_path()).unwrap();
        manager.delete().unwrap();
        assert!(!manager.record_path.exists());
    }

    #[test]
    #[cfg(not(any(
        all(target_os = "windows", feature = "windows-tpm"),
        all(target_os = "linux", feature = "linux-tpm"),
        all(target_os = "macos", feature = "macos-secure-enclave")
    )))]
    fn legacy_singleton_record_can_unlock_and_migrate_on_password_change() {
        let (_dir, manager) = fixture();
        let record = manager.record.as_ref().unwrap();
        let dkm = platform::retrieve_record_dkm(record).unwrap();
        platform::store_dkm(&dkm).unwrap();
        platform::delete_record_dkm(record).unwrap();
        write_counter(
            &counter_path(&manager.record_path),
            &UnlockRateLimiter::new(),
            &dkm,
        )
        .unwrap();
        let mut reopened = IdentityManager::new(manager.record_path.clone()).unwrap();
        reopened.unlock("original password").unwrap();
        reopened
            .change_password("original password", "harbor violet canyon thimble")
            .unwrap();
        assert!(platform::retrieve_dkm().is_err());
        assert!(IdentityManager::unlock_once(&manager.record_path, "harbor violet canyon thimble").is_ok());
    }

    // S02 §13.2 end-to-end at the crate layer: create with a recovery record,
    // lose the identity record, recover from the phrase, and observe the
    // typed S02 §13.2 step-9 obligation.
    #[test]
    fn recovery_record_roundtrip_end_to_end() {
        // Full unlock needs a DKM backend; the in-memory mock makes the flow
        // deterministic on every gate (Docker has no Secret Service).
        crate::platform::set_dkm_storage_for_test(crate::platform::MockDkmStorage::with_key(
            [0x42u8; 32],
        ));

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.najwa");

        let mut creator = IdentityManager::new(path.clone()).unwrap();
        let mnemonic = creator
            .create_with_recovery_record("correct horse battery staple", 24)
            .unwrap();
        assert_eq!(mnemonic.split_whitespace().count(), 24);
        assert!(path.with_extension("recovery").exists());
        let original_pub = creator.identity().unwrap().keypair.public().to_bytes();
        drop(creator);

        // New device: the main record is gone; only the recovery sidecar and
        // the phrase remain (S02 §13.2 steps 1–4).
        std::fs::remove_file(&path).unwrap();
        let mut recoverer = IdentityManager::new(path.clone()).unwrap();
        let recovered = recoverer
            .recover_from_recovery_record_at(&mnemonic, "copper meadow lantern drift")
            .unwrap();

        // Byte-for-byte identity (S02 §13.2 step 7). `created_at` is intentionally
        // fresh: step 8 builds a NEW record on a new device.
        assert_eq!(recovered.ik_pub, original_pub);
        assert!(recoverer.is_unlocked());
        assert!(path.exists());

        // S02 §13.2 step 9: the obligation is attached and un-discharged.
        let _ = recovered.prekey_hygiene;

        // The new record unlocks under the NEW password — and under it only
        // (stateless `unlock_once`; the manager method short-circuits when
        // already unlocked).
        drop(recoverer);
        assert!(IdentityManager::unlock_once(&path, "copper meadow lantern drift").is_ok());
        assert!(IdentityManager::unlock_once(&path, "correct horse battery staple").is_err());
    }

    #[test]
    fn recovery_fails_cleanly_without_record() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.najwa");
        let mut mgr = IdentityManager::new(path).unwrap();
        mgr.create("maple quartz ferry lantern").unwrap();
        let err = mgr
            .recover_from_recovery_record_at("any phrase here", "copper meadow lantern drift")
            .unwrap_err();
        assert!(matches!(err, IdentityError::RecoveryRecordMissing));
    }

    #[test]
    fn recovery_fails_closed_on_tampered_record() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.najwa");
        let mut mgr = IdentityManager::new(path.clone()).unwrap();
        let mnemonic = mgr
            .create_with_recovery_record("maple quartz ferry lantern", 12)
            .unwrap();

        // Flip one byte INSIDE enc_ik_recovery (offsets 56..104 of the
        // 105-byte record) so AEAD authentication fails.
        let sidecar = path.with_extension("recovery");
        let mut data = std::fs::read(&sidecar).unwrap();
        assert_eq!(data.len(), 105);
        data[100] ^= 0x01;
        std::fs::write(&sidecar, &data).unwrap();

        let err = mgr
            .recover_from_recovery_record_at(&mnemonic, "copper meadow lantern drift")
            .unwrap_err();
        assert!(matches!(err, IdentityError::Backup(_)));
    }

    // S02 §11.1: each new-passphrase entry point refuses a weak passphrase
    // before it writes anything.
    const WEAK: &str = "aaaaaaaaaaaa";

    fn files(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
        let mut files: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| {
                let path = entry.unwrap().path();
                let bytes = std::fs::read(&path).unwrap_or_default();
                (path, bytes)
            })
            .collect();
        files.sort();
        files
    }

    fn assert_weak(result: Result<impl Sized>) {
        assert!(matches!(
            result.map(|_| ()),
            Err(IdentityError::WeakPassphrase { hint: Some(_) })
        ));
    }

    #[test]
    fn create_refuses_weak_passphrase() {
        let (dir, _) = fixture();
        let mut manager = IdentityManager::new(dir.path().join("new.najwa")).unwrap();
        let before = files(dir.path());
        assert_weak(manager.create(WEAK));
        assert_weak(manager.create_with_recovery_record(WEAK, 24));
        assert!(!manager.exists());
        assert_eq!(files(dir.path()), before);
    }

    #[test]
    fn change_password_refuses_weak_passphrase() {
        let (dir, mut manager) = fixture();
        let before = files(dir.path());
        assert_weak(manager.change_password("original password", WEAK));
        assert_eq!(manager.rate_limiter().attempts(), 0);
        assert_eq!(files(dir.path()), before);
        assert!(IdentityManager::unlock_once(&manager.record_path, "original password").is_ok());
    }

    #[test]
    fn recover_from_seed_refuses_weak_passphrase() {
        let (dir, _) = fixture();
        let mut manager = IdentityManager::new(dir.path().join("new.najwa")).unwrap();
        let before = files(dir.path());
        assert_weak(manager.recover_from_seed(&[7; 32], WEAK));
        assert!(!manager.is_unlocked());
        assert_eq!(files(dir.path()), before);
    }

    #[test]
    fn recover_from_recovery_record_refuses_weak_passphrase() {
        let (dir, _) = fixture();
        let mut manager = IdentityManager::new(dir.path().join("new.najwa")).unwrap();
        let (_, identity) = candidate(41);
        let (mnemonic, recovery) = backup::create_recovery_record(&identity, 12).unwrap();
        atomic_write(&manager.recovery_record_path(), &recovery.to_bytes()).unwrap();
        let before = files(dir.path());
        assert_weak(manager.recover_from_recovery_record_at(&mnemonic, WEAK));
        assert!(!manager.is_unlocked());
        assert_eq!(files(dir.path()), before);
    }

    #[test]
    fn new_passphrase_length_limits() {
        assert!(matches!(
            crate::password::validate_new_passphrase("Xq7#vB2m!kP"),
            Err(IdentityError::PasswordTooShort(12))
        ));
        assert!(matches!(
            crate::password::validate_new_passphrase(&"word ".repeat(205)),
            Err(IdentityError::PasswordTooLong(1024))
        ));
        assert!(crate::password::validate_new_passphrase("harbor violet canyon thimble").is_ok());
    }

    // S02 §10.1: the counter survives a process restart, so an attacker cannot
    // reset backoff/lockout by restarting between guesses.
    #[test]
    fn counter_persists_across_reload() {
        let dkm = [0x11u8; 32];
        let dir = tempfile::tempdir().unwrap();
        let record_path = dir.path().join("id.dat");

        let mut rl = UnlockRateLimiter::new();
        rl.record_failure();
        rl.record_failure();
        rl.record_failure();
        write_counter(&record_path, &rl, &dkm).unwrap();

        // A fresh manager (new process) reloads the same count.
        let reloaded = read_counter(&record_path, &dkm);
        assert_eq!(reloaded.attempts(), 3);
    }

    // S02 §10.1: a tampered/rebound counter (wrong DKM) fails closed to lockout.
    #[test]
    fn counter_fail_closed_on_tamper() {
        let dir = tempfile::tempdir().unwrap();
        let record_path = dir.path().join("id.dat");

        let mut rl = UnlockRateLimiter::new();
        rl.record_failure();
        write_counter(&record_path, &rl, &[0x11; 32]).unwrap();

        let reloaded = read_counter(&record_path, &[0x22; 32]);
        assert_eq!(reloaded.attempts(), UnlockRateLimiter::MAX_ATTEMPTS);
        assert!(reloaded.is_locked());
    }

    #[test]
    fn missing_counter_file_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let record_path = dir.path().join("id.dat");
        assert!(read_counter(&record_path, &[0x11; 32]).is_locked());
    }

    #[test]
    fn argon_timing_persists_across_reload() {
        let dir = tempfile::tempdir().unwrap();
        let record_path = dir.path().join("id.dat");
        let dkm = [0x33; 32];
        let measured = Duration::from_millis(1_237);

        write_argon_timing(&record_path, measured, &dkm);

        assert_eq!(read_argon_timing(&record_path, &dkm), measured);
    }

    #[test]
    fn missing_or_tampered_argon_timing_uses_creation_seed() {
        let dir = tempfile::tempdir().unwrap();
        let record_path = dir.path().join("id.dat");
        assert_eq!(
            read_argon_timing(&record_path, &[0x44; 32]),
            INITIAL_SUCCESSFUL_ARGON_TIME
        );

        write_argon_timing(&record_path, Duration::from_millis(1), &[0x55; 32]);
        assert_eq!(
            read_argon_timing(&record_path, &[0x66; 32]),
            INITIAL_SUCCESSFUL_ARGON_TIME
        );
    }
}
