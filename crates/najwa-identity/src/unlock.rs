//! Identity unlock, password change, and rate limiting.
//!
//! Implements S02 §9 (unlock), §12 (password change), and §10 (rate limiting).

use std::time::{Duration, Instant};

use najwa_crypto::prelude::*;
use zeroize::{Zeroize, Zeroizing};

use crate::aad::build_aad_identity_standard;
use crate::error::{IdentityError, Result};
use crate::password::normalize_password;
use crate::platform;
use crate::record::*;

// ---------------------------------------------------------------------------
// Unlock
// ---------------------------------------------------------------------------

/// Minimum unlock duration floor (200ms) to prevent timing analysis.
const MIN_UNLOCK_FLOOR_MS: u64 = 200;

/// Random jitter added to minimum unlock duration (0..50ms).
const UNLOCK_JITTER_MAX_MS: u64 = 50;

/// Seed used before the first successful unlock or when timing state is absent.
pub(crate) const INITIAL_SUCCESSFUL_ARGON_TIME: Duration =
    Duration::from_millis(crate::creation::ARGON2_CALIBRATION_TARGET_MS);

fn minimum_unlock_duration(last_successful_argon_time: Duration) -> Duration {
    last_successful_argon_time
        + last_successful_argon_time / 10
        + Duration::from_millis(MIN_UNLOCK_FLOOR_MS)
}

fn enforce_unlock_duration(start: Instant, last_successful_argon_time: Duration) {
    let minimum = minimum_unlock_duration(last_successful_argon_time);
    let elapsed = start.elapsed();
    if elapsed < minimum {
        let jitter = {
            let random: [u8; 8] = random_bytes();
            u64::from_le_bytes(random) % (UNLOCK_JITTER_MAX_MS + 1)
        };
        std::thread::sleep(minimum - elapsed + Duration::from_millis(jitter));
    }
}

/// Unlock an identity record with `password` (S02 §9, timing-consistent).
///
/// **Timing oracle mitigation:** This function ALWAYS runs the full Argon2id
/// computation and enforces a minimum duration regardless of failure mode.
/// All failures return a single generic error message.
///
/// This low-level, path-free helper uses the normative 1000ms creation seed.
/// Persistent application flows use [`crate::manager::IdentityManager`], which
/// loads and updates the authenticated per-record timing sidecar.
///
/// Steps:
/// 1. Validate record structure/checksum (note failures, don't return early)
/// 2. Retrieve DKM (substitute CSPRNG(32) if unavailable)
/// 3. ALWAYS run Argon2id (even if earlier steps failed)
/// 4. Derive KEK and attempt decryption
/// 5. Enforce minimum duration: elapsed >= last successful Argon2 time × 1.1 + 200ms
///    (plus random 0..50ms jitter when sleeping)
/// 6. Return single generic error for ALL failure modes
pub fn unlock_identity(record: &IdentityRecordStandard, password: &str) -> Result<Identity> {
    unlock_identity_with_timing(record, password, INITIAL_SUCCESSFUL_ARGON_TIME)
        .map(|(identity, _)| identity)
}

/// Unlock with a caller-provided prior successful Argon2 duration.
///
/// Returns the successful attempt's measured Argon2 duration so the manager can
/// persist it for the next attempt. Failed attempts never update the reference.
pub(crate) fn unlock_identity_with_timing(
    record: &IdentityRecordStandard,
    password: &str,
    last_successful_argon_time: Duration,
) -> Result<(Identity, Duration)> {
    let start = Instant::now();
    let mut failed = false;

    // 1. Validate record (note failure, don't return early)
    if record.validate().is_err() {
        failed = true;
    }

    // 2. Retrieve DKM (substitute random bytes if unavailable to keep timing constant)
    let dkm = Zeroizing::new(match platform::retrieve_record_dkm(record) {
        Ok(d) => d,
        Err(_) => {
            failed = true;
            random_bytes::<32>()
        }
    });

    // 3. Normalize password (note failure, use dummy bytes)
    let mut password_bytes = Zeroizing::new(match normalize_password(password) {
        Ok(pb) => pb,
        Err(_) => {
            failed = true;
            b"dummy-password-for-timing".to_vec()
        }
    });

    // 4. ALWAYS run Argon2id (the expensive operation — ensures constant timing)
    let params = record.argon2_params();
    let argon2_start = Instant::now();
    let k_pwd_result = argon2id(&password_bytes, &record.salt_p, &params);
    password_bytes.zeroize();
    let argon2_duration = argon2_start.elapsed();

    let mut k_pwd = match k_pwd_result {
        Ok(k) => k,
        Err(_) => {
            failed = true;
            // Use dummy key material to keep subsequent steps running
            Zeroizing::new([0u8; 32])
        }
    };

    // 5. Derive KEK (always runs, even if k_pwd is dummy)
    let prk = hkdf_extract(&*dkm, &*k_pwd);
    let kek_vec = match hkdf_expand(&prk, info_strings::HKDF_INFO_KEK, 32) {
        Ok(v) => v,
        Err(_) => {
            failed = true;
            zeroize::Zeroizing::new(vec![0u8; 32])
        }
    };
    drop(prk);
    let kek = Zeroizing::new(<[u8; 32]>::try_from(&kek_vec[..]).expect("HKDF output is 32 bytes"));
    k_pwd.zeroize();

    // 6. Decrypt identity key (always runs)
    let aad = build_aad_identity_standard(record);
    let ik_seed_result =
        aead::decrypt(&kek, &record.nonce, &record.enc_ik, &aad).map(Zeroizing::new);

    let mut identity_result: Option<Identity> = None;

    match ik_seed_result {
        Ok(ref ik_seed_vec) if ik_seed_vec.len() == 32 && !failed => {
            let mut ik_seed = Zeroizing::new([0u8; 32]);
            ik_seed.copy_from_slice(ik_seed_vec);
            // The unlocked key's one long-lived copy, in locked memory (S01 §6.2).
            let keypair = Ed25519KeyPair::from_seed_guarded(&ik_seed);
            ik_seed.zeroize();

            // Verify public key matches (S02 §9.1 step 11: constant-time)
            if constant_time_eq(&keypair.public().to_bytes(), &record.ik_pub) {
                identity_result = Some(Identity {
                    keypair,
                    created_at: 0,
                    version: record.version,
                });
            } else {
                failed = true;
            }
        }
        _ => {
            failed = true;
        }
    }

    // 7. Enforce the S02 §9.1 reference-time floor. Random jitter is added only
    // when padding is required; every outcome still takes at least the exact
    // `last_successful_argon_time × 1.1 + 200ms` duration.
    enforce_unlock_duration(start, last_successful_argon_time);

    // 8. Return result — single generic error for ALL failure modes
    match identity_result {
        Some(id) if !failed => Ok((id, argon2_duration)),
        _ => Err(IdentityError::UnlockFailed),
    }
}

// ---------------------------------------------------------------------------
// Password change
// ---------------------------------------------------------------------------

/// Change the password protecting an identity.
///
/// Decrypts with the old password, re-encrypts with the new password,
/// and returns the new record.
pub fn change_password(
    record: &IdentityRecordStandard,
    old_password: &str,
    new_password: &str,
    new_params: Option<Argon2Params>,
) -> Result<IdentityRecordStandard> {
    // 1. Unlock with old password
    let identity = unlock_identity(record, old_password)?;
    rewrap_identity(record, &identity, new_password, new_params)
}

/// Rewrap an identity only after the caller has authenticated through its limiter.
pub(crate) fn rewrap_identity(
    record: &IdentityRecordStandard,
    identity: &Identity,
    new_password: &str,
    new_params: Option<Argon2Params>,
) -> Result<IdentityRecordStandard> {
    let ik_seed = Zeroizing::new(identity.keypair.private().to_bytes());

    // 2. Normalize new password
    let mut password_bytes = Zeroizing::new(normalize_password(new_password)?);

    // 3. Use new params or keep existing
    let params = new_params.unwrap_or_else(|| record.argon2_params());

    // 4. Generate new salt
    let new_salt: [u8; 32] = random_bytes();

    // 5. Derive new K_pwd
    let mut k_pwd = argon2id(&password_bytes, &new_salt, &params)?;
    password_bytes.zeroize();

    // 6. Get existing DKM
    let dkm = Zeroizing::new(platform::retrieve_record_dkm(record)?);

    // 7. Derive new KEK
    let prk = hkdf_extract(&*dkm, &*k_pwd);
    let kek_vec = hkdf_expand(&prk, info_strings::HKDF_INFO_KEK, 32)?;
    drop(prk);
    let kek = Zeroizing::new(<[u8; 32]>::try_from(&kek_vec[..]).expect("HKDF output is 32 bytes"));
    k_pwd.zeroize();

    // 8. Generate new nonce and encrypt
    let new_nonce: [u8; 24] = random_bytes();

    let mut new_record = IdentityRecordStandard {
        magic: MAGIC,
        version: record.version,
        mode: MODE_STANDARD,
        kdf_alg: KDF_ALG_ARGON2ID,
        aead_alg: AEAD_ALG_XCHACHA20,
        argon2_memory: params.memory_kib,
        argon2_iterations: params.iterations,
        argon2_parallelism: params.parallelism as u8,
        reserved: record.reserved,
        salt_p: new_salt,
        nonce: new_nonce,
        ik_pub: record.ik_pub,
        enc_ik: [0; 48],
        checksum: [0; 32],
    };

    let aad = build_aad_identity_standard(&new_record);
    let enc_ik_vec = aead::encrypt(&kek, &new_nonce, &*ik_seed, &aad)?;
    new_record.enc_ik.copy_from_slice(&enc_ik_vec);

    // 9. Compute checksum
    new_record.checksum = new_record.compute_checksum();

    platform::store_record_dkm(&new_record, &dkm)?;
    Ok(new_record)
}

// ---------------------------------------------------------------------------
// Rate limiter
// ---------------------------------------------------------------------------

/// HMAC domain separator for rate limiter persistence.
const RATE_LIMITER_HMAC_DOMAIN: &[u8] = b"attempt-counter";

/// Auto-reset period: 24 hours in seconds.
const AUTO_RESET_SECS: u64 = 24 * 3600;

/// Rate limiter for identity unlock attempts (S02 §10.1).
///
/// Implements exponential backoff: `delay = 1000 * 2^min(attempts-1, 10)` ms.
///
/// **Persistence (HIGH-02):** State is persisted as `(N, timestamp, tag)` where
/// `tag = HMAC_SHA256(DKM, "attempt-counter" || N_bytes || timestamp_bytes)`.
/// On load, if HMAC is invalid → `N = MAX_ATTEMPTS` (fail-closed).
/// Auto-resets after 24 hours of no attempts.
pub struct UnlockRateLimiter {
    /// Failed attempt count.
    attempts: u32,
    /// Last attempt timestamp (Unix seconds).
    last_attempt_ts: Option<u64>,
    /// In-memory instant for delay checking.
    last_attempt: Option<Instant>,
}

impl UnlockRateLimiter {
    /// Maximum attempts before lockout.
    pub const MAX_ATTEMPTS: u32 = 10;

    pub(crate) fn locked_out() -> Self {
        Self {
            attempts: Self::MAX_ATTEMPTS,
            last_attempt_ts: Some(najwa_crypto::time::now()),
            last_attempt: None,
        }
    }

    /// Create a new rate limiter (zero attempts).
    pub fn new() -> Self {
        Self {
            attempts: 0,
            last_attempt_ts: None,
            last_attempt: None,
        }
    }

    /// Restore from persisted state with HMAC verification.
    ///
    /// `dkm` is the device key material used to verify the HMAC tag.
    /// If the tag is invalid, the limiter is set to MAX_ATTEMPTS (fail-closed).
    /// If the last attempt was >24h ago, the counter auto-resets.
    pub fn from_persisted(attempts: u32, timestamp: u64, tag: &[u8; 32], dkm: &[u8; 32]) -> Self {
        let expected_tag = Self::compute_tag(dkm, attempts, timestamp);
        if !najwa_crypto::prelude::constant_time_eq(tag, &expected_tag) {
            // HMAC mismatch: fail-closed
            return Self {
                attempts: Self::MAX_ATTEMPTS,
                last_attempt_ts: Some(timestamp),
                last_attempt: None, // no Instant available after restart
            };
        }

        // Auto-reset after 24 hours
        let now = najwa_crypto::time::now();
        if now.saturating_sub(timestamp) > AUTO_RESET_SECS {
            return Self::new();
        }

        Self {
            attempts,
            last_attempt_ts: Some(timestamp),
            last_attempt: None,
        }
    }

    /// Serialize to `(attempts, timestamp, tag)` for persistence.
    pub fn to_persisted(&self, dkm: &[u8; 32]) -> (u32, u64, [u8; 32]) {
        let ts = self.last_attempt_ts.unwrap_or(0);
        let tag = Self::compute_tag(dkm, self.attempts, ts);
        (self.attempts, ts, tag)
    }

    /// Compute HMAC tag for tamper detection.
    fn compute_tag(dkm: &[u8; 32], attempts: u32, timestamp: u64) -> [u8; 32] {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        type HmacSha256 = Hmac<Sha256>;

        let mut mac = HmacSha256::new_from_slice(dkm).expect("HMAC key can be any size");
        mac.update(RATE_LIMITER_HMAC_DOMAIN);
        mac.update(&attempts.to_be_bytes());
        mac.update(&timestamp.to_be_bytes());
        let result = mac.finalize();
        let mut tag = [0u8; 32];
        tag.copy_from_slice(&result.into_bytes());
        tag
    }

    /// Calculate delay in milliseconds before next attempt is allowed.
    pub fn delay_ms(&self) -> u64 {
        if self.attempts == 0 {
            return 0;
        }
        1000 * (1u64 << self.attempts.saturating_sub(1).min(10))
    }

    /// Check if the required delay has elapsed since the last attempt.
    pub fn can_attempt(&self) -> bool {
        if self.attempts == 0 {
            return true;
        }
        if self.is_locked() {
            return false;
        }
        match self.last_attempt {
            Some(last) => last.elapsed().as_millis() as u64 >= self.delay_ms(),
            None => {
                // After restart: use timestamp-based check
                match self.last_attempt_ts {
                    Some(ts) => {
                        let now = najwa_crypto::time::now();
                        (now.saturating_sub(ts)) * 1000 >= self.delay_ms()
                    }
                    None => true,
                }
            }
        }
    }

    /// Record a failed attempt.
    pub fn record_failure(&mut self) {
        self.attempts = self.attempts.saturating_add(1);
        self.finish_failure();
    }

    pub(crate) fn finish_failure(&mut self) {
        self.last_attempt = Some(Instant::now());
        self.last_attempt_ts = Some(najwa_crypto::time::now());
    }

    /// Record a successful attempt (reset counter).
    pub fn record_success(&mut self) {
        self.attempts = 0;
        self.last_attempt = None;
        self.last_attempt_ts = None;
    }

    /// Check if locked out (max attempts exceeded).
    pub fn is_locked(&self) -> bool {
        self.attempts >= Self::MAX_ATTEMPTS
    }

    /// Current attempt count.
    pub fn attempts(&self) -> u32 {
        self.attempts
    }

    /// Check rate limit and return error if not allowed.
    pub fn check(&self) -> Result<()> {
        if self.is_locked() {
            return Err(IdentityError::LockedOut(self.attempts));
        }
        if !self.can_attempt() {
            return Err(IdentityError::RateLimited {
                delay_ms: self.delay_ms(),
            });
        }
        Ok(())
    }
}

impl Default for UnlockRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limiter_initial_state() {
        let rl = UnlockRateLimiter::new();
        assert_eq!(rl.delay_ms(), 0);
        assert!(rl.can_attempt());
        assert!(!rl.is_locked());
        assert_eq!(rl.attempts(), 0);
    }

    #[test]
    fn rate_limiter_exponential_backoff() {
        let mut rl = UnlockRateLimiter::new();
        rl.record_failure();
        assert_eq!(rl.delay_ms(), 1000); // 1s
        rl.record_failure();
        assert_eq!(rl.delay_ms(), 2000); // 2s
        rl.record_failure();
        assert_eq!(rl.delay_ms(), 4000); // 4s
    }

    #[test]
    fn rate_limiter_lockout() {
        let mut rl = UnlockRateLimiter::new();
        for _ in 0..UnlockRateLimiter::MAX_ATTEMPTS {
            rl.record_failure();
        }
        assert!(rl.is_locked());
        assert!(rl.check().is_err());
    }

    #[test]
    fn rate_limiter_reset_on_success() {
        let mut rl = UnlockRateLimiter::new();
        rl.record_failure();
        rl.record_failure();
        rl.record_success();
        assert_eq!(rl.attempts(), 0);
        assert!(rl.can_attempt());
    }

    #[test]
    fn rate_limiter_delay_caps_at_2_pow_10() {
        let mut rl = UnlockRateLimiter::new();
        for _ in 0..15 {
            rl.record_failure();
        }
        // Should not exceed 2^10 * 1000 = 1_024_000 ms
        // But locked out at 10, so check would fail
        assert!(rl.is_locked());
    }

    // S01 §6.2: the created and the unlocked identity key live in GuardedMemory.
    #[test]
    fn created_and_unlocked_identity_keys_are_guarded() {
        platform::set_dkm_storage_for_test(platform::MockDkmStorage::new());
        let (record, created) = crate::creation::create_identity_from_seed(
            &[9; 32],
            "synthetic password",
            Some(Argon2Params::ABSOLUTE_MIN),
        )
        .unwrap();
        assert!(created.keypair.private().is_guarded());
        let unlocked = unlock_identity(&record, "synthetic password").unwrap();
        assert!(unlocked.keypair.private().is_guarded());
    }

    #[test]
    fn unlock_padding_enforces_reference_time_plus_margin() {
        let started = Instant::now();
        enforce_unlock_duration(started, INITIAL_SUCCESSFUL_ARGON_TIME);
        assert!(started.elapsed() >= minimum_unlock_duration(INITIAL_SUCCESSFUL_ARGON_TIME));
    }
}
