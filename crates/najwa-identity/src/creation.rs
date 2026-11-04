//! Identity creation from password + entropy.
//!
//! Implements the identity record creation flow (S02 §4.1).

use najwa_crypto::prelude::*;
use zeroize::{Zeroize, Zeroizing};

use crate::aad::build_aad_identity_standard;
use crate::error::Result;
use crate::password::normalize_password;
use crate::platform;
use crate::record::*;

/// S02 §6.2 calibration target. Iterations remain device-calibrated.
pub(crate) const ARGON2_CALIBRATION_TARGET_MS: u64 = 1_000;

/// Mobile platforms use a 64 MiB target, the S02 §6.1 memory floor.
#[cfg(any(target_os = "android", target_os = "ios"))]
pub(crate) const ARGON2_PLATFORM_MEMORY_KIB: u32 = 64 * 1024;

/// Desktop platforms use the 512 MiB target from S02 §6.2.
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub(crate) const ARGON2_PLATFORM_MEMORY_KIB: u32 = 512 * 1024;

fn calibrate_default_argon2() -> Result<Argon2Params> {
    let mut memory_kib = ARGON2_PLATFORM_MEMORY_KIB;
    loop {
        match calibrate_argon2(ARGON2_CALIBRATION_TARGET_MS, memory_kib) {
            Ok(params) => return Ok(params),
            Err(error @ CryptoError::Argon2AllocationFailed { .. })
                if memory_kib > Argon2Params::ABSOLUTE_MIN.memory_kib =>
            {
                memory_kib = (memory_kib / 2).max(Argon2Params::ABSOLUTE_MIN.memory_kib);
                tracing::warn!(
                    memory_kib,
                    %error,
                    "Argon2 platform memory target unavailable; retrying at lower S02-compliant memory"
                );
            }
            Err(error) => return Err(error.into()),
        }
    }
}

/// Create a new identity protected by `password`.
///
/// 1. Generates a fresh Ed25519 identity key pair.
/// 2. Generates fresh DKM in memory.
/// 3. Derives KEK = HKDF(Argon2id(password, salt), DKM, "najwa/v1/kek").
/// 4. Encrypts the identity private key with XChaCha20-Poly1305.
/// 5. Stores DKM under the record's random salt, preserving existing credentials.
/// 6. Returns the record and unlocked identity. Persistent application flows use
///    `IdentityManager`, which commits the record together with its attempt state.
pub fn create_identity(
    password: &str,
    params: Option<Argon2Params>,
) -> Result<(IdentityRecordStandard, Identity)> {
    // Generate fresh identity seed
    let ik_seed = Zeroizing::new(random_bytes::<32>());
    create_identity_from_seed(&ik_seed, password, params)
}

/// Create an identity from an existing 32-byte seed.
///
/// Used for recovery from paper key / seed phrase.
pub fn create_identity_from_seed(
    ik_seed: &[u8; 32],
    password: &str,
    params: Option<Argon2Params>,
) -> Result<(IdentityRecordStandard, Identity)> {
    // 1. Normalize password
    let mut password_bytes = Zeroizing::new(normalize_password(password)?);

    // 2. Derive identity key pair, in locked memory (S01 §6.2)
    let keypair = Ed25519KeyPair::from_seed_guarded(ik_seed);
    let ik_pub = keypair.public().to_bytes();

    // 3. Generate a fresh DKM. Persist only after every derivation succeeds,
    // in this record's own credential slot (never replacing a live DKM).
    let dkm = Zeroizing::new(random_bytes::<32>());

    // 4. Calibrate or use provided Argon2 params. Production callers pass None,
    // selecting the normative ~1000ms target and platform memory target while
    // leaving the iteration count calibrated to the current device.
    let params = match params {
        Some(p) => p,
        None => calibrate_default_argon2()?,
    };

    // 5. Generate salt
    let salt_p: [u8; 32] = random_bytes();

    // 6. Derive K_pwd = Argon2id(password, salt)
    let mut k_pwd = argon2id(&password_bytes, &salt_p, &params)?;
    password_bytes.zeroize();

    // 7. Derive KEK = HKDF-Expand(HKDF-Extract(DKM, K_pwd), info_kek, 32)
    let prk = hkdf_extract(&*dkm, &*k_pwd);
    k_pwd.zeroize();
    let kek_vec = hkdf_expand(&prk, info_strings::HKDF_INFO_KEK, 32)?;
    drop(prk);
    let kek = Zeroizing::new(<[u8; 32]>::try_from(&kek_vec[..]).expect("HKDF output is 32 bytes"));

    // 8. Encrypt identity key
    let nonce: [u8; 24] = random_bytes();

    // Build a partial record to compute AAD
    let mut record = IdentityRecordStandard {
        magic: MAGIC,
        version: VERSION,
        mode: MODE_STANDARD,
        kdf_alg: KDF_ALG_ARGON2ID,
        aead_alg: AEAD_ALG_XCHACHA20,
        argon2_memory: params.memory_kib,
        argon2_iterations: params.iterations,
        argon2_parallelism: params.parallelism as u8,
        reserved: [0; 3],
        salt_p,
        nonce,
        ik_pub,
        enc_ik: [0; 48],   // placeholder
        checksum: [0; 32], // placeholder
    };

    let aad = build_aad_identity_standard(&record);
    let enc_ik_vec = aead::encrypt(&kek, &nonce, ik_seed, &aad)?;

    // enc_ik should be exactly 48 bytes (32 plaintext + 16 tag)
    if enc_ik_vec.len() != 48 {
        return Err(crate::error::IdentityError::InternalError(format!(
            "enc_ik length mismatch: expected 48, got {}",
            enc_ik_vec.len()
        )));
    }
    record.enc_ik.copy_from_slice(&enc_ik_vec);

    // 9. Compute checksum
    record.checksum = record.compute_checksum();

    let identity = Identity {
        keypair,
        created_at: now(),
        version: VERSION,
    };

    platform::store_record_dkm(&record, &dkm)?;
    Ok((record, identity))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Exercise real allocator failure in a child: resource limits must never
    /// constrain the test runner or other identity tests.
    #[cfg(target_os = "linux")]
    #[test]
    fn calibration_falls_back_on_allocation_failure_but_never_below_floor() {
        const CHILD: &str = "NAJWA_TEST_ARGON_MEMORY_BUDGET";
        if let Ok(budget) = std::env::var(CHILD) {
            let budget: u64 = budget.parse().unwrap();
            let statm = std::fs::read_to_string("/proc/self/statm").unwrap();
            let pages: u64 = statm.split_whitespace().next().unwrap().parse().unwrap();
            // SAFETY: sysconf and setrlimit operate on this isolated child only.
            let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
            assert!(page_size > 0);
            let ceiling = pages * page_size as u64 + budget * 1024 * 1024;
            let limit = libc::rlimit {
                rlim_cur: ceiling,
                rlim_max: ceiling,
            };
            assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_AS, &limit) }, 0);

            assert!(matches!(
                calibrate_argon2(1_000, 512 * 1024),
                Err(CryptoError::Argon2AllocationFailed { .. })
            ));
            assert!(matches!(
                najwa_crypto::kdf::argon2id_variable(
                    b"synthetic",
                    &[7; 32],
                    &Argon2Params::ABSOLUTE_MIN,
                    512 * 1024 * 1024
                ),
                Err(CryptoError::Argon2AllocationFailed { .. })
            ));
            let result = calibrate_default_argon2();
            if budget == 96 {
                let params = result.expect("64 MiB must remain usable after 512/256/128 MiB fail");
                assert_eq!(params.memory_kib, Argon2Params::ABSOLUTE_MIN.memory_kib);
                params.validate().unwrap();
                argon2id(b"synthetic password", &[7; 32], &params).unwrap();
            } else {
                assert!(matches!(
                    result,
                    Err(crate::error::IdentityError::Crypto(
                        CryptoError::Argon2AllocationFailed { .. }
                    ))
                ));
            }
            return;
        }
        for budget in [96, 32] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "creation::tests::calibration_falls_back_on_allocation_failure_but_never_below_floor", "--nocapture", "--test-threads=1"])
                .env(CHILD, budget.to_string())
                .output().unwrap();
            assert!(
                output.status.success(),
                "budget {budget} MiB: {}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    /// That calibration reaches the target in practice is timed in
    /// najwa-crypto/tests/argon2_calibration.rs, alone in its test binary.
    #[test]
    fn calibration_target_and_platform_memory() {
        assert_eq!(ARGON2_CALIBRATION_TARGET_MS, 1_000);
        #[cfg(any(target_os = "android", target_os = "ios"))]
        assert_eq!(ARGON2_PLATFORM_MEMORY_KIB, 64 * 1024);
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        assert_eq!(ARGON2_PLATFORM_MEMORY_KIB, 512 * 1024);
    }
}
