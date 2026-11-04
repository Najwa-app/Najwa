//! Key derivation functions: HKDF-SHA256 and Argon2id.
//!
//! Implements KDF primitives for the Najwa protocol:
//! - HKDF-SHA256 (S01 §3.5)
//! - Argon2id password hashing (S01 §3.8)

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::error::{CryptoError, Result};

// ---------------------------------------------------------------------------
// HKDF-SHA256
// ---------------------------------------------------------------------------

/// Full HKDF (extract + expand): derive `length` bytes from input keying material.
///
/// # Arguments
///
/// * `ikm`  – Input keying material.
/// * `salt` – Optional salt (use `&[]` for no salt).
/// * `info` – Context / application-specific info string.
/// * `length` – Desired output length in bytes.
pub fn hkdf_sha256(
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    length: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = Zeroizing::new(vec![0u8; length]);
    hk.expand(info, &mut okm)
        .map_err(|e| CryptoError::HkdfInvalidLength(e.to_string()))?;
    Ok(okm)
}

/// HKDF-Extract only — returns a PRK that is wiped on every exit path.
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> Zeroizing<[u8; 32]> {
    let (mut prk, _) = Hkdf::<Sha256>::extract(Some(salt), ikm);
    let mut output = Zeroizing::new([0u8; 32]);
    output.copy_from_slice(&prk);
    prk.as_mut_slice().zeroize();
    output
}

/// HKDF-Expand only — expand `prk` with `info` to `length` bytes.
pub fn hkdf_expand(prk: &[u8; 32], info: &[u8], length: usize) -> Result<Zeroizing<Vec<u8>>> {
    let hk =
        Hkdf::<Sha256>::from_prk(prk).map_err(|e| CryptoError::HkdfInvalidLength(e.to_string()))?;
    let mut okm = Zeroizing::new(vec![0u8; length]);
    hk.expand(info, &mut okm)
        .map_err(|e| CryptoError::HkdfInvalidLength(e.to_string()))?;
    Ok(okm)
}

// ---------------------------------------------------------------------------
// Domain separation constants
// ---------------------------------------------------------------------------

/// Domain separation constants for HKDF `info` parameters and AAD prefixes.
///
/// `docs/reference/hkdf-strings.md` is the registry of every label the release
/// uses, with its exact bytes, call sites and defining spec section (S01 §3.5).
/// Some constants here have no release caller and are not in that registry;
/// some call sites keep their own copy of a registered label. Every constant is
/// pinned byte for byte by `tests/vectors.rs::s18_18_hkdf_string_registry_byte_exact`.
///
/// Most labels have the form `"najwa/<version>/<context>"`; a few local-only
/// labels are bare strings.
///
/// **IMPORTANT:** These strings are protocol constants.  Changing them
/// breaks compatibility with all existing sessions and stored data.
pub mod info_strings {
    // -----------------------------------------------------------------------
    // Identity & Key Protection (S02)
    // -----------------------------------------------------------------------

    /// Key-encryption key derivation from password + device factors.
    pub const HKDF_INFO_KEK: &[u8] = b"najwa/v1/kek";
    /// Verification key operations (Hardware Mode).
    pub const HKDF_INFO_VK: &[u8] = b"najwa/v1/vk";
    /// Paper key recovery key derivation.
    pub const HKDF_INFO_RECOVERY: &[u8] = b"najwa/v1/recovery";
    /// Info label of `najwa_storage::database::derive_db_key`, which the
    /// application does not call. The SQLCipher key uses the
    /// `najwa/v1/sqlcipher-key` derivation in `najwa-ffi` (S03 §3).
    pub const DB_KEY_INFO: &[u8] = b"najwa/v1/storage/db-key";
    /// Per-device signing key derivation label. Not used by the app.
    pub const DEVICE_KEY_INFO: &[u8] = b"najwa/v1/device-key";
    /// iOS Secure Enclave ECIES wrapping key.
    pub const SE_WRAP_INFO: &[u8] = b"najwa/v1/se-wrap";

    // -----------------------------------------------------------------------
    // AAD prefixes. The app uses only `najwa/v1/recovery` (S02 §8.6); the
    // identity record's AAD (S02 §8.1) has no prefix.
    // -----------------------------------------------------------------------

    /// AAD prefix for identity-key encryption (Standard Mode).
    pub const AAD_IK_ENCRYPT: &[u8] = b"najwa/v1/ik-encrypt";
    /// AAD prefix for VK encryption (Hardware Mode inner layer).
    pub const AAD_VK_ENCRYPT: &[u8] = b"najwa/v1/vk-encrypt";
    /// AAD prefix for IK encryption under Hardware Mode.
    pub const AAD_IK_ENCRYPT_HW: &[u8] = b"najwa/v1/ik-encrypt-hw";
    /// AAD prefix for hardware wrapping (outer layer, when HW supports AAD).
    pub const AAD_HW_WRAP: &[u8] = b"najwa/v1/hw-wrap";
    /// AAD prefix for backup encryption.
    pub const AAD_BACKUP: &[u8] = b"najwa/v1/backup";
    /// AAD prefix for paper key recovery encryption.
    pub const AAD_RECOVERY: &[u8] = b"najwa/v1/recovery";

    // -----------------------------------------------------------------------
    // Key Agreement & Session (S06)
    // -----------------------------------------------------------------------

    /// X3DH shared-secret derivation prefix (S06 §2.2).
    /// Full info = `X3DH_INFO_PREFIX || X_IK_A_pub || X_IK_B_pub`.
    pub const X3DH_INFO_PREFIX: &[u8] = b"najwa/v1/x3dh/";
    /// Double Ratchet root-key ratchet step (KDF_RK).
    pub const RATCHET_INFO: &[u8] = b"najwa/v1/ratchet/rk";
    /// Message key derivation info (used in HKDF for derive_message_keys).
    pub const MESSAGE_KEY_INFO: &[u8] = b"najwa/v1/ratchet/mk";

    // -----------------------------------------------------------------------
    // Pseudonyms (S01 §8)
    // -----------------------------------------------------------------------

    /// Pairwise pseudonym derivation prefix.
    /// Prefix; full info = `PSEUDONYM_INFO || role` where role = "initiator" or
    /// "responder" (S01 §8, S18 §11 — registry strings 37 bytes each).
    pub const PSEUDONYM_INFO: &[u8] = b"najwa/v1/pairwise-pseudonym/";
    /// Group pseudonym derivation prefix. Not used by the app.
    /// Full info = `GROUP_PSEUDONYM_INFO || group_id || member_ik_pub`.
    pub const GROUP_PSEUDONYM_INFO: &[u8] = b"najwa/v1/group-pseudonym/";

    // -----------------------------------------------------------------------
    // Messaging (S07)
    // -----------------------------------------------------------------------

    /// Deterministic message ID generation.
    pub const MESSAGE_ID_INFO: &[u8] = b"najwa/v1/message-id";
    /// Deposit envelope outer encryption salt.
    pub const DEPOSIT_ENVELOPE_SALT: &[u8] = b"najwa/v1/deposit-envelope";
    /// Deposit envelope outer encryption key info.
    pub const DEPOSIT_ENVELOPE_KEY_INFO: &[u8] = b"outer-key";

    // -----------------------------------------------------------------------
    // Contact Establishment (S05)
    // -----------------------------------------------------------------------

    /// Per-mailbox derived signing key derivation.
    pub const MAILBOX_SIGNING_KEY_INFO: &[u8] = b"najwa/v1/mailbox-signing-key";
    /// Handshake payload signature domain prefix.
    /// Full domain = `HANDSHAKE_PREFIX || payload_bytes`.
    pub const HANDSHAKE_PREFIX: &[u8] = b"najwa/v1/handshake/";
    /// Signed prekey signature domain prefix.
    /// Full domain = `SPK_PREFIX || spk_pub || spk_id || spk_timestamp`.
    pub const SPK_PREFIX: &[u8] = b"najwa/v1/spk/";

    // -----------------------------------------------------------------------
    // Rendezvous (library code; no app path uses it)
    // -----------------------------------------------------------------------

    /// Rendezvous Argon2id salt derivation prefix.
    /// Full salt = `SHA256(RENDEZVOUS_SALT_PREFIX || normalized_phrase)[0:32]`.
    pub const RENDEZVOUS_SALT_PREFIX: &[u8] = b"najwa/v1/rendezvous-salt";
    /// Legacy rendezvous aliases (kept for code that still references them).
    pub const RENDEZVOUS_ID_INFO: &[u8] = b"najwa/v1/rendezvous/rendezvous-id";
    pub const RENDEZVOUS_CAP_INFO: &[u8] = b"najwa/v1/rendezvous/deposit-cap";
    pub const RENDEZVOUS_SALT: &[u8] = b"najwa/v1/rendezvous";

    // -----------------------------------------------------------------------
    // Group messaging labels. Not used by the app.
    // -----------------------------------------------------------------------

    /// Group message key derivation prefix.
    /// Full info = `GROUP_MESSAGE_KEY_PREFIX || counter`.
    pub const GROUP_MESSAGE_KEY_PREFIX: &[u8] = b"najwa/v1/group/message-key/";
    /// Group sender key chain advancement.
    pub const GROUP_CHAIN_KEY_INFO: &[u8] = b"najwa/v1/group/chain-key";

    // -----------------------------------------------------------------------
    // Backup labels. Not used by the app.
    // -----------------------------------------------------------------------

    /// Contact backup encryption key salt.
    pub const BACKUP_SALT: &[u8] = b"najwa/v1/backup";
    /// Mnemonic-entropy expansion to a 32-byte identity seed
    /// (`seed = HKDF(entropy_16, "", SEED_EXPAND_INFO, 32)`).
    pub const SEED_EXPAND_INFO: &[u8] = b"najwa/v1/seed-expand";
    /// Contact-list backup encryption key derivation from IK_priv
    /// (`backup_key = HKDF(IK_priv, "", CONTACT_BACKUP_INFO, 32)`).
    pub const CONTACT_BACKUP_INFO: &[u8] = b"najwa/v1/contact-backup";
}

// ---------------------------------------------------------------------------
// Argon2id
// ---------------------------------------------------------------------------

/// Argon2id tuning parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2Params {
    /// Memory cost in KiB.
    pub memory_kib: u32,
    /// Time cost (iterations).
    pub iterations: u32,
    /// Degree of parallelism (threads).
    pub parallelism: u32,
}

impl Argon2Params {
    /// Absolute minimum — 64 MiB, 3 iterations, 1 thread.
    pub const ABSOLUTE_MIN: Self = Self {
        memory_kib: 65536,
        iterations: 3,
        parallelism: 1,
    };

    /// Recommended minimum for mobile — 64 MiB, 3 iterations, 2 lanes.
    ///
    /// Parallelism is 2 (not 4): higher parallelism splits the 64 MiB across more
    /// lanes, reducing memory-hardness per lane, so a GPU/ASIC attacker benefits.
    /// The spec / OWASP guidance is p ≤ 2 for mobile. Records persist the params
    /// they were created with (`argon2_parallelism`), so existing records keep
    /// unlocking — only newly-created records use these. NOTE: hitting the spec's
    /// ≥1000 ms target is device-dependent and needs an on-device calibration
    /// routine; these are the conservative static floor until that lands.
    pub const MIN_MOBILE: Self = Self {
        memory_kib: 65536,
        iterations: 3,
        parallelism: 2,
    };

    /// Recommended for desktop — 512 MiB, 3 iterations, 4 threads.
    pub const RECOMMENDED_DESKTOP: Self = Self {
        memory_kib: 524288,
        iterations: 3,
        parallelism: 4,
    };

    /// Fixed reference parameters: m=262144 KiB (256 MiB), t=4, p=2. Identity
    /// records use calibrated parameters instead (S02 §6.3).
    pub const SPEC_REFERENCE: Self = Self {
        memory_kib: 262144,
        iterations: 4,
        parallelism: 2,
    };

    /// Maximum memory in KiB (4 GiB, S01 §3.8).
    pub const MAX_MEMORY_KIB: u32 = 4_194_304;
    /// Maximum iterations (S01 §3.8).
    pub const MAX_ITERATIONS: u32 = 100;
    /// Maximum parallelism (S01 §3.8).
    pub const MAX_PARALLELISM: u32 = 16;

    /// Validate that parameters are within the S01 §3.8 bounds.
    pub fn validate(&self) -> Result<()> {
        if self.memory_kib < Self::ABSOLUTE_MIN.memory_kib {
            return Err(CryptoError::InvalidArgon2Params(format!(
                "memory_kib {} < minimum {}",
                self.memory_kib,
                Self::ABSOLUTE_MIN.memory_kib
            )));
        }
        if self.memory_kib > Self::MAX_MEMORY_KIB {
            return Err(CryptoError::InvalidArgon2Params(format!(
                "memory_kib {} > maximum {}",
                self.memory_kib,
                Self::MAX_MEMORY_KIB
            )));
        }
        if self.iterations < Self::ABSOLUTE_MIN.iterations {
            return Err(CryptoError::InvalidArgon2Params(format!(
                "iterations {} < minimum {}",
                self.iterations,
                Self::ABSOLUTE_MIN.iterations
            )));
        }
        if self.iterations > Self::MAX_ITERATIONS {
            return Err(CryptoError::InvalidArgon2Params(format!(
                "iterations {} > maximum {}",
                self.iterations,
                Self::MAX_ITERATIONS
            )));
        }
        if self.parallelism == 0 || self.parallelism > Self::MAX_PARALLELISM {
            return Err(CryptoError::InvalidArgon2Params(format!(
                "parallelism {} not in range 1..={}",
                self.parallelism,
                Self::MAX_PARALLELISM
            )));
        }
        Ok(())
    }
}

/// Derive a 32-byte key from `password` and `salt` using Argon2id.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidArgon2Params`] if parameters are below the
/// absolute minimum, [`CryptoError::Argon2AllocationFailed`] if working memory
/// cannot be reserved, or [`CryptoError::Argon2Failed`] on internal failure.
pub fn argon2id(
    password: &[u8],
    salt: &[u8; 32],
    params: &Argon2Params,
) -> Result<Zeroizing<[u8; 32]>> {
    let mut output = Zeroizing::new([0u8; 32]);
    argon2id_into(password, salt, params, &mut *output)?;
    Ok(output)
}

/// Derive a variable-length output from `password` and `salt` using Argon2id (LOW-02).
///
/// Unlike [`argon2id`], this accepts a variable-length salt and produces
/// a variable-length output. Used for rendezvous derivation,
/// where the output is 160 bytes split into 5×32-byte components.
pub fn argon2id_variable(
    password: &[u8],
    salt: &[u8],
    params: &Argon2Params,
    output_len: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    // Validate before allocating attacker-influenced output sizes.
    checked_argon2_params(params, output_len)?;
    let mut output = Zeroizing::new(Vec::new());
    output
        .try_reserve_exact(output_len)
        .map_err(|_| CryptoError::Argon2AllocationFailed { bytes: output_len })?;
    output.resize(output_len, 0);
    argon2id_into(password, salt, params, &mut output)?;
    Ok(output)
}

fn checked_argon2_params(params: &Argon2Params, output_len: usize) -> Result<argon2::Params> {
    params.validate()?;
    argon2::Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(output_len),
    )
    .map_err(|e| CryptoError::InvalidArgon2Params(e.to_string()))
}

/// Own the working memory: the dependency's allocating API neither allocates
/// fallibly nor wipes its block vector. Guard before hashing so errors and
/// unwinding clear the same buffer as success (S01 §3.8, §6.1).
fn argon2id_into(
    password: &[u8],
    salt: &[u8],
    params: &Argon2Params,
    output: &mut [u8],
) -> Result<()> {
    let argon2_params = checked_argon2_params(params, output.len())?;
    let count = argon2_params.block_count();
    let mut blocks = Zeroizing::new(Vec::new());
    blocks
        .try_reserve_exact(count)
        .map_err(|_| CryptoError::Argon2AllocationFailed {
            bytes: count.saturating_mul(std::mem::size_of::<argon2::Block>()),
        })?;
    blocks.resize(count, argon2::Block::default());
    let hasher = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2_params,
    );

    hasher
        .hash_password_into_with_memory(password, salt, output, blocks.as_mut_slice())
        .map_err(|e| CryptoError::Argon2Failed(e.to_string()))
}

/// Maximum iterations cap during calibration.
const CALIBRATION_MAX_ITERATIONS: u32 = 100;

/// Auto-calibrate Argon2id parameters for the current device (S02 §6.3).
///
/// Algorithm (S01 §3.8):
/// 1. `parallelism = clamp(available cores, 1, 16)`
/// 2. Memory is fixed at `max_memory_kib`; if it cannot be allocated, this
///    function returns `Err` and never lowers the memory itself. The caller
///    decides whether to retry at half the memory, never below 64 MiB.
/// 3. Start `iterations = 3`; time a trial hash and increase iterations until
///    it reaches `target_time_ms`, capped at CALIBRATION_MAX_ITERATIONS (100).
pub fn calibrate_argon2(target_time_ms: u64, max_memory_kib: u32) -> Result<Argon2Params> {
    // S01 §3.8: parallelism = clamp(available cores, 1, 16).
    let parallelism = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .clamp(1, 16) as u32;
    let dummy_pw = [0u8; 16];
    let dummy_salt = [0u8; 32];

    // S01 §3.8: the requested memory must be allocatable. If it is not, return
    // the allocation error; any lower-memory retry is the caller's explicit
    // choice and stays at or above the 64 MiB floor.
    let memory = max_memory_kib;
    let base = Argon2Params {
        memory_kib: memory,
        iterations: 3,
        parallelism,
    };
    argon2id(&dummy_pw, &dummy_salt, &base)?;

    // With memory fixed, increase iterations until the trial hash reaches
    // target_time_ms (capped at CALIBRATION_MAX_ITERATIONS).
    let mut iterations = 3u32;
    loop {
        let params = Argon2Params {
            memory_kib: memory,
            iterations,
            parallelism,
        };

        let start = std::time::Instant::now();
        argon2id(&dummy_pw, &dummy_salt, &params)?;
        let elapsed = start.elapsed().as_millis() as u64;
        if elapsed >= target_time_ms || iterations >= CALIBRATION_MAX_ITERATIONS {
            return Ok(params);
        }
        iterations += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hkdf_rfc5869_test1() {
        // RFC 5869 Test Case 1
        let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let expected = hex::decode(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        )
        .unwrap();

        let okm = hkdf_sha256(&ikm, &salt, &info, 42).unwrap();
        assert_eq!(&*okm, &expected);
    }

    #[test]
    fn hkdf_extract_expand_roundtrip() {
        let ikm = b"input keying material";
        let salt = b"salt value";
        let info = b"context info";

        let prk = hkdf_extract(salt, ikm);
        let okm = hkdf_expand(&prk, info, 64).unwrap();
        assert_eq!(okm.len(), 64);

        // Must match full HKDF
        let full = hkdf_sha256(ikm, salt, info, 64).unwrap();
        assert_eq!(*okm, *full);
    }

    #[test]
    fn argon2id_basic() {
        let password = b"correct horse battery staple";
        let salt = [0u8; 32];
        let params = Argon2Params::ABSOLUTE_MIN;

        let hash = argon2id(password, &salt, &params).unwrap();
        assert_eq!(hash.len(), 32);

        // Same inputs → same output (deterministic)
        let hash2 = argon2id(password, &salt, &params).unwrap();
        assert_eq!(hash, hash2);
    }

    #[test]
    fn argon2id_different_passwords_differ() {
        let salt = [0x01u8; 32];
        let params = Argon2Params::ABSOLUTE_MIN;
        let h1 = argon2id(b"password1", &salt, &params).unwrap();
        let h2 = argon2id(b"password2", &salt, &params).unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn argon2id_different_salts_differ() {
        let params = Argon2Params::ABSOLUTE_MIN;
        let h1 = argon2id(b"pw", &[0x01; 32], &params).unwrap();
        let h2 = argon2id(b"pw", &[0x02; 32], &params).unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn argon2_params_validate_below_min_fails() {
        let bad = Argon2Params {
            memory_kib: 1024, // way below 64 MiB
            iterations: 3,
            parallelism: 1,
        };
        assert!(bad.validate().is_err());
    }

    #[test]
    fn argon2_params_validate_zero_parallelism_fails() {
        let bad = Argon2Params {
            memory_kib: 65536,
            iterations: 3,
            parallelism: 0,
        };
        assert!(bad.validate().is_err());
    }

    #[test]
    fn info_strings_are_correct() {
        // Smoke test: ensure constants are non-empty and have correct prefix
        assert!(info_strings::HKDF_INFO_KEK.starts_with(b"najwa/v1/"));
        assert!(info_strings::X3DH_INFO_PREFIX.starts_with(b"najwa/v1/"));
        assert!(info_strings::RENDEZVOUS_SALT.starts_with(b"najwa/v1/"));
    }
}
