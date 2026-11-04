//! Cryptographic primitives for the Najwa messaging protocol (S01).
//!
//! Single source of truth for all cryptographic operations.
//! No other crate may implement crypto primitives directly.
//!
//! Provides:
//! - Ed25519 signatures ([`keys::ed25519`]) — S01 §3.1
//! - X25519 key agreement ([`keys::x25519`]) — S01 §3.2
//! - Ed25519 ↔ X25519 conversion ([`keys::conversion`]) — S01 §3.3
//! - XChaCha20-Poly1305 AEAD ([`aead`]) — S01 §3.4
//! - HKDF-SHA256 + domain separation registry ([`kdf`]) — S01 §3.5, §8
//! - Argon2id password hashing ([`kdf`]) — S01 §3.8
//! - SHA-256 / HMAC-SHA256 / constant-time comparison ([`hash`]) — S01 §3.6, §3.7, §7
//! - CSPRNG with entropy verification ([`random`]) — S01 §5
//! - Secure memory: zeroize, mlock, core dump prevention ([`memory`]) — S01 §6
//! - Timestamp utility ([`time`])

pub mod aead;
pub mod error;
pub mod hash;
pub mod kdf;
pub mod keys;
pub mod memory;
pub mod random;
pub mod time;
pub mod types;

/// Apply S01 §5.2 / §6.3 startup protections before loading any secret state.
/// Callers MUST refuse initialization if either protection fails. Also raises
/// the locked-memory quota (§6.2), best effort.
pub fn initialize() -> error::Result<()> {
    memory::ensure_lock_quota();
    initialize_with(memory::disable_core_dumps, random::verify_csprng_seeded)
}

fn initialize_with(
    disable_dumps: impl FnOnce() -> error::Result<()>,
    check_entropy: impl FnOnce() -> error::Result<()>,
) -> error::Result<()> {
    disable_dumps()?;
    check_entropy()
}

#[cfg(test)]
mod startup_tests {
    use super::*;

    #[test]
    fn startup_fails_closed_on_either_protection_failure() {
        assert!(matches!(
            initialize_with(
                || Err(error::CryptoError::CoreDumpDisableFailed(
                    "test failure".into()
                )),
                || panic!("must stop after dump protection fails"),
            ),
            Err(error::CryptoError::CoreDumpDisableFailed(_))
        ));
        assert!(matches!(
            initialize_with(|| Ok(()), || Err(error::CryptoError::EntropyUnavailable)),
            Err(error::CryptoError::EntropyUnavailable)
        ));
        assert!(initialize_with(|| Ok(()), || Ok(())).is_ok());
    }
}

/// Convenience re-exports for common usage.
pub mod prelude {
    pub use crate::aead;
    pub use crate::error::{CryptoError, Result};
    pub use crate::hash::{constant_time_eq, hmac_sha256, hmac_sha256_verify, sha256};
    pub use crate::kdf::{
        argon2id, calibrate_argon2, hkdf_expand, hkdf_extract, hkdf_sha256, info_strings,
        Argon2Params,
    };
    pub use crate::keys::{
        ed25519_priv_to_x25519, ed25519_pub_to_x25519, Ed25519KeyPair, Ed25519Private,
        Ed25519Public, Ed25519Signature, X25519KeyPair, X25519Private, X25519Public,
        X25519SharedSecret,
    };
    pub use crate::memory::{disable_core_dumps, mlock, munlock, zeroize_slice, GuardedMemory};
    pub use crate::random::{fill_random, random_bytes, random_bytes_vec};
    pub use crate::time::{now, now_ms};
    pub use crate::types::*;
}
