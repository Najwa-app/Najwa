//! CSPRNG wrapper using OS entropy.
//!
//! All randomness in the Najwa protocol MUST come through this module
//! to ensure a single auditable source of entropy (S01 §5).

use crate::error::{CryptoError, Result};
use rand::rngs::OsRng;
use rand::RngCore;

/// Generate `N` random bytes from the OS CSPRNG (S01 §5.1).
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    OsRng.fill_bytes(&mut buf);
    buf
}

/// Generate `length` random bytes as a `Vec`.
pub fn random_bytes_vec(length: usize) -> Vec<u8> {
    let mut buf = vec![0u8; length];
    OsRng.fill_bytes(&mut buf);
    buf
}

/// Fill `buffer` with random bytes from the OS CSPRNG.
pub fn fill_random(buffer: &mut [u8]) {
    OsRng.fill_bytes(buffer);
}

/// Verify that the CSPRNG is properly seeded (S01 §5.2).
///
/// Returns an error on unavailable entropy or all-zero output. Startup MUST
/// propagate this error before creating state or accepting operations.
pub fn verify_csprng_seeded() -> Result<()> {
    verify_with_rng(&mut OsRng)
}

fn verify_with_rng(rng: &mut impl RngCore) -> Result<()> {
    let mut test = [0u8; 32];
    rng.try_fill_bytes(&mut test)
        .map_err(|_| CryptoError::EntropyUnavailable)?;
    if test.iter().all(|&b| b == 0) {
        return Err(CryptoError::EntropyUnavailable);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestRng {
        fail: bool,
        byte: u8,
    }
    impl RngCore for TestRng {
        fn next_u32(&mut self) -> u32 {
            unreachable!()
        }
        fn next_u64(&mut self) -> u64 {
            unreachable!()
        }
        fn fill_bytes(&mut self, _: &mut [u8]) {
            panic!("use the fallible RNG API")
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> std::result::Result<(), rand::Error> {
            if self.fail {
                return Err(rand::Error::from(
                    std::num::NonZeroU32::new(rand::Error::CUSTOM_START).unwrap(),
                ));
            }
            dest.fill(self.byte);
            Ok(())
        }
    }

    #[test]
    fn startup_rejects_zero_entropy_and_rng_errors() {
        for fail in [false, true] {
            assert!(matches!(
                verify_with_rng(&mut TestRng { fail, byte: 0 }),
                Err(CryptoError::EntropyUnavailable)
            ));
        }
        assert!(verify_with_rng(&mut TestRng {
            fail: false,
            byte: 1
        })
        .is_ok());
        assert!(verify_csprng_seeded().is_ok());
    }

    #[test]
    fn random_bytes_nonzero() {
        let a: [u8; 32] = random_bytes();
        let b: [u8; 32] = random_bytes();
        // Extremely unlikely to be equal
        assert_ne!(a, b);
    }

    #[test]
    fn random_bytes_vec_length() {
        let v = random_bytes_vec(64);
        assert_eq!(v.len(), 64);
    }

    #[test]
    fn fill_random_works() {
        let mut buf = [0u8; 16];
        fill_random(&mut buf);
        // At least one byte should be non-zero (probability ≈ 1 - 2^-128)
        assert!(buf.iter().any(|&b| b != 0));
    }
}
