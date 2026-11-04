//! X25519 key types: generation, Diffie-Hellman key agreement.

use crate::error::{CryptoError, Result};
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// X25519 private (static secret) key. Zeroized on drop.
pub struct X25519Private {
    inner: StaticSecret,
}

/// X25519 public key (32 bytes).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct X25519Public {
    bytes: [u8; 32],
}

/// X25519 shared secret (32 bytes). Zeroized on drop.
#[derive(ZeroizeOnDrop)]
pub struct X25519SharedSecret {
    #[zeroize]
    bytes: [u8; 32],
}

/// X25519 key pair (private + public).
pub struct X25519KeyPair {
    private: X25519Private,
    public: X25519Public,
}

// -- X25519Private ----------------------------------------------------------

impl X25519Private {
    /// Crate-internal constructor from raw 32 bytes.
    pub(crate) fn from_bytes_unchecked(bytes: [u8; 32]) -> Self {
        Self {
            inner: StaticSecret::from(bytes),
        }
    }

    /// Derive the corresponding public key.
    pub fn public_key(&self) -> X25519Public {
        let pk = PublicKey::from(&self.inner);
        X25519Public {
            bytes: pk.to_bytes(),
        }
    }

    /// Access the inner `StaticSecret` (crate-internal, used in later phases).
    #[allow(dead_code)]
    pub(crate) fn inner(&self) -> &StaticSecret {
        &self.inner
    }

    /// Return the raw 32-byte secret. **Handle with extreme care.**
    pub fn to_bytes(&self) -> [u8; 32] {
        self.inner.to_bytes()
    }
}

impl Drop for X25519Private {
    fn drop(&mut self) {
        // StaticSecret implements Zeroize (via curve25519-dalek v4 Scalar).
        self.inner.zeroize();
    }
}

impl std::fmt::Debug for X25519Private {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X25519Private")
            .field("inner", &"[REDACTED]")
            .finish()
    }
}

// -- X25519Public -----------------------------------------------------------

impl X25519Public {
    /// Decode from 32 bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// Encode as 32 bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.bytes
    }

    /// Convert to the inner `x25519_dalek::PublicKey`.
    pub(crate) fn to_dalek(&self) -> PublicKey {
        PublicKey::from(self.bytes)
    }
}

// -- X25519SharedSecret -----------------------------------------------------

impl X25519SharedSecret {
    /// Access the raw 32-byte shared secret.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

// -- X25519KeyPair ----------------------------------------------------------

impl X25519KeyPair {
    /// Generate a fresh key pair from a CSPRNG.
    pub fn generate<R: CryptoRngCore>(rng: &mut R) -> Self {
        let secret = StaticSecret::random_from_rng(rng);
        let public = PublicKey::from(&secret);
        Self {
            private: X25519Private { inner: secret },
            public: X25519Public {
                bytes: public.to_bytes(),
            },
        }
    }

    /// Create a key pair from a 32-byte seed.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let secret = StaticSecret::from(seed);
        let public = PublicKey::from(&secret);
        Self {
            private: X25519Private { inner: secret },
            public: X25519Public {
                bytes: public.to_bytes(),
            },
        }
    }

    /// Perform X25519 Diffie-Hellman with `their_pub` (S01 §3.2).
    ///
    /// # Errors
    ///
    /// Rejects non-contributory (low-order) peer keys without unwinding the
    /// receive task. The shared-secret check is constant-time (S01 §3.2, §7).
    pub fn diffie_hellman(&self, their_pub: &X25519Public) -> Result<X25519SharedSecret> {
        let shared = self.private.inner.diffie_hellman(&their_pub.to_dalek());
        if !shared.was_contributory() {
            return Err(CryptoError::InvalidPublicKey);
        }
        Ok(X25519SharedSecret {
            bytes: shared.to_bytes(),
        })
    }

    /// Borrow the private key.
    pub fn private(&self) -> &X25519Private {
        &self.private
    }

    /// Borrow the public key.
    pub fn public(&self) -> &X25519Public {
        &self.public
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_and_dh_agree() {
        let mut rng = rand::thread_rng();
        let alice = X25519KeyPair::generate(&mut rng);
        let bob = X25519KeyPair::generate(&mut rng);

        let shared_ab = alice.diffie_hellman(bob.public()).unwrap();
        let shared_ba = bob.diffie_hellman(alice.public()).unwrap();
        assert_eq!(shared_ab.as_bytes(), shared_ba.as_bytes());
    }

    #[test]
    fn from_seed_deterministic() {
        let seed = [0x55u8; 32];
        let kp1 = X25519KeyPair::from_seed(seed);
        let kp2 = X25519KeyPair::from_seed(seed);
        assert_eq!(kp1.public().to_bytes(), kp2.public().to_bytes());
    }

    #[test]
    fn roundtrip_public_bytes() {
        let mut rng = rand::thread_rng();
        let kp = X25519KeyPair::generate(&mut rng);
        let bytes = kp.public().to_bytes();
        let restored = X25519Public::from_bytes(bytes);
        assert_eq!(restored.to_bytes(), bytes);
    }
}
