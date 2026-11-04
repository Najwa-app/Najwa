//! Ed25519 key types: generation, signing, verification.

use std::sync::Arc;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

use crate::error::{CryptoError, Result};
use crate::memory::GuardedMemory;

/// Ed25519 private (signing) key. Zeroized on drop.
///
/// Clones share one copy of the key: no secret bytes are copied, and the last
/// clone dropped zeroizes it.
#[derive(Clone)]
pub struct Ed25519Private {
    inner: Arc<Slot>,
}

// The last `Arc` drops the `SigningKey`, which zeroizes its seed.
impl ZeroizeOnDrop for Ed25519Private {}

/// Where the key lives. `SigningKey` holds only the 32-byte seed and the public
/// key, zeroizes the seed on drop (ed25519-dalek `zeroize` feature) and expands
/// it per signature into a value that also zeroizes on drop.
enum Slot {
    Heap(SigningKey),
    /// The long-lived identity key, in its own locked pages (S01 §6.2).
    Guarded(GuardedMemory<SigningKey>),
}

/// Ed25519 public (verifying) key (32 bytes).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ed25519Public {
    inner: VerifyingKey,
}

/// Ed25519 signature (64 bytes).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ed25519Signature {
    inner: Signature,
}

/// Ed25519 key pair (private + public). Clones share the private key.
#[derive(Clone)]
pub struct Ed25519KeyPair {
    private: Ed25519Private,
    public: Ed25519Public,
}

// -- Ed25519Private ---------------------------------------------------------

impl Ed25519Private {
    /// Access the inner `SigningKey` (crate-internal).
    pub(crate) fn inner(&self) -> &SigningKey {
        match &*self.inner {
            Slot::Heap(key) => key,
            Slot::Guarded(key) => key,
        }
    }

    /// Return the raw 32-byte seed (secret scalar pre-image).
    pub fn to_bytes(&self) -> [u8; 32] {
        self.inner().to_bytes()
    }

    /// Whether the key is held in [`GuardedMemory`] (S01 §6.2).
    pub fn is_guarded(&self) -> bool {
        matches!(*self.inner, Slot::Guarded(_))
    }
}

impl std::fmt::Debug for Ed25519Private {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ed25519Private")
            .field("inner", &"[REDACTED]")
            .finish()
    }
}

// -- Ed25519Public ----------------------------------------------------------

impl Ed25519Public {
    /// Decode a public key from 32 bytes.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self> {
        let inner = VerifyingKey::from_bytes(bytes).map_err(|_| CryptoError::InvalidPublicKey)?;
        Ok(Self { inner })
    }

    /// Encode the public key as 32 bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.inner.to_bytes()
    }

    /// Verify `msg` against `sig`.
    pub fn verify(&self, msg: &[u8], sig: &Ed25519Signature) -> Result<()> {
        self.inner
            .verify(msg, &sig.inner)
            .map_err(|_| CryptoError::SignatureVerificationFailed)
    }

    /// Access the inner `VerifyingKey` (crate-internal, used in later phases).
    #[allow(dead_code)]
    pub(crate) fn inner(&self) -> &VerifyingKey {
        &self.inner
    }
}

// -- Ed25519Signature -------------------------------------------------------

impl Ed25519Signature {
    /// Decode a signature from 64 bytes.
    pub fn from_bytes(bytes: &[u8; 64]) -> Result<Self> {
        let inner = Signature::from_bytes(bytes);
        Ok(Self { inner })
    }

    /// Encode the signature as 64 bytes.
    pub fn to_bytes(&self) -> [u8; 64] {
        self.inner.to_bytes()
    }
}

// -- Ed25519KeyPair ---------------------------------------------------------

impl Ed25519KeyPair {
    /// Generate a fresh key pair from a CSPRNG.
    pub fn generate<R: CryptoRngCore>(rng: &mut R) -> Self {
        Self::with_slot(Slot::Heap(SigningKey::generate(rng)))
    }

    /// Deterministically derive a key pair from a 32-byte seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self::with_slot(Slot::Heap(SigningKey::from_bytes(seed)))
    }

    /// [`Self::from_seed`] with the key in its own locked pages (S01 §6.2).
    /// Only for the unlocked identity key: each call takes one page of the
    /// process's locked-memory allowance. Share it with `clone`.
    pub fn from_seed_guarded(seed: &[u8; 32]) -> Self {
        Self::with_slot(Slot::Guarded(GuardedMemory::new(SigningKey::from_bytes(
            seed,
        ))))
    }

    fn with_slot(slot: Slot) -> Self {
        let private = Ed25519Private {
            inner: Arc::new(slot),
        };
        let public = Ed25519Public {
            inner: private.inner().verifying_key(),
        };
        Self { private, public }
    }

    /// Sign `message` and return the signature.
    pub fn sign(&self, message: &[u8]) -> Ed25519Signature {
        let sig = self.private.inner().sign(message);
        Ed25519Signature { inner: sig }
    }

    /// Borrow the private key.
    pub fn private(&self) -> &Ed25519Private {
        &self.private
    }

    /// Borrow the public key.
    pub fn public(&self) -> &Ed25519Public {
        &self.public
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_sign_verify() {
        let mut rng = rand::thread_rng();
        let kp = Ed25519KeyPair::generate(&mut rng);
        let msg = b"hello najwa";
        let sig = kp.sign(msg);
        assert!(kp.public().verify(msg, &sig).is_ok());
    }

    #[test]
    fn verify_wrong_message_fails() {
        let mut rng = rand::thread_rng();
        let kp = Ed25519KeyPair::generate(&mut rng);
        let sig = kp.sign(b"correct");
        assert!(kp.public().verify(b"wrong", &sig).is_err());
    }

    #[test]
    fn from_seed_deterministic() {
        let seed = [0x42u8; 32];
        let kp1 = Ed25519KeyPair::from_seed(&seed);
        let kp2 = Ed25519KeyPair::from_seed(&seed);
        assert_eq!(kp1.public().to_bytes(), kp2.public().to_bytes());
    }

    // S01 §6.2: a guarded key signs like any other, and clones share the one
    // locked copy instead of copying the seed.
    #[test]
    fn guarded_key_signs_identically_and_clones_share_it() {
        let heap = Ed25519KeyPair::from_seed(&[0x42; 32]);
        let guarded = Ed25519KeyPair::from_seed_guarded(&[0x42; 32]);
        let shared = guarded.clone();
        assert!(!heap.private().is_guarded() && shared.private().is_guarded());
        assert_eq!(shared.sign(b"m").to_bytes(), heap.sign(b"m").to_bytes());
        assert_eq!(shared.public(), heap.public());
        assert!(std::ptr::eq(shared.private().inner(), guarded.private().inner()));
    }

    #[test]
    fn roundtrip_public_key_bytes() {
        let mut rng = rand::thread_rng();
        let kp = Ed25519KeyPair::generate(&mut rng);
        let bytes = kp.public().to_bytes();
        let restored = Ed25519Public::from_bytes(&bytes).unwrap();
        assert_eq!(restored.to_bytes(), bytes);
    }

    #[test]
    fn roundtrip_signature_bytes() {
        let mut rng = rand::thread_rng();
        let kp = Ed25519KeyPair::generate(&mut rng);
        let sig = kp.sign(b"test");
        let bytes = sig.to_bytes();
        let restored = Ed25519Signature::from_bytes(&bytes).unwrap();
        assert_eq!(restored.to_bytes(), bytes);
    }
}
