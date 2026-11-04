//! Ed25519 ↔ X25519 key conversion (Edwards to Montgomery form).

use curve25519_dalek::edwards::CompressedEdwardsY;
use sha2::{Digest, Sha512};
use zeroize::Zeroize;

use super::ed25519::{Ed25519Private, Ed25519Public};
use super::x25519::{X25519Private, X25519Public};
use crate::error::{CryptoError, Result};

/// Convert an Ed25519 public key to an X25519 public key.
///
/// Uses the birational map from Edwards to Montgomery form.
pub fn ed25519_pub_to_x25519(ed_pub: &Ed25519Public) -> Result<X25519Public> {
    let compressed = CompressedEdwardsY(ed_pub.to_bytes());
    let point = compressed
        .decompress()
        .ok_or_else(|| CryptoError::KeyConversionFailed("point not on curve".into()))?;
    // S01 §3.3: reject low-order (small-order subgroup) points. A small-order
    // Ed25519 identity key maps to a low-order X25519 point whose DH output is
    // all-zero, which would otherwise trip a downstream `assert!` in
    // `diffie_hellman` — a remote DoS triggerable by an attacker-chosen contact
    // IK. Fail the conversion gracefully instead.
    if point.is_small_order() {
        return Err(CryptoError::KeyConversionFailed(
            "low-order point rejected".into(),
        ));
    }
    let montgomery = point.to_montgomery();
    Ok(X25519Public::from_bytes(montgomery.to_bytes()))
}

/// Convert an Ed25519 private key to an X25519 private key.
///
/// Hashes the seed with SHA-512 and clamps the first 32 bytes,
/// matching the standard Ed25519 → X25519 derivation.
pub fn ed25519_priv_to_x25519(ed_priv: &Ed25519Private) -> X25519Private {
    let mut hash = Sha512::digest(ed_priv.to_bytes());

    // Clamp: clear the bottom 3 bits and the top bit, set second-highest bit.
    hash[0] &= 248;
    hash[31] &= 127;
    hash[31] |= 64;

    let mut scalar = [0u8; 32];
    scalar.copy_from_slice(&hash[..32]);
    hash.zeroize();

    // StaticSecret::from also clamps, but clamping is idempotent.
    let private = X25519Private::from_bytes_unchecked(scalar);
    scalar.zeroize();
    private
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::ed25519::Ed25519KeyPair;

    #[test]
    fn ed25519_to_x25519_conversion_matches() {
        let ed_kp = Ed25519KeyPair::from_seed(&[0x42; 32]);
        let x_pub = ed25519_pub_to_x25519(ed_kp.public()).unwrap();
        let x_priv = ed25519_priv_to_x25519(ed_kp.private());

        // The public key derived from the converted private must match
        // the independently converted public key.
        assert_eq!(x_priv.public_key().to_bytes(), x_pub.to_bytes());
    }

    #[test]
    fn conversion_different_seeds_differ() {
        let kp1 = Ed25519KeyPair::from_seed(&[0x01; 32]);
        let kp2 = Ed25519KeyPair::from_seed(&[0x02; 32]);
        let x1 = ed25519_pub_to_x25519(kp1.public()).unwrap();
        let x2 = ed25519_pub_to_x25519(kp2.public()).unwrap();
        assert_ne!(x1.to_bytes(), x2.to_bytes());
    }

    #[test]
    fn low_order_point_rejected() {
        // S01 §3.3: a small-order Ed25519 point (here the Edwards identity, y=1)
        // must NOT convert to a low-order X25519 key (whose DH is all-zero and
        // trips a downstream assert! — a remote DoS). Either the public-key parser
        // rejects the encoding or the conversion does; both are acceptable, a
        // successful conversion is not.
        let mut ident = [0u8; 32];
        ident[0] = 1; // canonical identity encoding (y = 1, sign 0)
        if let Ok(ed_pub) = Ed25519Public::from_bytes(&ident) {
            assert!(
                ed25519_pub_to_x25519(&ed_pub).is_err(),
                "small-order Ed25519 point must not convert to X25519"
            );
        }
    }
}
