//! Group pseudonym derivation. Not used by the app or the receive path.
//!
//! A group pseudonym is unique to each (member, group) pair. Unlike a pairwise
//! pseudonym, it is derived from the member's identity key and the group ID, so
//! it is unlinkable across groups.

use najwa_crypto::hash::constant_time_eq;
use najwa_crypto::kdf::hkdf_sha256;
use najwa_crypto::keys::Ed25519Public;

use super::error::{PseudonymError, Result};
use super::types::Pseudonym;

/// Domain separation prefix for group pseudonym derivation.
const GROUP_PSEUDONYM_INFO_PREFIX: &[u8] = b"najwa/v1/group-pseudonym/";

/// Derive a group-specific pseudonym for a member.
///
/// Each member independently derives their own group pseudonym.
/// Other members verify it by re-deriving from the member's IK_pub + group_id.
///
/// **Properties:**
/// - Deterministic: same (IK_pub, group_id) always produces the same pseudonym.
/// - Unlinkable: different group_ids produce different pseudonyms for the same member.
/// - Verifiable: any member who knows IK_pub can verify a group pseudonym.
pub fn derive_group_pseudonym(
    member_ik_pub: &Ed25519Public,
    group_id: &[u8; 32],
) -> Result<Pseudonym> {
    let mut info = Vec::with_capacity(GROUP_PSEUDONYM_INFO_PREFIX.len() + 32 + 32);
    info.extend_from_slice(GROUP_PSEUDONYM_INFO_PREFIX);
    info.extend_from_slice(group_id);
    info.extend_from_slice(&member_ik_pub.to_bytes());

    let derived = hkdf_sha256(
        &member_ik_pub.to_bytes(), // IKM
        group_id,                  // salt = group_id
        &info,
        32,
    )
    .map_err(|e| PseudonymError::KeyDerivationFailed(e.to_string()))?;

    Ok(Pseudonym(
        derived[..].try_into().expect("HKDF returned 32 bytes"),
    ))
}

/// Verify that a claimed group pseudonym matches the member's identity key.
pub fn verify_group_pseudonym(
    claimed: &Pseudonym,
    member_ik_pub: &Ed25519Public,
    group_id: &[u8; 32],
) -> Result<bool> {
    let expected = derive_group_pseudonym(member_ik_pub, group_id)?;
    Ok(constant_time_eq(&claimed.0, &expected.0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use najwa_crypto::keys::Ed25519KeyPair;

    fn pub_key(seed: u8) -> Ed25519Public {
        let kp = Ed25519KeyPair::from_seed(&[seed; 32]);
        Ed25519Public::from_bytes(&kp.public().to_bytes()).unwrap()
    }

    #[test]
    fn group_pseudonym_deterministic() {
        let pk = pub_key(0x01);
        let group_id = [0xAA; 32];

        let p1 = derive_group_pseudonym(&pk, &group_id).unwrap();
        let p2 = derive_group_pseudonym(&pk, &group_id).unwrap();
        assert_eq!(p1, p2);
    }

    #[test]
    fn different_groups_different_pseudonyms() {
        let pk = pub_key(0x01);
        let g1 = [0x01; 32];
        let g2 = [0x02; 32];

        let p1 = derive_group_pseudonym(&pk, &g1).unwrap();
        let p2 = derive_group_pseudonym(&pk, &g2).unwrap();
        assert_ne!(p1, p2);
    }

    #[test]
    fn different_members_different_pseudonyms() {
        let pk1 = pub_key(0x01);
        let pk2 = pub_key(0x02);
        let group_id = [0xAA; 32];

        let p1 = derive_group_pseudonym(&pk1, &group_id).unwrap();
        let p2 = derive_group_pseudonym(&pk2, &group_id).unwrap();
        assert_ne!(p1, p2);
    }

    #[test]
    fn verify_correct_pseudonym() {
        let pk = pub_key(0x01);
        let group_id = [0xAA; 32];
        let pseudo = derive_group_pseudonym(&pk, &group_id).unwrap();

        assert!(verify_group_pseudonym(&pseudo, &pk, &group_id).unwrap());
    }

    #[test]
    fn verify_wrong_pseudonym() {
        let pk = pub_key(0x01);
        let group_id = [0xAA; 32];
        let fake = Pseudonym([0xFF; 32]);

        assert!(!verify_group_pseudonym(&fake, &pk, &group_id).unwrap());
    }

    #[test]
    fn verify_wrong_group_fails() {
        let pk = pub_key(0x01);
        let g1 = [0x01; 32];
        let g2 = [0x02; 32];
        let pseudo = derive_group_pseudonym(&pk, &g1).unwrap();

        assert!(!verify_group_pseudonym(&pseudo, &pk, &g2).unwrap());
    }
}
