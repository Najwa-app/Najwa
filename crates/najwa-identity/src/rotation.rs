//! Identity key rotation library. Not used by the app. Its announcement
//! layout differs from the `0x21` body the receive path accepts (S02 §18.1).
//!
//! Provides:
//! - RotationAnnouncement with mutual cross-attestation
//! - Identity key rotation flow
//! - Identity history tracking
//! - Rotation verification (receiving side)

use najwa_crypto::keys::ed25519::{Ed25519KeyPair, Ed25519Public, Ed25519Signature};
use najwa_crypto::prelude::*;

use crate::creation::create_identity_from_seed;
use crate::error::IdentityError;
use crate::record::{Identity, IdentityRecordStandard};

/// Rotation announcement with mutual attestation.
///
/// Both the old and new keys sign the other to prove ownership of both.
#[derive(Debug, Clone)]
pub struct RotationAnnouncement {
    /// Public key of the old (current) identity.
    pub old_ik_pub: [u8; 32],
    /// Public key of the new identity.
    pub new_ik_pub: [u8; 32],
    /// Old key signs new key (proves old key holder authorized rotation).
    pub signature_old: [u8; 64],
    /// New key signs old key (proves new key holder is same person).
    pub signature_new: [u8; 64],
    /// Unix timestamp of rotation.
    pub timestamp: u64,
}

impl RotationAnnouncement {
    /// Serialize to bytes for transport.
    ///
    /// Format: old_ik_pub(32) || new_ik_pub(32) || sig_old(64) || sig_new(64) || timestamp(8BE)
    /// Total: 200 bytes.
    pub fn to_bytes(&self) -> [u8; 200] {
        let mut out = [0u8; 200];
        out[0..32].copy_from_slice(&self.old_ik_pub);
        out[32..64].copy_from_slice(&self.new_ik_pub);
        out[64..128].copy_from_slice(&self.signature_old);
        out[128..192].copy_from_slice(&self.signature_new);
        out[192..200].copy_from_slice(&self.timestamp.to_be_bytes());
        out
    }

    /// Deserialize from bytes.
    pub fn from_bytes(data: &[u8]) -> std::result::Result<Self, RotationError> {
        if data.len() < 200 {
            return Err(RotationError::InvalidFormat("too short".into()));
        }
        let map_err = |_| RotationError::InvalidFormat("slice conversion failed".into());
        let old_ik_pub: [u8; 32] = data[0..32].try_into().map_err(map_err)?;
        let new_ik_pub: [u8; 32] = data[32..64].try_into().map_err(map_err)?;
        let signature_old: [u8; 64] = data[64..128].try_into().map_err(map_err)?;
        let signature_new: [u8; 64] = data[128..192].try_into().map_err(map_err)?;
        let timestamp = u64::from_be_bytes(data[192..200].try_into().map_err(map_err)?);
        Ok(Self {
            old_ik_pub,
            new_ik_pub,
            signature_old,
            signature_new,
            timestamp,
        })
    }
}

/// Errors specific to key rotation.
#[derive(Debug, thiserror::Error)]
pub enum RotationError {
    /// Old key in announcement doesn't match known contact key.
    #[error("unknown old key: announcement old_ik_pub doesn't match contact")]
    UnknownOldKey,

    /// Cross-attestation signature verification failed.
    #[error("signature verification failed: {0}")]
    SignatureVerificationFailed(String),

    /// Invalid announcement format.
    #[error("invalid rotation announcement: {0}")]
    InvalidFormat(String),

    /// Wrapped identity error.
    #[error(transparent)]
    Identity(#[from] IdentityError),

    /// Wrapped crypto error.
    #[error(transparent)]
    Crypto(#[from] najwa_crypto::error::CryptoError),
}

/// Result of rotation verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationResult {
    /// Both cross-attestation signatures verified successfully.
    Valid,
}

/// Maximum number of retry attempts for rotation announcement delivery.
pub const ROTATION_ANNOUNCEMENT_MAX_RETRIES: u32 = 5;

/// Delay between retry attempts in seconds (exponential backoff base).
pub const ROTATION_ANNOUNCEMENT_RETRY_BASE_SECS: u64 = 3600; // 1 hour

/// Grace period for accepting messages under the old pseudonym.
/// After rotation, the old pseudonym is accepted for 30 days to handle in-flight
/// messages and contacts who haven't processed the rotation announcement yet.
pub const OLD_PSEUDONYM_GRACE_PERIOD_SECS: u64 = 30 * 86_400; // 30 days

/// Reason for key rotation (for history tracking).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationReason {
    /// User initiated the rotation manually.
    UserInitiated,
    /// Rotation due to suspected compromise.
    SuspectedCompromise,
    /// Rotation after device recovery.
    DeviceRecovery,
}

/// An entry in the identity history log.
#[derive(Debug, Clone)]
pub struct IdentityHistoryEntry {
    /// The public key that was rotated away from.
    pub ik_pub: [u8; 32],
    /// When this key was rotated.
    pub rotated_at: u64,
    /// Why this key was rotated.
    pub reason: RotationReason,
}

/// In-memory identity history tracker.
#[derive(Debug, Clone, Default)]
pub struct IdentityHistory {
    entries: Vec<IdentityHistoryEntry>,
}

impl IdentityHistory {
    /// Create a new empty history.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Record a rotation event.
    pub fn record_rotation(&mut self, ik_pub: [u8; 32], reason: RotationReason) {
        self.entries.push(IdentityHistoryEntry {
            ik_pub,
            rotated_at: now(),
            reason,
        });
    }

    /// Record a rotation event with explicit timestamp (for testing).
    pub fn record_rotation_at(
        &mut self,
        ik_pub: [u8; 32],
        rotated_at: u64,
        reason: RotationReason,
    ) {
        self.entries.push(IdentityHistoryEntry {
            ik_pub,
            rotated_at,
            reason,
        });
    }

    /// Get all history entries.
    pub fn entries(&self) -> &[IdentityHistoryEntry] {
        &self.entries
    }

    /// Check if a given public key was a previous identity.
    pub fn was_previous_key(&self, ik_pub: &[u8; 32]) -> bool {
        self.entries.iter().any(|e| &e.ik_pub == ik_pub)
    }

    /// Number of past rotations.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether there is any rotation history.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Create a rotation announcement.
///
/// Generates a new identity key pair and creates mutual cross-attestation:
/// - Old key signs new key's public bytes
/// - New key signs old key's public bytes
pub fn create_rotation_announcement(
    old_keypair: &Ed25519KeyPair,
) -> (RotationAnnouncement, [u8; 32], Ed25519KeyPair) {
    // 1. Generate new identity seed and key pair
    let new_seed: [u8; 32] = random_bytes();
    let new_keypair = Ed25519KeyPair::from_seed(&new_seed);

    // 2. Cross-attestation signatures
    let sig_old = old_keypair.sign(&new_keypair.public().to_bytes());
    let sig_new = new_keypair.sign(&old_keypair.public().to_bytes());

    let announcement = RotationAnnouncement {
        old_ik_pub: old_keypair.public().to_bytes(),
        new_ik_pub: new_keypair.public().to_bytes(),
        signature_old: sig_old.to_bytes(),
        signature_new: sig_new.to_bytes(),
        timestamp: now(),
    };

    (announcement, new_seed, new_keypair)
}

/// Perform a full identity rotation.
///
/// 1. Generate new key pair and cross-attestation
/// 2. Create new identity record encrypted with password
/// 3. Return announcement + new record + new identity
///
/// Caller is responsible for:
/// - Persisting the new record to disk
/// - Re-deriving pseudonyms
/// - Announcing rotation to contacts
/// - Uploading new prekey bundle
/// - Recording identity history
pub fn rotate_identity_key(
    current_identity: &Identity,
    password: &str,
) -> std::result::Result<
    (
        RotationAnnouncement,
        IdentityRecordStandard,
        Identity,
        [u8; 32],
    ),
    RotationError,
> {
    // 1. Create rotation announcement
    let (announcement, new_seed, _new_keypair) =
        create_rotation_announcement(&current_identity.keypair);

    // 2. Create new identity record with new seed
    let (new_record, new_identity) = create_identity_from_seed(&new_seed, password, None)?;

    Ok((announcement, new_record, new_identity, new_seed))
}

/// Verify a key rotation announcement in this module's layout. The receive
/// path verifies `0x21` bodies with its own checks (S02 §18.1).
///
/// Checks:
/// 1. Old key matches the known contact key
/// 2. Old key signed the new key
/// 3. New key signed the old key
pub fn verify_key_rotation(
    known_contact_ik_pub: &[u8; 32],
    announcement: &RotationAnnouncement,
) -> std::result::Result<VerificationResult, RotationError> {
    // 1. Verify old key matches what we have for this contact
    if known_contact_ik_pub != &announcement.old_ik_pub {
        return Err(RotationError::UnknownOldKey);
    }

    // 2. Verify old key signed new key
    let old_pub = Ed25519Public::from_bytes(&announcement.old_ik_pub)?;
    let sig_old = Ed25519Signature::from_bytes(&announcement.signature_old)?;
    old_pub
        .verify(&announcement.new_ik_pub, &sig_old)
        .map_err(|_| {
            RotationError::SignatureVerificationFailed("old key signature invalid".into())
        })?;

    // 3. Verify new key signed old key
    let new_pub = Ed25519Public::from_bytes(&announcement.new_ik_pub)?;
    let sig_new = Ed25519Signature::from_bytes(&announcement.signature_new)?;
    new_pub
        .verify(&announcement.old_ik_pub, &sig_new)
        .map_err(|_| {
            RotationError::SignatureVerificationFailed("new key signature invalid".into())
        })?;

    Ok(VerificationResult::Valid)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_keypair() -> Ed25519KeyPair {
        let seed: [u8; 32] = random_bytes();
        Ed25519KeyPair::from_seed(&seed)
    }

    fn make_test_identity() -> Identity {
        let keypair = make_test_keypair();
        Identity {
            keypair,
            created_at: 1000,
            version: 0x03,
        }
    }

    // -- RotationAnnouncement tests --

    #[test]
    fn rotation_announcement_serialization_roundtrip() {
        let old_kp = make_test_keypair();
        let (announcement, _, _) = create_rotation_announcement(&old_kp);

        let bytes = announcement.to_bytes();
        assert_eq!(bytes.len(), 200);

        let parsed = RotationAnnouncement::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.old_ik_pub, announcement.old_ik_pub);
        assert_eq!(parsed.new_ik_pub, announcement.new_ik_pub);
        assert_eq!(parsed.signature_old, announcement.signature_old);
        assert_eq!(parsed.signature_new, announcement.signature_new);
        assert_eq!(parsed.timestamp, announcement.timestamp);
    }

    #[test]
    fn rotation_announcement_too_short() {
        let result = RotationAnnouncement::from_bytes(&[0u8; 100]);
        assert!(result.is_err());
    }

    // -- Cross-attestation verification tests --

    #[test]
    fn verify_valid_rotation() {
        let old_kp = make_test_keypair();
        let old_pub = old_kp.public().to_bytes();
        let (announcement, _, _) = create_rotation_announcement(&old_kp);

        let result = verify_key_rotation(&old_pub, &announcement);
        assert_eq!(result.unwrap(), VerificationResult::Valid);
    }

    #[test]
    fn verify_rotation_wrong_old_key() {
        let old_kp = make_test_keypair();
        let (announcement, _, _) = create_rotation_announcement(&old_kp);

        let wrong_pub: [u8; 32] = random_bytes();
        // Will likely fail because random bytes aren't a valid Ed25519 pub,
        // but the first check (UnknownOldKey) will catch it anyway
        let result = verify_key_rotation(&wrong_pub, &announcement);
        assert!(matches!(result, Err(RotationError::UnknownOldKey)));
    }

    #[test]
    fn verify_rotation_tampered_old_signature() {
        let old_kp = make_test_keypair();
        let old_pub = old_kp.public().to_bytes();
        let (mut announcement, _, _) = create_rotation_announcement(&old_kp);

        announcement.signature_old[0] ^= 0xFF;

        let result = verify_key_rotation(&old_pub, &announcement);
        assert!(matches!(
            result,
            Err(RotationError::SignatureVerificationFailed(_))
        ));
    }

    #[test]
    fn verify_rotation_tampered_new_signature() {
        let old_kp = make_test_keypair();
        let old_pub = old_kp.public().to_bytes();
        let (mut announcement, _, _) = create_rotation_announcement(&old_kp);

        announcement.signature_new[0] ^= 0xFF;

        let result = verify_key_rotation(&old_pub, &announcement);
        assert!(matches!(
            result,
            Err(RotationError::SignatureVerificationFailed(_))
        ));
    }

    #[test]
    fn verify_rotation_swapped_keys() {
        let old_kp = make_test_keypair();
        let old_pub = old_kp.public().to_bytes();
        let (mut announcement, _, _) = create_rotation_announcement(&old_kp);

        // Swap old and new public keys (signatures won't match)
        std::mem::swap(&mut announcement.old_ik_pub, &mut announcement.new_ik_pub);

        // old_pub won't match the now-swapped old_ik_pub
        let result = verify_key_rotation(&old_pub, &announcement);
        assert!(result.is_err());
    }

    // -- Full rotation flow tests --

    #[test]
    fn rotate_identity_key_produces_new_key() {
        let identity = make_test_identity();
        let old_pub = identity.keypair.public().to_bytes();

        let (announcement, _record, new_identity, _seed) =
            rotate_identity_key(&identity, "test_password_123").unwrap();

        let new_pub = new_identity.keypair.public().to_bytes();

        // New key is different from old key
        assert_ne!(old_pub, new_pub);
        // Announcement references correct keys
        assert_eq!(announcement.old_ik_pub, old_pub);
        assert_eq!(announcement.new_ik_pub, new_pub);
    }

    #[test]
    fn rotate_and_verify_roundtrip() {
        let identity = make_test_identity();
        let old_pub = identity.keypair.public().to_bytes();

        let (announcement, _record, _new_identity, _seed) =
            rotate_identity_key(&identity, "test_password_123").unwrap();

        // Verify the announcement from the contact's perspective
        let result = verify_key_rotation(&old_pub, &announcement);
        assert_eq!(result.unwrap(), VerificationResult::Valid);
    }

    #[test]
    fn rotate_new_record_has_correct_pub_key() {
        let identity = make_test_identity();

        let (_announcement, record, new_identity, _seed) =
            rotate_identity_key(&identity, "test_password_123").unwrap();

        assert_eq!(record.ik_pub, new_identity.keypair.public().to_bytes());
    }

    // -- Identity history tests --

    #[test]
    fn identity_history_tracks_rotations() {
        let mut history = IdentityHistory::new();
        assert!(history.is_empty());

        let pub1: [u8; 32] = random_bytes();
        history.record_rotation_at(pub1, 1000, RotationReason::UserInitiated);

        assert_eq!(history.len(), 1);
        assert!(history.was_previous_key(&pub1));

        let pub2: [u8; 32] = random_bytes();
        assert!(!history.was_previous_key(&pub2));
    }

    #[test]
    fn identity_history_multiple_entries() {
        let mut history = IdentityHistory::new();

        let pub1: [u8; 32] = random_bytes();
        let pub2: [u8; 32] = random_bytes();
        history.record_rotation_at(pub1, 1000, RotationReason::UserInitiated);
        history.record_rotation_at(pub2, 2000, RotationReason::SuspectedCompromise);

        assert_eq!(history.len(), 2);
        assert!(history.was_previous_key(&pub1));
        assert!(history.was_previous_key(&pub2));

        let entries = history.entries();
        assert_eq!(entries[0].reason, RotationReason::UserInitiated);
        assert_eq!(entries[1].reason, RotationReason::SuspectedCompromise);
    }

    #[test]
    fn identity_history_device_recovery_reason() {
        let mut history = IdentityHistory::new();
        let pub1: [u8; 32] = random_bytes();
        history.record_rotation_at(pub1, 3000, RotationReason::DeviceRecovery);

        assert_eq!(history.entries()[0].reason, RotationReason::DeviceRecovery);
        assert_eq!(history.entries()[0].rotated_at, 3000);
    }
}
