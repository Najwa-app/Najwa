//! Contact introduction payload (S05 §11).
//!
//! Alice introduces Bob to Charlie by sending each of them an
//! `IntroductionPayload` containing the other's identity key and
//! mailbox information, signed by Alice.
//!
//! Flow:
//! 1. Alice creates two payloads: one for Bob (about Charlie), one for Charlie (about Bob)
//! 2. Each recipient verifies Alice's signature
//! 3. If accepted, auto-initiate X3DH between the introduced parties

use najwa_crypto::keys::{Ed25519KeyPair, Ed25519Public, Ed25519Signature};
use najwa_crypto::time::now;

/// A complete deposit destination, shared only inside the encrypted introduction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntroductionMailbox {
    pub onion_address: String,
    pub deposit_capability: [u8; 32],
    pub envelope_secret: [u8; 32],
}

/// Current introduction payload version.
pub const INTRODUCTION_VERSION: u8 = 0x02;

/// Default introduction validity in days (7 days).
pub const DEFAULT_INTRODUCTION_VALIDITY_DAYS: u32 = 7;

/// Errors during introduction operations.
#[derive(Debug, thiserror::Error)]
pub enum IntroductionError {
    /// Introduction has expired.
    #[error("introduction expired")]
    Expired,

    /// Introducer's identity key does not match.
    #[error("introducer identity key mismatch")]
    IntroducerMismatch,

    /// Signature verification failed.
    #[error("invalid signature: {0}")]
    InvalidSignature(String),

    /// The introduced contact is already known.
    #[error("already a contact")]
    AlreadyContact,

    /// Payload format is invalid.
    #[error("invalid format: {0}")]
    InvalidFormat(String),

    /// Unsupported payload version.
    #[error("unsupported version: {0}")]
    UnsupportedVersion(u8),

    /// Crypto error.
    #[error("crypto error: {0}")]
    CryptoError(String),

    /// Storage error.
    #[error("storage error: {0}")]
    StorageError(String),
}

impl From<najwa_crypto::error::CryptoError> for IntroductionError {
    fn from(e: najwa_crypto::error::CryptoError) -> Self {
        Self::CryptoError(e.to_string())
    }
}

/// Mutual introduction payload (S05 §11.1).
///
/// Contains everything the recipient needs to:
/// 1. Verify the introducer's identity (signature)
/// 2. Identify the introduced contact (IK + display name)
/// 3. Reach the introduced contact (mailbox endpoints)
#[derive(Debug, Clone)]
pub struct IntroductionPayload {
    /// Protocol version (0x02; includes per-destination envelope secrets).
    pub version: u8,
    /// Identity public key of the person being introduced (32 bytes).
    pub introduced_ik_pub: [u8; 32],
    /// Display name of the introduced person.
    pub introduced_display_name: String,
    /// Mailbox endpoints for the introduced person.
    pub introduced_mailboxes: Vec<IntroductionMailbox>,
    /// Identity public key of the introducer (32 bytes).
    pub introducer_ik_pub: [u8; 32],
    /// Ed25519 signature by the introducer over all above fields (64 bytes).
    pub introducer_signature: [u8; 64],
    /// Creation timestamp (Unix seconds).
    pub timestamp: u64,
    /// Expiration timestamp (Unix seconds).
    pub expires_at: u64,
}

impl IntroductionPayload {
    /// Create an introduction payload signed by the introducer (S05 §11.2).
    ///
    /// Alice introduces Bob to Charlie:
    /// - `introducer_ik`: Alice's Ed25519 key pair
    /// - `introduced_ik_pub`: Bob's (or Charlie's) identity public key
    /// - `introduced_display_name`: Bob's (or Charlie's) display name
    /// - `introduced_mailboxes`: Bob's (or Charlie's) mailbox endpoints
    /// - `validity_days`: how many days the introduction remains valid (default 7)
    pub fn create(
        introducer_ik: &Ed25519KeyPair,
        introduced_ik_pub: &[u8; 32],
        introduced_display_name: &str,
        introduced_mailboxes: &[IntroductionMailbox],
        validity_days: u32,
    ) -> Result<Self, IntroductionError> {
        let ts = now();
        let mut payload = Self {
            version: INTRODUCTION_VERSION,
            introduced_ik_pub: *introduced_ik_pub,
            introduced_display_name: introduced_display_name.to_string(),
            introduced_mailboxes: introduced_mailboxes.to_vec(),
            introducer_ik_pub: introducer_ik.public().to_bytes(),
            introducer_signature: [0u8; 64],
            timestamp: ts,
            expires_at: ts + (validity_days as u64 * 86400),
        };

        payload.validate_structure()?;
        // Sign all fields except the signature itself
        let signable = payload.signable_bytes();
        payload.introducer_signature = introducer_ik.sign(&signable).to_bytes();
        Ok(payload)
    }

    /// Create an introduction signed with a one-time ephemeral key instead of the
    /// introducer's identity key. Receivers reject it as `IntroducerMismatch`;
    /// no app path calls this.
    ///
    /// The introducer generates a one-time Ed25519 key pair so their real
    /// identity is not revealed to the introduced parties. The ephemeral
    /// public key is stored in `introducer_ik_pub` — the recipient cannot
    /// link it to the real introducer.
    pub fn create_anonymous(
        introduced_ik_pub: &[u8; 32],
        introduced_display_name: &str,
        introduced_mailboxes: &[IntroductionMailbox],
        validity_days: u32,
    ) -> Result<Self, IntroductionError> {
        let ephemeral_ik = Ed25519KeyPair::generate(&mut rand::rngs::OsRng);
        Self::create(
            &ephemeral_ik,
            introduced_ik_pub,
            introduced_display_name,
            introduced_mailboxes,
            validity_days,
        )
    }

    /// Verify introduction authenticity (S05 §11.2, §11.4).
    ///
    /// Checks:
    /// 1. Payload has not expired
    /// 2. Introducer's key matches what we know
    /// 3. Signature over all fields is valid
    pub fn verify(&self, introducer_ik_pub: &Ed25519Public) -> Result<(), IntroductionError> {
        self.validate_structure()?;
        // 1. Check expiration
        if now() > self.expires_at {
            return Err(IntroductionError::Expired);
        }

        // 2. Verify introducer's key matches
        if introducer_ik_pub.to_bytes() != self.introducer_ik_pub {
            return Err(IntroductionError::IntroducerMismatch);
        }

        // 3. Verify signature
        let sig = Ed25519Signature::from_bytes(&self.introducer_signature)
            .map_err(|e| IntroductionError::InvalidSignature(e.to_string()))?;
        introducer_ik_pub
            .verify(&self.signable_bytes(), &sig)
            .map_err(|e| IntroductionError::InvalidSignature(e.to_string()))?;

        Ok(())
    }

    /// Verify with a custom timestamp (for testing expiration logic).
    #[cfg(test)]
    pub(crate) fn verify_at(
        &self,
        ts: u64,
        introducer_ik_pub: &Ed25519Public,
    ) -> Result<(), IntroductionError> {
        self.validate_structure()?;
        if ts > self.expires_at {
            return Err(IntroductionError::Expired);
        }
        if introducer_ik_pub.to_bytes() != self.introducer_ik_pub {
            return Err(IntroductionError::IntroducerMismatch);
        }
        let sig = Ed25519Signature::from_bytes(&self.introducer_signature)
            .map_err(|e| IntroductionError::InvalidSignature(e.to_string()))?;
        introducer_ik_pub
            .verify(&self.signable_bytes(), &sig)
            .map_err(|e| IntroductionError::InvalidSignature(e.to_string()))?;
        Ok(())
    }

    fn validate_structure(&self) -> Result<(), IntroductionError> {
        if self.version != INTRODUCTION_VERSION {
            return Err(IntroductionError::UnsupportedVersion(self.version));
        }
        if self.introduced_mailboxes.len() > 8
            || self.introduced_display_name.len() > 128
            || self.expires_at <= self.timestamp
            || self
                .introduced_mailboxes
                .iter()
                .any(|m| m.onion_address.is_empty() || m.onion_address.len() > 56)
        {
            return Err(IntroductionError::InvalidFormat(
                "invalid introduction structure".into(),
            ));
        }
        Ok(())
    }

    /// Return the bytes covered by the introducer's signature.
    ///
    /// This is everything in the serialized payload except the final 64-byte signature.
    pub fn signable_bytes(&self) -> Vec<u8> {
        let full = self.to_bytes();
        // Everything before the last 64 bytes (the signature)
        full[..full.len() - 64].to_vec()
    }

    // -----------------------------------------------------------------------
    // Binary serialization
    // -----------------------------------------------------------------------

    /// Serialize the introduction payload to bytes.
    ///
    /// Wire format:
    /// ```text
    /// version(1) || introduced_ik_pub(32) ||
    /// mailbox_count(2 BE) || [mailbox_info...] ||
    /// display_name_len(2 BE) || display_name(UTF-8) ||
    /// introducer_ik_pub(32) ||
    /// timestamp(8 BE) || expires_at(8 BE) ||
    /// introducer_signature(64)
    /// ```
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);

        // Header
        buf.push(self.version);
        buf.extend_from_slice(&self.introduced_ik_pub);

        // Mailboxes
        let mb_count = self.introduced_mailboxes.len() as u16;
        buf.extend_from_slice(&mb_count.to_be_bytes());
        for mb in &self.introduced_mailboxes {
            let addr_bytes = mb.onion_address.as_bytes();
            buf.extend_from_slice(&(addr_bytes.len() as u16).to_be_bytes());
            buf.extend_from_slice(addr_bytes);
            buf.extend_from_slice(&mb.deposit_capability);
            buf.extend_from_slice(&mb.envelope_secret);
        }

        // Display name
        let name_bytes = self.introduced_display_name.as_bytes();
        buf.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(name_bytes);

        // Introducer key
        buf.extend_from_slice(&self.introducer_ik_pub);

        // Timestamps
        buf.extend_from_slice(&self.timestamp.to_be_bytes());
        buf.extend_from_slice(&self.expires_at.to_be_bytes());

        // Signature (last 64 bytes)
        buf.extend_from_slice(&self.introducer_signature);

        buf
    }

    /// Deserialize an introduction payload from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, IntroductionError> {
        // Minimum size: version(1) + ik(32) + mb_count(2) + name_len(2)
        //             + introducer_ik(32) + ts(8) + expires(8) + sig(64) = 149
        const MIN_SIZE: usize = 149;
        if data.len() > super::types::MAX_HANDSHAKE_SIZE {
            return Err(IntroductionError::InvalidFormat(
                "introduction too large".into(),
            ));
        }
        if data.len() < MIN_SIZE {
            return Err(IntroductionError::InvalidFormat(format!(
                "too short: {} < {}",
                data.len(),
                MIN_SIZE
            )));
        }

        let mut pos = 0;

        // Version
        let version = data[pos];
        pos += 1;
        if version != INTRODUCTION_VERSION {
            return Err(IntroductionError::UnsupportedVersion(version));
        }

        // introduced_ik_pub
        let introduced_ik_pub: [u8; 32] = data[pos..pos + 32]
            .try_into()
            .map_err(|_| IntroductionError::InvalidFormat("introduced_ik truncated".into()))?;
        pos += 32;

        // Mailboxes
        if pos + 2 > data.len() {
            return Err(IntroductionError::InvalidFormat(
                "mailbox count truncated".into(),
            ));
        }
        let mb_count = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;

        if mb_count > super::types::MAX_MAILBOX_COUNT as usize {
            return Err(IntroductionError::InvalidFormat(
                "invalid mailbox count".into(),
            ));
        }
        let mut introduced_mailboxes = Vec::with_capacity(mb_count);
        for _ in 0..mb_count {
            if pos + 2 > data.len() {
                return Err(IntroductionError::InvalidFormat(
                    "mailbox addr_len truncated".into(),
                ));
            }
            let addr_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
            pos += 2;

            if addr_len == 0 || addr_len > 56 || pos + addr_len + 64 > data.len() {
                return Err(IntroductionError::InvalidFormat(
                    "mailbox entry truncated".into(),
                ));
            }
            let onion_address = std::str::from_utf8(&data[pos..pos + addr_len])
                .map_err(|_| {
                    IntroductionError::InvalidFormat("invalid UTF-8 in onion addr".into())
                })?
                .to_string();
            pos += addr_len;

            let deposit_capability: [u8; 32] = data[pos..pos + 32]
                .try_into()
                .map_err(|_| IntroductionError::InvalidFormat("deposit_cap truncated".into()))?;
            pos += 32;

            let envelope_secret = data[pos..pos + 32].try_into().unwrap();
            pos += 32;

            introduced_mailboxes.push(IntroductionMailbox {
                onion_address,
                deposit_capability,
                envelope_secret,
            });
        }

        // Display name
        if pos + 2 > data.len() {
            return Err(IntroductionError::InvalidFormat(
                "display_name_len truncated".into(),
            ));
        }
        let name_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;

        if pos + name_len > data.len() {
            return Err(IntroductionError::InvalidFormat(
                "display_name truncated".into(),
            ));
        }
        let introduced_display_name = std::str::from_utf8(&data[pos..pos + name_len])
            .map_err(|_| IntroductionError::InvalidFormat("invalid UTF-8 in display name".into()))?
            .to_string();
        pos += name_len;

        // Introducer key + timestamps + signature
        if pos + 32 + 8 + 8 + 64 > data.len() {
            return Err(IntroductionError::InvalidFormat(
                "introducer/timestamps/signature truncated".into(),
            ));
        }

        let introducer_ik_pub: [u8; 32] = data[pos..pos + 32]
            .try_into()
            .map_err(|_| IntroductionError::InvalidFormat("introducer_ik truncated".into()))?;
        pos += 32;

        let timestamp = u64::from_be_bytes(
            data[pos..pos + 8]
                .try_into()
                .map_err(|_| IntroductionError::InvalidFormat("timestamp truncated".into()))?,
        );
        pos += 8;
        let expires_at = u64::from_be_bytes(
            data[pos..pos + 8]
                .try_into()
                .map_err(|_| IntroductionError::InvalidFormat("expires_at truncated".into()))?,
        );
        pos += 8;

        let introducer_signature: [u8; 64] = data[pos..pos + 64]
            .try_into()
            .map_err(|_| IntroductionError::InvalidFormat("signature truncated".into()))?;

        if pos + 64 != data.len() {
            return Err(IntroductionError::InvalidFormat(
                "trailing introduction bytes".into(),
            ));
        }
        let payload = Self {
            version,
            introduced_ik_pub,
            introduced_display_name,
            introduced_mailboxes,
            introducer_ik_pub,
            introducer_signature,
            timestamp,
            expires_at,
        };
        payload.validate_structure()?;
        Ok(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alice_keys() -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed(&[0x01; 32])
    }

    fn bob_ik_pub() -> [u8; 32] {
        Ed25519KeyPair::from_seed(&[0x02; 32]).public().to_bytes()
    }

    fn charlie_ik_pub() -> [u8; 32] {
        Ed25519KeyPair::from_seed(&[0x03; 32]).public().to_bytes()
    }

    fn test_mailboxes() -> Vec<IntroductionMailbox> {
        vec![IntroductionMailbox {
            onion_address: "testmailbox123456.onion".to_string(),
            deposit_capability: [0xAA; 32],
            envelope_secret: [0xE1; 32],
        }]
    }

    // -- Introduction round-trip --

    #[test]
    fn create_verify_roundtrip() {
        let alice = alice_keys();
        let bob_ik = bob_ik_pub();

        let intro =
            IntroductionPayload::create(&alice, &bob_ik, "Bob", &test_mailboxes(), 7).unwrap();

        assert_eq!(intro.version, INTRODUCTION_VERSION);
        assert_eq!(intro.introduced_ik_pub, bob_ik);
        assert_eq!(intro.introduced_display_name, "Bob");
        assert_eq!(intro.introduced_mailboxes.len(), 1);
        assert_eq!(intro.introducer_ik_pub, alice.public().to_bytes());

        // Verify with Alice's known public key
        assert!(intro.verify(alice.public()).is_ok());
    }

    #[test]
    fn bytes_serialization_roundtrip() {
        let alice = alice_keys();
        let intro = IntroductionPayload::create(&alice, &bob_ik_pub(), "Bob", &test_mailboxes(), 7)
            .unwrap();

        let bytes = intro.to_bytes();
        let restored = IntroductionPayload::from_bytes(&bytes).unwrap();

        assert_eq!(restored.version, intro.version);
        assert_eq!(restored.introduced_ik_pub, intro.introduced_ik_pub);
        assert_eq!(
            restored.introduced_display_name,
            intro.introduced_display_name
        );
        assert_eq!(
            restored.introduced_mailboxes.len(),
            intro.introduced_mailboxes.len()
        );
        assert_eq!(restored.introducer_ik_pub, intro.introducer_ik_pub);
        assert_eq!(restored.introducer_signature, intro.introducer_signature);
        assert_eq!(restored.timestamp, intro.timestamp);
        assert_eq!(restored.expires_at, intro.expires_at);

        // Restored should verify
        assert!(restored.verify(alice.public()).is_ok());
    }

    #[test]
    fn mutual_introduction_creates_two_payloads() {
        let alice = alice_keys();
        let bob_ik = bob_ik_pub();
        let charlie_ik = charlie_ik_pub();

        // Alice introduces Bob to Charlie (sends to Charlie)
        let intro_for_charlie =
            IntroductionPayload::create(&alice, &bob_ik, "Bob", &test_mailboxes(), 7).unwrap();

        // Alice introduces Charlie to Bob (sends to Bob)
        let intro_for_bob =
            IntroductionPayload::create(&alice, &charlie_ik, "Charlie", &test_mailboxes(), 7)
                .unwrap();

        // Both verify with Alice's key
        assert!(intro_for_charlie.verify(alice.public()).is_ok());
        assert!(intro_for_bob.verify(alice.public()).is_ok());

        // Each contains the correct introduced party
        assert_eq!(intro_for_charlie.introduced_ik_pub, bob_ik);
        assert_eq!(intro_for_bob.introduced_ik_pub, charlie_ik);
    }

    // -- Expired introduction rejection --

    #[test]
    fn expired_introduction_rejected() {
        let alice = alice_keys();
        let intro = IntroductionPayload::create(&alice, &bob_ik_pub(), "Bob", &test_mailboxes(), 7)
            .unwrap();

        // Verify at a time far in the future (past expiration)
        let future_ts = intro.expires_at + 1;
        assert!(matches!(
            intro.verify_at(future_ts, alice.public()),
            Err(IntroductionError::Expired)
        ));
    }

    #[test]
    fn wrong_introducer_rejected() {
        let alice = alice_keys();
        let eve = Ed25519KeyPair::from_seed(&[0xFF; 32]);

        let intro = IntroductionPayload::create(&alice, &bob_ik_pub(), "Bob", &test_mailboxes(), 7)
            .unwrap();

        // Try to verify with Eve's key instead of Alice's
        assert!(matches!(
            intro.verify(eve.public()),
            Err(IntroductionError::IntroducerMismatch)
        ));
    }

    #[test]
    fn tampered_introduction_rejected() {
        let alice = alice_keys();
        let mut intro =
            IntroductionPayload::create(&alice, &bob_ik_pub(), "Bob", &test_mailboxes(), 7)
                .unwrap();

        // Tamper with the display name
        intro.introduced_display_name = "Evil".to_string();

        // Signature should fail
        assert!(intro.verify(alice.public()).is_err());
    }

    #[test]
    fn empty_mailboxes_allowed() {
        let alice = alice_keys();
        let intro = IntroductionPayload::create(
            &alice,
            &bob_ik_pub(),
            "Bob",
            &[], // No mailboxes
            7,
        )
        .unwrap();

        assert!(intro.verify(alice.public()).is_ok());
        assert!(intro.introduced_mailboxes.is_empty());
    }

    #[test]
    fn multiple_mailboxes_preserved() {
        let alice = alice_keys();
        let mbs = vec![
            IntroductionMailbox {
                onion_address: "first.onion".to_string(),
                deposit_capability: [0xAA; 32],
                envelope_secret: [0xE1; 32],
            },
            IntroductionMailbox {
                onion_address: "second.onion".to_string(),
                deposit_capability: [0xBB; 32],
                envelope_secret: [0xE1; 32],
            },
        ];

        let intro = IntroductionPayload::create(&alice, &bob_ik_pub(), "Bob", &mbs, 7).unwrap();

        assert_eq!(intro.introduced_mailboxes.len(), 2);
        assert!(intro.verify(alice.public()).is_ok());

        // Roundtrip preserves all mailboxes
        let bytes = intro.to_bytes();
        let restored = IntroductionPayload::from_bytes(&bytes).unwrap();
        assert_eq!(restored.introduced_mailboxes.len(), 2);
        assert_eq!(
            restored.introduced_mailboxes[0].onion_address,
            "first.onion"
        );
        assert_eq!(
            restored.introduced_mailboxes[1].onion_address,
            "second.onion"
        );
    }

    #[test]
    fn from_bytes_rejects_truncated() {
        assert!(IntroductionPayload::from_bytes(&[0u8; 10]).is_err());
    }

    #[test]
    fn from_bytes_rejects_wrong_version() {
        let alice = alice_keys();
        let intro = IntroductionPayload::create(&alice, &bob_ik_pub(), "Bob", &test_mailboxes(), 7)
            .unwrap();
        let mut bytes = intro.to_bytes();
        bytes[0] = 0xFF; // Wrong version
        assert!(matches!(
            IntroductionPayload::from_bytes(&bytes),
            Err(IntroductionError::UnsupportedVersion(0xFF))
        ));
    }
}
