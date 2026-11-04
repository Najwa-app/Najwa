//! Per-mailbox derived signing keys (S05 §3).
//!
//! Each mailbox uses a derived Ed25519 signing key to prevent cross-mailbox
//! identity linkage by colluding operators. Different servers see different,
//! unlinkable `mailbox_ik_pub` values.
//!
//! Also provides `MailboxCertificate` (S05 §2.3) which proves the derived
//! key belongs to the claimed identity.

use serde::{Deserialize, Serialize};

use najwa_crypto::kdf::{hkdf_sha256, info_strings};
use najwa_crypto::keys::ed25519::{Ed25519KeyPair, Ed25519Public};

use super::error::HandshakeError;

/// Derive a per-mailbox Ed25519 signing key from the identity private key
/// and the mailbox onion address (S05 §3).
///
/// ```text
/// seed = HKDF(
///     IKM  = IK_priv,
///     salt = UTF8(mailbox_onion_address),
///     info = "najwa/v1/mailbox-signing-key",
///     length = 32
/// )
/// (mailbox_ik_priv, mailbox_ik_pub) = Ed25519_Generate(seed)
/// ```
///
/// **Properties:**
/// - Deterministic: same `(IK_priv, onion_address)` always produces the same key
/// - Different servers see different, unlinkable `mailbox_ik_pub` values
pub fn derive_mailbox_signing_key(
    ik_priv: &[u8; 32],
    onion_address: &str,
) -> Result<Ed25519KeyPair, HandshakeError> {
    let seed_vec = zeroize::Zeroizing::new(hkdf_sha256(
        ik_priv,
        onion_address.as_bytes(),
        info_strings::MAILBOX_SIGNING_KEY_INFO,
        32,
    )
    .map_err(|e| HandshakeError::CryptoError(e.to_string()))?);

    let mut seed = zeroize::Zeroizing::new([0u8; 32]);
    seed.copy_from_slice(&seed_vec);
    Ok(Ed25519KeyPair::from_seed(&seed))
}

/// Size of a serialized MailboxCertificate (S05 §2.3).
pub const MAILBOX_CERTIFICATE_SIZE: usize = 200;

/// Default validity of a MailboxCertificate (S05 §2.3): 180 days in seconds.
/// `expires_at = created_at + MAILBOX_CERT_VALIDITY_SECS` — deterministic, so a
/// verifier reconstructs the same `expires_at` from the payload's `created_at`.
pub const MAILBOX_CERT_VALIDITY_SECS: u64 = 15_552_000;

/// A certificate proving the `mailbox_ik_pub` belongs to the claimed identity (S05 §2.3).
///
/// ```text
/// struct MailboxCertificate {
///     u8  ik_pub[32];             // Real identity public key
///     u8  mailbox_ik_pub[32];     // Derived mailbox signing key
///     u8  mailbox_onion[56];      // Onion address this key is for
///     u64 created_at;             // Timestamp (big-endian)
///     u64 expires_at;             // Expiration (big-endian), created_at + 180d
///     u8  signature[64];          // Ed25519_Sign(IK_priv, bytes 0–135)
/// }
/// ```
#[derive(Debug, Clone)]
pub struct MailboxCertificate {
    pub ik_pub: [u8; 32],
    pub mailbox_ik_pub: [u8; 32],
    pub mailbox_onion: [u8; 56],
    pub created_at: u64,
    pub expires_at: u64,
    pub signature: [u8; 64],
}

impl MailboxCertificate {
    /// Create a new certificate and sign it with the identity key (S05 §4.2).
    ///
    /// ```text
    /// cert_signable = ik_pub || mailbox_ik_pub || mailbox_onion || created_at || expires_at
    /// cert_signature = Ed25519_Sign(IK_priv, cert_signable)
    /// ```
    ///
    /// `expires_at` is `created_at + MAILBOX_CERT_VALIDITY_SECS` (180 days) so a
    /// verifier reconstructs it deterministically from `created_at`.
    pub fn create(
        ik: &Ed25519KeyPair,
        mailbox_ik_pub: &[u8; 32],
        onion_address: &str,
        created_at: u64,
    ) -> Self {
        let ik_pub = ik.public().to_bytes();
        let mut mailbox_onion = [0u8; 56];
        let onion_bytes = onion_address.as_bytes();
        let copy_len = onion_bytes.len().min(56);
        mailbox_onion[..copy_len].copy_from_slice(&onion_bytes[..copy_len]);

        let expires_at = created_at.saturating_add(MAILBOX_CERT_VALIDITY_SECS);
        let signable = Self::signable_bytes(
            &ik_pub,
            mailbox_ik_pub,
            &mailbox_onion,
            created_at,
            expires_at,
        );
        let signature = ik.sign(&signable);

        Self {
            ik_pub,
            mailbox_ik_pub: *mailbox_ik_pub,
            mailbox_onion,
            created_at,
            expires_at,
            signature: signature.to_bytes(),
        }
    }

    /// Verify the certificate signature and expiry against the claimed identity
    /// key, using the current wall-clock time.
    pub fn verify(&self, ik_pub: &Ed25519Public) -> Result<(), HandshakeError> {
        self.verify_at(ik_pub, najwa_crypto::time::now())
    }

    /// Verify against an explicit `now_ts` (S05 §8 step 6a expiry check;
    /// time-injectable so callers with a custom clock — e.g. `verify_at` on the
    /// enclosing handshake — check the cert against the same timestamp).
    pub fn verify_at(&self, ik_pub: &Ed25519Public, now_ts: u64) -> Result<(), HandshakeError> {
        if self.ik_pub != ik_pub.to_bytes() {
            return Err(HandshakeError::InvalidSignature(
                "certificate ik_pub does not match".into(),
            ));
        }

        let signable = Self::signable_bytes(
            &self.ik_pub,
            &self.mailbox_ik_pub,
            &self.mailbox_onion,
            self.created_at,
            self.expires_at,
        );

        let sig = najwa_crypto::keys::ed25519::Ed25519Signature::from_bytes(&self.signature)
            .map_err(|e| HandshakeError::CryptoError(e.to_string()))?;

        ik_pub.verify(&signable, &sig).map_err(|_| {
            HandshakeError::InvalidSignature("certificate signature verification failed".into())
        })?;

        // S05 §2.3 / §8 step 6a: an expired certificate MUST be rejected.
        if self.expires_at <= now_ts {
            return Err(HandshakeError::Expired);
        }

        Ok(())
    }

    /// Build the signable bytes: `ik_pub(32) || mailbox_ik_pub(32) || onion(56) || created_at(8) || expires_at(8)`.
    fn signable_bytes(
        ik_pub: &[u8; 32],
        mailbox_ik_pub: &[u8; 32],
        mailbox_onion: &[u8; 56],
        created_at: u64,
        expires_at: u64,
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(136);
        out.extend_from_slice(ik_pub);
        out.extend_from_slice(mailbox_ik_pub);
        out.extend_from_slice(mailbox_onion);
        out.extend_from_slice(&created_at.to_be_bytes());
        out.extend_from_slice(&expires_at.to_be_bytes());
        out
    }

    /// Serialize to 200 bytes.
    pub fn to_bytes(&self) -> [u8; MAILBOX_CERTIFICATE_SIZE] {
        let mut out = [0u8; MAILBOX_CERTIFICATE_SIZE];
        out[0..32].copy_from_slice(&self.ik_pub);
        out[32..64].copy_from_slice(&self.mailbox_ik_pub);
        out[64..120].copy_from_slice(&self.mailbox_onion);
        out[120..128].copy_from_slice(&self.created_at.to_be_bytes());
        out[128..136].copy_from_slice(&self.expires_at.to_be_bytes());
        out[136..200].copy_from_slice(&self.signature);
        out
    }

    /// Deserialize from 200 bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, HandshakeError> {
        if data.len() < MAILBOX_CERTIFICATE_SIZE {
            return Err(HandshakeError::InvalidFormat(format!(
                "certificate too short: {} < {}",
                data.len(),
                MAILBOX_CERTIFICATE_SIZE
            )));
        }

        let mut ik_pub = [0u8; 32];
        ik_pub.copy_from_slice(&data[0..32]);
        let mut mailbox_ik_pub = [0u8; 32];
        mailbox_ik_pub.copy_from_slice(&data[32..64]);
        let mut mailbox_onion = [0u8; 56];
        mailbox_onion.copy_from_slice(&data[64..120]);
        let created_at = u64::from_be_bytes(data[120..128].try_into().unwrap());
        let expires_at = u64::from_be_bytes(data[128..136].try_into().unwrap());
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&data[136..200]);

        Ok(Self {
            ik_pub,
            mailbox_ik_pub,
            mailbox_onion,
            created_at,
            expires_at,
            signature,
        })
    }
}

/// Size of a serialized MailboxEntry (S05 §2.2).
pub const MAILBOX_ENTRY_SIZE: usize = 217;

/// A single mailbox entry in a HandshakePayload (S05 §2.2).
///
/// ```text
/// struct MailboxEntry {
///     u8  onion_address[56];
///     u8  deposit_capability[32];     // Ephemeral 48h cap (server-known, routing)
///     u8  envelope_secret[32];        // D3: keys the deposit envelope; server NEVER sees it
///     u8  mailbox_ik_pub[32];         // Per-mailbox derived signing key
///     u8  cert_signature[64];         // Certificate signature
///     u8  capability_type;            // 0x01=ephemeral, 0x02=long-term
/// }
/// ```
/// The `envelope_secret` (D3) is authenticated by the enclosing HandshakePayload's
/// outer signature; the per-mailbox `cert_signature` does NOT cover the entry body.
/// Custom serde for `[u8; 56]`.
mod serde_byte_array_56 {
    use serde::{self, Deserialize, Deserializer, Serializer};
    pub fn serialize<S>(bytes: &[u8; 56], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(bytes)
    }
    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 56], D::Error>
    where
        D: Deserializer<'de>,
    {
        let v: Vec<u8> = Vec::deserialize(deserializer)?;
        v.try_into()
            .map_err(|_| serde::de::Error::custom("expected 56 bytes"))
    }
}

/// Custom serde for `[u8; 64]`.
mod serde_byte_array_64 {
    use serde::{self, Deserialize, Deserializer, Serializer};
    pub fn serialize<S>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(bytes)
    }
    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let v: Vec<u8> = Vec::deserialize(deserializer)?;
        v.try_into()
            .map_err(|_| serde::de::Error::custom("expected 64 bytes"))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailboxEntry {
    #[serde(with = "serde_byte_array_56")]
    pub onion_address: [u8; 56],
    pub deposit_capability: [u8; 32],
    /// D3: per-deposit-capability secret that keys the deposit envelope. Minted by
    /// the capability owner, shared only with parties given the deposit cap, and
    /// NEVER sent to the mailbox server (which stores the deposit_cap for routing).
    pub envelope_secret: [u8; 32],
    pub mailbox_ik_pub: [u8; 32],
    #[serde(with = "serde_byte_array_64")]
    pub cert_signature: [u8; 64],
    pub capability_type: u8,
}

/// Capability type: ephemeral (48h TTL).
pub const CAP_TYPE_EPHEMERAL: u8 = 0x01;
/// Capability type: long-term.
pub const CAP_TYPE_LONG_TERM: u8 = 0x02;

impl MailboxEntry {
    /// Serialize to 217 bytes.
    pub fn to_bytes(&self) -> [u8; MAILBOX_ENTRY_SIZE] {
        let mut out = [0u8; MAILBOX_ENTRY_SIZE];
        out[0..56].copy_from_slice(&self.onion_address);
        out[56..88].copy_from_slice(&self.deposit_capability);
        out[88..120].copy_from_slice(&self.envelope_secret);
        out[120..152].copy_from_slice(&self.mailbox_ik_pub);
        out[152..216].copy_from_slice(&self.cert_signature);
        out[216] = self.capability_type;
        out
    }

    /// Deserialize from 217 bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, HandshakeError> {
        if data.len() < MAILBOX_ENTRY_SIZE {
            return Err(HandshakeError::InvalidFormat(format!(
                "mailbox entry too short: {} < {}",
                data.len(),
                MAILBOX_ENTRY_SIZE
            )));
        }

        let mut onion_address = [0u8; 56];
        onion_address.copy_from_slice(&data[0..56]);
        let mut deposit_capability = [0u8; 32];
        deposit_capability.copy_from_slice(&data[56..88]);
        let mut envelope_secret = [0u8; 32];
        envelope_secret.copy_from_slice(&data[88..120]);
        let mut mailbox_ik_pub = [0u8; 32];
        mailbox_ik_pub.copy_from_slice(&data[120..152]);
        let mut cert_signature = [0u8; 64];
        cert_signature.copy_from_slice(&data[152..216]);
        let capability_type = data[216];

        Ok(Self {
            onion_address,
            deposit_capability,
            envelope_secret,
            mailbox_ik_pub,
            cert_signature,
            capability_type,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_keypair() -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed(&[0x42u8; 32])
    }

    #[test]
    fn derive_mailbox_key_deterministic() {
        let ik = test_keypair();
        let ik_priv = ik.private().to_bytes();

        let kp1 = derive_mailbox_signing_key(&ik_priv, "abc123.onion").unwrap();
        let kp2 = derive_mailbox_signing_key(&ik_priv, "abc123.onion").unwrap();
        assert_eq!(kp1.public().to_bytes(), kp2.public().to_bytes());
    }

    #[test]
    fn derive_mailbox_key_different_onions_differ() {
        let ik = test_keypair();
        let ik_priv = ik.private().to_bytes();

        let kp1 = derive_mailbox_signing_key(&ik_priv, "server1.onion").unwrap();
        let kp2 = derive_mailbox_signing_key(&ik_priv, "server2.onion").unwrap();
        assert_ne!(kp1.public().to_bytes(), kp2.public().to_bytes());
    }

    #[test]
    fn derive_mailbox_key_different_identities_differ() {
        let ik1 = Ed25519KeyPair::from_seed(&[0x01u8; 32]);
        let ik2 = Ed25519KeyPair::from_seed(&[0x02u8; 32]);

        let kp1 = derive_mailbox_signing_key(&ik1.private().to_bytes(), "same.onion").unwrap();
        let kp2 = derive_mailbox_signing_key(&ik2.private().to_bytes(), "same.onion").unwrap();
        assert_ne!(kp1.public().to_bytes(), kp2.public().to_bytes());
    }

    #[test]
    fn certificate_create_and_verify() {
        let ik = test_keypair();
        let mailbox_kp =
            derive_mailbox_signing_key(&ik.private().to_bytes(), "testmailbox.onion").unwrap();

        // A fresh cert verifies; expires_at = created_at + 180d.
        let now = najwa_crypto::time::now();
        let cert = MailboxCertificate::create(
            &ik,
            &mailbox_kp.public().to_bytes(),
            "testmailbox.onion",
            now,
        );
        assert_eq!(cert.expires_at, now + MAILBOX_CERT_VALIDITY_SECS);
        assert!(cert.verify(ik.public()).is_ok());

        // S05 §2.3 / §8 step 6a: an expired cert (created_at + 180d < now) is
        // rejected with HandshakeError::Expired.
        let old = MailboxCertificate::create(
            &ik,
            &mailbox_kp.public().to_bytes(),
            "testmailbox.onion",
            1000,
        );
        assert!(matches!(
            old.verify(ik.public()),
            Err(HandshakeError::Expired)
        ));
    }

    #[test]
    fn certificate_wrong_ik_fails() {
        let ik = test_keypair();
        let other_ik = Ed25519KeyPair::from_seed(&[0x99u8; 32]);
        let mailbox_kp =
            derive_mailbox_signing_key(&ik.private().to_bytes(), "testmailbox.onion").unwrap();

        let cert = MailboxCertificate::create(
            &ik,
            &mailbox_kp.public().to_bytes(),
            "testmailbox.onion",
            1000,
        );

        assert!(cert.verify(other_ik.public()).is_err());
    }

    #[test]
    fn certificate_roundtrip() {
        let ik = test_keypair();
        let mailbox_kp =
            derive_mailbox_signing_key(&ik.private().to_bytes(), "test.onion").unwrap();

        let created_at = najwa_crypto::time::now();
        let cert = MailboxCertificate::create(
            &ik,
            &mailbox_kp.public().to_bytes(),
            "test.onion",
            created_at,
        );

        let bytes = cert.to_bytes();
        assert_eq!(bytes.len(), MAILBOX_CERTIFICATE_SIZE);

        let restored = MailboxCertificate::from_bytes(&bytes).unwrap();
        assert_eq!(restored.ik_pub, cert.ik_pub);
        assert_eq!(restored.mailbox_ik_pub, cert.mailbox_ik_pub);
        assert_eq!(restored.created_at, created_at);
        assert_eq!(restored.expires_at, created_at + MAILBOX_CERT_VALIDITY_SECS);
        assert!(restored.verify(ik.public()).is_ok());
    }

    #[test]
    fn mailbox_entry_roundtrip() {
        let entry = MailboxEntry {
            onion_address: [0x01; 56],
            deposit_capability: [0x02; 32],
            envelope_secret: [0x07; 32],
            mailbox_ik_pub: [0x03; 32],
            cert_signature: [0x04; 64],
            capability_type: CAP_TYPE_EPHEMERAL,
        };

        let bytes = entry.to_bytes();
        assert_eq!(bytes.len(), MAILBOX_ENTRY_SIZE);

        let restored = MailboxEntry::from_bytes(&bytes).unwrap();
        assert_eq!(restored.onion_address, entry.onion_address);
        assert_eq!(restored.deposit_capability, entry.deposit_capability);
        assert_eq!(restored.envelope_secret, entry.envelope_secret);
        assert_eq!(restored.mailbox_ik_pub, entry.mailbox_ik_pub);
        assert_eq!(restored.cert_signature, entry.cert_signature);
        assert_eq!(restored.capability_type, CAP_TYPE_EPHEMERAL);
    }

    #[test]
    fn mailbox_entry_too_short_rejected() {
        assert!(MailboxEntry::from_bytes(&[0u8; 100]).is_err());
    }
}
