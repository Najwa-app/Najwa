//! Handshake payload creation and verification (S05 §2, §4, v0x02).

use najwa_crypto::keys::{Ed25519KeyPair, Ed25519Public, Ed25519Signature};
use najwa_crypto::time::now;

use super::error::HandshakeError;
use super::mailbox_key::{
    derive_mailbox_signing_key, MailboxCertificate, MailboxEntry, CAP_TYPE_EPHEMERAL,
    MAILBOX_CERT_VALIDITY_SECS,
};
use super::types::{
    HandshakePayload, MailboxInfo, HANDSHAKE_VERSION, MAX_DISPLAY_NAME_LEN, MAX_HANDSHAKE_SIZE,
    MAX_MAILBOX_COUNT,
};
use crate::mailbox::types::MailboxConfig;

impl HandshakePayload {
    /// Create a new signed handshake payload (S05 §2, v0x02).
    ///
    /// - `ik`: the user's Ed25519 identity key pair (signs the payload)
    /// - `mailboxes`: the user's mailbox configurations (deposit_capability is used as-is)
    /// - `display_name`: optional display name
    /// - `validity_hours`: how many hours the payload remains valid
    ///
    /// For each mailbox, derives a per-mailbox signing key and creates
    /// a MailboxCertificate binding it to the real identity key.
    /// The `deposit_capability` from each `MailboxConfig` is included in the
    /// payload so recipients can deposit to a capability the server actually knows.
    pub fn create(
        ik: &Ed25519KeyPair,
        mailboxes: &[MailboxConfig],
        display_name: &str,
        validity_hours: u64,
    ) -> Result<Self, HandshakeError> {
        if mailboxes.is_empty()
            || mailboxes.len() > MAX_MAILBOX_COUNT as usize
            || display_name.len() > MAX_DISPLAY_NAME_LEN
        {
            return Err(HandshakeError::InvalidFormat(
                "invalid mailbox count or display name length".into(),
            ));
        }
        let ts = now();
        let expires_at = validity_hours
            .checked_mul(3600)
            .and_then(|seconds| ts.checked_add(seconds))
            .filter(|expiry| *expiry > ts)
            .ok_or_else(|| HandshakeError::InvalidFormat("invalid validity duration".into()))?;
        let ik_priv_bytes = zeroize::Zeroizing::new(ik.private().to_bytes());

        let mut mailbox_entries = Vec::with_capacity(mailboxes.len());
        let mut mailbox_infos = Vec::with_capacity(mailboxes.len());

        for m in mailboxes {
            let dep_cap = m.deposit_capability;
            let mailbox_kp = derive_mailbox_signing_key(&ik_priv_bytes, &m.onion_address)?;
            let cert = MailboxCertificate::create(
                ik,
                &mailbox_kp.public().to_bytes(),
                &m.onion_address,
                ts,
            );

            let mut onion_bytes = [0u8; 56];
            let src = m.onion_address.as_bytes();
            let copy_len = src.len().min(56);
            onion_bytes[..copy_len].copy_from_slice(&src[..copy_len]);

            mailbox_entries.push(MailboxEntry {
                onion_address: onion_bytes,
                deposit_capability: dep_cap,
                envelope_secret: m.envelope_secret,
                mailbox_ik_pub: mailbox_kp.public().to_bytes(),
                cert_signature: cert.signature,
                capability_type: CAP_TYPE_EPHEMERAL,
            });

            mailbox_infos.push(MailboxInfo {
                onion_address: m.onion_address.clone(),
                deposit_capability: dep_cap,
            });
        }

        let mut payload = Self {
            version: HANDSHAKE_VERSION,
            ik_pub: ik.public().to_bytes(),
            mailbox_entries,
            mailboxes: mailbox_infos,
            display_name: display_name.to_string(),
            created_at: ts,
            expires_at,
            signature: [0u8; 64],
        };

        payload.validate_structure()?;
        let signable = payload.signable_bytes();
        payload.signature = ik.sign(&signable).to_bytes();
        Ok(payload)
    }

    /// Create a payload with a specific timestamp (for testing).
    #[cfg(test)]
    pub(crate) fn create_with_time(
        ik: &Ed25519KeyPair,
        mailboxes: &[MailboxConfig],
        display_name: &str,
        created_at: u64,
        expires_at: u64,
    ) -> Self {
        let ik_priv_bytes = ik.private().to_bytes();

        let mut mailbox_entries = Vec::with_capacity(mailboxes.len());
        let mut mailbox_infos = Vec::with_capacity(mailboxes.len());

        for m in mailboxes {
            let dep_cap = m.deposit_capability;
            let mailbox_kp = derive_mailbox_signing_key(&ik_priv_bytes, &m.onion_address).unwrap();
            let cert = MailboxCertificate::create(
                ik,
                &mailbox_kp.public().to_bytes(),
                &m.onion_address,
                created_at,
            );

            let mut onion_bytes = [0u8; 56];
            let src = m.onion_address.as_bytes();
            let copy_len = src.len().min(56);
            onion_bytes[..copy_len].copy_from_slice(&src[..copy_len]);

            mailbox_entries.push(MailboxEntry {
                onion_address: onion_bytes,
                deposit_capability: dep_cap,
                envelope_secret: m.envelope_secret,
                mailbox_ik_pub: mailbox_kp.public().to_bytes(),
                cert_signature: cert.signature,
                capability_type: CAP_TYPE_EPHEMERAL,
            });

            mailbox_infos.push(MailboxInfo {
                onion_address: m.onion_address.clone(),
                deposit_capability: dep_cap,
            });
        }

        let mut payload = Self {
            version: HANDSHAKE_VERSION,
            ik_pub: ik.public().to_bytes(),
            mailbox_entries,
            mailboxes: mailbox_infos,
            display_name: display_name.to_string(),
            created_at,
            expires_at,
            signature: [0u8; 64],
        };

        let signable = payload.signable_bytes();
        payload.signature = ik.sign(&signable).to_bytes();
        payload
    }

    /// Verify payload signature, expiration, and cert signatures (S05 §2, §4).
    ///
    /// Checks:
    /// 1. Payload has not expired
    /// 2. Outer Ed25519 signature over all fields is valid
    /// 3. Each MailboxEntry cert_signature is valid (IK signed the derived key)
    pub fn verify(&self) -> Result<(), HandshakeError> {
        let ts = now();
        self.verify_at(ts)
    }

    /// Verify with a custom timestamp (useful for testing expiration logic).
    ///
    /// Allows a 5-minute clock-skew tolerance (`TIMESTAMP_TOLERANCE_NORMAL_SECS`)
    /// so that handshakes don't fail when the device clock is slightly ahead
    /// of the sender's clock.
    pub fn verify_at(&self, ts: u64) -> Result<(), HandshakeError> {
        self.validate_structure()?;
        let tolerance = najwa_crypto::time::TIMESTAMP_TOLERANCE_NORMAL_SECS;
        if ts > self.expires_at.saturating_add(tolerance) {
            return Err(HandshakeError::Expired);
        }

        let ik_pub = Ed25519Public::from_bytes(&self.ik_pub)
            .map_err(|e| HandshakeError::InvalidSignature(e.to_string()))?;
        let sig = Ed25519Signature::from_bytes(&self.signature)
            .map_err(|e| HandshakeError::InvalidSignature(e.to_string()))?;
        ik_pub
            .verify(&self.signable_bytes(), &sig)
            .map_err(|e| HandshakeError::InvalidSignature(e.to_string()))?;

        // Verify each MailboxEntry cert_signature
        for entry in &self.mailbox_entries {
            let onion_str = std::str::from_utf8(&entry.onion_address)
                .unwrap_or("")
                .trim_end_matches('\0');
            let cert = MailboxCertificate {
                ik_pub: self.ik_pub,
                mailbox_ik_pub: entry.mailbox_ik_pub,
                mailbox_onion: entry.onion_address,
                created_at: self.created_at,
                // Deterministic: created_at + 180d (S05 §2.3), reconstructed for
                // signature verification (the entry carries only the signature).
                expires_at: self.created_at.saturating_add(MAILBOX_CERT_VALIDITY_SECS),
                signature: entry.cert_signature,
            };
            cert.verify_at(&ik_pub, ts).map_err(|e| {
                HandshakeError::InvalidSignature(format!(
                    "cert verification failed for {}: {}",
                    onion_str, e
                ))
            })?;
        }

        Ok(())
    }

    /// Validate the common binary/typed payload invariants before signing,
    /// encoding, or accepting. Signature verification alone is insufficient:
    /// serde and direct construction do not go through `from_bytes`.
    pub fn validate_structure(&self) -> Result<(), HandshakeError> {
        if self.version != HANDSHAKE_VERSION {
            return Err(HandshakeError::UnsupportedVersion(self.version));
        }
        if self.mailbox_entries.is_empty()
            || self.mailbox_entries.len() > MAX_MAILBOX_COUNT as usize
        {
            return Err(HandshakeError::InvalidFormat(
                "mailbox count outside 1..=8".into(),
            ));
        }
        if self.display_name.len() > MAX_DISPLAY_NAME_LEN {
            return Err(HandshakeError::InvalidFormat(
                "display name exceeds 128 bytes".into(),
            ));
        }
        if 116
            + self.mailbox_entries.len() * super::mailbox_key::MAILBOX_ENTRY_SIZE
            + self.display_name.len()
            > MAX_HANDSHAKE_SIZE
        {
            return Err(HandshakeError::InvalidFormat(
                "handshake payload too large".into(),
            ));
        }
        if self.expires_at <= self.created_at {
            return Err(HandshakeError::InvalidFormat(
                "expires_at must be greater than created_at".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_mailboxes() -> Vec<MailboxConfig> {
        vec![MailboxConfig::new(
            "testmailbox123456".to_string(),
            [0xAA; 32],
            [0xBB; 32],
        )]
    }

    #[test]
    fn create_and_verify_succeeds() {
        let ik = Ed25519KeyPair::from_seed(&[0x01; 32]);
        let payload = HandshakePayload::create(&ik, &test_mailboxes(), "Alice", 24).unwrap();

        assert_eq!(payload.version, HANDSHAKE_VERSION);
        assert_eq!(payload.ik_pub, ik.public().to_bytes());
        assert_eq!(payload.display_name, "Alice");
        assert!(payload.expires_at > payload.created_at);
        assert!(!payload.mailbox_entries.is_empty());
        assert!(payload.verify().is_ok());
    }

    #[test]
    fn expired_payload_rejected() {
        let ik = Ed25519KeyPair::from_seed(&[0x01; 32]);
        let payload =
            HandshakePayload::create_with_time(&ik, &test_mailboxes(), "Alice", 1000, 1001);
        assert!(matches!(
            payload.verify_at(2000),
            Err(HandshakeError::Expired)
        ));
    }

    #[test]
    fn not_yet_expired_accepted() {
        let ik = Ed25519KeyPair::from_seed(&[0x01; 32]);
        let payload = HandshakePayload::create_with_time(
            &ik,
            &test_mailboxes(),
            "Alice",
            1000,
            999_999_999_999,
        );
        assert!(payload.verify_at(1500).is_ok());
    }

    #[test]
    fn tampered_signature_rejected() {
        let ik = Ed25519KeyPair::from_seed(&[0x01; 32]);
        let mut payload = HandshakePayload::create(&ik, &test_mailboxes(), "Alice", 24).unwrap();
        payload.signature[0] ^= 0xFF;
        assert!(payload.verify().is_err());
    }

    #[test]
    fn tampered_ik_pub_rejected() {
        let ik = Ed25519KeyPair::from_seed(&[0x01; 32]);
        let mut payload = HandshakePayload::create(&ik, &test_mailboxes(), "Alice", 24).unwrap();
        payload.ik_pub[0] ^= 0xFF;
        assert!(payload.verify().is_err());
    }

    // S05 §5: `create()` advertises the caller-provided deposit caps verbatim;
    // the caller mints a fresh invitation queue per invitation, not `create()`.
    // Assert faithful pass-through of distinct caps. Per-contact long-term
    // queues are registered later (S05 §8 step 10).
    #[test]
    fn create_preserves_provided_deposit_caps() {
        let ik = Ed25519KeyPair::from_seed(&[0x01; 32]);
        let mbs = vec![
            MailboxConfig::new("mb1".to_string(), [1; 32], [0xAA; 32]),
            MailboxConfig::new("mb2".to_string(), [2; 32], [0xBB; 32]),
        ];
        let p = HandshakePayload::create(&ik, &mbs, "A", 24).unwrap();
        assert_eq!(p.mailboxes[0].deposit_capability, [0xAA; 32]);
        assert_eq!(p.mailboxes[1].deposit_capability, [0xBB; 32]);
    }

    #[test]
    fn mailbox_entries_have_cert_signatures() {
        let ik = Ed25519KeyPair::from_seed(&[0x01; 32]);
        let payload = HandshakePayload::create(&ik, &test_mailboxes(), "Alice", 24).unwrap();
        assert_eq!(payload.mailbox_entries.len(), 1);
        assert_ne!(payload.mailbox_entries[0].cert_signature, [0u8; 64]);
        assert_ne!(payload.mailbox_entries[0].mailbox_ik_pub, [0u8; 32]);
    }
}
