//! HandshakePayload binary serialization (S05 §2, v0x02).
//!
//! Wire format:
//! ```text
//! version(1) || ik_pub(32) || mailbox_count(1) || mailboxes[217 each] ||
//! display_name_len(2 BE) || display_name(UTF-8) ||
//! created_at(8 BE) || expires_at(8 BE) || signature(64)
//! ```

use super::error::HandshakeError;
use super::mailbox_key::{MailboxEntry, MAILBOX_ENTRY_SIZE};
use super::types::*;

/// Minimum payload size: version(1) + ik(32) + mb_count(1) + name_len(2)
/// + created(8) + expires(8) + sig(64) = 116 (with 0 mailboxes)
const MIN_PAYLOAD_SIZE: usize = 116;

impl HandshakePayload {
    /// Serialize the payload to bytes (S05 §2.1, v0x02 wire format).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mb_count = self.mailbox_entries.len();
        let name_bytes = self.display_name.as_bytes();
        let total =
            1 + 32 + 1 + (mb_count * MAILBOX_ENTRY_SIZE) + 2 + name_bytes.len() + 8 + 8 + 64;
        let mut buf = Vec::with_capacity(total);

        buf.push(self.version);
        buf.extend_from_slice(&self.ik_pub);
        buf.push(mb_count as u8);

        for entry in &self.mailbox_entries {
            buf.extend_from_slice(&entry.to_bytes());
        }

        buf.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(name_bytes);
        buf.extend_from_slice(&self.created_at.to_be_bytes());
        buf.extend_from_slice(&self.expires_at.to_be_bytes());
        buf.extend_from_slice(&self.signature);

        buf
    }

    /// Deserialize a payload from bytes (S05 §2.1).
    pub fn from_bytes(data: &[u8]) -> Result<Self, HandshakeError> {
        if data.len() > MAX_HANDSHAKE_SIZE {
            return Err(HandshakeError::InvalidFormat(format!(
                "payload too large: {} > {}",
                data.len(),
                MAX_HANDSHAKE_SIZE
            )));
        }
        if data.len() < MIN_PAYLOAD_SIZE {
            return Err(HandshakeError::InvalidFormat(format!(
                "too short: {} < {}",
                data.len(),
                MIN_PAYLOAD_SIZE
            )));
        }

        let mut pos = 0;

        let version = data[pos];
        pos += 1;
        if version != HANDSHAKE_VERSION {
            return Err(HandshakeError::UnsupportedVersion(version));
        }

        let ik_pub: [u8; 32] = data[pos..pos + 32]
            .try_into()
            .map_err(|_| HandshakeError::InvalidFormat("ik_pub truncated".into()))?;
        pos += 32;

        let mb_count = data[pos] as usize;
        pos += 1;
        if mb_count == 0 || mb_count > MAX_MAILBOX_COUNT as usize {
            return Err(HandshakeError::InvalidFormat(format!(
                "mailbox_count {} out of range 1..={}",
                mb_count, MAX_MAILBOX_COUNT
            )));
        }

        let mut mailbox_entries = Vec::with_capacity(mb_count);
        let mut mailboxes = Vec::with_capacity(mb_count);
        for _ in 0..mb_count {
            if pos + MAILBOX_ENTRY_SIZE > data.len() {
                return Err(HandshakeError::InvalidFormat(
                    "mailbox entry truncated".into(),
                ));
            }
            let entry = MailboxEntry::from_bytes(&data[pos..pos + MAILBOX_ENTRY_SIZE])?;
            // Build legacy MailboxInfo from entry
            let onion_str = std::str::from_utf8(&entry.onion_address)
                .unwrap_or("")
                .trim_end_matches('\0')
                .to_string();
            mailboxes.push(MailboxInfo {
                onion_address: onion_str,
                deposit_capability: entry.deposit_capability,
            });
            mailbox_entries.push(entry);
            pos += MAILBOX_ENTRY_SIZE;
        }

        if pos + 2 > data.len() {
            return Err(HandshakeError::InvalidFormat(
                "display_name_len truncated".into(),
            ));
        }
        let name_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        if name_len > MAX_DISPLAY_NAME_LEN {
            return Err(HandshakeError::InvalidFormat(format!(
                "display_name_len {} > {}",
                name_len, MAX_DISPLAY_NAME_LEN
            )));
        }

        if pos + name_len > data.len() {
            return Err(HandshakeError::InvalidFormat(
                "display_name truncated".into(),
            ));
        }
        let display_name = std::str::from_utf8(&data[pos..pos + name_len])
            .map_err(|_| HandshakeError::InvalidFormat("invalid UTF-8 in display name".into()))?
            .to_string();
        pos += name_len;

        if pos + 8 + 8 + 64 > data.len() {
            return Err(HandshakeError::InvalidFormat(
                "timestamps/signature truncated".into(),
            ));
        }
        let created_at = u64::from_be_bytes(data[pos..pos + 8].try_into().unwrap());
        pos += 8;
        let expires_at = u64::from_be_bytes(data[pos..pos + 8].try_into().unwrap());
        pos += 8;
        if expires_at <= created_at {
            return Err(HandshakeError::InvalidFormat(
                "expires_at must be > created_at".into(),
            ));
        }
        let signature: [u8; 64] = data[pos..pos + 64]
            .try_into()
            .map_err(|_| HandshakeError::InvalidFormat("signature truncated".into()))?;

        if pos + 64 != data.len() {
            return Err(HandshakeError::InvalidFormat(
                "trailing handshake bytes".into(),
            ));
        }

        let payload = Self {
            version,
            ik_pub,
            mailbox_entries,
            mailboxes,
            display_name,
            created_at,
            expires_at,
            signature,
        };
        payload.validate_structure()?;
        Ok(payload)
    }

    /// Return the bytes covered by the outer signature (everything except last 64 bytes).
    pub fn signable_bytes(&self) -> Vec<u8> {
        // S05 §4.1: the outer signature is over the domain prefix followed by
        // the serialized fields (everything except the trailing 64-byte sig).
        let full = self.to_bytes();
        let body = &full[..full.len() - 64];
        let mut signable = Vec::with_capacity(HANDSHAKE_SIG_PREFIX.len() + body.len());
        signable.extend_from_slice(HANDSHAKE_SIG_PREFIX);
        signable.extend_from_slice(body);
        signable
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contact::mailbox_key::CAP_TYPE_EPHEMERAL;

    fn test_entry() -> MailboxEntry {
        MailboxEntry {
            onion_address: [0x41; 56], // 'A' repeated
            deposit_capability: [0x04; 32],
            envelope_secret: [0x07; 32],
            mailbox_ik_pub: [0x05; 32],
            cert_signature: [0x06; 64],
            capability_type: CAP_TYPE_EPHEMERAL,
        }
    }

    fn test_payload() -> HandshakePayload {
        HandshakePayload {
            version: HANDSHAKE_VERSION,
            ik_pub: [0x01; 32],
            mailbox_entries: vec![test_entry()],
            mailboxes: vec![MailboxInfo {
                onion_address: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                    .to_string(),
                deposit_capability: [0x04; 32],
            }],
            display_name: "Alice".to_string(),
            created_at: 1700000000,
            expires_at: 1700003600,
            signature: [0x07; 64],
        }
    }

    #[test]
    fn roundtrip_serialization() {
        let payload = test_payload();
        let bytes = payload.to_bytes();
        let restored = HandshakePayload::from_bytes(&bytes).unwrap();

        assert_eq!(restored.version, HANDSHAKE_VERSION);
        assert_eq!(restored.ik_pub, payload.ik_pub);
        assert_eq!(restored.mailbox_entries.len(), 1);
        assert_eq!(restored.mailbox_entries[0].deposit_capability, [0x04; 32]);
        assert_eq!(restored.mailbox_entries[0].mailbox_ik_pub, [0x05; 32]);
        assert_eq!(restored.display_name, "Alice");
        assert_eq!(restored.created_at, payload.created_at);
        assert_eq!(restored.expires_at, payload.expires_at);
        assert_eq!(restored.signature, payload.signature);
    }

    #[test]
    fn roundtrip_multiple_mailboxes() {
        let mut payload = test_payload();
        let mut entry2 = test_entry();
        entry2.onion_address = [0x42; 56]; // 'B' repeated
        payload.mailbox_entries.push(entry2);
        let bytes = payload.to_bytes();
        let restored = HandshakePayload::from_bytes(&bytes).unwrap();
        assert_eq!(restored.mailbox_entries.len(), 2);
    }

    #[test]
    fn roundtrip_empty_display_name() {
        let mut payload = test_payload();
        payload.display_name = String::new();
        let bytes = payload.to_bytes();
        let restored = HandshakePayload::from_bytes(&bytes).unwrap();
        assert!(restored.display_name.is_empty());
    }

    #[test]
    fn too_short_rejected() {
        let data = vec![0u8; 10];
        assert!(HandshakePayload::from_bytes(&data).is_err());
    }

    #[test]
    fn wrong_version_rejected() {
        let payload = test_payload();
        let mut bytes = payload.to_bytes();
        bytes[0] = 0xFF;
        assert!(matches!(
            HandshakePayload::from_bytes(&bytes),
            Err(HandshakeError::UnsupportedVersion(0xFF))
        ));
    }

    #[test]
    fn signable_bytes_prefixes_domain_and_excludes_signature() {
        let payload = test_payload();
        let signable = payload.signable_bytes();
        let full = payload.to_bytes();
        // S05 §4.1: prefix || (all serialized bytes except the 64-byte sig).
        assert_eq!(
            &signable[..HANDSHAKE_SIG_PREFIX.len()],
            HANDSHAKE_SIG_PREFIX
        );
        assert_eq!(
            &signable[HANDSHAKE_SIG_PREFIX.len()..],
            &full[..full.len() - 64]
        );
        assert_eq!(signable.len(), HANDSHAKE_SIG_PREFIX.len() + full.len() - 64);
    }

    #[test]
    fn too_large_rejected() {
        let data = vec![0u8; MAX_HANDSHAKE_SIZE + 1];
        assert!(HandshakePayload::from_bytes(&data).is_err());
    }
}
