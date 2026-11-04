//! Device certificates, signed device lists and revocation. Not used by the
//! app or the receive path: the app has one device per identity.
//!
//! Each device in a multi-device setup has its own Ed25519 key pair.
//! The master identity key signs a certificate binding the device key
//! to the identity. Revocation is a signed statement invalidating
//! a device certificate.

use najwa_crypto::keys::ed25519::{Ed25519KeyPair, Ed25519Public, Ed25519Signature};
use najwa_crypto::time::now;

/// Maximum devices per identity. Indices are 1-based and dense,
/// so `1..=MAX_DEVICES` is the whole valid range.
pub const MAX_DEVICES: u8 = 5;

/// Whether `index` is a valid 1-based device index.
pub fn is_valid_device_index(index: u8) -> bool {
    (1..=MAX_DEVICES).contains(&index)
}

/// A device certificate binding a device key to a master identity.
///
/// ```text
/// DeviceCertificate {
///     master_ik_pub: [u8; 32],
///     device_ik_pub: [u8; 32],
///     device_name:   String (max 64 bytes UTF-8),
///     timestamp:     u64,
///     signature:     [u8; 64],  // Ed25519_Sign(master_ik_priv, signable)
/// }
/// ```
#[derive(Debug, Clone)]
pub struct DeviceCertificate {
    pub master_ik_pub: [u8; 32],
    pub device_ik_pub: [u8; 32],
    /// 1-based device index within the identity's device set.
    pub device_index: u8,
    pub device_name: String,
    pub timestamp: u64,
    pub signature: [u8; 64],
}

impl DeviceCertificate {
    /// Create and sign a new device certificate.
    pub fn create(
        master_ik: &Ed25519KeyPair,
        device_ik_pub: &[u8; 32],
        device_index: u8,
        device_name: &str,
    ) -> Self {
        let ts = now();
        let mut cert = Self {
            master_ik_pub: master_ik.public().to_bytes(),
            device_ik_pub: *device_ik_pub,
            device_index,
            device_name: device_name.to_string(),
            timestamp: ts,
            signature: [0u8; 64],
        };
        let signable = cert.signable_bytes();
        cert.signature = master_ik.sign(&signable).to_bytes();
        cert
    }

    /// Verify the certificate signature against the master identity key.
    ///
    /// Also enforces the device cap. `device_index` comes from peer-supplied
    /// data and is attacker-chosen, so an
    /// out-of-range index must be rejected here rather than trusted because the
    /// signature checks out — a valid signature only proves the *master* key
    /// authored it, not that the value is in range. The index is inside
    /// `signable_bytes`, so this cannot be bypassed by editing the cert.
    pub fn verify(&self, master_pub: &Ed25519Public) -> Result<(), String> {
        if self.master_ik_pub != master_pub.to_bytes() {
            return Err("master key mismatch".into());
        }
        if !is_valid_device_index(self.device_index) {
            return Err(format!(
                "device_index {} outside 1..={} (S15 §2)",
                self.device_index, MAX_DEVICES
            ));
        }
        let sig = Ed25519Signature::from_bytes(&self.signature)
            .map_err(|e| format!("invalid signature: {e}"))?;
        master_pub
            .verify(&self.signable_bytes(), &sig)
            .map_err(|e| format!("signature verification failed: {e}"))
    }

    fn signable_bytes(&self) -> Vec<u8> {
        let name_bytes = self.device_name.as_bytes();
        let mut out = Vec::with_capacity(32 + 32 + 1 + 2 + name_bytes.len() + 8);
        out.extend_from_slice(&self.master_ik_pub);
        out.extend_from_slice(&self.device_ik_pub);
        // device_index is signed, between device_pub and name_len.
        out.push(self.device_index);
        out.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
        out.extend_from_slice(name_bytes);
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        out
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.signable_bytes();
        out.extend_from_slice(&self.signature);
        out
    }
}

/// Device status within a `SignedDeviceList` entry.
pub const DEVICE_STATUS_ACTIVE: u8 = 0x00;
/// Revoked-device status — the entry remains in the list forever.
pub const DEVICE_STATUS_REVOKED: u8 = 0x01;

/// One device's entry in a `SignedDeviceList`.
///
/// Canonical serialization: `device_pub[32] || device_index(u8) ||
/// status(u8) || cert_timestamp(u64 BE)` = 42 bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceListEntry {
    pub device_pub: [u8; 32],
    pub device_index: u8,
    /// [`DEVICE_STATUS_ACTIVE`] or [`DEVICE_STATUS_REVOKED`].
    pub status: u8,
    pub cert_timestamp: u64,
}

/// Serialized size of a [`DeviceListEntry`]: 32 + 1 + 1 + 8.
pub const DEVICE_LIST_ENTRY_SIZE: usize = 42;

impl DeviceListEntry {
    /// Canonical serialization (42 bytes).
    pub fn to_bytes(&self) -> [u8; DEVICE_LIST_ENTRY_SIZE] {
        let mut out = [0u8; DEVICE_LIST_ENTRY_SIZE];
        out[..32].copy_from_slice(&self.device_pub);
        out[32] = self.device_index;
        out[33] = self.status;
        out[34..42].copy_from_slice(&self.cert_timestamp.to_be_bytes());
        out
    }

    /// Parse a single entry from the front of `data`.
    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        if data.len() < DEVICE_LIST_ENTRY_SIZE {
            return Err("device list entry truncated".into());
        }
        let mut device_pub = [0u8; 32];
        device_pub.copy_from_slice(&data[..32]);
        // Fail closed on an out-of-range index rather than storing it.
        // A `SignedDeviceList` is peer-supplied; accepting index 200 would let a
        // list claim devices the cap forbids.
        let device_index = data[32];
        if !is_valid_device_index(device_index) {
            return Err(format!(
                "device_index {device_index} outside 1..={MAX_DEVICES} (S15 §2)"
            ));
        }
        Ok(Self {
            device_pub,
            device_index,
            status: data[33],
            cert_timestamp: u64::from_be_bytes(data[34..42].try_into().unwrap()),
        })
    }
}

/// The signed, versioned list of ALL devices ever certified for an identity —
/// including revoked ones. The monotonic `device_list_version` is the
/// sole ordering and anti-replay key; timestamps do not order lists.
///
/// Canonical serialization: `device_list_version(u64 BE) ||
/// entry_count(u16 BE) || entries || signature[64]`.
#[derive(Debug, Clone)]
pub struct SignedDeviceList {
    pub device_list_version: u64,
    pub entries: Vec<DeviceListEntry>,
    pub signature: [u8; 64],
}

impl SignedDeviceList {
    /// Create and sign a device list with the master identity key (primary only).
    pub fn create(
        master_ik: &Ed25519KeyPair,
        device_list_version: u64,
        entries: Vec<DeviceListEntry>,
    ) -> Self {
        let mut list = Self {
            device_list_version,
            entries,
            signature: [0u8; 64],
        };
        let signable = list.signable_bytes();
        list.signature = master_ik.sign(&signable).to_bytes();
        list
    }

    /// Verify the list signature against the master identity key.
    pub fn verify(&self, master_pub: &Ed25519Public) -> Result<(), String> {
        let sig = Ed25519Signature::from_bytes(&self.signature)
            .map_err(|e| format!("invalid signature: {e}"))?;
        master_pub
            .verify(&self.signable_bytes(), &sig)
            .map_err(|e| format!("device-list signature verification failed: {e}"))
    }

    /// Whether this list supersedes a previously-seen version: a
    /// contact persists the highest version seen and MUST reject any older one,
    /// killing revoked-device resurrection via replayed old announcements.
    pub fn supersedes(&self, seen_version: u64) -> bool {
        self.device_list_version > seen_version
    }

    fn signable_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + 2 + self.entries.len() * DEVICE_LIST_ENTRY_SIZE);
        out.extend_from_slice(&self.device_list_version.to_be_bytes());
        out.extend_from_slice(&(self.entries.len() as u16).to_be_bytes());
        for e in &self.entries {
            out.extend_from_slice(&e.to_bytes());
        }
        out
    }

    /// Full canonical serialization including the signature.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.signable_bytes();
        out.extend_from_slice(&self.signature);
        out
    }

    /// Parse a list from the front of `data`, returning it plus the number of
    /// bytes consumed (so it can be embedded in a `DeviceRevocation`).
    pub fn from_prefix(data: &[u8]) -> Result<(Self, usize), String> {
        if data.len() < 10 {
            return Err("device list header truncated".into());
        }
        let device_list_version = u64::from_be_bytes(data[..8].try_into().unwrap());
        let count = u16::from_be_bytes(data[8..10].try_into().unwrap()) as usize;
        let entries_end = 10 + count * DEVICE_LIST_ENTRY_SIZE;
        let sig_end = entries_end + 64;
        if data.len() < sig_end {
            return Err("device list truncated".into());
        }
        let mut entries = Vec::with_capacity(count);
        for i in 0..count {
            let off = 10 + i * DEVICE_LIST_ENTRY_SIZE;
            entries.push(DeviceListEntry::from_bytes(&data[off..])?);
        }
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&data[entries_end..sig_end]);
        Ok((
            Self {
                device_list_version,
                entries,
                signature,
            },
            sig_end,
        ))
    }
}

/// A signed device revocation. Control subtype `0x24` is unassigned; the
/// receiver rejects it.
///
/// Only the primary (holding `IK_priv`) can produce a valid revocation, so a
/// timestamp race is impossible by construction — ordering is the monotonic
/// `device_list_version`, not `timestamp` (which is informational only). The
/// revocation embeds the new post-revocation [`SignedDeviceList`].
///
/// Canonical serialization: `revoked_device_pub[32] ||
/// device_list_version(u64 BE) || timestamp(u64 BE) || reason_flag(u8)
/// [|| reason_len(u16 BE) || reason] || SignedDeviceList || signature[64]`.
#[derive(Debug, Clone)]
pub struct DeviceRevocation {
    pub revoked_device_pub: [u8; 32],
    /// The version of the `SignedDeviceList` this revocation produces — the sole
    /// ordering / anti-replay key.
    pub device_list_version: u64,
    /// Creation time — informational ONLY (ordering is by `device_list_version`).
    pub timestamp: u64,
    pub reason: Option<String>,
    /// The new post-revocation device list.
    pub device_list: SignedDeviceList,
    /// Signature by the master identity key over all preceding fields.
    pub signature: [u8; 64],
}

impl DeviceRevocation {
    /// Create and sign a device revocation. `device_list` must be the new
    /// post-revocation list (its `device_list_version` should match
    /// `device_list_version`).
    pub fn create(
        master_ik: &Ed25519KeyPair,
        revoked_device_pub: &[u8; 32],
        device_list_version: u64,
        reason: Option<&str>,
        device_list: SignedDeviceList,
    ) -> Self {
        let mut rev = Self {
            revoked_device_pub: *revoked_device_pub,
            device_list_version,
            timestamp: now(),
            reason: reason.map(|s| s.to_string()),
            device_list,
            signature: [0u8; 64],
        };
        let signable = rev.signable_bytes();
        rev.signature = master_ik.sign(&signable).to_bytes();
        rev
    }

    /// Verify the revocation signature (and, separately, callers should verify
    /// the embedded list via [`SignedDeviceList::verify`]).
    pub fn verify(&self, master_pub: &Ed25519Public) -> Result<(), String> {
        let sig = Ed25519Signature::from_bytes(&self.signature)
            .map_err(|e| format!("invalid signature: {e}"))?;
        master_pub
            .verify(&self.signable_bytes(), &sig)
            .map_err(|e| format!("revocation signature verification failed: {e}"))
    }

    fn signable_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 8 + 8 + 1 + 64);
        out.extend_from_slice(&self.revoked_device_pub);
        out.extend_from_slice(&self.device_list_version.to_be_bytes());
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        // reason: Option<String> — 0x00 = None, 0x01 || len(u16 BE) || bytes.
        match &self.reason {
            None => out.push(0x00),
            Some(r) => {
                out.push(0x01);
                let b = r.as_bytes();
                out.extend_from_slice(&(b.len() as u16).to_be_bytes());
                out.extend_from_slice(b);
            }
        }
        out.extend_from_slice(&self.device_list.to_bytes());
        out
    }

    /// Full canonical serialization including the signature.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.signable_bytes();
        out.extend_from_slice(&self.signature);
        out
    }

    /// Parse a revocation from its canonical serialization.
    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        if data.len() < 32 + 8 + 8 + 1 {
            return Err("revocation truncated".into());
        }
        let mut revoked_device_pub = [0u8; 32];
        revoked_device_pub.copy_from_slice(&data[..32]);
        let device_list_version = u64::from_be_bytes(data[32..40].try_into().unwrap());
        let timestamp = u64::from_be_bytes(data[40..48].try_into().unwrap());

        let mut pos = 48;
        let reason = match data[pos] {
            0x00 => {
                pos += 1;
                None
            }
            0x01 => {
                pos += 1;
                if data.len() < pos + 2 {
                    return Err("revocation reason truncated".into());
                }
                let len = u16::from_be_bytes(data[pos..pos + 2].try_into().unwrap()) as usize;
                pos += 2;
                let end = pos + len;
                let s = std::str::from_utf8(data.get(pos..end).ok_or("reason truncated")?)
                    .map_err(|_| "reason not UTF-8")?
                    .to_string();
                pos = end;
                Some(s)
            }
            other => return Err(format!("invalid reason flag {other:#04x}")),
        };

        let (device_list, consumed) = SignedDeviceList::from_prefix(&data[pos..])?;
        pos += consumed;

        if data.len() < pos + 64 {
            return Err("revocation signature truncated".into());
        }
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&data[pos..pos + 64]);

        Ok(Self {
            revoked_device_pub,
            device_list_version,
            timestamp,
            reason,
            device_list,
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_cert_create_and_verify() {
        let master = Ed25519KeyPair::from_seed(&[0x01; 32]);
        let device = Ed25519KeyPair::from_seed(&[0x02; 32]);
        let cert = DeviceCertificate::create(&master, &device.public().to_bytes(), 1, "My Phone");
        assert!(cert.verify(master.public()).is_ok());
    }

    #[test]
    fn device_cert_wrong_master_fails() {
        let master = Ed25519KeyPair::from_seed(&[0x01; 32]);
        let other = Ed25519KeyPair::from_seed(&[0x03; 32]);
        let device = Ed25519KeyPair::from_seed(&[0x02; 32]);
        let cert = DeviceCertificate::create(&master, &device.public().to_bytes(), 1, "My Phone");
        assert!(cert.verify(other.public()).is_err());
    }

    fn sample_list(master: &Ed25519KeyPair, version: u64) -> SignedDeviceList {
        let entries = vec![
            DeviceListEntry {
                device_pub: [0x02; 32],
                device_index: 1,
                status: DEVICE_STATUS_ACTIVE,
                cert_timestamp: 1000,
            },
            DeviceListEntry {
                device_pub: [0x42; 32],
                device_index: 2,
                status: DEVICE_STATUS_REVOKED,
                cert_timestamp: 2000,
            },
        ];
        SignedDeviceList::create(master, version, entries)
    }

    #[test]
    fn device_list_entry_round_trips() {
        let e = DeviceListEntry {
            device_pub: [0x07; 32],
            device_index: 3,
            status: DEVICE_STATUS_REVOKED,
            cert_timestamp: 0xDEAD_BEEF,
        };
        let bytes = e.to_bytes();
        assert_eq!(bytes.len(), DEVICE_LIST_ENTRY_SIZE);
        assert_eq!(DeviceListEntry::from_bytes(&bytes).unwrap(), e);
    }

    #[test]
    fn signed_device_list_signs_verifies_and_round_trips() {
        let master = Ed25519KeyPair::from_seed(&[0x01; 32]);
        let list = sample_list(&master, 5);
        assert!(list.verify(master.public()).is_ok());

        // Wrong master rejected.
        let other = Ed25519KeyPair::from_seed(&[0x09; 32]);
        assert!(list.verify(other.public()).is_err());

        // Canonical byte round-trip.
        let bytes = list.to_bytes();
        let (parsed, consumed) = SignedDeviceList::from_prefix(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(parsed.device_list_version, 5);
        assert_eq!(parsed.entries, list.entries);
        assert!(parsed.verify(master.public()).is_ok());
    }

    #[test]
    fn signed_device_list_version_is_monotonic_ordering_key() {
        let master = Ed25519KeyPair::from_seed(&[0x01; 32]);
        let list = sample_list(&master, 7);
        // Contacts persist the highest version and reject older.
        assert!(list.supersedes(6));
        assert!(!list.supersedes(7)); // equal is not newer
        assert!(!list.supersedes(8)); // older-than-seen is rejected
    }

    #[test]
    fn device_revocation_signs_verifies_and_round_trips_with_reason() {
        let master = Ed25519KeyPair::from_seed(&[0x01; 32]);
        let list = sample_list(&master, 3);
        let rev = DeviceRevocation::create(&master, &[0x42; 32], 3, Some("lost device"), list);
        assert!(rev.verify(master.public()).is_ok());
        assert_eq!(rev.device_list_version, 3);
        assert_eq!(rev.reason.as_deref(), Some("lost device"));

        let bytes = rev.to_bytes();
        let parsed = DeviceRevocation::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.revoked_device_pub, [0x42; 32]);
        assert_eq!(parsed.device_list_version, 3);
        assert_eq!(parsed.reason.as_deref(), Some("lost device"));
        assert_eq!(parsed.device_list.entries, rev.device_list.entries);
        assert_eq!(parsed.signature, rev.signature);
        assert!(parsed.verify(master.public()).is_ok());
        assert!(parsed.device_list.verify(master.public()).is_ok());
    }

    #[test]
    fn device_revocation_round_trips_with_no_reason() {
        let master = Ed25519KeyPair::from_seed(&[0x01; 32]);
        let list = sample_list(&master, 4);
        let rev = DeviceRevocation::create(&master, &[0x42; 32], 4, None, list);
        assert!(rev.reason.is_none());
        let bytes = rev.to_bytes();
        // reason flag byte is 0x00 (None) at offset 48.
        assert_eq!(bytes[48], 0x00);
        let parsed = DeviceRevocation::from_bytes(&bytes).unwrap();
        assert!(parsed.reason.is_none());
        assert!(parsed.verify(master.public()).is_ok());
    }

    #[test]
    fn device_revocation_tamper_breaks_signature() {
        let master = Ed25519KeyPair::from_seed(&[0x01; 32]);
        let list = sample_list(&master, 2);
        let mut rev = DeviceRevocation::create(&master, &[0x42; 32], 2, None, list);
        // Bump the version without re-signing → signature no longer valid.
        rev.device_list_version = 99;
        assert!(rev.verify(master.public()).is_err());
    }
}

#[cfg(test)]
mod device_cap_tests {
    use super::*;

    fn master() -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed(&[0x42; 32])
    }

    // 1..=5 accepted, 0 and 6+ rejected. 0 matters because the index is
    // 1-based — a zero would silently alias "unset".
    #[test]
    fn device_index_range_is_enforced_on_verify() {
        let master = master();
        for index in 1..=MAX_DEVICES {
            let cert = DeviceCertificate::create(&master, &[0x11; 32], index, "phone");
            assert!(
                cert.verify(master.public()).is_ok(),
                "index {index} must be accepted"
            );
        }
        for index in [0u8, MAX_DEVICES + 1, 200, 255] {
            let cert = DeviceCertificate::create(&master, &[0x11; 32], index, "phone");
            let err = cert
                .verify(master.public())
                .expect_err("index {index} must be rejected");
            assert!(err.contains("device_index"), "unexpected error: {err}");
        }
    }

    // The index is peer-supplied and signed, so a valid signature must NOT be
    // taken as evidence the value is in range — that is the whole point of
    // checking after the key match rather than trusting the signer.
    #[test]
    fn out_of_range_index_is_rejected_even_with_a_valid_signature() {
        let master = master();
        let cert = DeviceCertificate::create(&master, &[0x11; 32], 9, "rogue");
        // Signature genuinely verifies over the signable bytes...
        let sig = Ed25519Signature::from_bytes(&cert.signature).unwrap();
        assert!(master.public().verify(&cert.signable_bytes(), &sig).is_ok());
        // ...and the certificate is still refused.
        assert!(cert.verify(master.public()).is_err());
    }

    // A `SignedDeviceList` entry is peer-supplied: reject at parse, do not store.
    #[test]
    fn device_list_entry_rejects_out_of_range_index() {
        let mut buf = vec![0u8; DEVICE_LIST_ENTRY_SIZE];
        buf[32] = 3;
        assert!(DeviceListEntry::from_bytes(&buf).is_ok());
        for bad in [0u8, MAX_DEVICES + 1, 255] {
            buf[32] = bad;
            assert!(
                DeviceListEntry::from_bytes(&buf).is_err(),
                "index {bad} must be rejected at parse"
            );
        }
    }
}
