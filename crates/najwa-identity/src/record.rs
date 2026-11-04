//! Identity record data structures and serialization.
//!
//! Implements on-disk formats from S02 §7.

use najwa_crypto::prelude::*;

use crate::error::{IdentityError, Result};

/// Magic bytes: `"NAJWA\x00\x00\x00"`.
pub const MAGIC: [u8; 8] = *b"NAJWA\x00\x00\x00";

/// Current record version.
pub const VERSION: u8 = 0x03;

/// Mode byte: Standard (password + DKM).
pub const MODE_STANDARD: u8 = 0x01;

/// Mode byte: Hardware wrapping.
pub const MODE_HARDWARE: u8 = 0x02;

/// KDF algorithm: Argon2id.
pub const KDF_ALG_ARGON2ID: u8 = 0x01;

/// AEAD algorithm: XChaCha20-Poly1305.
pub const AEAD_ALG_XCHACHA20: u8 = 0x01;

/// Total size of a standard identity record in bytes.
///
/// 8 (magic) + 1 (version) + 1 (mode) + 1 (kdf_alg) + 1 (aead_alg) +
/// 4 (argon2_memory) + 4 (argon2_iterations) + 1 (argon2_parallelism) +
/// 3 (reserved) + 32 (salt_p) + 24 (nonce) + 32 (ik_pub) +
/// 48 (enc_ik) + 32 (checksum) = 192.
///
/// See S02 §7.1 for exact offsets.
pub const STANDARD_RECORD_SIZE: usize = 192;

/// Checksum covers all bytes before the 32-byte checksum field.
pub const CHECKSUM_INPUT_LEN: usize = STANDARD_RECORD_SIZE - 32;

// ---------------------------------------------------------------------------
// IdentityRecordStandard
// ---------------------------------------------------------------------------

/// On-disk format for encrypted identity (Standard Mode).
///
/// See S02 §7.1.  Total: 192 bytes.
///
/// Field layout (matches spec exactly):
///   offset  0: magic(8)
///   offset  8: version(1)
///   offset  9: mode(1)
///   offset 10: kdf_alg(1)
///   offset 11: aead_alg(1)
///   offset 12: argon2_memory(4, BE)
///   offset 16: argon2_iterations(4, BE)
///   offset 20: argon2_parallelism(1)
///   offset 21: reserved(3)
///   offset 24: saltP(32)
///   offset 56: nonce(24)
///   offset 80: ik_pub(32)
///   offset 112: enc_ik(48)
///   offset 160: checksum(32)
///   total: 192
#[derive(Clone)]
pub struct IdentityRecordStandard {
    // Header (8 bytes)
    pub magic: [u8; 8],

    // Version and algorithms (offset 8–11)
    pub version: u8,
    pub mode: u8,
    pub kdf_alg: u8,
    pub aead_alg: u8,

    // Argon2 parameters (offset 12–20)
    pub argon2_memory: u32,
    pub argon2_iterations: u32,
    pub argon2_parallelism: u8,

    // Reserved (offset 21–23, must be zeros)
    pub reserved: [u8; 3],

    // Cryptographic material
    pub salt_p: [u8; 32],
    pub nonce: [u8; 24],
    pub ik_pub: [u8; 32],
    pub enc_ik: [u8; 48],

    // Integrity
    pub checksum: [u8; 32],
}

impl IdentityRecordStandard {
    /// Serialize to exactly 192 bytes (S02 §7.1).
    pub fn to_bytes(&self) -> [u8; STANDARD_RECORD_SIZE] {
        let mut out = [0u8; STANDARD_RECORD_SIZE];
        let mut pos = 0;

        // offset 0: magic(8)
        out[pos..pos + 8].copy_from_slice(&self.magic);
        pos += 8;
        // offset 8: version(1)
        out[pos] = self.version;
        pos += 1;
        // offset 9: mode(1)
        out[pos] = self.mode;
        pos += 1;
        // offset 10: kdf_alg(1)
        out[pos] = self.kdf_alg;
        pos += 1;
        // offset 11: aead_alg(1)
        out[pos] = self.aead_alg;
        pos += 1;
        // offset 12: argon2_memory(4, BE)
        out[pos..pos + 4].copy_from_slice(&self.argon2_memory.to_be_bytes());
        pos += 4;
        // offset 16: argon2_iterations(4, BE)
        out[pos..pos + 4].copy_from_slice(&self.argon2_iterations.to_be_bytes());
        pos += 4;
        // offset 20: argon2_parallelism(1)
        out[pos] = self.argon2_parallelism;
        pos += 1;
        // offset 21: reserved(3)
        out[pos..pos + 3].copy_from_slice(&self.reserved);
        pos += 3;
        // offset 24: saltP(32)
        out[pos..pos + 32].copy_from_slice(&self.salt_p);
        pos += 32;
        // offset 56: nonce(24)
        out[pos..pos + 24].copy_from_slice(&self.nonce);
        pos += 24;
        // offset 80: ik_pub(32)
        out[pos..pos + 32].copy_from_slice(&self.ik_pub);
        pos += 32;
        // offset 112: enc_ik(48)
        out[pos..pos + 48].copy_from_slice(&self.enc_ik);
        pos += 48;
        // offset 160: checksum(32)
        out[pos..pos + 32].copy_from_slice(&self.checksum);

        out
    }

    /// Deserialize from bytes (S02 §7.1).
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < STANDARD_RECORD_SIZE {
            return Err(IdentityError::RecordTooShort);
        }

        let mut pos = 0;

        let mut magic = [0u8; 8];
        magic.copy_from_slice(&data[pos..pos + 8]);
        pos += 8;
        if magic != MAGIC {
            return Err(IdentityError::InvalidMagic);
        }

        // offset 8: version, mode, kdf_alg, aead_alg (4 bytes)
        let version = data[pos];
        pos += 1;
        let mode = data[pos];
        pos += 1;
        let kdf_alg = data[pos];
        pos += 1;
        let aead_alg = data[pos];
        pos += 1;

        // offset 12: argon2 params (9 bytes)
        let argon2_memory = u32::from_be_bytes(
            data[pos..pos + 4]
                .try_into()
                .map_err(|_| IdentityError::RecordTooShort)?,
        );
        pos += 4;
        let argon2_iterations = u32::from_be_bytes(
            data[pos..pos + 4]
                .try_into()
                .map_err(|_| IdentityError::RecordTooShort)?,
        );
        pos += 4;
        let argon2_parallelism = data[pos];
        pos += 1;

        // offset 21: reserved(3)
        let mut reserved = [0u8; 3];
        reserved.copy_from_slice(&data[pos..pos + 3]);
        pos += 3;

        // offset 24: cryptographic material
        let mut salt_p = [0u8; 32];
        salt_p.copy_from_slice(&data[pos..pos + 32]);
        pos += 32;
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&data[pos..pos + 24]);
        pos += 24;
        let mut ik_pub = [0u8; 32];
        ik_pub.copy_from_slice(&data[pos..pos + 32]);
        pos += 32;
        let mut enc_ik = [0u8; 48];
        enc_ik.copy_from_slice(&data[pos..pos + 48]);
        pos += 48;
        let mut checksum = [0u8; 32];
        checksum.copy_from_slice(&data[pos..pos + 32]);

        Ok(Self {
            magic,
            version,
            mode,
            kdf_alg,
            aead_alg,
            argon2_memory,
            argon2_iterations,
            argon2_parallelism,
            reserved,
            salt_p,
            nonce,
            ik_pub,
            enc_ik,
            checksum,
        })
    }

    /// Compute the SHA-256 checksum over `[0..160]`.
    pub fn compute_checksum(&self) -> [u8; 32] {
        let bytes = self.to_bytes();
        sha256(&bytes[..CHECKSUM_INPUT_LEN])
    }

    /// Verify the record checksum.
    pub fn verify_checksum(&self) -> bool {
        let expected = self.compute_checksum();
        constant_time_eq(&self.checksum, &expected)
    }

    /// Extract Argon2 parameters from the record.
    pub fn argon2_params(&self) -> Argon2Params {
        Argon2Params {
            memory_kib: self.argon2_memory,
            iterations: self.argon2_iterations,
            parallelism: self.argon2_parallelism as u32,
        }
    }

    /// Validate the record header fields (S02 §9.1 structure validation).
    pub fn validate(&self) -> Result<()> {
        if self.magic != MAGIC {
            return Err(IdentityError::InvalidMagic);
        }
        // S02 §9.1: version <= 0x03 — accept the current or an older format, reject
        // only newer/unknown versions.
        if self.version > VERSION {
            return Err(IdentityError::UnsupportedVersion(self.version));
        }
        // S02 §7.3 / §9.1: reserved MUST be 0x000000, verified on parse (a crafted
        // record with nonzero reserved + a recomputed checksum must be rejected).
        if self.reserved != [0u8; 3] {
            return Err(IdentityError::ReservedNotZero);
        }
        if !self.verify_checksum() {
            return Err(IdentityError::ChecksumMismatch);
        }
        Ok(())
    }
}

impl std::fmt::Debug for IdentityRecordStandard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityRecordStandard")
            .field("version", &self.version)
            .field("mode", &self.mode)
            .field("ik_pub", &hex_short(&self.ik_pub))
            .finish()
    }
}

// ---------------------------------------------------------------------------
// IdentityRecordHardware
// ---------------------------------------------------------------------------

/// On-disk format for a hardware-wrapped identity record (mode 0x02).
///
/// Variable-length due to `hw_wrapped_blob`. The app never writes or unlocks
/// this mode; S02 §19.3 reserves it and the migration API fails closed.
///
/// Field layout:
///   offset   0: magic(8)
///   offset   8: version(1)
///   offset   9: mode(1)  = 0x02
///   offset  10: kdf_alg(1)
///   offset  11: aead_alg(1)
///   offset  12: argon2_memory(4, BE)
///   offset  16: argon2_iterations(4, BE)
///   offset  20: argon2_parallelism(1)
///   offset  21: reserved(3)
///   offset  24: saltP(32)
///   offset  56: nonce_inner(24)
///   offset  80: nonce_ik(24)
///   offset 104: ik_pub(32)
///   offset 136: hw_blob_len(4, BE)
///   offset 140: hw_wrapped_blob(N bytes, 48..8192)
///   offset 140+N: enc_ik(48)
///   offset 188+N: checksum(32)
#[derive(Clone)]
pub struct IdentityRecordHardware {
    pub magic: [u8; 8],
    pub version: u8,
    pub mode: u8,
    pub kdf_alg: u8,
    pub aead_alg: u8,
    pub argon2_memory: u32,
    pub argon2_iterations: u32,
    pub argon2_parallelism: u8,
    pub reserved: [u8; 3],
    pub salt_p: [u8; 32],
    pub nonce_inner: [u8; 24],
    pub nonce_ik: [u8; 24],
    pub ik_pub: [u8; 32],
    pub hw_wrapped_blob: Vec<u8>,
    pub enc_ik: [u8; 48],
    pub checksum: [u8; 32],
}

impl IdentityRecordHardware {
    /// Fixed header length before the variable-length blob (140 bytes).
    /// 8+1+1+1+1+4+4+1+3+32+24+24+32+4 = 140
    const HEADER_LEN: usize = 140;
    /// Tail length: enc_ik(48) + checksum(32).
    const TAIL_LEN: usize = 80;

    /// Serialize to bytes with 4-byte BE length prefix for the blob.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(Self::HEADER_LEN + self.hw_wrapped_blob.len() + Self::TAIL_LEN);
        out.extend_from_slice(&self.magic);
        out.push(self.version);
        out.push(self.mode);
        out.push(self.kdf_alg);
        out.push(self.aead_alg);
        out.extend_from_slice(&self.argon2_memory.to_be_bytes());
        out.extend_from_slice(&self.argon2_iterations.to_be_bytes());
        out.push(self.argon2_parallelism);
        out.extend_from_slice(&self.reserved);
        out.extend_from_slice(&self.salt_p);
        out.extend_from_slice(&self.nonce_inner);
        out.extend_from_slice(&self.nonce_ik);
        out.extend_from_slice(&self.ik_pub);
        out.extend_from_slice(&(self.hw_wrapped_blob.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.hw_wrapped_blob);
        out.extend_from_slice(&self.enc_ik);
        out.extend_from_slice(&self.checksum);
        out
    }

    /// Deserialize from bytes, reading fields in layout order.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < Self::HEADER_LEN + Self::TAIL_LEN {
            return Err(IdentityError::RecordTooShort);
        }

        let mut pos = 0;

        let mut magic = [0u8; 8];
        magic.copy_from_slice(&data[pos..pos + 8]);
        pos += 8;
        if magic != MAGIC {
            return Err(IdentityError::InvalidMagic);
        }

        let version = data[pos];
        pos += 1;
        let mode = data[pos];
        pos += 1;
        let kdf_alg = data[pos];
        pos += 1;
        let aead_alg = data[pos];
        pos += 1;

        let argon2_memory = u32::from_be_bytes(
            data[pos..pos + 4]
                .try_into()
                .map_err(|_| IdentityError::RecordTooShort)?,
        );
        pos += 4;
        let argon2_iterations = u32::from_be_bytes(
            data[pos..pos + 4]
                .try_into()
                .map_err(|_| IdentityError::RecordTooShort)?,
        );
        pos += 4;
        let argon2_parallelism = data[pos];
        pos += 1;

        let mut reserved = [0u8; 3];
        reserved.copy_from_slice(&data[pos..pos + 3]);
        pos += 3;

        let mut salt_p = [0u8; 32];
        salt_p.copy_from_slice(&data[pos..pos + 32]);
        pos += 32;
        let mut nonce_inner = [0u8; 24];
        nonce_inner.copy_from_slice(&data[pos..pos + 24]);
        pos += 24;
        let mut nonce_ik = [0u8; 24];
        nonce_ik.copy_from_slice(&data[pos..pos + 24]);
        pos += 24;
        let mut ik_pub = [0u8; 32];
        ik_pub.copy_from_slice(&data[pos..pos + 32]);
        pos += 32;

        // hw_blob_len is u32 (4 bytes, BE)
        let blob_len = u32::from_be_bytes(
            data[pos..pos + 4]
                .try_into()
                .map_err(|_| IdentityError::RecordTooShort)?,
        ) as usize;
        pos += 4;

        if data.len() < pos + blob_len + Self::TAIL_LEN {
            return Err(IdentityError::RecordTooShort);
        }

        let hw_wrapped_blob = data[pos..pos + blob_len].to_vec();
        pos += blob_len;

        let mut enc_ik = [0u8; 48];
        enc_ik.copy_from_slice(&data[pos..pos + 48]);
        pos += 48;
        let mut checksum = [0u8; 32];
        checksum.copy_from_slice(&data[pos..pos + 32]);

        Ok(Self {
            magic,
            version,
            mode,
            kdf_alg,
            aead_alg,
            argon2_memory,
            argon2_iterations,
            argon2_parallelism,
            reserved,
            salt_p,
            nonce_inner,
            nonce_ik,
            ik_pub,
            hw_wrapped_blob,
            enc_ik,
            checksum,
        })
    }

    /// Compute checksum over everything except the last 32 bytes.
    pub fn compute_checksum(&self) -> [u8; 32] {
        let bytes = self.to_bytes();
        sha256(&bytes[..bytes.len() - 32])
    }
}

impl std::fmt::Debug for IdentityRecordHardware {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityRecordHardware")
            .field("version", &self.version)
            .field("mode", &self.mode)
            .field("ik_pub", &hex_short(&self.ik_pub))
            .field("blob_len", &self.hw_wrapped_blob.len())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Identity (in-memory unlocked)
// ---------------------------------------------------------------------------

/// In-memory unlocked identity.
pub struct Identity {
    /// Ed25519 identity key pair.
    pub keypair: Ed25519KeyPair,
    /// Identity creation timestamp.
    pub created_at: u64,
    /// Record version.
    pub version: u8,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("public_key", &hex_short(&self.keypair.public().to_bytes()))
            .field("created_at", &self.created_at)
            .field("version", &self.version)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// IdentityState
// ---------------------------------------------------------------------------

/// Identity manager state machine.
pub enum IdentityState {
    /// No identity exists.
    None,
    /// Identity exists but locked.
    Locked(IdentityRecordStandard),
    /// Identity unlocked (boxed to reduce enum size difference).
    Unlocked(Box<Identity>),
}

impl std::fmt::Debug for IdentityState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "IdentityState::None"),
            Self::Locked(_) => write!(f, "IdentityState::Locked"),
            Self::Unlocked(id) => write!(f, "IdentityState::Unlocked({:?})", id),
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Format first 4 bytes as hex for debug output.
fn hex_short(bytes: &[u8]) -> String {
    if bytes.len() >= 4 {
        format!(
            "{:02x}{:02x}{:02x}{:02x}...",
            bytes[0], bytes[1], bytes[2], bytes[3]
        )
    } else {
        String::from("(empty)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_record() -> IdentityRecordStandard {
        let mut rec = IdentityRecordStandard {
            magic: MAGIC,
            version: VERSION,
            mode: MODE_STANDARD,
            kdf_alg: KDF_ALG_ARGON2ID,
            aead_alg: AEAD_ALG_XCHACHA20,
            argon2_memory: 65536,
            argon2_iterations: 3,
            argon2_parallelism: 1,
            reserved: [0; 3],
            salt_p: [0x01; 32],
            nonce: [0x02; 24],
            ik_pub: [0x03; 32],
            enc_ik: [0x04; 48],
            checksum: [0; 32],
        };
        rec.checksum = rec.compute_checksum();
        rec
    }

    #[test]
    fn standard_record_roundtrip() {
        let rec = make_test_record();
        let bytes = rec.to_bytes();
        assert_eq!(bytes.len(), STANDARD_RECORD_SIZE);

        let rec2 = IdentityRecordStandard::from_bytes(&bytes).unwrap();
        assert_eq!(rec2.magic, MAGIC);
        assert_eq!(rec2.version, VERSION);
        assert_eq!(rec2.salt_p, rec.salt_p);
        assert_eq!(rec2.ik_pub, rec.ik_pub);
        assert_eq!(rec2.enc_ik, rec.enc_ik);
        assert_eq!(rec2.checksum, rec.checksum);
    }

    #[test]
    fn standard_record_checksum_valid() {
        let rec = make_test_record();
        assert!(rec.verify_checksum());
    }

    #[test]
    fn standard_record_checksum_detects_tamper() {
        let mut rec = make_test_record();
        rec.salt_p[0] ^= 0xFF;
        assert!(!rec.verify_checksum());
    }

    #[test]
    fn standard_record_validate_bad_magic() {
        let mut rec = make_test_record();
        rec.magic = *b"BADMAGIC";
        rec.checksum = rec.compute_checksum();
        assert!(matches!(rec.validate(), Err(IdentityError::InvalidMagic)));
    }

    #[test]
    fn standard_record_validate_rejects_nonzero_reserved() {
        // S02 §7.3 / §9.1: a crafted record with nonzero reserved AND a recomputed
        // checksum must still be rejected on parse.
        let mut rec = make_test_record();
        rec.reserved = [0, 0, 1];
        rec.checksum = rec.compute_checksum();
        assert!(matches!(
            rec.validate(),
            Err(IdentityError::ReservedNotZero)
        ));
    }

    #[test]
    fn standard_record_validate_version_bounds() {
        // S02 §9.1: version <= 0x03 accepted; a newer/unknown version rejected.
        let mut older = make_test_record();
        older.version = 0x02;
        older.checksum = older.compute_checksum();
        assert!(older.validate().is_ok());

        let mut newer = make_test_record();
        newer.version = 0x04;
        newer.checksum = newer.compute_checksum();
        assert!(matches!(
            newer.validate(),
            Err(IdentityError::UnsupportedVersion(0x04))
        ));
    }

    #[test]
    fn standard_record_too_short() {
        assert!(IdentityRecordStandard::from_bytes(&[0u8; 10]).is_err());
    }

    #[test]
    fn hardware_record_roundtrip() {
        let rec = IdentityRecordHardware {
            magic: MAGIC,
            version: VERSION,
            mode: MODE_HARDWARE,
            kdf_alg: KDF_ALG_ARGON2ID,
            aead_alg: AEAD_ALG_XCHACHA20,
            argon2_memory: 65536,
            argon2_iterations: 3,
            argon2_parallelism: 1,
            reserved: [0; 3],
            salt_p: [0x01; 32],
            nonce_inner: [0x05; 24],
            nonce_ik: [0x06; 24],
            ik_pub: [0x03; 32],
            hw_wrapped_blob: vec![0xAA; 64],
            enc_ik: [0x07; 48],
            checksum: [0; 32],
        };
        let bytes = rec.to_bytes();
        let rec2 = IdentityRecordHardware::from_bytes(&bytes).unwrap();
        assert_eq!(rec2.hw_wrapped_blob, vec![0xAA; 64]);
        assert_eq!(rec2.ik_pub, rec.ik_pub);
    }
}
