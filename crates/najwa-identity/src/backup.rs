//! Recovery kit: BIP-39 words and the recovery record (S02 §13).
//!
//! Provides:
//! - Recovery record creation and recovery (S02 §13), used by the app
//! - Seed phrase export from identity key (not used by the app)
//! - Seed phrase recovery to restore identity (not used by the app)
//! - Backup verification challenge (3 random words)
//! - Passphrase-encrypted backup record creation and restoration (not used by the app)

use bip39::Mnemonic;
use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use zeroize::{Zeroize, Zeroizing};

use najwa_crypto::prelude::*;

use crate::creation::create_identity_from_seed;
use crate::error::IdentityError;
use crate::record::{Identity, IdentityRecordStandard};

// Keep decrypted heap buffers guarded from their first owner through every exit.
fn secret_vec(bytes: Vec<u8>) -> Zeroizing<Vec<u8>> {
    let secret = Zeroizing::new(bytes);
    #[cfg(test)]
    cleanup_tests::observe(&secret);
    secret
}

#[cfg(test)]
#[path = "backup_cleanup_tests.rs"]
mod cleanup_tests;

/// Errors specific to backup/recovery operations.
#[derive(Debug, thiserror::Error)]
pub enum BackupError {
    /// Invalid BIP-39 mnemonic phrase.
    #[error("invalid mnemonic phrase: {0}")]
    InvalidMnemonic(String),

    /// Entropy length mismatch (expected 32 bytes for 24-word mnemonic).
    #[error("entropy length mismatch: expected 32 bytes, got {0}")]
    EntropyLengthMismatch(usize),

    /// Wrapped cryptographic error from `najwa-crypto`.
    #[error(transparent)]
    Crypto(#[from] najwa_crypto::error::CryptoError),

    /// I/O error.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// Backup operation error.
    #[error("backup error: {0}")]
    Backup(String),

    /// Identity error during recovery.
    #[error(transparent)]
    Identity(#[from] IdentityError),

    /// Recovery phrase word count does not match the record's `phrase_length`.
    #[error("recovery phrase length mismatch")]
    PhraseLengthMismatch,

    /// The key recovered from the mnemonic + record does not match `ik_pub`.
    #[error("recovered key does not match recovery record")]
    RecoveryVerificationFailed,
}

/// Generate a BIP-39 mnemonic (24 words) that encodes the identity private key.
///
/// The seed is the Ed25519 private key bytes (32 bytes → 24-word mnemonic).
/// Not used by the app; its recovery kit is the S02 §13 recovery record.
pub fn export_seed_phrase(identity: &Identity) -> std::result::Result<String, BackupError> {
    let seed = Zeroizing::new(identity.keypair.private().to_bytes());
    let mnemonic =
        Mnemonic::from_entropy(&*seed).map_err(|e| BackupError::InvalidMnemonic(e.to_string()))?;
    Ok(mnemonic.to_string())
}

/// 12-word export of the identity private key. Always returns an error.
///
/// A 12-word (128-bit) phrase cannot encode the 256-bit identity key. 12-word
/// recovery phrases exist only as recovery-record seeds (S02 §13.1).
pub fn export_seed_phrase_12(_identity: &Identity) -> std::result::Result<String, BackupError> {
    // A 12-word phrase can only unlock a recovery record (S02 §13); it cannot
    // carry the identity key itself. Truncating and re-expanding the key would
    // produce a different identity.
    Err(BackupError::InvalidMnemonic(
        "12-word export is unavailable; use the 24-word recovery phrase".into(),
    ))
}

/// Recover an identity from a 24-word mnemonic that encodes the private key
/// directly (the [`export_seed_phrase`] format). Not used by the app.
///
/// Steps:
/// 1. Parse and validate the mnemonic
/// 2. Extract entropy: 32 bytes is the seed; 16 bytes (12 words) is rejected
/// 3. Create a new identity record protected by `new_password`
pub fn recover_from_seed_phrase(
    mnemonic_str: &str,
    new_password: &str,
) -> std::result::Result<(IdentityRecordStandard, Identity), BackupError> {
    // 1. Parse and validate mnemonic
    let mnemonic = Mnemonic::parse_normalized(mnemonic_str)
        .map_err(|e| BackupError::InvalidMnemonic(e.to_string()))?;

    // 2. Extract entropy
    let entropy = secret_vec(mnemonic.to_entropy());
    let seed = Zeroizing::new(match entropy.len() {
        32 => {
            // 24-word mnemonic: entropy is the seed directly
            entropy
                .as_slice()
                .try_into()
                .map_err(|_| BackupError::EntropyLengthMismatch(0))?
        }
        16 => {
            // A 12-word (128-bit) phrase CANNOT losslessly reconstruct the
            // 256-bit identity key; expanding it would build a DIFFERENT
            // identity. 12-word phrases only unlock a recovery record
            // (S02 §13); the 24-word phrase carries the full key.
            return Err(BackupError::InvalidMnemonic(
                "12-word recovery is not supported; use your 24-word recovery phrase".into(),
            ));
        }
        other => return Err(BackupError::EntropyLengthMismatch(other)),
    });

    // 3. Create identity from seed with new password
    let (record, identity) = create_identity_from_seed(&seed, new_password, None)?;
    Ok((record, identity))
}

/// HKDF `info` / domain separator and AAD prefix for paper-key recovery
/// (S02 §8.6 / §13.1). Exactly 17 bytes.
const RECOVERY_INFO: &[u8] = b"najwa/v1/recovery";

/// `AAD_recovery = "najwa/v1/recovery"(17) || ik_pub(32)` — 49 bytes (S02 §8.6).
fn aad_recovery(ik_pub: &[u8; 32]) -> [u8; 49] {
    let mut aad = [0u8; 49];
    aad[..17].copy_from_slice(RECOVERY_INFO);
    aad[17..].copy_from_slice(ik_pub);
    aad
}

/// A persisted paper-key recovery record (S02 §13.0 / §13.1).
///
/// Together with the BIP-39 mnemonic — which encodes a `recovery_seed` that is
/// **separate** from the identity seed (S02 §13; conflating the two seeds
/// downgrades IK_priv entropy or loses the recovery path) — this record yields
/// `IK_priv` byte-for-byte on a new device. It is device-independent by design:
/// `ik_pub` / `nonce_recovery` are stored in the clear and only `enc_ik_recovery`
/// is sealed, under a key derived from the mnemonic. A 12-word (128-bit) phrase
/// recovers the full 256-bit key precisely because the phrase decrypts a stored
/// record rather than *being* the key.
#[derive(Clone)]
pub struct RecoveryRecord {
    /// The identity public key this record recovers (also the HKDF salt + AAD).
    pub ik_pub: [u8; 32],
    /// XChaCha20-Poly1305 nonce for `enc_ik_recovery`.
    pub nonce_recovery: [u8; 24],
    /// `IK_priv` sealed under `K_recovery`: 32-byte ciphertext + 16-byte tag.
    pub enc_ik_recovery: [u8; 48],
    /// Word count of the mnemonic (12 or 24), so recovery can auto-detect it.
    pub phrase_length: u8,
}

/// Serialized size of a [`RecoveryRecord`]: 32 + 24 + 48 + 1.
pub const RECOVERY_RECORD_SIZE: usize = 105;

impl RecoveryRecord {
    /// Fixed-layout serialization `ik_pub(32) || nonce_recovery(24) ||
    /// enc_ik_recovery(48) || phrase_length(1)` (S02 §13.0).
    ///
    /// This is the in-memory encoding of the record's fields; the at-rest
    /// framing (atomic write + `fsync`, S02 §12.2) is applied by the persistence
    /// layer that stores it.
    pub fn to_bytes(&self) -> [u8; RECOVERY_RECORD_SIZE] {
        let mut out = [0u8; RECOVERY_RECORD_SIZE];
        out[..32].copy_from_slice(&self.ik_pub);
        out[32..56].copy_from_slice(&self.nonce_recovery);
        out[56..104].copy_from_slice(&self.enc_ik_recovery);
        out[104] = self.phrase_length;
        out
    }

    /// Parse a [`RecoveryRecord`] from its fixed 105-byte layout.
    pub fn from_bytes(data: &[u8]) -> std::result::Result<Self, BackupError> {
        if data.len() != RECOVERY_RECORD_SIZE {
            return Err(BackupError::Backup(format!(
                "recovery record must be {RECOVERY_RECORD_SIZE} bytes, got {}",
                data.len()
            )));
        }
        let mut ik_pub = [0u8; 32];
        ik_pub.copy_from_slice(&data[..32]);
        let mut nonce_recovery = [0u8; 24];
        nonce_recovery.copy_from_slice(&data[32..56]);
        let mut enc_ik_recovery = [0u8; 48];
        enc_ik_recovery.copy_from_slice(&data[56..104]);
        Ok(Self {
            ik_pub,
            nonce_recovery,
            enc_ik_recovery,
            phrase_length: data[104],
        })
    }
}

/// Create a paper-key recovery record and its BIP-39 mnemonic (S02 §13.1).
///
/// `phrase_length` selects 12 words (128-bit `recovery_seed`, the default) or 24
/// words (256-bit). The returned mnemonic is shown to the user exactly once and
/// then dropped; the [`RecoveryRecord`] is persisted. `recovery_seed` and the
/// derived AEAD key are zeroised before returning.
pub fn create_recovery_record(
    identity: &Identity,
    phrase_length: u8,
) -> std::result::Result<(String, RecoveryRecord), BackupError> {
    let seed_len = match phrase_length {
        12 => 16,
        24 => 32,
        other => {
            return Err(BackupError::Backup(format!(
                "phrase_length must be 12 or 24, got {other}"
            )))
        }
    };

    let ik_pub = identity.keypair.public().to_bytes();
    let mut ik_priv = Zeroizing::new(identity.keypair.private().to_bytes());

    // recovery_seed = CSPRNG(16 or 32) — SEPARATE from the identity seed (S02 §13.1 step 2).
    let mut recovery_seed = secret_vec(random_bytes_vec(seed_len));

    // words = BIP39_Encode(recovery_seed)
    let mnemonic = Mnemonic::from_entropy(&recovery_seed)
        .map_err(|e| BackupError::InvalidMnemonic(e.to_string()))?;

    // K_recovery = HKDF(ikm=recovery_seed, salt=ik_pub, info="najwa/v1/recovery", 32)
    let k = hkdf_sha256(&recovery_seed, &ik_pub, RECOVERY_INFO, 32)?;
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&k);

    // nonce_recovery = CSPRNG(24); enc_ik_recovery = AEAD(K, nonce, IK_priv, AAD_recovery)
    let nonce_recovery: [u8; 24] = random_bytes();
    let aad = aad_recovery(&ik_pub);
    let enc = aead::encrypt(&key, &nonce_recovery, &*ik_priv, &aad)?;
    let enc_ik_recovery: [u8; 48] = enc
        .as_slice()
        .try_into()
        .map_err(|_| BackupError::Backup("enc_ik_recovery must be 48 bytes".into()))?;

    // Zero: recovery_seed, K_recovery, the IK_priv working copy (S02 §13.1 step 8).
    recovery_seed.zeroize();
    key.zeroize();
    ik_priv.zeroize();

    Ok((
        mnemonic.to_string(),
        RecoveryRecord {
            ik_pub,
            nonce_recovery,
            enc_ik_recovery,
            phrase_length,
        },
    ))
}

/// Recover `IK_priv` from a mnemonic + [`RecoveryRecord`] (S02 §13.2), then build
/// a fresh Standard-mode identity record under `new_password`.
///
/// Fails loudly on a wrong mnemonic (AEAD auth failure), a phrase-length
/// mismatch, or a recovered pubkey that does not equal `record.ik_pub` — never
/// silently returns a different identity.
///
/// NOTE: prekey hygiene (S02 §13.2 step 9 — fresh SPK + brand-new OPK pool) is
/// returned as a typed obligation, not a prose promise: the manager-level
/// flow ([`crate::manager::IdentityManager::recover_from_recovery_record_at`])
/// wraps this function and hands the caller a
/// [`crate::manager::PrekeyHygieneRequired`] marker whose docs carry the
/// normative split (mint+upload: S06 §5.8 prekey manager; reject
/// pre-restore-id Initials: core receive path). This function itself performs
/// S02 §13.2 steps 1–8 and 10 only.
pub fn recover_from_recovery_record(
    mnemonic_str: &str,
    record: &RecoveryRecord,
    new_password: &str,
) -> std::result::Result<(IdentityRecordStandard, Identity), BackupError> {
    let expected_words = match record.phrase_length {
        12 => 12,
        24 => 24,
        other => {
            return Err(BackupError::Backup(format!(
                "record phrase_length must be 12 or 24, got {other}"
            )))
        }
    };
    if mnemonic_str.split_whitespace().count() != expected_words {
        return Err(BackupError::PhraseLengthMismatch);
    }

    // recovery_seed = BIP39_Decode(words)
    let mnemonic = Mnemonic::parse_normalized(mnemonic_str)
        .map_err(|e| BackupError::InvalidMnemonic(e.to_string()))?;
    let mut recovery_seed = secret_vec(mnemonic.to_entropy());

    // K_recovery = HKDF(ikm=recovery_seed, salt=ik_pub, info="najwa/v1/recovery", 32)
    let k = hkdf_sha256(&recovery_seed, &record.ik_pub, RECOVERY_INFO, 32)?;
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&k);

    // IK_priv = AEAD_Decrypt(K, nonce_recovery, enc_ik_recovery, AAD_recovery)
    let aad = aad_recovery(&record.ik_pub);
    let mut ik_priv = secret_vec(aead::decrypt(
        &key,
        &record.nonce_recovery,
        &record.enc_ik_recovery,
        &aad,
    )?);
    recovery_seed.zeroize();
    key.zeroize();

    let mut seed = Zeroizing::new([0u8; 32]);
    seed.copy_from_slice(
        ik_priv
            .as_slice()
            .get(..32)
            .ok_or_else(|| BackupError::Backup("recovered IK_priv must be 32 bytes".into()))?,
    );
    ik_priv.zeroize();

    // Verify: Ed25519_DerivePublic(IK_priv) == ik_pub (S02 §13.2 step 7).
    let keypair = Ed25519KeyPair::from_seed(&seed);
    if keypair.public().to_bytes() != record.ik_pub {
        seed.zeroize();
        return Err(BackupError::RecoveryVerificationFailed);
    }

    // Build a fresh Standard-mode identity record under the new password.
    let (new_record, identity) = create_identity_from_seed(&seed, new_password, None)?;
    seed.zeroize();
    Ok((new_record, identity))
}

/// Backup verification challenge. Not used by the app, whose UI runs its own
/// three-word check (S02 §13.3).
///
/// Asks the user to confirm 3 random words from their seed phrase
/// to verify they have correctly written it down.
pub struct BackupVerification {
    /// The 3 random word indices the user must confirm (0-indexed).
    pub challenge_indices: Vec<usize>,
}

impl BackupVerification {
    /// Create a new verification challenge for a 24-word mnemonic.
    pub fn new() -> Self {
        let mut indices: Vec<usize> = (0..24).collect();
        indices.shuffle(&mut OsRng);
        Self {
            challenge_indices: indices[..3].to_vec(),
        }
    }

    /// Create a challenge with specific indices (for testing).
    pub fn with_indices(indices: Vec<usize>) -> Self {
        Self {
            challenge_indices: indices,
        }
    }

    /// Verify the user's answers against the mnemonic.
    ///
    /// `answers` is a slice of `(word_index, word)` pairs.
    pub fn verify(&self, mnemonic: &str, answers: &[(usize, &str)]) -> bool {
        let words: Vec<&str> = mnemonic.split_whitespace().collect();
        if self.challenge_indices.is_empty() || answers.len() != self.challenge_indices.len() {
            return false;
        }
        let mut seen = std::collections::HashSet::new();
        answers.iter().all(|(idx, word)| {
            seen.insert(*idx)
                && self.challenge_indices.contains(idx)
                && words.get(*idx).map(|w| *w == *word).unwrap_or(false)
        })
    }
}

impl Default for BackupVerification {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Encrypted Backup Record (passphrase-only identity backup; not used by the app)
// ---------------------------------------------------------------------------

/// Magic bytes for encrypted backup: `"ANONBAK\x00"`.
pub const BACKUP_MAGIC: [u8; 8] = *b"ANONBAK\0";

/// AAD domain prefix for the backup AEAD. The full AAD is
/// `AAD_BACKUP_PREFIX(15) || backup_version(1) || ik_pub(32)` = 48 bytes — NOT
/// the record magic, and the random salt is deliberately excluded.
pub const AAD_BACKUP_PREFIX: &[u8] = b"najwa/v1/backup";

/// KDF algorithm id in the backup record: Argon2id.
pub const BACKUP_KDF_ALG: u8 = 0x01;

/// AEAD algorithm id in the backup record: XChaCha20-Poly1305.
pub const BACKUP_AEAD_ALG: u8 = 0x01;

/// Total size of an encrypted backup record in bytes. Fixed layout:
/// magic(8)@0 || version(1)@8 || kdf_alg(1)@9 || aead_alg(1)@10 || reserved(1)@11
/// || argon2_memory(4 BE)@12 || argon2_iterations(4 BE)@16 || argon2_parallelism
/// (4 BE)@20 || salt(32)@24 || nonce(24)@56 || ik_pub(32)@80 ||
/// enc_ik_priv(48)@112 || checksum(32)@160 = 192.
pub const BACKUP_RECORD_SIZE: usize = 192;

/// Argon2id memory for backup key derivation: 512 MiB.
pub const BACKUP_ARGON2_MEMORY_KIB: u32 = 524_288;

/// Argon2id iterations for backup.
pub const BACKUP_ARGON2_ITERATIONS: u32 = 4;

/// Argon2id parallelism for backup.
pub const BACKUP_ARGON2_PARALLELISM: u8 = 2;

/// Encrypted backup record (not used by the app).
///
/// Allows restoring an identity from a backup password without the original
/// device or DKM. Uses Argon2id with 512 MiB memory to resist brute-force.
#[derive(Debug, Clone)]
pub struct BackupRecord {
    pub version: u8,
    pub salt: [u8; 32],
    pub nonce: [u8; 24],
    pub argon2_memory_kib: u32,
    pub argon2_iterations: u32,
    pub argon2_parallelism: u8,
    pub ik_pub: [u8; 32],
    pub encrypted_ik_priv: Vec<u8>,
    pub checksum: [u8; 32],
}

/// Create an encrypted backup record from an identity and a backup password.
///
/// The backup password should be strong (≥20 chars recommended) since this
/// is the sole protection — no DKM second factor.
pub fn create_encrypted_backup(
    identity: &Identity,
    backup_password: &str,
) -> std::result::Result<Vec<u8>, BackupError> {
    let salt: [u8; 32] = random_bytes();
    let nonce: [u8; 24] = random_bytes();
    let ik_priv = Zeroizing::new(identity.keypair.private().to_bytes());
    let ik_pub = identity.keypair.public().to_bytes();

    // Derive backup key via Argon2id with 512 MiB
    let backup_params = Argon2Params {
        memory_kib: BACKUP_ARGON2_MEMORY_KIB,
        iterations: BACKUP_ARGON2_ITERATIONS,
        parallelism: BACKUP_ARGON2_PARALLELISM as u32,
    };
    let key = argon2id(backup_password.as_bytes(), &salt, &backup_params)?;

    // Build AAD: prefix || version || ik_pub = 48 bytes (no magic,
    // no salt).
    let mut aad = Vec::with_capacity(AAD_BACKUP_PREFIX.len() + 1 + 32);
    aad.extend_from_slice(AAD_BACKUP_PREFIX);
    aad.push(0x01); // backup_version
    aad.extend_from_slice(&ik_pub);

    // Encrypt identity private key
    let encrypted = aead::encrypt(&key, &nonce, &*ik_priv, &aad)?;

    // Serialize to the fixed 192-byte layout of BACKUP_RECORD_SIZE.
    let mut record = Vec::with_capacity(BACKUP_RECORD_SIZE);
    record.extend_from_slice(&BACKUP_MAGIC); // 0..8
    record.push(0x01); // 8: version
    record.push(BACKUP_KDF_ALG); // 9: kdf_alg
    record.push(BACKUP_AEAD_ALG); // 10: aead_alg
    record.push(0x00); // 11: reserved
    record.extend_from_slice(&BACKUP_ARGON2_MEMORY_KIB.to_be_bytes()); // 12..16
    record.extend_from_slice(&BACKUP_ARGON2_ITERATIONS.to_be_bytes()); // 16..20
    record.extend_from_slice(&(BACKUP_ARGON2_PARALLELISM as u32).to_be_bytes()); // 20..24
    record.extend_from_slice(&salt); // 24..56
    record.extend_from_slice(&nonce); // 56..80
    record.extend_from_slice(&ik_pub); // 80..112
    record.extend_from_slice(&encrypted); // 112..160 (32+16=48)

    // Checksum: SHA-256 over record[0..160]; it fills 160..192 (no padding).
    debug_assert_eq!(record.len(), 160);
    let checksum = sha256(&record);
    record.extend_from_slice(&checksum); // 160..192

    Ok(record)
}

// ---------------------------------------------------------------------------
// Contact & Data Backup (not used by the app)
// ---------------------------------------------------------------------------

/// Serializable contact backup entry.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ContactBackupEntry {
    pub their_ik_pub: [u8; 32],
    pub their_pseudonym: [u8; 32],
    pub our_pseudonym: [u8; 32],
    pub display_name: Option<String>,
    pub verified: bool,
}

/// Serializable mailbox backup entry.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MailboxBackupEntry {
    pub onion_address: String,
    pub fetch_capability: Vec<u8>,
    pub deposit_capability: Vec<u8>,
}

/// Full contact & data backup payload.
///
/// Excludes ratchet state and disappearing messages.
/// Encrypted with `HKDF(IK_priv, "najwa/v1/contact-backup", 32)`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ContactBackup {
    pub version: u8,
    pub created_at: u64,
    pub contacts: Vec<ContactBackupEntry>,
    pub mailboxes: Vec<MailboxBackupEntry>,
}

/// Create an encrypted contact backup blob.
///
/// Key derivation: `backup_key = HKDF(IKM=IK_priv, salt="", info="najwa/v1/contact-backup", 32)`
pub fn create_contact_backup(
    ik_priv: &[u8; 32],
    backup: &ContactBackup,
) -> std::result::Result<Vec<u8>, BackupError> {
    let backup_key_vec = hkdf_sha256(ik_priv, b"", info_strings::CONTACT_BACKUP_INFO, 32)?;
    let mut backup_key = Zeroizing::new([0u8; 32]);
    backup_key.copy_from_slice(&backup_key_vec);

    let plaintext = secret_vec(
        serde_json::to_vec(backup)
            .map_err(|e| BackupError::Identity(IdentityError::InternalError(e.to_string())))?,
    );

    let nonce: [u8; 24] = random_bytes();
    let ciphertext = aead::encrypt(&backup_key, &nonce, &plaintext, b"contact-backup")?;

    let mut blob = Vec::with_capacity(24 + ciphertext.len());
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);
    Ok(blob)
}

/// Restore a contact backup from an encrypted blob.
pub fn restore_contact_backup(
    ik_priv: &[u8; 32],
    blob: &[u8],
) -> std::result::Result<ContactBackup, BackupError> {
    if blob.len() < 24 {
        return Err(BackupError::Identity(IdentityError::RecordTooShort));
    }

    let backup_key_vec = hkdf_sha256(ik_priv, b"", info_strings::CONTACT_BACKUP_INFO, 32)?;
    let mut backup_key = Zeroizing::new([0u8; 32]);
    backup_key.copy_from_slice(&backup_key_vec);

    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&blob[..24]);
    let ciphertext = &blob[24..];

    let plaintext = secret_vec(
        aead::decrypt(&backup_key, &nonce, ciphertext, b"contact-backup")
            .map_err(|_| BackupError::Identity(IdentityError::UnlockFailed))?,
    );

    serde_json::from_slice(&plaintext)
        .map_err(|e| BackupError::Identity(IdentityError::InternalError(e.to_string())))
}

/// Restore an identity from an encrypted backup record and password.
pub fn restore_encrypted_backup(
    record_bytes: &[u8],
    backup_password: &str,
    new_password: &str,
) -> std::result::Result<(IdentityRecordStandard, Identity), BackupError> {
    if record_bytes.len() < BACKUP_RECORD_SIZE {
        return Err(BackupError::Identity(IdentityError::RecordTooShort));
    }

    // Verify magic
    if record_bytes[0..8] != BACKUP_MAGIC {
        return Err(BackupError::Identity(IdentityError::InvalidMagic));
    }

    let _version = record_bytes[8];
    // Layout: kdf_alg@9, aead_alg@10, reserved@11.
    if record_bytes[9] != BACKUP_KDF_ALG || record_bytes[10] != BACKUP_AEAD_ALG {
        return Err(BackupError::Backup(
            "unsupported backup KDF/AEAD algorithm".into(),
        ));
    }
    if record_bytes[11] != 0x00 {
        return Err(BackupError::Backup(
            "backup reserved bytes must be zero".into(),
        ));
    }
    let argon2_mem = u32::from_be_bytes(record_bytes[12..16].try_into().unwrap());
    let argon2_iter = u32::from_be_bytes(record_bytes[16..20].try_into().unwrap());
    let argon2_par = u32::from_be_bytes(record_bytes[20..24].try_into().unwrap());
    let mut salt = [0u8; 32];
    salt.copy_from_slice(&record_bytes[24..56]);
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&record_bytes[56..80]);
    let mut ik_pub = [0u8; 32];
    ik_pub.copy_from_slice(&record_bytes[80..112]);
    let encrypted = &record_bytes[112..160];

    // Verify checksum (over record[0..160]).
    let stored_checksum = &record_bytes[160..192];
    let computed_checksum = sha256(&record_bytes[..160]);
    if stored_checksum != computed_checksum.as_slice() {
        return Err(BackupError::Identity(IdentityError::ChecksumMismatch));
    }

    // Derive backup key
    let restore_params = Argon2Params {
        memory_kib: argon2_mem,
        iterations: argon2_iter,
        parallelism: argon2_par,
    };
    let key = argon2id(backup_password.as_bytes(), &salt, &restore_params)?;

    // Build AAD: prefix || version || ik_pub = 48 bytes.
    let mut aad = Vec::with_capacity(AAD_BACKUP_PREFIX.len() + 1 + 32);
    aad.extend_from_slice(AAD_BACKUP_PREFIX);
    aad.push(_version);
    aad.extend_from_slice(&ik_pub);

    // Decrypt
    let ik_priv = secret_vec(
        aead::decrypt(&key, &nonce, encrypted, &aad)
            .map_err(|_| BackupError::Identity(IdentityError::UnlockFailed))?,
    );

    if ik_priv.len() != 32 {
        return Err(BackupError::EntropyLengthMismatch(ik_priv.len()));
    }

    let mut seed = Zeroizing::new([0u8; 32]);
    seed.copy_from_slice(&ik_priv);

    // Verify decrypted key matches stored public key
    let kp = najwa_crypto::keys::ed25519::Ed25519KeyPair::from_seed(&seed);
    if kp.public().to_bytes() != ik_pub {
        return Err(BackupError::Identity(IdentityError::PublicKeyMismatch));
    }

    // Create new identity record with new password
    let (record, identity) = create_identity_from_seed(&seed, new_password, None)?;
    Ok((record, identity))
}

#[cfg(test)]
mod tests {
    use super::*;
    use najwa_crypto::keys::ed25519::Ed25519KeyPair;

    #[test]
    fn backup_verification_requires_every_distinct_challenge_answer() {
        let challenge = BackupVerification::with_indices(vec![0, 1, 2]);
        let phrase = "alpha beta gamma delta";
        for answers in [
            vec![],
            vec![(0, "alpha")],
            vec![(0, "alpha"), (0, "alpha"), (0, "alpha")],
            vec![(0, "alpha"), (1, "beta"), (3, "delta")],
            vec![(0, "alpha"), (1, "beta"), (2, "gamma"), (3, "delta")],
        ] {
            assert!(!challenge.verify(phrase, &answers));
        }
        assert!(challenge.verify(phrase, &[(2, "gamma"), (0, "alpha"), (1, "beta")]));
        assert!(!BackupVerification::with_indices(vec![]).verify(phrase, &[]));
        assert!(!BackupVerification::with_indices(vec![0, 0, 1])
            .verify(phrase, &[(0, "alpha"), (0, "alpha"), (1, "beta")]));
    }

    fn make_test_identity() -> Identity {
        let seed: [u8; 32] = najwa_crypto::random::random_bytes();
        let keypair = Ed25519KeyPair::from_seed(&seed);
        Identity {
            keypair,
            created_at: 1000,
            version: 0x03,
        }
    }

    fn make_deterministic_identity(seed: [u8; 32]) -> Identity {
        let keypair = Ed25519KeyPair::from_seed(&seed);
        Identity {
            keypair,
            created_at: 1000,
            version: 0x03,
        }
    }

    #[test]
    fn export_produces_24_words() {
        let identity = make_test_identity();
        let phrase = export_seed_phrase(&identity).unwrap();
        let word_count = phrase.split_whitespace().count();
        assert_eq!(word_count, 24);
    }

    #[test]
    fn export_is_deterministic() {
        let seed = [0x42u8; 32];
        let id1 = make_deterministic_identity(seed);
        let id2 = make_deterministic_identity(seed);
        let phrase1 = export_seed_phrase(&id1).unwrap();
        let phrase2 = export_seed_phrase(&id2).unwrap();
        assert_eq!(phrase1, phrase2);
    }

    #[test]
    fn export_different_seeds_produce_different_phrases() {
        let id1 = make_deterministic_identity([0x01; 32]);
        let id2 = make_deterministic_identity([0x02; 32]);
        let phrase1 = export_seed_phrase(&id1).unwrap();
        let phrase2 = export_seed_phrase(&id2).unwrap();
        assert_ne!(phrase1, phrase2);
    }

    #[test]
    fn roundtrip_export_recover() {
        let seed = [0x42u8; 32];
        let original = make_deterministic_identity(seed);
        let original_pub = original.keypair.public().to_bytes();

        // Export
        let phrase = export_seed_phrase(&original).unwrap();

        // Recover
        let (_record, recovered) = recover_from_seed_phrase(&phrase, "test_password_123").unwrap();
        let recovered_pub = recovered.keypair.public().to_bytes();

        assert_eq!(original_pub, recovered_pub);
    }

    #[test]
    fn recover_invalid_mnemonic_fails() {
        let result = recover_from_seed_phrase("invalid words here", "password123");
        assert!(result.is_err());
    }

    #[test]
    fn recover_rejects_12_word_phrase() {
        // A valid 12-word phrase MUST be rejected, never silently mis-recovered
        // into a different identity (S02 §13). Canonical all-zero BIP-39 mnemonic.
        let phrase12 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let err = recover_from_seed_phrase(phrase12, "pw").unwrap_err();
        assert!(matches!(err, BackupError::InvalidMnemonic(_)));
    }

    #[test]
    fn export_12_word_disabled() {
        let id = make_deterministic_identity([0x42; 32]);
        assert!(export_seed_phrase_12(&id).is_err());
    }

    #[test]
    fn recovery_record_roundtrip_recovers_ik_priv_byte_for_byte() {
        // S02 §13.4: a 12-word phrase recovers the FULL 32-byte IK_priv byte-for-byte
        // (the phrase decrypts a stored record, it is not the key itself).
        for phrase_length in [12u8, 24u8] {
            let seed = [0x37u8; 32];
            let original = make_deterministic_identity(seed);
            let original_priv = original.keypair.private().to_bytes();
            let original_pub = original.keypair.public().to_bytes();

            let (mnemonic, record) = create_recovery_record(&original, phrase_length).unwrap();
            assert_eq!(mnemonic.split_whitespace().count(), phrase_length as usize);
            assert_eq!(record.phrase_length, phrase_length);
            assert_eq!(record.ik_pub, original_pub);

            let (_new_record, recovered) =
                recover_from_recovery_record(&mnemonic, &record, "new_password_123!").unwrap();
            assert_eq!(recovered.keypair.private().to_bytes(), original_priv);
            assert_eq!(recovered.keypair.public().to_bytes(), original_pub);
        }
    }

    #[test]
    fn recovery_record_uses_separate_seed_not_the_ik() {
        // The mnemonic encodes a CSPRNG recovery_seed, NOT IK_priv — so the same
        // identity produces a different mnemonic each time (S02 §13, separate seeds).
        let id = make_deterministic_identity([0x11; 32]);
        let (m1, _) = create_recovery_record(&id, 24).unwrap();
        let (m2, _) = create_recovery_record(&id, 24).unwrap();
        assert_ne!(m1, m2);
        // And the mnemonic is not the 24-word export of IK_priv.
        assert_ne!(m1, export_seed_phrase(&id).unwrap());
    }

    #[test]
    fn recovery_record_wrong_mnemonic_fails_loudly() {
        // A wrong (but valid) mnemonic derives a wrong K_recovery → AEAD auth
        // failure, never a silently-different identity.
        let id = make_deterministic_identity([0x42; 32]);
        let (_mnemonic, record) = create_recovery_record(&id, 12).unwrap();
        let wrong = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let err = recover_from_recovery_record(wrong, &record, "pw").unwrap_err();
        assert!(matches!(
            err,
            BackupError::Crypto(_) | BackupError::RecoveryVerificationFailed
        ));
    }

    #[test]
    fn recovery_record_phrase_length_mismatch_rejected() {
        let id = make_deterministic_identity([0x42; 32]);
        let (m12, r12) = create_recovery_record(&id, 12).unwrap();
        // Record claims 24 words but the presented phrase has 12 → mismatch.
        let bad = RecoveryRecord {
            phrase_length: 24,
            ..r12
        };
        let err = recover_from_recovery_record(&m12, &bad, "pw").unwrap_err();
        assert!(matches!(err, BackupError::PhraseLengthMismatch));
    }

    #[test]
    fn recovery_record_serialization_roundtrips() {
        let id = make_deterministic_identity([0x99; 32]);
        let (_m, record) = create_recovery_record(&id, 12).unwrap();
        let bytes = record.to_bytes();
        assert_eq!(bytes.len(), RECOVERY_RECORD_SIZE);
        let restored = RecoveryRecord::from_bytes(&bytes).unwrap();
        assert_eq!(restored.ik_pub, record.ik_pub);
        assert_eq!(restored.nonce_recovery, record.nonce_recovery);
        assert_eq!(restored.enc_ik_recovery, record.enc_ik_recovery);
        assert_eq!(restored.phrase_length, record.phrase_length);
        // A wrong-length buffer is rejected.
        assert!(RecoveryRecord::from_bytes(&bytes[..104]).is_err());
    }

    #[test]
    fn backup_verification_correct_answers() {
        let seed = [0x42u8; 32];
        let identity = make_deterministic_identity(seed);
        let phrase = export_seed_phrase(&identity).unwrap();
        let words: Vec<&str> = phrase.split_whitespace().collect();

        let verification = BackupVerification::with_indices(vec![0, 5, 12]);

        let answers = vec![(0, words[0]), (5, words[5]), (12, words[12])];
        assert!(verification.verify(&phrase, &answers));
    }

    #[test]
    fn backup_verification_wrong_answer_fails() {
        let seed = [0x42u8; 32];
        let identity = make_deterministic_identity(seed);
        let phrase = export_seed_phrase(&identity).unwrap();

        let verification = BackupVerification::with_indices(vec![0, 5, 12]);

        let answers = vec![(0, "wrong"), (5, "words"), (12, "here")];
        assert!(!verification.verify(&phrase, &answers));
    }

    #[test]
    fn backup_verification_new_generates_3_indices() {
        let verification = BackupVerification::new();
        assert_eq!(verification.challenge_indices.len(), 3);
        for &idx in &verification.challenge_indices {
            assert!(idx < 24);
        }
    }
}
