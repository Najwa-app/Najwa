//! S18 conformance vectors for S02 identity records (S18 §13, §14).
//!
//! S18 §13 gives a fully concrete 192-byte standard record (checksum = SHA-256
//! over the first 160 bytes), asserted byte-for-byte here. S18 §14 gives the
//! recovery inputs; the intermediates are computed at runtime, and the
//! assertions are the spec's verification clause: mnemonic → `recovery_seed`
//! → `K_recovery` → `IK_priv` byte-for-byte, on both phrase lengths.

use bip39::Mnemonic;
use najwa_crypto::kdf::hkdf_sha256;
use najwa_identity::backup::{recover_from_recovery_record, RecoveryRecord};
use najwa_identity::record::IdentityRecordStandard;

// S18 §2 — common test data.
const TEST_SALT_32: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
    0x17, 0x18, 0x19, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x30, 0x31, 0x32,
];
const TEST_NONCE_24: [u8; 24] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
];
const TEST_IK_PRIV: [u8; 32] = [0xBB; 32];

// ---------------------------------------------------------------------------
// S18 §13 — Identity Record Roundtrip (Standard Mode), 192 bytes, byte-exact
// ---------------------------------------------------------------------------

#[test]
fn s18_13_standard_record_roundtrip_byte_exact() {
    // Assemble the 160-byte pre-checksum body exactly as S18 §13 specifies.
    let mut body = Vec::with_capacity(160);
    body.extend_from_slice(b"NAJWA\x00\x00\x00"); // magic (8)
    body.push(0x03); // version
    body.push(0x01); // mode (standard)
    body.push(0x01); // kdf_alg
    body.push(0x01); // aead_alg
    body.extend_from_slice(&0x0001_0000u32.to_be_bytes()); // argon2_memory 65536
    body.extend_from_slice(&3u32.to_be_bytes()); // argon2_iterations
    body.push(0x04); // argon2_parallelism
    body.extend_from_slice(&[0x00; 3]); // reserved
    body.extend_from_slice(&TEST_SALT_32);
    body.extend_from_slice(&TEST_NONCE_24);
    body.extend_from_slice(&[0x55; 32]); // ik_pub
    body.extend_from_slice(&[0x66; 48]); // enc_ik (32 + 16 tag)
    assert_eq!(body.len(), 160);

    let mut full = body.clone();
    full.extend_from_slice(&najwa_crypto::hash::sha256(&body));
    assert_eq!(full.len(), 192);

    // Parse → every field matches; serialize → byte-identical.
    let record = IdentityRecordStandard::from_bytes(&full).unwrap();
    assert_eq!(record.magic, *b"NAJWA\x00\x00\x00");
    assert_eq!(record.version, 0x03);
    assert_eq!(record.mode, 0x01);
    assert_eq!(record.kdf_alg, 0x01);
    assert_eq!(record.aead_alg, 0x01);
    assert_eq!(record.argon2_memory, 65536);
    assert_eq!(record.argon2_iterations, 3);
    assert_eq!(record.argon2_parallelism, 4);
    assert_eq!(record.reserved, [0x00; 3]);
    assert_eq!(record.salt_p, TEST_SALT_32);
    assert_eq!(record.nonce, TEST_NONCE_24);
    assert_eq!(record.ik_pub, [0x55; 32]);
    assert_eq!(record.enc_ik, [0x66; 48]);
    assert!(record.validate().is_ok());
    assert_eq!(record.to_bytes(), full.as_slice());

    // A flipped payload byte must fail validation (from_bytes parses the
    // layout; validate() enforces the checksum — S02 §9.1).
    let mut tampered = full.clone();
    tampered[100] ^= 0x01;
    assert!(IdentityRecordStandard::from_bytes(&tampered)
        .unwrap()
        .validate()
        .is_err());
}

// ---------------------------------------------------------------------------
// S18 §14 — Recovery Record Roundtrip, 12-word and 24-word
// ---------------------------------------------------------------------------

/// Build the S18 §14 record from its inputs and recover through the crate.
///
/// `ik_pub` is the Ed25519 public key of `ik_priv`, as S18 §14.1 and §14.2
/// specify, so the recovered-key check (S02 §13.2 step 7) can hold. The
/// decrypt-level case with `ik_pub = 0x55×32` (S18 §14.3) is
/// [`s18_14_spec_literal_decrypts_byte_for_byte`].
fn recovery_roundtrip(
    recovery_seed: &[u8],
    phrase_length: u8,
    nonce: [u8; 24],
    ik_priv: &[u8; 32],
) -> ([u8; 32], String) {
    // Real keychains are tested separately in an isolated desktop session.
    // Serialize the two recovery vectors' process-wide test backend override.
    static DKM_ENV: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _guard = DKM_ENV.lock().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let previous = std::env::var_os("NAJWA_DKM_FILE");
    struct RestoreEnvironment(Option<std::ffi::OsString>);
    impl Drop for RestoreEnvironment {
        fn drop(&mut self) {
            match &self.0 {
                Some(value) => std::env::set_var("NAJWA_DKM_FILE", value),
                None => std::env::remove_var("NAJWA_DKM_FILE"),
            }
        }
    }
    let _restore = RestoreEnvironment(previous);
    std::env::set_var("NAJWA_DKM_FILE", directory.path().join("dkm"));
    // A consistent pair: ik_pub = Ed25519_DerivePublic(ik_priv) (S18 §6.1
    // pins the primitive), so S02 §13.2 step 7 can hold.
    let keypair = najwa_crypto::keys::Ed25519KeyPair::from_seed(ik_priv);
    let ik_pub = keypair.public().to_bytes();

    // K_recovery = HKDF(IKM=recovery_seed, salt=ik_pub, info="najwa/v1/recovery", 32)
    let k = hkdf_sha256(recovery_seed, &ik_pub, b"najwa/v1/recovery", 32).unwrap();
    let mut key = [0u8; 32];
    key.copy_from_slice(&k);

    // AAD_recovery = "najwa/v1/recovery" || ik_pub (49 bytes, S02 §8.6).
    let aad = [b"najwa/v1/recovery".as_slice(), &ik_pub].concat();
    let enc = najwa_crypto::prelude::aead::encrypt(&key, &nonce, ik_priv, &aad).unwrap();

    let record = RecoveryRecord {
        ik_pub,
        nonce_recovery: nonce,
        enc_ik_recovery: enc.try_into().unwrap(),
        phrase_length,
    };
    assert_eq!(record.to_bytes().len(), 105);

    let mnemonic = Mnemonic::from_entropy(recovery_seed).unwrap().to_string();
    assert_eq!(mnemonic.split_whitespace().count(), phrase_length as usize);

    let (new_record, identity) =
        recover_from_recovery_record(&mnemonic, &record, "a new password").unwrap();
    struct DeleteGeneration(IdentityRecordStandard);
    impl Drop for DeleteGeneration {
        fn drop(&mut self) {
            let _ = najwa_identity::platform::delete_record_dkm(&self.0);
        }
    }
    let _cleanup = DeleteGeneration(new_record.clone());

    // S18 §14 verification clause: IK_priv recovered byte-for-byte, and the
    // pubkey derived from it equals the record's ik_pub (S02 §13.2 step 7).
    assert_eq!(identity.keypair.private().to_bytes(), *ik_priv);
    assert_eq!(identity.keypair.public().to_bytes(), ik_pub);

    // The fresh standard record built under the new password is well-formed.
    assert!(new_record.validate().is_ok());
    (new_record.ik_pub, mnemonic)
}

#[test]
#[cfg_attr(
    any(
        all(target_os = "windows", feature = "windows-tpm"),
        all(target_os = "linux", feature = "linux-tpm"),
        all(target_os = "macos", feature = "macos-secure-enclave")
    ),
    ignore = "strict builds require the real hardware keystore for recovery provisioning"
)]
fn s18_14_1_recovery_record_12_word() {
    // S18 §14.1: recovery_seed = 0x000102030405060708090A0B0C0D0E0F (16 bytes).
    let seed: Vec<u8> = (1..=16).rev().map(|i| (0x10 - i) as u8).collect();
    // S18 §14.1 nonce_recovery (24 bytes).
    let nonce: [u8; 24] = hex::decode("7766554433221100FFEEDDCCBBAA99887766554433221100")
        .unwrap()
        .try_into()
        .unwrap();
    let (ik_pub, _) = recovery_roundtrip(&seed, 12, nonce, &TEST_IK_PRIV);
    assert_ne!(ik_pub, [0u8; 32]);
}

#[test]
#[cfg_attr(
    any(
        all(target_os = "windows", feature = "windows-tpm"),
        all(target_os = "linux", feature = "linux-tpm"),
        all(target_os = "macos", feature = "macos-secure-enclave")
    ),
    ignore = "strict builds require the real hardware keystore for recovery provisioning"
)]
fn s18_14_2_recovery_record_24_word() {
    // S18 §14.2: recovery_seed = 0x33, 0x32, … 0x14 (32 bytes), nonce = TEST_NONCE_24.
    let seed: Vec<u8> = (0..32u8).map(|i| 0x33 - i).collect();
    let nonce = TEST_NONCE_24;
    let (ik_pub, _) = recovery_roundtrip(&seed, 24, nonce, &TEST_IK_PRIV);
    assert_ne!(ik_pub, [0u8; 32]);
}

#[test]
fn s18_14_spec_literal_decrypts_byte_for_byte() {
    // S18 §14.3 decrypt-level case: ik_pub = 0x55×32 and the §14.1
    // recovery_seed (0x000102…0F) give K_recovery; seal TEST_IK_PRIV, decrypt
    // → byte-for-byte.
    let ik_pub = [0x55u8; 32];
    let seed: Vec<u8> = (1..=16).rev().map(|i| (0x10 - i) as u8).collect();
    let k = hkdf_sha256(&seed, &ik_pub, b"najwa/v1/recovery", 32).unwrap();
    let mut key = [0u8; 32];
    key.copy_from_slice(&k);
    let aad = [b"najwa/v1/recovery".as_slice(), &ik_pub].concat();
    let nonce: [u8; 24] = hex::decode("7766554433221100FFEEDDCCBBAA99887766554433221100")
        .unwrap()
        .try_into()
        .unwrap();
    let enc = najwa_crypto::prelude::aead::encrypt(&key, &nonce, &TEST_IK_PRIV, &aad).unwrap();
    let pt = najwa_crypto::prelude::aead::decrypt(&key, &nonce, &enc, &aad).unwrap();
    assert_eq!(pt, TEST_IK_PRIV);
}

// ---------------------------------------------------------------------------
// S18 §14.3 negative path — a wrong phrase must fail, never yield another identity.
// ---------------------------------------------------------------------------

#[test]
fn s18_14_wrong_phrase_fails_closed() {
    let ik_pub = [0x55u8; 32];
    let seed: Vec<u8> = (1..=16).rev().map(|i| (0x10 - i) as u8).collect();
    let k = hkdf_sha256(&seed, &ik_pub, b"najwa/v1/recovery", 32).unwrap();
    let mut key = [0u8; 32];
    key.copy_from_slice(&k);
    let aad = [b"najwa/v1/recovery".as_slice(), &ik_pub].concat();
    let enc =
        najwa_crypto::prelude::aead::encrypt(&key, &TEST_NONCE_24, &TEST_IK_PRIV, &aad).unwrap();
    let record = RecoveryRecord {
        ik_pub,
        nonce_recovery: TEST_NONCE_24,
        enc_ik_recovery: enc.try_into().unwrap(),
        phrase_length: 12,
    };

    // A DIFFERENT valid 12-word mnemonic has a different recovery_seed, so
    // K_recovery differs and AEAD auth fails — the crate must not "recover"
    // some other identity.
    let wrong = Mnemonic::from_entropy(&[0x11u8; 16]).unwrap().to_string();
    assert!(recover_from_recovery_record(&wrong, &record, "pw").is_err());
}
