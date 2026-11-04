//! S18 test-vector conformance for the S01 crypto primitives (S18 §3–§7, §18).
//!
//! Two kinds of expectations live here, and the distinction matters:
//!
//! * **Independent vectors** come from external standards (RFC 5869, RFC 7748,
//!   RFC 8032) and would catch a broken primitive even if every other test
//!   were wrong.
//! * **Reference pins** are the byte-exact outputs S18 lists for Najwa's own
//!   inputs. Any change in output, including one caused by a dependency
//!   version bump, fails here. They are equality pins, not independent proof of
//!   correctness; the RFC vectors are.
//!
//! If a pin fails after a `[workspace.dependencies]` bump, that is the
//! intended signal: investigate the change, do not silence the test.
//!
//! The RFC 5869 values are taken from the RFC text (case A.1 uses a 13-byte
//! salt). The RFC 9106 vector needs secret and associated-data inputs that the
//! `argon2` password API cannot express, so S18 §3 pins the crate's output for
//! the same password, salt and cost instead.

use najwa_crypto::kdf::{hkdf_extract, hkdf_sha256, Argon2Params};
use najwa_crypto::keys::{
    ed25519_priv_to_x25519, ed25519_pub_to_x25519, Ed25519KeyPair, Ed25519Signature,
    X25519KeyPair,
};
use najwa_crypto::prelude::aead;

// ---------------------------------------------------------------------------
// S18 §2 — Common test data
// ---------------------------------------------------------------------------

const TEST_SALT_32: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
    0x16, 0x17, 0x18, 0x19, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x30,
    0x31, 0x32,
];
const TEST_NONCE_24: [u8; 24] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
    0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
];
const TEST_KEY_32: [u8; 32] = [0xAA; 32];
const TEST_PLAINTEXT: &[u8] = b"Hello Najwa!";
const TEST_IK_PRIV: [u8; 32] = [0xBB; 32];

/// RFC 8032 §7.1 TEST 1 seed (also S18 §6.1).
const RFC8032_TEST1_SEED: [u8; 32] = [
    0x9D, 0x61, 0xB1, 0x9D, 0xEF, 0xFD, 0x5A, 0x60, 0xBA, 0x84, 0x4A, 0xF4, 0x92, 0xEC, 0x2C,
    0xC4, 0x44, 0x49, 0xC5, 0x69, 0x7B, 0x32, 0x69, 0x19, 0x70, 0x3B, 0xAC, 0x03, 0x1C, 0xAE,
    0x7F, 0x60,
];

// ---------------------------------------------------------------------------
// S18 §3 — Argon2id
// ---------------------------------------------------------------------------

#[test]
fn s18_3_argon2id_k_pwd() {
    // S18 §3: password = TEST_PASSWORD, salt = TEST_SALT_32, 64 MiB, t=3, p=4.
    let params = Argon2Params {
        memory_kib: 65536,
        iterations: 3,
        parallelism: 4,
    };
    let k_pwd = najwa_crypto::kdf::argon2id(b"correct horse battery staple", &TEST_SALT_32, &params)
        .unwrap();
    // Reference pin (S18 §3).
    assert_eq!(
        hex::encode(k_pwd),
        "440cb3a8345021c114911e6b2051a1bb4c68e58d57b5b3aad9862e3363c83eda"
    );
}

#[test]
fn rfc9106_argon2id_dependency_pin() {
    // S18 §3 dependency pin, NOT the full RFC vector: RFC 9106 §5.3 feeds a
    // non-empty secret (0x03×8) and associated data (0x04×12), which the
    // `argon2` crate's public `hash_password_into` API cannot express, so the
    // RFC tag (0d640df5…) is unreachable through it. This pins the crate's
    // output for the same vector's password/salt/params with empty secret/AD,
    // so a dependency bump that changes Argon2 behavior fails here. Runs against
    // the argon2 crate DIRECTLY: `najwa_crypto::kdf::argon2id` enforces the
    // S01 §3.8 64-MiB minimum, which this 32-KiB vector is deliberately below.
    let password = [0x01u8; 32];
    let salt = [0x02u8; 16];
    let params = argon2::Params::new(32, 3, 4, Some(32)).unwrap();
    let hasher = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut out = [0u8; 32];
    hasher.hash_password_into(&password, &salt, &mut out).unwrap();
    assert_eq!(
        hex::encode(out),
        "03aab965c12001c9d7d0d2de33192c0494b684bb148196d73c1df1acaf6d0c2e"
    );
}

// ---------------------------------------------------------------------------
// S18 §4 — HKDF-SHA256
// ---------------------------------------------------------------------------

#[test]
fn rfc5869_hkdf_sha256_vectors() {
    // S18 §4.5: RFC 5869 A.1–A.3, taken from the RFC text directly. Note A.1's
    // salt is 13 octets ending 0c.
    // Case 1
    let okm = hkdf_sha256(
        &[0x0b; 22],
        &hex::decode("000102030405060708090a0b0c").unwrap(),
        &hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap(),
        42,
    )
    .unwrap();
    assert_eq!(
        hex::encode(&*okm),
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    );

    // Case 2: sequential ranges 0x00..=0x4f, 0x60..=0xaf, 0xb0..=0xff (80 each).
    let okm = hkdf_sha256(
        &(0x00..=0x4f).collect::<Vec<u8>>(),
        &(0x60..=0xaf).collect::<Vec<u8>>(),
        &(0xb0..=0xff).collect::<Vec<u8>>(),
        82,
    )
    .unwrap();
    assert_eq!(
        hex::encode(&*okm),
        "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87"
    );

    // Case 3: zero-length salt and info.
    let okm = hkdf_sha256(&[0x0b; 22], b"", b"", 42).unwrap();
    assert_eq!(
        hex::encode(&*okm),
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
    );
}

#[test]
fn s18_4_1_kek_from_k_pwd() {
    // Chains S18 §3 → §4.1: IKM = K_pwd, salt = TEST_SALT_32, info = "najwa/v1/kek".
    let params = Argon2Params {
        memory_kib: 65536,
        iterations: 3,
        parallelism: 4,
    };
    let k_pwd =
        najwa_crypto::kdf::argon2id(b"correct horse battery staple", &TEST_SALT_32, &params)
            .unwrap();
    let kek = hkdf_sha256(&*k_pwd, &TEST_SALT_32, b"najwa/v1/kek", 32).unwrap();
    assert_eq!(
        hex::encode(&*kek),
        "3f5b9d89526e527bf9a25be188db431641943b10521443cba85823115b6ea95a"
    );
}

#[test]
fn s18_4_2_db_key() {
    let db_key = hkdf_sha256(
        &TEST_IK_PRIV,
        b"najwa-db-key",
        b"najwa/v1/storage/db-key",
        32,
    )
    .unwrap();
    assert_eq!(
        hex::encode(&*db_key),
        "62361d0d9df0630c6e2318d50ffe5e7048ccf077a840146b5ac622e32246da0a"
    );
}

#[test]
fn s18_4_3_ratchet_root_key_step() {
    let out = hkdf_sha256(&[0xCC; 32], &[0xDD; 32], b"najwa/v1/ratchet/rk", 64).unwrap();
    assert_eq!(hex::encode(&out[..32]), "9c855dfbcbc662d3ee6199bbaa10cde0938090fbfe00779385450d32c1210a19");
    assert_eq!(hex::encode(&out[32..]), "dc3b14c839c129036174bf6aeb5f9d56869af8f08029f1eda26df04e0c5f6fbd");
}

#[test]
fn s18_4_4_device_signing_seed() {
    let seed = hkdf_sha256(
        &TEST_IK_PRIV,
        b"device-2-aa11bb22cc33dd44",
        b"najwa/v1/device-key",
        32,
    )
    .unwrap();
    assert_eq!(
        hex::encode(&*seed),
        "1f7a54fa0f3773ff678c4d9f294e5513bb059a43bf05cfe665edaeaa8ca39078"
    );
}

// ---------------------------------------------------------------------------
// S18 §5 — XChaCha20-Poly1305
// ---------------------------------------------------------------------------

#[test]
fn s18_5_xchacha20poly1305() {
    let aad = [0x01u8, 0x02, 0x00, 0x00];
    let ct = aead::encrypt(&TEST_KEY_32, &TEST_NONCE_24, TEST_PLAINTEXT, &aad).unwrap();
    // Reference pin (S18 §5): ciphertext || 16-byte tag.
    assert_eq!(
        hex::encode(&ct),
        "28407b5c42f3efbf05b2423d4996e67892bc45b8cc919161482abcd4"
    );

    // S18 §5 verification clause: decrypting with the same key/nonce/aad
    // returns the original plaintext.
    let pt = aead::decrypt(&TEST_KEY_32, &TEST_NONCE_24, &ct, &aad).unwrap();
    assert_eq!(pt, TEST_PLAINTEXT);

    // ...and a wrong AAD fails authentication.
    assert!(aead::decrypt(&TEST_KEY_32, &TEST_NONCE_24, &ct, &[0x01, 0x02, 0x00, 0x01]).is_err());
    // ...and a flipped ciphertext bit fails.
    let mut tampered = ct.clone();
    tampered[0] ^= 0x01;
    assert!(aead::decrypt(&TEST_KEY_32, &TEST_NONCE_24, &tampered, &aad).is_err());
}

// ---------------------------------------------------------------------------
// S18 §6 — Ed25519
// ---------------------------------------------------------------------------

#[test]
fn s18_6_1_ed25519_key_generation_matches_rfc8032() {
    // Independent vector: RFC 8032 §7.1 TEST 1 public key.
    let kp = Ed25519KeyPair::from_seed(&RFC8032_TEST1_SEED);
    assert_eq!(
        hex::encode(kp.public().to_bytes()),
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    );
}

#[test]
fn s18_6_2_ed25519_sign() {
    let kp = Ed25519KeyPair::from_seed(&RFC8032_TEST1_SEED);
    let sig = kp.sign(TEST_PLAINTEXT);
    // Reference pin (S18 §6.2) — 64 bytes.
    assert_eq!(
        hex::encode(sig.to_bytes()),
        "e8f0859ab2356d6fb6092f4c607c20b32cfa59d58c9d8138ff0865bff1e2eccda5da3b0bdda4ef7182ec0e7a328d670ec81581f1435a4ba49826542589a52e04"
    );
}

#[test]
fn s18_6_3_ed25519_verify() {
    let kp = Ed25519KeyPair::from_seed(&RFC8032_TEST1_SEED);
    let sig = kp.sign(TEST_PLAINTEXT);
    let pub_key = kp.public();

    // Valid signature verifies.
    assert!(pub_key.verify(TEST_PLAINTEXT, &sig).is_ok());
    // message || 0x00 does not.
    let extended = [TEST_PLAINTEXT, &[0x00]].concat();
    assert!(pub_key.verify(&extended, &sig).is_err());
    // A bit-flipped signature does not.
    let mut bytes = sig.to_bytes();
    bytes[0] ^= 0x01;
    let flipped = Ed25519Signature::from_bytes(&bytes).unwrap();
    assert!(pub_key.verify(TEST_PLAINTEXT, &flipped).is_err());
}

// ---------------------------------------------------------------------------
// S18 §7 — Ed25519 → X25519 conversion
// ---------------------------------------------------------------------------

#[test]
fn s18_7_ed25519_to_x25519_conversion() {
    let kp = Ed25519KeyPair::from_seed(&RFC8032_TEST1_SEED);

    let x_pub = ed25519_pub_to_x25519(kp.public()).unwrap();
    // Reference pin (S18 §7).
    assert_eq!(
        hex::encode(x_pub.to_bytes()),
        "d85e07ec22b0ad881537c2f44d662d1a143cf830c57aca4305d85c7a90f6b62e"
    );

    // Consistency: the private-key conversion must agree with the public one —
    // deriving the Montgomery public point from the converted private key
    // reproduces the converted public key.
    let x_priv = ed25519_priv_to_x25519(kp.private());
    let derived_pub = x_priv.public_key();
    assert_eq!(derived_pub.to_bytes(), x_pub.to_bytes());
}

// Keep the extract-only path exercised at the vector level too (S01 §3.5).
#[test]
fn hkdf_extract_matches_rfc5869_prks() {
    // A.1
    let prk = hkdf_extract(
        &hex::decode("000102030405060708090a0b0c").unwrap(),
        &[0x0b; 22],
    );
    assert_eq!(
        hex::encode(prk),
        "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
    );
    // A.3 (empty salt)
    let prk = hkdf_extract(b"", &[0x0b; 22]);
    assert_eq!(
        hex::encode(prk),
        "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"
    );
}

// ---------------------------------------------------------------------------
// S18 §18 — HKDF-string registry byte-exactness
// ---------------------------------------------------------------------------

#[test]
fn s18_18_hkdf_string_registry_byte_exact() {
    use najwa_crypto::kdf::info_strings as is;

    // (crate constant, pinned hex). Every constant in `info_strings` is pinned,
    // including those without a release caller; S18 §18 lists the hex of the
    // labels the release uses. A "drift" failure here means someone edited a
    // protocol string: that breaks AEAD/key derivation for every message using
    // it and must be a conscious, version-bumped act.
    let registry: &[(&[u8], &str)] = &[
        (is::HKDF_INFO_VK, "6e616a77612f76312f766b"),
        (is::HKDF_INFO_KEK, "6E616A77612F76312F6B656B"),
        (is::HKDF_INFO_RECOVERY, "6E616A77612F76312F7265636F76657279"),
        (is::DB_KEY_INFO, "6E616A77612F76312F73746F726167652F64622D6B6579"),
        (is::DEVICE_KEY_INFO, "6E616A77612F76312F6465766963652D6B6579"),
        (is::SE_WRAP_INFO, "6e616a77612f76312f73652d77726170"),
        (is::AAD_IK_ENCRYPT, "6e616a77612f76312f696b2d656e6372797074"),
        (is::AAD_VK_ENCRYPT, "6E616A77612F76312F766B2D656E6372797074"),
        (is::AAD_IK_ENCRYPT_HW, "6E616A77612F76312F696B2D656E63727970742D6877"),
        (is::AAD_HW_WRAP, "6E616A77612F76312F68772D77726170"),
        (is::AAD_BACKUP, "6E616A77612F76312F6261636B7570"),
        (is::AAD_RECOVERY, "6E616A77612F76312F7265636F76657279"),
        (is::X3DH_INFO_PREFIX, "6e616a77612f76312f783364682f"),
        (is::RATCHET_INFO, "6E616A77612F76312F726174636865742F726B"),
        (is::MESSAGE_KEY_INFO, "6E616A77612F76312F726174636865742F6D6B"),
        (is::GROUP_PSEUDONYM_INFO, "6E616A77612F76312F67726F75702D70736575646F6E796D2F"),
        (is::MESSAGE_ID_INFO, "6E616A77612F76312F6D6573736167652D6964"),
        (is::DEPOSIT_ENVELOPE_SALT, "6E616A77612F76312F6465706F7369742D656E76656C6F7065"),
        (is::DEPOSIT_ENVELOPE_KEY_INFO, "6F757465722D6B6579"),
        (is::MAILBOX_SIGNING_KEY_INFO, "6E616A77612F76312F6D61696C626F782D7369676E696E672D6B6579"),
        (is::HANDSHAKE_PREFIX, "6e616a77612f76312f68616e647368616b652f"),
        (is::SPK_PREFIX, "6e616a77612f76312f73706b2f"),
        (is::RENDEZVOUS_SALT_PREFIX, "6E616A77612F76312F72656E64657A766F75732D73616C74"),
        (is::RENDEZVOUS_ID_INFO, "6e616a77612f76312f72656e64657a766f75732f72656e64657a766f75732d6964"),
        (is::RENDEZVOUS_CAP_INFO, "6e616a77612f76312f72656e64657a766f75732f6465706f7369742d636170"),
        (is::RENDEZVOUS_SALT, "6e616a77612f76312f72656e64657a766f7573"),
        (is::GROUP_MESSAGE_KEY_PREFIX, "6e616a77612f76312f67726f75702f6d6573736167652d6b65792f"),
        (is::GROUP_CHAIN_KEY_INFO, "6e616a77612f76312f67726f75702f636861696e2d6b6579"),
        (is::BACKUP_SALT, "6E616A77612F76312F6261636B7570"),
        (is::SEED_EXPAND_INFO, "6e616a77612f76312f736565642d657870616e64"),
        (is::CONTACT_BACKUP_INFO, "6e616a77612f76312f636f6e746163742d6261636b7570"),
    ];
    assert!(
        registry.len() >= 30,
        "registry coverage shrank — every crate-owned string must stay pinned"
    );
    for (constant, expected) in registry {
        assert_eq!(
            hex::encode(constant),
            expected.to_lowercase(),
            "protocol string drifted from the S18 §18 table: {}",
            String::from_utf8_lossy(constant)
        );
    }

    // S18 §18 lists the composed pairwise-pseudonym forms (37 bytes each); the
    // crate owns the 28-byte prefix. Composition must reproduce both rows.
    assert_eq!(
        hex::encode([is::PSEUDONYM_INFO, b"initiator"].concat()),
        "6E616A77612F76312F70616972776973652D70736575646F6E796D2F696E69746961746F72"
            .to_lowercase()
    );
    assert_eq!(
        hex::encode([is::PSEUDONYM_INFO, b"responder"].concat()),
        "6E616A77612F76312F70616972776973652D70736575646F6E796D2F726573706F6E646572"
            .to_lowercase()
    );
}

// ---------------------------------------------------------------------------
// S18 §7.1 — X25519 (S01 §3.2): the RFC 7748 §6.1 Diffie-Hellman test is the
// independent anchor, plus low-order rejection
// ---------------------------------------------------------------------------

#[test]
fn rfc7748_x25519_diffie_hellman() {
    let alice = X25519KeyPair::from_seed(
        hex::decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
            .unwrap()
            .try_into()
            .unwrap(),
    );
    let bob = X25519KeyPair::from_seed(
        hex::decode("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
            .unwrap()
            .try_into()
            .unwrap(),
    );

    assert_eq!(
        hex::encode(alice.public().to_bytes()),
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
    );
    assert_eq!(
        hex::encode(bob.public().to_bytes()),
        "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
    );

    let k_ab = alice.diffie_hellman(bob.public()).unwrap();
    let k_ba = bob.diffie_hellman(alice.public()).unwrap();
    assert_eq!(k_ab.as_bytes(), k_ba.as_bytes());
    assert_eq!(
        hex::encode(k_ab.as_bytes()),
        "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
    );
}

#[test]
fn x25519_low_order_point_rejected() {
    // S01 §3.2: reject low-order points as ordinary errors, never panics.
    let alice = X25519KeyPair::from_seed([0x42; 32]);
    for bytes in [[0u8; 32], {
        let mut one = [0; 32];
        one[0] = 1;
        one
    }] {
        assert!(matches!(
            alice.diffie_hellman(&najwa_crypto::keys::X25519Public::from_bytes(bytes)),
            Err(najwa_crypto::error::CryptoError::InvalidPublicKey)
        ));
    }
}
