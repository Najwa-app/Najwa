---
id: S18
title: Test Vectors
crates: [najwa-crypto, najwa-identity, najwa-protocol, najwa-core, najwa-sanitize]
depends-on: [S01, S02, S03, S05, S06, S07, S08, S11]
---

# S18 — Test Vectors

## Overview

This spec lists the conformance vectors for the release: fixed inputs, the
exact outputs or properties they must produce, and the test in the repository
that pins each one. An implementation conforms to a vector when it produces the
same bytes, or satisfies the same assertions, from the same inputs.

There are two kinds of vector:

- **Independent vectors** come from external standards (RFC 5869, RFC 7748,
  RFC 8032). They catch a broken primitive even if every other test were wrong.
- **Reference pins** are byte-exact outputs of the Najwa implementation for the
  inputs given here. They detect any change in output, including one caused by
  a dependency upgrade, and they let a second implementation check itself
  against this one. They are equality pins, not independent proofs of
  correctness.

Some vectors pin a property instead of a value: for example, that a blob built
with the wrong key fails to open. Each section says which kind it is and names
the pinning test as `crate/path::test_name`.

## 1. Scope

| § | Vector | Spec |
|---|--------|------|
| 3 | Argon2id | [S01 §3.8](01-crypto-primitives.md) |
| 4 | HKDF-SHA256: KEK, ratchet root step, RFC 5869 | [S01 §3.5](01-crypto-primitives.md), [S02 §4](02-identity-key-protection.md), [S06 §3.3](06-key-agreement-ratchet.md) |
| 5 | XChaCha20-Poly1305 | [S01 §3.4](01-crypto-primitives.md) |
| 6 | Ed25519 | [S01 §3.1](01-crypto-primitives.md) |
| 7 | Ed25519 → X25519 conversion, X25519 | [S01 §3.2–§3.3](01-crypto-primitives.md) |
| 8 | Deposit envelope | [S07 §3](07-message-format.md) |
| 9 | Per-mailbox signing key | [S05 §3](05-contact-establishment.md) |
| 11 | Pairwise pseudonyms | [S01 §8.2](01-crypto-primitives.md) |
| 13 | Identity record | [S02 §7.1](02-identity-key-protection.md) |
| 14 | Recovery record | [S02 §13](02-identity-key-protection.md) |
| 15 | WireMessage and `epoch_link` | [S06 §3.9](06-key-agreement-ratchet.md), [S07 §2](07-message-format.md) |
| 17 | File sanitiser | [S11 §5–§8](11-file-transfer-sanitization.md) |
| 18 | Label encodings | [Label registry](../reference/hkdf-strings.md) |
| 19 | Reliability structures | [S07](07-message-format.md), [S08](08-messaging-service.md), [S12](12-disappearing-messages.md) |
| 22 | Protocol behaviour: ratchet, session repair, X3DH, gap repair, file transfer | [S06](06-key-agreement-ratchet.md), [S07](07-message-format.md), [S11](11-file-transfer-sanitization.md) |

## 2. Common Test Data

```
TEST_PASSWORD  = "correct horse battery staple"            // UTF-8, already NFC
TEST_SALT_32   = 0x0102030405060708091011121314151617181920212223242526272829303132
TEST_NONCE_24  = 0x000102030405060708090A0B0C0D0E0F1011121314151617
TEST_KEY_32    = 0xAA × 32
TEST_PLAINTEXT = 0x48656C6C6F204E616A776121                // "Hello Najwa!"
TEST_IK_PRIV   = 0xBB × 32                                 // an Ed25519 seed
TEST_ONION     = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz"  // 58 ASCII bytes
RFC8032_TEST1_SEED = 0x9D61B19DEFFD5A60BA844AF492EC2CC44449C5697B326919703BAC031CAE7F60
```

`TEST_ONION` is an arbitrary string; the derivation in §9 accepts any UTF-8
string as salt.

## 3. Argon2id Test Vector

Reference pin.

```
password    = TEST_PASSWORD
salt        = TEST_SALT_32
memory      = 65536 KiB
iterations  = 3
parallelism = 4
tag_length  = 32
version     = 0x13
```

**Expected output (`K_pwd`):**

```
440cb3a8345021c114911e6b2051a1bb4c68e58d57b5b3aad9862e3363c83eda
```

Pinned by `najwa-crypto/tests/vectors.rs::s18_3_argon2id_k_pwd`.

**Dependency pin.** The RFC 9106 §5.3 vector uses a secret and associated data,
which the `argon2` crate's password API does not take. The test instead pins
the crate's output for the RFC's password, salt and cost with empty secret and
associated data, so a dependency change is caught. The memory cost is below the
S01 §3.8 floor, so the test calls the `argon2` crate directly.

```
password = 0x01 × 32, salt = 0x02 × 16, m = 32 KiB, t = 3, p = 4, tag = 32
output   = 03aab965c12001c9d7d0d2de33192c0494b684bb148196d73c1df1acaf6d0c2e
```

Pinned by `najwa-crypto/tests/vectors.rs::rfc9106_argon2id_dependency_pin`.

## 4. HKDF-SHA256 Test Vectors

### 4.1 KEK Derivation

Reference pin. The release computes `HKDF_Expand(HKDF_Extract(salt = DKM,
IKM = K_pwd), "najwa/v1/kek", 32)`, which equals the single-call form below.

```
IKM    = K_pwd from §3
salt   = TEST_SALT_32            // stands in for the device factor (DKM)
info   = "najwa/v1/kek" = 0x6E616A77612F76312F6B656B
length = 32
```

**Expected output (KEK):**

```
3f5b9d89526e527bf9a25be188db431641943b10521443cba85823115b6ea95a
```

Pinned by `najwa-crypto/tests/vectors.rs::s18_4_1_kek_from_k_pwd`.

### 4.2 Database Key Derivation

The release derives the database key as
`HKDF(IKM = identity seed, salt = "najwa-sqlcipher-key", info =
"najwa/v1/sqlcipher-key", 32)` ([S03 §3](03-encrypted-storage.md)). There is no
vector for this derivation: no release test pins its output. The label bytes are
listed in §18.

### 4.3 Ratchet Root Key Step

Reference pin. `KDF_RK` computes `HKDF_Expand(HKDF_Extract(salt = RK,
IKM = DH_out), info, 64)`.

```
IKM    = 0xCC × 32               // DH output
salt   = 0xDD × 32               // current root key
info   = "najwa/v1/ratchet/rk" = 0x6E616A77612F76312F726174636865742F726B
length = 64
```

**Expected output:**

```
new_RK    = output[0:32]  = 9c855dfbcbc662d3ee6199bbaa10cde0938090fbfe00779385450d32c1210a19
chain_key = output[32:64] = dc3b14c839c129036174bf6aeb5f9d56869af8f08029f1eda26df04e0c5f6fbd
```

Pinned by `najwa-crypto/tests/vectors.rs::s18_4_3_ratchet_root_key_step`.

### 4.5 RFC 5869 Conformance

Independent vectors. Inputs are those of RFC 5869 Appendix A, test cases 1–3.

| Case | Expected OKM | Expected PRK |
|------|--------------|--------------|
| A.1 (42 bytes) | `3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865` | `077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5` |
| A.2 (82 bytes) | `b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87` | — |
| A.3 (42 bytes, empty salt and info) | `8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8` | `19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04` |

Pinned by `najwa-crypto/tests/vectors.rs::rfc5869_hkdf_sha256_vectors` and
`::hkdf_extract_matches_rfc5869_prks`, and again by
`najwa-protocol/tests/signal_vectors.rs::hkdf_rfc5869_vector_1` to `_3`.

## 5. XChaCha20-Poly1305 Test Vector

Reference pin.

```
key       = TEST_KEY_32
nonce     = TEST_NONCE_24
plaintext = TEST_PLAINTEXT
aad       = 0x01020000      // arbitrary primitive-level bytes, not a protocol AAD
```

**Expected output (`ciphertext ‖ tag`, 28 bytes):**

```
28407b5c42f3efbf05b2423d4996e67892bc45b8cc919161482abcd4
```

**Verification:**

- Decrypting with the same key, nonce and AAD returns `TEST_PLAINTEXT`.
- Decrypting with AAD `0x01020001` fails.
- Flipping bit 0 of the first ciphertext byte makes decryption fail.

Pinned by `najwa-crypto/tests/vectors.rs::s18_5_xchacha20poly1305`. The
protocol message AAD is exercised in §15.

## 6. Ed25519 Test Vectors

### 6.1 Key Generation

Independent vector (RFC 8032 §7.1 TEST 1).

```
seed       = RFC8032_TEST1_SEED
public_key = d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
```

Pinned by `najwa-crypto/tests/vectors.rs::s18_6_1_ed25519_key_generation_matches_rfc8032`.

### 6.2 Signing

Reference pin.

```
seed      = RFC8032_TEST1_SEED
message   = TEST_PLAINTEXT
signature = e8f0859ab2356d6fb6092f4c607c20b32cfa59d58c9d8138ff0865bff1e2eccd
            a5da3b0bdda4ef7182ec0e7a328d670ec81581f1435a4ba49826542589a52e04
```

Pinned by `najwa-crypto/tests/vectors.rs::s18_6_2_ed25519_sign`.

### 6.3 Verification

```
Ed25519_Verify(public_key, message, signature)                 == valid
Ed25519_Verify(public_key, message || 0x00, signature)         == invalid
Ed25519_Verify(public_key, message, signature with bit 0 of byte 0 flipped) == invalid
```

Pinned by `najwa-crypto/tests/vectors.rs::s18_6_3_ed25519_verify`.

## 7. Ed25519 → X25519 Conversion

Reference pin.

```
ed25519_public = public_key from §6.1
x25519_public  = d85e07ec22b0ad881537c2f44d662d1a143cf830c57aca4305d85c7a90f6b62e
```

**Verification:** `X25519_BasePoint(Ed25519_to_X25519_Private(RFC8032_TEST1_SEED))`
equals `x25519_public`.

Pinned by `najwa-crypto/tests/vectors.rs::s18_7_ed25519_to_x25519_conversion`.

**Small-order rejection.** The Ed25519 identity encoding
(`0x01` followed by 31 zero bytes) either fails to decode or fails conversion;
it never yields an X25519 key. Pinned by
`najwa-crypto/src/keys/conversion.rs::low_order_point_rejected`.

### 7.1 X25519 Diffie-Hellman

Independent vector (RFC 7748 §6.1).

```
alice_priv = 77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a
bob_priv   = 5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb
alice_pub  = 8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a
bob_pub    = de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f
shared     = 4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742
```

Both `X25519(alice_priv, bob_pub)` and `X25519(bob_priv, alice_pub)` equal
`shared`. Pinned by `najwa-crypto/tests/vectors.rs::rfc7748_x25519_diffie_hellman`.

**Low-order rejection.** With any private key, a peer public key of
`0x00 × 32` or `0x01` followed by 31 zero bytes returns `InvalidPublicKey`
without panicking. Pinned by
`najwa-crypto/tests/vectors.rs::x25519_low_order_point_rejected`.

## 8. Deposit Envelope Test Vector

Property vector. The construction is built from the pinned primitives of §4–§5.

```
envelope_secret    = 0xEE × 32
deposit_capability = 0xE1 × 32
inner_blob         = TEST_PLAINTEXT
nonce              = TEST_NONCE_24

outer_key = HKDF(IKM  = envelope_secret,
                 salt = "najwa/v1/deposit-envelope" = 0x6E616A77612F76312F6465706F7369742D656E76656C6F7065,
                 info = "outer-key" = 0x6F757465722D6B6579,
                 length = 32)
aad       = SHA256(deposit_capability)[0:8]        // also the fetch-response cap_hint
deposited_blob = nonce || XChaCha20Poly1305_Encrypt(outer_key, nonce, inner_blob, aad)
```

**Verification:**

- `envelope_decrypt(envelope_secret, deposit_capability, deposited_blob)`
  returns `inner_blob`.
- A blob built the same way but with `outer_key` derived from
  `deposit_capability` instead of `envelope_secret` MUST fail to open. The
  mailbox server holds the deposit capability, so a key derived from it would
  let the server read every envelope.
- Opening `deposited_blob` with deposit capability `0xE2 × 32` (different AAD)
  fails.
- `envelope_encrypt` output is `24 + len(inner_blob) + 16` bytes and opens with
  `envelope_decrypt`.

Pinned by `najwa-protocol/tests/s18_s07.rs::s18_8_deposit_envelope_construction`.

## 9. Per-Mailbox Derived Key Test Vector

Reference pin.

```
ik_priv       = TEST_IK_PRIV
onion_address = TEST_ONION

seed = HKDF(IKM = ik_priv, salt = UTF8(onion_address),
            info = "najwa/v1/mailbox-signing-key"
                 = 0x6E616A77612F76312F6D61696C626F782D7369676E696E672D6B6579,
            length = 32)
(mailbox_ik_priv, mailbox_ik_pub) = Ed25519_Generate(seed)
```

**Expected output:**

```
mailbox_ik_pub = b4345fde880de11080a2b4c88a75a5b500f5a1d14d2d7c6103f3dc186ae16eb4
```

**Verification:** the same `ik_priv` with `onion_address = "q" × 62` gives

```
mailbox_ik_pub = c29e8e6edd9e2f34bcb0b53d430e0606a0113be20ef8282ef6b72c36753d84a2
```

so two mailboxes see unlinkable keys.

Pinned by `najwa-protocol/tests/vectors.rs::s18_9_per_mailbox_derived_key`.

## 10. Reserved

## 11. Pairwise Pseudonym Test Vector

Reference pins for [S01 §8.2](01-crypto-primitives.md). Ordering is unsigned
bytewise comparison of the Ed25519 public keys.

### 11.1 Vector A

```
party A seed = RFC8032_TEST1_SEED
party A pub  = d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
party B seed = 0x02 × 32
party B pub  = 8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394

B's public key sorts lower (0x81 < 0xD7), so B holds the initiator pseudonym.
salt = B_pub || A_pub

P_initiator (B) = 93f48e8e0da7d944b528021303cb7c325c28e050e6e9455063b070335070d962
P_responder (A) = 1f0e77a114e637cab6be629bb256c9ae8a0382b2a047abb88ed688485980ee3e
```

**Verification:** deriving from A returns `(my = P_responder, their =
P_initiator)`; deriving from B returns the same two values with the roles
swapped.

Pinned by `najwa-protocol/tests/vectors.rs::s18_11_pairwise_pseudonyms`.

### 11.2 Vector B

```
party A seed = 0x11 × 32
party B seed = 0x22 × 32

A's own pseudonym  = 7d8b8b7344272aa526a854f0449f1aed21d9ef754da695ad11f7063c784d7512
B's pseudonym      = 897ee97c376027909937966837269c17fd261a54f9918fbfda41bee0bc63d061
```

Pinned by `najwa-protocol/src/pseudonym/derive.rs::pinned_vector`. The 37-byte
`info` strings are pinned by `::info_string_matches_registry`.

## 12. Reserved

## 13. Identity Record Roundtrip (Standard Mode) — 192 bytes

Property vector over a fully specified record.

| Offset | Field | Value | Size |
|-------:|-------|-------|-----:|
| 0 | magic | `4E414A5741000000` (`"NAJWA\0\0\0"`) | 8 |
| 8 | version | `0x03` | 1 |
| 9 | mode | `0x01` | 1 |
| 10 | kdf_alg | `0x01` | 1 |
| 11 | aead_alg | `0x01` | 1 |
| 12 | argon2_memory | `0x00010000` (65536, BE) | 4 |
| 16 | argon2_iterations | `0x00000003` (BE) | 4 |
| 20 | argon2_parallelism | `0x04` | 1 |
| 21 | reserved | `0x000000` | 3 |
| 24 | saltP | `TEST_SALT_32` | 32 |
| 56 | nonce | `TEST_NONCE_24` | 24 |
| 80 | ik_pub | `0x55 × 32` | 32 |
| 112 | enc_ik | `0x66 × 48` | 48 |
| 160 | checksum | `SHA256(bytes 0..160)` | 32 |

**Verification:**

- Parsing the 192 bytes returns every field above; serializing the parsed record
  returns the same 192 bytes.
- `validate()` succeeds.
- Flipping bit 0 of byte 100 makes `validate()` fail (checksum mismatch).

Pinned by `najwa-identity/tests/vectors.rs::s18_13_standard_record_roundtrip_byte_exact`.

## 14. Recovery Record Roundtrip — 12-word and 24-word

Property vectors for [S02 §13](02-identity-key-protection.md). The release
creates 24-word kits; recovery accepts records of either length.

```
K_recovery      = HKDF(IKM = recovery_seed, salt = ik_pub,
                       info = "najwa/v1/recovery" = 0x6E616A77612F76312F7265636F76657279,
                       length = 32)
AAD_recovery    = "najwa/v1/recovery" || ik_pub                       // 49 bytes
enc_ik_recovery = XChaCha20Poly1305_Encrypt(K_recovery, nonce_recovery, ik_seed, AAD_recovery)  // 48 bytes
record          = ik_pub(32) || nonce_recovery(24) || enc_ik_recovery(48) || phrase_length(1)  // 105 bytes
mnemonic        = BIP39_Encode(recovery_seed)                          // English word list
```

### 14.1 12-word case

```
recovery_seed  = 000102030405060708090a0b0c0d0e0f          // 16 bytes
ik_seed        = TEST_IK_PRIV
ik_pub         = Ed25519 public key of ik_seed
nonce_recovery = 7766554433221100FFEEDDCCBBAA99887766554433221100
phrase_length  = 12
```

**Verification:**

- The record serializes to 105 bytes and the mnemonic has 12 words.
- Recovering from the mnemonic and record returns `ik_seed` byte for byte, its
  public key equals `ik_pub`, and the new identity record under a new passphrase
  validates.

Pinned by `najwa-identity/tests/vectors.rs::s18_14_1_recovery_record_12_word`.

### 14.2 24-word case

```
recovery_seed  = 333231302f2e2d2c2b2a292827262524232221201f1e1d1c1b1a191817161514   // 32 bytes
ik_seed        = TEST_IK_PRIV
ik_pub         = Ed25519 public key of ik_seed
nonce_recovery = TEST_NONCE_24
phrase_length  = 24
```

Same verification with a 24-word mnemonic. Pinned by
`najwa-identity/tests/vectors.rs::s18_14_2_recovery_record_24_word`.

Both tests provision a device factor. Builds with the `hardware-keystore`
feature skip them, because they would need the real hardware key store.

### 14.3 Decrypt-level and negative cases

- With `ik_pub = 0x55 × 32`, the 12-word `recovery_seed` and nonce of §14.1,
  sealing `TEST_IK_PRIV` and decrypting returns it byte for byte. Pinned by
  `::s18_14_spec_literal_decrypts_byte_for_byte`.
- A different valid 12-word mnemonic (entropy `0x11 × 16`) fails to open the
  record; recovery never yields another identity. Pinned by
  `::s18_14_wrong_phrase_fails_closed`.

## 15. WireMessage Roundtrip with `epoch_link`

Property vector for the Standard (`0x02`) message layout and its AAD.

```
session_ad = 0xCC × 64

version        = 0x01
message_type   = 0x02
reserved       = 0x0000
payload_length = len(encrypted_payload), u32 BE
RatchetHeader (72 bytes):
    dh_pub     = 0xAA × 32
    pn         = 5,  u32 BE
    n          = 10, u32 BE
    epoch_link = 0xBB × 32
encrypted_payload = 0x66 × 24 || Payload bytes || 0x77 × 16
Payload = { sender_pseudonym = 0x44 × 32, content_type = Text, flags = 0,
            timestamp = 1700000000, msg_id = 0x77 × 16, logical_seq = 7,
            content = "hello najwa" }
```

**Expected layout:**

```
wire[0]      = 0x01
wire[1]      = 0x02
wire[2..4]   = 0x0000
wire[4..8]   = payload_length
wire[8..40]  = 0xAA × 32          // dh_pub
wire[40..44] = 0x00000005         // pn
wire[44..48] = 0x0000000A         // n
wire[48..80] = 0xBB × 32          // epoch_link, header offset 40
wire[80..]   = encrypted_payload
len(wire)    = 80 + payload_length
AAD          = session_ad || wire[0..80]          // 144 bytes
```

**Verification:**

- Parsing returns every header field, including `epoch_link = 0xBB × 32`. An
  implementation that treats header bytes 40..72 as reserved fails.
- The canonical wire prefix is 80 bytes and the AAD is 144 bytes.
- Live path: with `SK = 0x42 × 32`, Bob's signed prekey from X25519 seed
  `0x07 × 32` and Alice's ephemeral seed `0x08 × 32`, a message encrypted with
  `session_ad` decrypts with `session_ad || wire_prefix`, fails with an empty
  `session_ad`, and fails when the last ciphertext byte is flipped.

Pinned by `najwa-protocol/tests/s18_s06.rs::s18_15_wire_layout_and_epoch_link_offset`,
`::s18_15_aad_is_session_ad_plus_wire_prefix` and
`::s18_15_live_roundtrip_and_aad_negative_paths`.

## 16. Reserved

## 17. File Sanitiser Vectors

Property vectors for [S11](11-file-transfer-sanitization.md). Every format the
release accepts has tests that build an input carrying metadata and assert that
the output carries none and still decodes. Formats without a safe sanitiser are
refused.

| Format | Release behaviour | Pinned by |
|--------|-------------------|-----------|
| JPEG, PNG, GIF, BMP, TIFF | Decoded and re-encoded as WebP; the source container is discarded | `najwa-sanitize/tests/real_file_fixtures.rs::jpeg_conversion_destroys_metadata`, `::png_conversion_destroys_metadata`; `src/lib.rs::sanitize_png_converts_to_webp_and_verifies_output_format`, `::sanitize_tiff_converts_to_webp_and_passes_strict_verification`; `src/convert.rs::png_to_webp_structural_metadata_destruction` |
| WebP | EXIF, XMP and ICC chunks removed in place | `src/lib.rs::sanitize_webp_with_exif_strips_and_passes`; `src/stream.rs::streamed_mp3_flac_and_webp_match_verified_metadata_removal`; `najwa-core/src/filetransfer.rs::start_send_sanitizes_webp_at_the_boundary` |
| HEIC | Refused | `src/lib.rs::sanitize_heic_refused` |
| Unknown | Refused | `src/lib.rs::sanitize_unknown_type_rejected`; `najwa-core/src/filetransfer.rs::start_send_refuses_unsanitizable_data` |
| MP4, MOV | Metadata atoms removed, chunk offsets rewritten, creation and modification dates zeroed | `src/video.rs::mp4_strips_udta_and_adjusts_offsets`; `tests/real_file_fixtures.rs::mp4_udta_stripped`; `src/stream.rs::streamed_video_erases_metadata_and_dates_without_moving_media`, `::streamed_containers_fail_closed_on_malformed_sizes_and_fragmentation`; `najwa-core/tests/row11_regressions.rs::video_creation_and_modification_dates_are_zeroed`, `::video_offsets_account_for_top_level_metadata_removal`, `::malformed_extended_atom_is_refused_without_hanging` |
| PDF | Info-dictionary values emptied, XMP removed, xref offsets preserved | `src/document.rs::pdf_strips_author`, `::pdf_strips_hex_string_values`, `::pdf_strips_xmp_packet_preserving_length`; `src/pdf.rs::deeply_nested_pdf_objects_are_refused_without_aborting`; `row11_regressions.rs::pdf_escaped_author_is_removed_or_refused`, `::pdf_xmp_is_removed_or_refused_when_compressed`, `::pdf_xref_offsets_survive_sanitization` |
| DOCX | Metadata emptied; ZIP rebuilt with stored entries, original order and zero timestamps; output is a fixed point | `src/document.rs::docx_strips_and_rewrites_deterministically`; `src/zip.rs::stored_rewrite_is_deterministic_and_clean`, `::rejects_encrypted_and_truncated`; `row11_regressions.rs::docx_newline_before_attribute_does_not_leak_author` |
| ODT | `meta.xml` emptied; `mimetype` kept first | `src/document.rs::odt_strips_meta_xml_and_keeps_mimetype_first` |
| MP3 | ID3v2, ID3v1, APEv2 and appended ID3v2.4 removed | `src/audio.rs::mp3_strips_id3v2`, `::mp3_strips_id3v1`, `::mp3_strips_both_id3v2_and_v1`, `::mp3_strips_stacked_id3v2_and_apev2`, `::mp3_strips_apev2_header_and_footer_form`, `::mp3_strips_appended_id3v24_header_body_and_footer`; `tests/real_file_fixtures.rs::mp3_id3_tags_stripped` |
| OGG | Vorbis and Opus comment packets emptied; pages and checksums rebuilt | `src/audio.rs::ogg_strips_vorbis_comments_and_preserves_audio_page`, `::ogg_strips_opus_tags`, `::ogg_strips_comment_packet_continued_across_pages`; `src/lib.rs::sanitize_ogg_strips_tags_and_passes_strict_verification` |
| FLAC | VORBIS_COMMENT and PICTURE blocks removed | `src/audio.rs::flac_strips_vorbis_comment` |
| WAV | Closed keep-list; all other chunks removed | `src/audio.rs::wav_closed_keep_list_strips_metadata_and_preserves_audio`; `src/stream.rs::streamed_wav_matches_verified_sanitizer_and_removes_trailing_metadata` |

Test paths without a crate prefix are in `crates/najwa-sanitize/`.

**Fixed point.** For DOCX, running the sanitiser on its own output returns the
same bytes and reports nothing removed.

## 18. AAD / HKDF-String Literal Encodings

Byte encodings of the labels in the [label registry](../reference/hkdf-strings.md).
A deviation breaks key derivation, AEAD authentication or signature
verification for every use of the label.

| String | Hex | Length | Pinned by |
|--------|-----|-------:|-----------|
| `"najwa/v1/kek"` | `6E616A77612F76312F6B656B` | 12 | `s18_18`, §4.1 |
| `"najwa/v1/recovery"` | `6E616A77612F76312F7265636F76657279` | 17 | `s18_18` (crate constant); §14 through the copy used by recovery |
| `"najwa-sqlcipher-key"` | `6E616A77612D73716C6369706865722D6B6579` | 19 | none |
| `"najwa/v1/sqlcipher-key"` | `6E616A77612F76312F73716C6369706865722D6B6579` | 22 | none |
| `"ratchet_sessions"` | `726174636865745F73657373696F6E73` | 16 | none |
| `"prekeys"` | `7072656B657973` | 7 | none |
| `"najwa/v1/mailbox-signing-key"` | `6E616A77612F76312F6D61696C626F782D7369676E696E672D6B6579` | 28 | `s18_18`, §9 |
| `"najwa/v1/x3dh/"` (prefix) | `6E616A77612F76312F783364682F` | 14 | `s18_18` |
| `"najwa/v1/ratchet/rk"` | `6E616A77612F76312F726174636865742F726B` | 19 | `s18_18`, §4.3 |
| `"najwa/v1/ratchet/mk"` | `6E616A77612F76312F726174636865742F6D6B` | 19 | `s18_18` |
| `"najwa/v1/pairwise-pseudonym/initiator"` | `6E616A77612F76312F70616972776973652D70736575646F6E796D2F696E69746961746F72` | 37 | `s18_18`, `info_string_matches_registry`, §11 |
| `"najwa/v1/pairwise-pseudonym/responder"` | `6E616A77612F76312F70616972776973652D70736575646F6E796D2F726573706F6E646572` | 37 | `s18_18`, `info_string_matches_registry`, §11 |
| `"najwa/v1/message-id"` | `6E616A77612F76312F6D6573736167652D6964` | 19 | `s18_18` |
| `"najwa/v1/deposit-envelope"` | `6E616A77612F76312F6465706F7369742D656E76656C6F7065` | 25 | `s18_18` (crate constant); §8 through the copy used by the envelope |
| `"outer-key"` | `6F757465722D6B6579` | 9 | `s18_18` (crate constant); §8 through the copy used by the envelope |
| `"najwa/v1/handshake/"` (prefix) | `6E616A77612F76312F68616E647368616B652F` | 19 | `s18_18` (crate constant only) |
| `"najwa/v1/spk/"` (prefix) | `6E616A77612F76312F73706B2F` | 13 | `s18_18` (crate constant only) |
| `"NAJWA\0\0\0"` (record magic) | `4E414A5741000000` | 8 | §13 |
| `"field"` | `6669656C64` | 5 | none |
| `"volatile-key"` | `766F6C6174696C652D6B6579` | 12 | none |
| `"attempt-counter"` | `617474656D70742D636F756E746572` | 15 | none |
| `"last-successful-argon-time"` | `6C6173742D7375636365737366756C2D6172676F6E2D74696D65` | 26 | none |
| `"Najwa/v2/TPM/DKM\0"` | `4E616A77612F76322F54504D2F444B4D00` | 17 | none |
| `"Najwa/v2/Linux-TPM/DKM\0"` | `4E616A77612F76322F4C696E75782D54504D2F444B4D00` | 23 | none |
| `"Najwa/v2/Secure-Enclave/DKM\0"` | `4E616A77612F76322F5365637572652D456E636C6176652F444B4D00` | 28 | none |
| `"Najwa/approved-software/v1\0"` | `4E616A77612F617070726F7665642D736F6674776172652F763100` | 27 | none |
| `"najwa-responsive-file-circuit-v1\0"` | `6E616A77612D726573706F6E736976652D66696C652D636972637569742D763100` | 33 | none |
| `"najwa.desktop.mailbox-announcement.v2"` | `6E616A77612E6465736B746F702E6D61696C626F782D616E6E6F756E63656D656E742E7632` | 37 | none |
| `"najwa-batching-attestation-v1"` | `6E616A77612D6261746368696E672D6174746573746174696F6E2D7631` | 29 | none |
| `"najwa-operator-attestation-v2"` | `6E616A77612D6F70657261746F722D6174746573746174696F6E2D7632` | 29 | none |

`s18_18` is `najwa-crypto/tests/vectors.rs::s18_18_hkdf_string_registry_byte_exact`.
It pins the constants in `najwa_crypto::kdf::info_strings`. "Crate constant"
means the code path uses a separate literal with the same bytes; the named
section pins that literal through its behaviour. `info_string_matches_registry`
is in `najwa-protocol/src/pseudonym/derive.rs`.

## 19. Reliability Vectors

| Vector | Fixture and expected result | Spec | Pinned by |
|--------|-----------------------------|------|-----------|
| Endpoint-invariant `logical_msg_id` | `IK_a = 0x11 × 32`, `IK_b = 0x22 × 32`, `timestamp = 1700000000`, `logical_seq = 7`, `content_type = 0x01`, `content = "same second, same text"`. Preimage `IK_a ‖ IK_b ‖ 0x00 ‖ timestamp(8 BE) ‖ 0x00 ‖ seq(4 BE) ‖ 0x00 ‖ content_type ‖ 0x00 ‖ content`; output `SHA256(preimage)[0:16]` = `d99bf4c3d2f2c1d9a8e330f616b5e690`. Swapping the two keys gives the same value; `logical_seq = 8` gives a different one | [S07 §6](07-message-format.md) | `najwa-protocol/tests/s18_s06.rs::s19_logical_msg_id_endpoint_invariant`; `najwa-protocol/tests/row7_regressions.rs::logical_message_id_matches_spec_preimage` |
| `CumulativeAck` (`0x12`) | Ranges `(0x01 × 32, 3, 7)` and `(0x02 × 32, 9, 9)`: struct `0x12 ‖ 0x02 ‖ (dh_pub(32) ‖ start_n(4 BE) ‖ end_n(4 BE)) × 2`; padded plaintext `len(2 BE) ‖ struct ‖ zeros` to the bucket target; wire type byte `0x12`; struct round-trips | [S07 §8.1](07-message-format.md), [S07 §5.5](07-message-format.md) | `najwa-protocol/tests/s18_s07.rs::s07_24_cumulative_ack_wire_roundtrip` |
| `ReadReceiptContent` (`0x11`) | `msg_id = 0x5A × 16`, `timestamp = 1700000000`: 24 bytes `msg_id ‖ timestamp(8 BE)`. Fixed overhead 160, so it lands on the 256-byte bucket with a 96-byte padded plaintext; wire type byte `0x11`. Also sent and opened through a live ratchet session | [S07 §2.4](07-message-format.md), [S07 §5.5](07-message-format.md) | `najwa-protocol/tests/s18_s07.rs::s07_24_read_receipt_wire_roundtrip`, `::s07_24_read_receipt_live_ratchet_path` |
| `TextReplyContent` (`content_type = 0x02`) | `reply_to_msg_id(16) ‖ text_len(2 BE) ‖ text`; fixture `0x5A × 16`, `"a reply"` → 25 bytes | [S07 §4.3](07-message-format.md) | `najwa-protocol/tests/s18_s06.rs::s19_text_reply_content_roundtrip` |
| `ReSendRequest` control (`0x05`) | Mode `0x01`: `0x05 ‖ 0x01 ‖ since_logical_msg_id(16) ‖ fallback_floor(8 BE)`, 26 bytes. Mode `0x02`: `0x05 ‖ 0x02 ‖ u64 BE ‖ u64 BE`, 18 bytes. Mode `0x03`, a 23-byte mode-1 body and an empty mode-2 body are rejected | [S08](08-messaging-service.md) | `najwa-protocol/tests/s18_s07.rs::s19_resend_request_mode_1_roundtrip`, `::s19_resend_request_mode_2_and_fail_closed` |
| Timer change control (`0x01`) | `0x01 ‖ timer_secs(4 BE) ‖ set_at(8 BE)`, 13 bytes; fixture `86400`, `1700000123` | [S12](12-disappearing-messages.md) | `najwa-protocol/tests/s18_s06.rs::s19_timer_change_body_d15` |
| Padding buckets | 11 buckets: 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536, 131072, 262144. Fixed overhead 160 for `0x02`, `0x11`, `0x12`; 263 for Initial without an OPK id, 267 with one. A 3-byte Initial lands on 512. An oversized length returns no bucket | [S07 §5](07-message-format.md) | `najwa-protocol/tests/s18_s07.rs::s07_5_padding_buckets_and_overhead` |

## 20. Implementation Notes

### 20.1 Running the Vectors

```bash
cargo test -p najwa-crypto   --test vectors
cargo test -p najwa-identity --test vectors
cargo test -p najwa-protocol --test vectors --test s18_s06 --test s18_s07 --test signal_vectors --test row7_regressions
cargo test -p najwa-core     --test row11_regressions
cargo test -p najwa-sanitize
```

Unit-test vectors named `crate/src/file.rs::test` run with `cargo test -p <crate> --lib`.

### 20.2 Cross-Implementation Verification

A second implementation checks itself against §3–§11 by recomputing each
output from the stated inputs. The RFC vectors (§4.5, §6.1, §7.1) can be checked
with any conforming library. The HKDF, SHA-256 and HMAC vectors can be
recomputed with OpenSSL, libsodium or a standard-library HMAC.

### 20.3 Vector Storage

Vectors live in the test sources named in each section. There is no separate
fixture directory. Sanitiser inputs are generated by the tests.

## 22. Protocol Behaviour Vectors

### 22.1 Multi-Message Ratchet Conversation

Property vectors over full sessions built from fixed seeds.

| Scenario | Assertions | Pinned by |
|----------|------------|-----------|
| X3DH (with OPK) then three messages A→B, a reply B→A, and another A→B across DH ratchet steps | Every message decrypts to its plaintext | `najwa-protocol/tests/signal_vectors.rs::double_ratchet_known_answer_full_session` |
| 50 messages each way, alternating | Every message decrypts | `::double_ratchet_known_answer_50_message_exchange` |
| Three messages delivered in order 2, 0, 1 | Every message decrypts; skipped keys are used for 0 and 1 | `::double_ratchet_known_answer_out_of_order` |
| Skipped key past expiry; forged frame against a stored skipped key | Expired keys are dropped; a forged frame does not consume the skipped key | `najwa-protocol/src/ratchet/mod.rs::skipped_key_expiration`, `::forged_frame_does_not_destroy_skipped_key` |
| Low-order `dh_pub` in a ratchet header | Rejected without mutating state; the session still decrypts afterwards | `najwa-protocol/tests/low_order_keys.rs::ratchet_rejects_low_order_headers_without_mutation_and_still_decrypts` |

### 22.2 `SessionRepairInit` Wire Vector

Byte-exact control body:

```
0x31 || reason(1) || failed_dh_pub(32) || failed_epoch_link(32)     // 66 bytes
fixture: reason = 0x01, failed_dh_pub = 0xAB × 32, failed_epoch_link = 0xCD × 32
```

The body round-trips. A 65-byte body is rejected. Pinned by
`najwa-protocol/src/message/control.rs::session_repair_init_roundtrip` and
`::session_repair_init_too_short_rejected`.

### 22.3 X3DH Transcript

Property vectors with fixed keys: Alice IK seed `0x01 × 32`, Bob IK seed
`0x02 × 32`, Bob SPK X25519 seed `0x10 × 32` (id `0x00000001`, timestamp 0,
signed over `"najwa/v1/spk/" ‖ spk_pub ‖ spk_id ‖ timestamp`), Bob OPK X25519
seed `0x20 × 32` (id `0x00000002`).

| Assertion | Pinned by |
|-----------|-----------|
| Initiator and responder derive the same 32-byte `SK` and the same 64-byte AD; `SK` is not all zero | `najwa-protocol/tests/signal_vectors.rs::x3dh_known_answer_both_sides_agree` |
| Without an OPK (3-DH) both sides still agree | `::x3dh_known_answer_3dh_fallback` |
| The same keys with and without an OPK give different `SK` | `::x3dh_known_answer_opk_changes_secret` |
| A low-order ephemeral key, signed prekey or one-time prekey is rejected | `najwa-protocol/tests/low_order_keys.rs::x3dh_rejects_low_order_ephemeral_signed_and_one_time_prekeys` |
| A bundle without a signed manifest is rejected | `najwa-protocol/src/x3dh/initiator.rs::missing_manifest_is_rejected` |
| Manifest signatures verify and fail on tampering | `najwa-protocol/src/x3dh/types.rs::manifest_sign_verify_roundtrip_and_tamper`; `najwa-protocol/tests/row6_regressions.rs::manifest_requires_a_valid_membership_witness` |

### 22.4 GapRepair Roundtrip

Byte-exact control bodies (all integers big-endian):

```
GapRepairRequest:
  0x36 || epoch_count = 0x02
       || 0xAA × 32 || range_count = 0x02 || 00000001 00000003 || 00000009 00000009
       || 0xBB × 32 || range_count = 0x01 || FFFFFFFE FFFFFFFF

GapRepairUnavailable:                                                   // 41 bytes
  0x37 || 0xCC × 32 || 00000007 || 0000000B

GapRepairBundle:                                                        // 75 bytes
  0x38 || item_count = 0x01
       || original_dh_pub = 0xDD × 32 || original_n = 01020304
       || original_msg_id = 0xEE × 16 || original_timestamp = 0102030405060708
       || original_logical_seq = 11121314 || content_type = 0x01 || flags = 0x04
       || content_len = 00000003 || FA FB FC
```

Each body round-trips. Each body with its last byte removed is rejected. The
retired subtype `0x32` is rejected as an unknown control subtype. Pinned by
`najwa-protocol/src/message/control.rs::gap_repair_request_layout_is_byte_exact`,
`::gap_repair_unavailable_layout_is_byte_exact`,
`::gap_repair_bundle_layout_is_byte_exact`,
`::truncated_gap_repair_bodies_are_rejected` and
`::legacy_gap_repair_subtype_is_not_accepted`.

### 22.8 `FileMetadata` / `FileChunk` / `FileChunkNack` Layouts

| Assertion | Pinned by |
|-----------|-----------|
| `FileChunkNack` encodes as `0x3C ‖ session_id(16) ‖ count(2 BE) ‖ index(4 BE) × count` with a single subtype byte, identical through the control-message codec | `najwa-core/tests/row11_regressions.rs::nack_control_uses_exactly_one_subtype_byte` |
| A `FileChunkNack` whose indices are not ascending is rejected | `::nack_wire_parser_rejects_unsorted_indices` |
| `FileMetadata` and `FileChunk` produced by the transfer manager are accepted by the wire codec | `::manager_metadata_is_accepted_by_wire_codec`, `::manager_chunk_is_accepted_by_wire_codec` |
| A chunk that conflicts with a stored chunk permanently fails the receive; reassembly rejects a declared-size mismatch | `::chunk_conflict_permanently_fails_receive`, `::reassembly_rejects_declared_size_mismatch` |

## 21. Conformance Checklist

- [ ] §3 Argon2id output matches the pin, and the dependency pin holds.
- [ ] §4.1 and §4.3 HKDF outputs match; RFC 5869 cases A.1–A.3 pass.
- [ ] §5 XChaCha20-Poly1305 output matches; wrong AAD and tampered ciphertext fail.
- [ ] §6 Ed25519 public key matches RFC 8032 TEST 1; signature matches the pin; negative verifications fail.
- [ ] §7 converted X25519 key matches; private and public conversion agree; small-order points are rejected; RFC 7748 §6.1 passes.
- [ ] §8 the deposit envelope opens only with the envelope secret and the matching capability.
- [ ] §9 per-mailbox keys match both pins.
- [ ] §11 both pseudonym vectors match and both parties agree.
- [ ] §13 the 192-byte record round-trips and a flipped byte fails validation.
- [ ] §14 12-word and 24-word recovery return the identity seed byte for byte; a wrong phrase fails.
- [ ] §15 `epoch_link` sits at wire offset 48; the AAD is `session_ad ‖ wire_prefix` (144 bytes) on encrypt and decrypt.
- [ ] §17 every accepted format strips its metadata; HEIC and unknown types are refused; DOCX output is a fixed point.
- [ ] §18 every label pinned by `s18_18` matches its hex.
- [ ] §19 reliability structures match their layouts and the `logical_msg_id` pin.
- [ ] §22 ratchet, X3DH, session-repair, gap-repair and file-transfer vectors pass.
