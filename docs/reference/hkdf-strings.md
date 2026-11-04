# HKDF Strings and Domain Labels

This registry lists every domain-separation label the release uses: HKDF `info`
and salt strings, AEAD associated-data prefixes, signature prefixes, and the
fixed prefixes of domain-labelled hashes and MACs. For each label it gives the
exact bytes, where the code uses it, and the spec section that defines the
construction.

[S01 §3.5](../specs/01-crypto-primitives.md) sets the rules. The byte-level test
vectors are in [S18 §18](../specs/18-test-vectors.md). The key tree that uses
these labels is in [S01 §8.1](../specs/01-crypto-primitives.md) and the
[key inventory](keys.md).

## 1. Rules

1. **Exact bytes.** The hex column is authoritative. A different byte sequence
   produces different keys, fails AEAD authentication or fails signature
   verification.
2. **No terminator.** Labels are used without a trailing NUL. Where a label
   contains NUL, it is shown as `\0` and is part of the label.
3. **Case and spelling are exact.** No case folding, no normalization.
4. **Prefixes.** A label ending in `/` is a prefix. The full value is the prefix
   followed by the per-call suffix shown in the table, and the whole
   concatenation is the HKDF `info`, AAD or signed message.
5. **One purpose per label.** A label MUST NOT be reused for a second purpose,
   and the release MUST NOT use a label that is not listed here.
6. **Version tags.** `v1` and `v2` inside a label are format versions of that
   construction. They are not product versions and do not change with releases.

## 2. Key Derivation (HKDF-SHA256)

| Label | Len | Hex | Role | Used in | Defined in |
|-------|----:|-----|------|---------|------------|
| `najwa/v1/kek` | 12 | `6e616a77612f76312f6b656b` | `info`; IKM = `K_pwd`, salt = device factor, 32 bytes | `najwa-identity`: `creation.rs`, `unlock.rs` | [S02 §4.1](../specs/02-identity-key-protection.md) |
| `najwa/v1/recovery` | 17 | `6e616a77612f76312f7265636f76657279` | `info`; IKM = recovery seed, salt = `IK_pub`, 32 bytes. Also the AAD prefix in §3 | `najwa-identity`: `backup.rs` | [S02 §13.1](../specs/02-identity-key-protection.md) |
| `najwa-sqlcipher-key` | 19 | `6e616a77612d73716c6369706865722d6b6579` | salt; IKM = identity seed | `najwa-ffi`: `lib.rs` (`derive_sqlcipher_key`); `najwa-cli`: `main.rs` | [S03 §3](../specs/03-encrypted-storage.md) |
| `najwa/v1/sqlcipher-key` | 22 | `6e616a77612f76312f73716c6369706865722d6b6579` | `info` for the database key, 32 bytes | same as above | [S03 §3](../specs/03-encrypted-storage.md) |
| `ratchet_sessions` | 16 | `726174636865745f73657373696f6e73` | salt for per-row field keys; IKM = database key, `info` = contact id (u64 BE) | `najwa-storage`: `keys.rs`, `snapshot.rs` | [S03 §7](../specs/03-encrypted-storage.md) |
| `prekeys` | 7 | `7072656b657973` | salt for per-row field keys; `info` = prekey id as u32 BE widened to u64 BE | `najwa-storage`: `keys.rs`, `prekey_lifecycle.rs` | [S03 §7](../specs/03-encrypted-storage.md) |
| `najwa/v1/mailbox-signing-key` | 28 | `6e616a77612f76312f6d61696c626f782d7369676e696e672d6b6579` | `info`; IKM = identity seed, salt = UTF-8 onion address, 32-byte Ed25519 seed | `najwa-protocol`: `contact/mailbox_key.rs` | [S05 §3](../specs/05-contact-establishment.md) |
| `najwa/v1/x3dh/` | 14 | `6e616a77612f76312f783364682f` | `info` prefix; suffix `X_IK_A_pub(32) ‖ X_IK_B_pub(32)`, total 78 bytes; salt = 32 zero bytes | `najwa-protocol`: `x3dh/mod.rs` | [S06 §2.2](../specs/06-key-agreement-ratchet.md) |
| `najwa/v1/ratchet/rk` | 19 | `6e616a77612f76312f726174636865742f726b` | `info` for `KDF_RK`; salt = root key, IKM = DH output, 64 bytes | `najwa-protocol`: `ratchet/kdf.rs` | [S06 §3.3](../specs/06-key-agreement-ratchet.md) |
| `najwa/v1/ratchet/mk` | 19 | `6e616a77612f76312f726174636865742f6d6b` | `info` for message-key expansion; salt = 32 zero bytes, 80 bytes | `najwa-protocol`: `ratchet/kdf.rs` | [S06 §3.3](../specs/06-key-agreement-ratchet.md) |
| `najwa/v1/pairwise-pseudonym/initiator` | 37 | `6e616a77612f76312f70616972776973652d70736575646f6e796d2f696e69746961746f72` | `info`; IKM = X25519 shared secret, salt = sorted Ed25519 keys (64 bytes) | `najwa-protocol`: `pseudonym/derive.rs` | [S01 §8.2](../specs/01-crypto-primitives.md) |
| `najwa/v1/pairwise-pseudonym/responder` | 37 | `6e616a77612f76312f70616972776973652d70736575646f6e796d2f726573706f6e646572` | as above | `najwa-protocol`: `pseudonym/derive.rs` | [S01 §8.2](../specs/01-crypto-primitives.md) |
| `najwa/v1/message-id` | 19 | `6e616a77612f76312f6d6573736167652d6964` | `info`; IKM = `dh_pub ‖ n ‖ content_hash`, salt = sender pseudonym, 16 bytes | `najwa-protocol`: `message/id.rs` | [S07 §6.1](../specs/07-message-format.md) |
| `najwa/v1/deposit-envelope` | 25 | `6e616a77612f76312f6465706f7369742d656e76656c6f7065` | salt for the envelope outer key; IKM = envelope secret | `najwa-protocol`: `message/envelope.rs` | [S07 §3](../specs/07-message-format.md) |
| `outer-key` | 9 | `6f757465722d6b6579` | `info` for the envelope outer key, 32 bytes | `najwa-protocol`: `message/envelope.rs` | [S07 §3](../specs/07-message-format.md) |

The pairwise-pseudonym rows are the 28-byte prefix
`najwa/v1/pairwise-pseudonym/` (`6e616a77612f76312f70616972776973652d70736575646f6e796d2f`)
followed by the 9-byte role word `initiator` (`696e69746961746f72`) or
`responder` (`726573706f6e646572`).

## 3. AEAD Associated Data

| Label | Len | Hex | Full AAD | Used in | Defined in |
|-------|----:|-----|----------|---------|------------|
| `NAJWA\0\0\0` | 8 | `4e414a5741000000` | Identity-record magic; first 8 bytes of the 85-byte `AAD_identity` (record header fields, `saltP`, `ik_pub`) | `najwa-identity`: `aad.rs`, `record.rs` | [S02 §8.1](../specs/02-identity-key-protection.md) |
| `najwa/v1/recovery` | 17 | `6e616a77612f76312f7265636f76657279` | `prefix ‖ ik_pub(32)`, 49 bytes | `najwa-identity`: `backup.rs` | [S02 §8.6](../specs/02-identity-key-protection.md) |
| `field` | 5 | `6669656c64` | the label alone | `najwa-storage`: `encrypted_field.rs` | [S03 §7](../specs/03-encrypted-storage.md) |
| `volatile-key` | 12 | `766f6c6174696c652d6b6579` | the label alone; key = database key | `najwa-core`: `disappearing/volatile_cache.rs`; `najwa-storage`: `snapshot.rs` | [S12 §4](../specs/12-disappearing-messages.md) |

AEAD uses whose AAD carries no fixed label:

| Context | AAD | Defined in |
|---------|-----|------------|
| Ratchet message | `session_ad(64) ‖ wire_prefix` | [S07 §2.3](../specs/07-message-format.md) |
| Deposit envelope | `cap_hint = SHA256(deposit_capability)[0:8]` | [S07 §3](../specs/07-message-format.md) |
| Disappearing-message content | `msg_id(16)` | [S12 §4](../specs/12-disappearing-messages.md) |

## 4. Signature Prefixes (Ed25519)

| Label | Len | Hex | Signed message | Signing key | Used in | Defined in |
|-------|----:|-----|----------------|-------------|---------|------------|
| `najwa/v1/handshake/` | 19 | `6e616a77612f76312f68616e647368616b652f` | `prefix ‖ HandshakePayload body` | identity key | `najwa-protocol`: `contact/types.rs`, `contact/serialize.rs` | [S05 §4.1](../specs/05-contact-establishment.md) |
| `najwa/v1/spk/` | 13 | `6e616a77612f76312f73706b2f` | `prefix ‖ spk_pub(32) ‖ spk_id(4) ‖ spk_timestamp(8 BE)`, 57 bytes | per-mailbox signing key | `najwa-protocol`: `x3dh/types.rs`, `prekey/manager.rs` | [S06 §4.2](../specs/06-key-agreement-ratchet.md) |

Signed structures without a prefix. Each has a fixed length that differs from
every other message signed by the same key:

| Structure | Signed bytes | Signing key | Defined in |
|-----------|--------------|-------------|------------|
| MailboxCertificate | `ik_pub ‖ mailbox_ik_pub ‖ mailbox_onion(56) ‖ created_at ‖ expires_at`, 136 bytes | identity key | [S05 §4.2](../specs/05-contact-establishment.md) |
| Prekey manifest | `spk_id(4) ‖ opk_id_set_hash(32) ‖ opk_count(4 BE) ‖ timestamp(8 BE)`, 48 bytes | per-mailbox signing key | [S06 §2.2](../specs/06-key-agreement-ratchet.md) |
| Identity rotation (received) | `old_ik(32) ‖ new_ik(32) ‖ timestamp(8)`, 72 bytes, signed by both keys | old and new identity keys | [S02 §18](../specs/02-identity-key-protection.md) |

## 5. Hash and MAC Labels

| Label | Len | Hex | Construction | Used in | Defined in |
|-------|----:|-----|--------------|---------|------------|
| `attempt-counter` | 15 | `617474656d70742d636f756e746572` | `HMAC_SHA256(DKM, label ‖ attempts(4 BE) ‖ timestamp(8 BE))` | `najwa-identity`: `unlock.rs` | [S02 §10.1](../specs/02-identity-key-protection.md) |
| `last-successful-argon-time` | 26 | `6c6173742d7375636365737366756c2d6172676f6e2d74696d65` | `HMAC_SHA256(DKM, label ‖ duration_ns(8 BE))` | `najwa-identity`: `manager.rs` | [S02 §9.1](../specs/02-identity-key-protection.md) |
| `Najwa/v2/TPM/DKM\0` | 17 | `4e616a77612f76322f54504d2f444b4d00` | `SHA256(label ‖ credential_name)`, sealed with the device factor | `najwa-identity`: `platform/windows_tpm.rs` | [S02 §17](../specs/02-identity-key-protection.md) |
| `Najwa/v2/Linux-TPM/DKM\0` | 23 | `4e616a77612f76322f4c696e75782d54504d2f444b4d00` | `SHA256(label ‖ credential_name)`, sealed with the device factor | `najwa-identity`: `platform/linux_tpm.rs` | [S02 §17](../specs/02-identity-key-protection.md) |
| `Najwa/v2/Secure-Enclave/DKM\0` | 28 | `4e616a77612f76322f5365637572652d456e636c6176652f444b4d00` | `SHA256(label ‖ credential_name)`, sealed with the device factor | `najwa-identity`: `platform/macos_enclave.rs` | [S02 §17](../specs/02-identity-key-protection.md) |
| `Najwa/approved-software/v1\0` | 27 | `4e616a77612f617070726f7665642d736f6674776172652f763100` | `SHA256(label ‖ salt_p(32) ‖ ik_pub(32))`, stored with the device factor | `najwa-identity`: `platform/approved_software.rs` | [S02 §17](../specs/02-identity-key-protection.md) |
| `najwa-responsive-file-circuit-v1\0` | 33 | `6e616a77612d726573706f6e736976652d66696c652d636972637569742d763100` | `SHA256(label ‖ contact_id(8 BE) ‖ session ‖ deposit_capability ‖ envelope_secret ‖ onion)`, circuit-isolation key for one file transfer | `najwa-core`: `send.rs` | [S04 §4](../specs/04-transport.md) |
| `najwa.desktop.mailbox-announcement.v2` | 37 | `6e616a77612e6465736b746f702e6d61696c626f782d616e6e6f756e63656d656e742e7632` | `SHA256(label ‖ for each mailbox: len(8 BE) ‖ onion ‖ fetch_cap ‖ deposit_cap ‖ envelope_secret)`, local marker for a sent MailboxUpdate | `najwa-ffi`: `desktop.rs` | [S05 §12](../specs/05-contact-establishment.md) |
| `najwa-batching-attestation-v1` | 29 | `6e616a77612d6261746368696e672d6174746573746174696f6e2d7631` | `SHA256(label ‖ min_hold ‖ max_hold ‖ jitter ‖ now)`, signed by the mailbox operator key | `najwa-mailbox`: `state.rs` | [S16 §6](../specs/16-mailbox-server.md) |
| `najwa-operator-attestation-v2` | 29 | `6e616a77612d6f70657261746f722d6174746573746174696f6e2d7632` | `SHA256(label ‖ for each of onion_address, jurisdiction, infrastructure_provider: len(8 BE) ‖ UTF-8 ‖ timestamp(8 BE))`, signed by the mailbox operator key; replaces the unlabelled v1 digest without lengths | `najwa-mailbox`: `api/attestation.rs`; `najwa-protocol`: `examples/onion_mailbox_probe.rs` | [S16 §3.10](../specs/16-mailbox-server.md) |

## 6. Verification

- `najwa-crypto/tests/vectors.rs::s18_18_hkdf_string_registry_byte_exact` pins
  the hex of the labels defined as constants in
  `najwa_crypto::kdf::info_strings`, and the composition of both
  pairwise-pseudonym labels.
- `najwa-protocol/src/pseudonym/derive.rs::info_string_matches_registry` pins
  the two 37-byte pseudonym labels.
- [S18 §18](../specs/18-test-vectors.md) lists which labels have a pinning test.
- Before adding or changing a label, search the code for the literal and update
  this table and S18 in the same change.
