# Wire Formats

This is a lookup reference. Each structure names the spec section that defines
its rules; this page reproduces the layout. Numeric type codes are registered in
[Message Types](message-types.md).

**Conventions.** Multi-byte integers are big-endian unless stated otherwise.
`[N]` is a fixed-size byte array. `var` is a length given by another field or by
the end of the enclosing structure. `‖` is concatenation. JSON byte fields use
standard base64 with padding.

## 1. Identity Record (Standard Mode)

Defined in [S02 §7](../specs/02-identity-key-protection.md). Stored at rest as
`identity.najwa` in the profile directory. **Total: 192 bytes.**

| Offset | Size | Field |
|-------:|-----:|-------|
| 0 | 8 | `magic` — `"NAJWA\x00\x00\x00"` (`4E 41 4A 57 41 00 00 00`) |
| 8 | 1 | `version` — `0x03` |
| 9 | 1 | `mode` — `0x01` standard |
| 10 | 1 | `kdf_alg` — `0x01` Argon2id |
| 11 | 1 | `aead_alg` — `0x01` XChaCha20-Poly1305 |
| 12 | 4 | `argon2_memory` (KiB) |
| 16 | 4 | `argon2_iterations` |
| 20 | 1 | `argon2_parallelism` |
| 21 | 3 | `reserved` — MUST be zero |
| 24 | 32 | `salt_p` — Argon2id password salt |
| 56 | 24 | `nonce` |
| 80 | 32 | `ik_pub` — Ed25519 identity public key |
| 112 | 48 | `enc_ik` — 32-byte identity seed + 16-byte tag |
| 160 | 32 | `checksum` — `SHA256(bytes[0..160])` |

```
AAD_identity = magic ‖ version ‖ mode ‖ kdf_alg ‖ aead_alg ‖ argon2_memory ‖
               argon2_iterations ‖ argon2_parallelism ‖ salt_p ‖ ik_pub       // 85 bytes; reserved excluded
enc_ik       = XChaCha20-Poly1305(KEK, nonce, ik_seed(32), AAD_identity)
```

`KEK` derivation is defined in [S02 §4](../specs/02-identity-key-protection.md).
A reader rejects a record with the wrong magic, `version > 0x03`, non-zero
`reserved` or a checksum mismatch.

## 2. Recovery Record

Defined in [S02 §13](../specs/02-identity-key-protection.md). Stored at rest as
the sidecar file `identity.recovery` next to the identity record. The app exports
and imports it as the standard base64 encoding of these 105 bytes.

| Offset | Size | Field |
|-------:|-----:|-------|
| 0 | 32 | `ik_pub` |
| 32 | 24 | `nonce_recovery` |
| 56 | 48 | `enc_ik_recovery` — 32-byte identity seed + 16-byte tag |
| 104 | 1 | `phrase_length` — `12` or `24` (BIP-39 word count) |

```
recovery_seed   = BIP39_Decode(words)                 // 16 bytes (12 words) or 32 bytes (24 words)
K_recovery      = HKDF-SHA256(IKM = recovery_seed, salt = ik_pub, info = "najwa/v1/recovery", L = 32)
AAD_recovery    = "najwa/v1/recovery"(17) ‖ ik_pub(32)                 // 49 bytes
enc_ik_recovery = XChaCha20-Poly1305(K_recovery, nonce_recovery, ik_seed, AAD_recovery)
```

The record is exactly 105 bytes; other lengths are rejected.

## 3. HandshakePayload (Version 0x02)

Defined in [S05 §2](../specs/05-contact-establishment.md). It is the content of
an invitation (§3.3) and of a `0x04 ReciprocalHandshake` Payload.

| Offset | Size | Field |
|-------:|-----:|-------|
| 0 | 1 | `version` — `0x02` |
| 1 | 32 | `ik_pub` — Ed25519 identity public key |
| 33 | 1 | `mailbox_count` — 1–8 |
| 34 | 217 × N | `mailboxes[mailbox_count]` — §3.1 |
| … | 2 | `display_name_len` (u16) — 0–128 |
| … | var | `display_name` — UTF-8 |
| … | 8 | `created_at` (u64) |
| … | 8 | `expires_at` (u64) — MUST be greater than `created_at` |
| … | 64 | `signature` |

```
signature = Ed25519_Sign(IK_priv, "najwa/v1/handshake/"(19) ‖ bytes[0 .. len − 64])
```

Size is `116 + 217 × mailbox_count + display_name_len`, at most **2,048 bytes**.
A parser rejects a larger input before parsing, and rejects an unknown
`version`, a count outside 1–8, a name over 128 bytes or not UTF-8,
`expires_at <= created_at`, or bytes after the signature.

### 3.1 MailboxEntry (217 bytes)

Defined in [S05 §2.2](../specs/05-contact-establishment.md). Also the body unit
of control subtype `0x20 MailboxUpdate` (§10.5).

| Offset | Size | Field |
|-------:|-----:|-------|
| 0 | 56 | `onion_address` — v3 onion without `.onion`, ASCII, zero-padded |
| 56 | 32 | `deposit_capability` |
| 88 | 32 | `envelope_secret` — keys the deposit envelope (§7); never sent to a server |
| 120 | 32 | `mailbox_ik_pub` — per-mailbox derived Ed25519 key |
| 152 | 64 | `cert_signature` — signature of the MailboxCertificate (§3.2) |
| 216 | 1 | `capability_type` — `0x01` single-use handshake, `0x02` long-term |

The entry body is covered by the enclosing HandshakePayload signature, not by
`cert_signature`.

### 3.2 MailboxCertificate (200 bytes)

Defined in [S05 §2.3](../specs/05-contact-establishment.md). Only
`cert_signature` travels inside a MailboxEntry; the verifier rebuilds the other
fields.

| Offset | Size | Field | Source when verifying a MailboxEntry |
|-------:|-----:|-------|--------------------------------------|
| 0 | 32 | `ik_pub` | HandshakePayload `ik_pub` |
| 32 | 32 | `mailbox_ik_pub` | entry `mailbox_ik_pub` |
| 64 | 56 | `mailbox_onion` | entry `onion_address` |
| 120 | 8 | `created_at` (u64) | HandshakePayload `created_at` |
| 128 | 8 | `expires_at` (u64) | `created_at + 15,552,000` (180 days) |
| 136 | 64 | `signature` | entry `cert_signature` |

```
signature = Ed25519_Sign(IK_priv, bytes[0..136])
```

Verification fails when the signature does not verify under `ik_pub` or when
`expires_at <= now`.

The derived key is
`mailbox_ik = Ed25519_FromSeed(HKDF-SHA256(IKM = IK_seed, salt = UTF8(onion_address), info = "najwa/v1/mailbox-signing-key", L = 32))`
([S05 §3](../specs/05-contact-establishment.md)).

### 3.3 Invitation Encodings

Defined in [S05 §6–§7](../specs/05-contact-establishment.md). The app produces
and accepts both forms.

| Form | Encoding |
|------|----------|
| QR text | `"NAJWA:" ‖ D ‖ Base45(CRC32(D))`, where `D = Base45(zlib(payload))`. The checksum is the 4-byte big-endian CRC-32 (IEEE) of the ASCII string `D`, encoded as 6 Base45 characters. |
| Link | `"najwa://contact?data=" ‖ Base64URL(payload)`, without padding. |

Base45 uses the alphabet `0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:`
(RFC 9285). Decoders bound the input, verify the checksum, limit decompression
to 2,048 bytes and then parse the HandshakePayload.

## 4. Prekey Bundle and Manifest

Defined in [S06 §2.2 and §4](../specs/06-key-agreement-ratchet.md); transported
as JSON by `/v1/prekey/upload` and `/v1/prekey/fetch`
([S16 §3.6–§3.7](../specs/16-mailbox-server.md)).

| JSON field | Type | Content |
|------------|------|---------|
| `mailbox_ik_pub` | base64, 32 bytes | per-mailbox signing key, never the real identity key (`identity_key` accepted as an alias) |
| `signed_prekey` | base64, 32 bytes | X25519 signed prekey |
| `signed_prekey_id` | u32 | |
| `signed_prekey_signature` | base64, 64 bytes | SPK signature, below |
| `signed_prekey_timestamp` | u64 | SPK creation time, Unix seconds |
| `one_time_prekeys` | array of `{ "id": u32, "key": base64 32 bytes }` | upload: the batch; fetch: at most one, omitted when none is served |
| `manifest` | object | below; the server stores and returns it unchanged |

| `manifest` field | Type | Content |
|------------------|------|---------|
| `opk_id_set_hash` | base64, 32 bytes | `SHA256(id_1 ‖ id_2 ‖ …)` over the OPK IDs as u32, sorted ascending |
| `opk_count` | u32 | number of OPK IDs committed; `0` means signed X3DH without a one-time prekey |
| `opk_ids` | array of u32 | sorted, unique, at most 200 |
| `timestamp` | u64 | manifest creation time |
| `signature` | base64, 64 bytes | manifest signature, below |

```
spk_signature      = Ed25519_Sign(mailbox_ik_priv,
                         "najwa/v1/spk/"(13) ‖ signed_prekey(32) ‖ signed_prekey_id(u32) ‖ signed_prekey_timestamp(u64))   // 57 bytes
manifest_signature = Ed25519_Sign(mailbox_ik_priv,
                         signed_prekey_id(u32) ‖ opk_id_set_hash(32) ‖ opk_count(u32) ‖ timestamp(u64))                     // 48 bytes
```

An initiator rejects a bundle without a manifest, with a manifest that does not
verify, whose `opk_ids` are not strictly ascending, exceed 200, differ from
`opk_count` or do not hash to `opk_id_set_hash`, or that serves an OPK whose ID
is not listed. A manifest with `opk_count > 0` and no OPK served is treated as
withholding.

## 5. X3DH Initial-Message Header

Defined in [S06 §2.4](../specs/06-key-agreement-ratchet.md); position in
[S07 §2](../specs/07-message-format.md). Travels in cleartext in the wire prefix
of a `0x01 Initial`, after a u16 length (101 or 105), inside the deposit
envelope.

| Offset | Size | Field |
|-------:|-----:|-------|
| 0 | 32 | `ik_pub` — initiator's Ed25519 identity key |
| 32 | 32 | `ek_pub` — initiator's ephemeral X25519 key |
| 64 | 32 | `device_pub` — equals `ik_pub` in this release |
| 96 | 4 | `spk_id` |
| 100 | 1 | `opk_flag` — `0x00` absent, `0x01` present |
| 101 | 4 | `opk_id` — only when `opk_flag = 0x01` |

**Total:** 101 bytes (no OPK) or 105 bytes (with OPK); 103 / 107 bytes on the
wire with the length prefix. Any other length or flag value is rejected.

## 6. WireMessage

Defined in [S07 §2](../specs/07-message-format.md).

| Offset (`0x02`, `0x11`, `0x12`) | Offset (`0x01`) | Size | Field |
|---:|---:|---:|---|
| 0 | 0 | 1 | `version` — `0x01` |
| 1 | 1 | 1 | `message_type` |
| 2 | 2 | 2 | `reserved` — `0x0000` |
| 4 | 4 | 4 | `payload_length` (u32) |
| — | 8 | 2 | `x3dh_header_length` (u16) — 101 or 105 |
| — | 10 | 101 / 105 | `x3dh_header` — §5 |
| 8 | 111 / 115 | 72 | `ratchet_header` — §6.1 |
| 80 | 183 / 187 | `payload_length` | `encrypted_payload` = `nonce(24) ‖ ciphertext ‖ tag(16)` |

**Total:** `80 + payload_length` bytes; `183 / 187 + payload_length` bytes for
`0x01`.

**AAD:** `session_ad(64) ‖ wire_prefix`, where `wire_prefix` is every byte before
`encrypted_payload` (80 bytes, or 183 / 187 for `0x01`), so the AAD is 144 bytes
(247 / 251 for `0x01`). `session_ad = IK_initiator_pub ‖ IK_responder_pub`. The
24-byte nonce is `iv(16) ‖ zeros(8)`, derived from the message key
([S07 §2.3](../specs/07-message-format.md)).

### 6.1 RatchetHeader (72 bytes)

Defined in [S07 §2.2](../specs/07-message-format.md) and
[S06 §3.9](../specs/06-key-agreement-ratchet.md).

| Offset | Size | Field |
|-------:|-----:|-------|
| 0 | 32 | `dh_pub` — current ratchet X25519 public key |
| 32 | 4 | `previous_chain_length` (PN, u32) |
| 36 | 4 | `message_number` (N, u32) |
| 40 | 32 | `epoch_link` — previous sending-epoch `dh_pub`, or `zeros(32)` |

## 7. Deposit Envelope

Defined in [S07 §3](../specs/07-message-format.md). Wraps every deposited blob.

| Offset | Size | Field |
|-------:|-----:|-------|
| 0 | 24 | `nonce` — CSPRNG, fresh per deposit attempt |
| 24 | var | `ciphertext ‖ tag(16)` |

```
outer_key = HKDF-SHA256(IKM = envelope_secret, salt = "najwa/v1/deposit-envelope", info = "outer-key", L = 32)
aad       = SHA256(deposit_capability)[0:8]          // cap_hint, also returned by fetch
blob      = nonce ‖ XChaCha20-Poly1305(outer_key, nonce, inner_blob, aad)
```

`inner_blob` is a serialized WireMessage, or `CSPRNG(bucket − 40)` random bytes
under a cover envelope secret. **Overhead:** 40 bytes.

## 8. Payload

Defined in [S07 §4](../specs/07-message-format.md). AEAD plaintext of `0x01` and
`0x02` frames.

| Offset | Size | Field |
|-------:|-----:|-------|
| 0 | 32 | `sender_pseudonym` |
| 32 | 1 | `content_type` |
| 33 | 1 | `flags` — bits 3–7 MUST be zero |
| 34 | 8 | `timestamp` (u64) — sender's Unix seconds |
| 42 | 16 | `msg_id` |
| 58 | 4 | `logical_seq` (u32) — per-contact counter; 0 for control |
| 62 | 4 | `content_length` (u32) — authoritative content length, at most 261,918 |
| 66 | var | `content` |
| … | var | `padding` — all `0x00` |

**`PAYLOAD_HEADER_SIZE` = 66 bytes.** The padded plaintext is
`bucket − fixed_overhead` bytes, with fixed overhead 160 (`0x02`), 263 (`0x01`
without OPK) or 267 (`0x01` with OPK). Buckets: 256, 512, 1,024, 2,048, 4,096,
8,192, 16,384, 32,768, 65,536, 131,072, 262,144 bytes
([S07 §5](../specs/07-message-format.md)).

```
msg_id         = HKDF-SHA256(IKM = dh_pub ‖ message_number(u32) ‖ SHA256(content_type ‖ content),
                             salt = sender_pseudonym, info = "najwa/v1/message-id", L = 16)
logical_msg_id = SHA256(min(IK_a, IK_b) ‖ max(IK_a, IK_b) ‖ 0x00 ‖ timestamp(u64) ‖ 0x00 ‖
                        logical_seq(u32) ‖ 0x00 ‖ content_type ‖ 0x00 ‖ content)[0:16]
```

### 8.1 TextReplyContent (`content_type = 0x02`)

Defined in [S07 §4.3](../specs/07-message-format.md).

| Offset | Size | Field |
|-------:|-----:|-------|
| 0 | 16 | `reply_to_msg_id` — transport `msg_id` of the replied-to message |
| 16 | 2 | `text_length` (u16) |
| 18 | `text_length` | `text` — UTF-8; nothing may follow |

## 9. CumulativeAck (`message_type = 0x12`)

Defined in [S07 §8.1](../specs/07-message-format.md). AEAD plaintext:
`struct_length(u16) ‖ struct ‖ 0x00 fill`, padded to the 256 bucket (up to 2
ranges), 512 (up to 8) or 1,024 (up to 16).

| Offset | Size | Field |
|-------:|-----:|-------|
| 0 | 1 | `type` — `0x12` |
| 1 | 1 | `range_count` — 1–16 |
| 2 | 40 × N | `ranges[range_count]` |

`AckRange` (40 bytes):

| Offset | Size | Field |
|-------:|-----:|-------|
| 0 | 32 | `sender_dh_pub` |
| 32 | 4 | `start_n` (u32) — inclusive |
| 36 | 4 | `end_n` (u32) — inclusive; `start_n <= end_n` |

The struct is exactly `2 + 40 × range_count` bytes. Every number inside a range
was decrypted and committed by the sender of the ACK.

## 9a. ReadReceiptContent (`message_type = 0x11`)

Defined in [S07 §8.2](../specs/07-message-format.md). AEAD plaintext:
`struct_length(u16) = 24 ‖ struct ‖ 0x00 fill` (256 bucket). Exactly 24 bytes.

| Offset | Size | Field |
|-------:|-----:|-------|
| 0 | 16 | `msg_id` — transport `msg_id` of the message that was read |
| 16 | 8 | `timestamp` (u64) — reader's Unix seconds at display time |

## 10. Control Messages (`content_type = 0x20`)

A control message is a Payload whose `content` is `subtype(1) ‖ subtype_body`.
Offsets in this section are **within `subtype_body`**, after the subtype byte.
Subtype codes are registered in [Message Types §5](message-types.md).

### 10.1 TimerChange (`0x01`)

Defined in [S12 §2.3](../specs/12-disappearing-messages.md). 12 bytes.

| Offset | Size | Field |
|-------:|-----:|-------|
| 0 | 4 | `timer_secs` (u32) — 0 turns the timer off; values 1–29 are ignored |
| 4 | 8 | `set_at` (u64) — Unix seconds of the change; merge is last-writer-wins ([S12 §2.2](../specs/12-disappearing-messages.md)) |

### 10.2 SessionRepairInit (`0x31`)

Defined in [S06 §3.7.1](../specs/06-key-agreement-ratchet.md). 65 bytes. Sent
inside a `0x01 Initial` frame whose X3DH header starts the new session.

| Offset | Size | Field |
|-------:|-----:|-------|
| 0 | 1 | `reason` — `0x01` MissedEpochBoundary, `0x02` TooManySkipped |
| 1 | 32 | `failed_dh_pub` |
| 33 | 32 | `failed_epoch_link` |

### 10.3 ReSendRequest (`0x05`)

Defined in [S08 §10.2](../specs/08-messaging-service.md).

| Offset | Size | Field |
|-------:|-----:|-------|
| 0 | 1 | `mode` — `0x01` or `0x02` |
| 1 | var | `mode_body` — 24 bytes for `0x01`, 16 bytes for `0x02`; any other mode or length is rejected |

Mode `0x01` body:

| Offset | Size | Field |
|-------:|-----:|-------|
| 0 | 16 | `since_logical_msg_id` — `logical_msg_id` ([S07 §6.2](../specs/07-message-format.md)) of the last message the requester has; `zeros(16)` asks for all history the responder still holds |
| 16 | 8 | `fallback_floor` (u64) — Unix seconds, used when the responder does not know the anchor |

Mode `0x02` body:

| Offset | Size | Field |
|-------:|-----:|-------|
| 0 | 8 | `time_range_start` (u64) |
| 8 | 8 | `time_range_end` (u64) |

### 10.4 IdentityRotation (`0x21`)

Defined in [S02 §18](../specs/02-identity-key-protection.md). Exactly 200 bytes.

| Offset | Size | Field |
|-------:|-----:|-------|
| 0 | 32 | `old_ik_pub` — MUST equal the contact's known identity key |
| 32 | 32 | `new_ik_pub` |
| 64 | 8 | `timestamp` (u64) |
| 72 | 64 | `signature_old` — `Ed25519_Sign(old_IK_priv, bytes[0..72])` |
| 136 | 64 | `signature_new` — `Ed25519_Sign(new_IK_priv, bytes[0..72])` |

Both signatures MUST verify.

### 10.5 MailboxUpdate (`0x20`)

Defined in [S05 §12](../specs/05-contact-establishment.md). 1 to 8 MailboxEntry
records (§3.1) back to back, `217 × N` bytes. Every entry MUST have
`capability_type = 0x02` and an onion address of lowercase base32 characters
(`a`–`z`, `2`–`7`).

### 10.6 Introduction (`0x25`)

Defined in [S05 §11](../specs/05-contact-establishment.md). The body is exactly
one IntroductionPayload, at most 2,048 bytes, with no trailing bytes:

| Offset | Size | Field |
|-------:|-----:|-------|
| 0 | 1 | `version` — `0x02` |
| 1 | 32 | `introduced_ik_pub` |
| 33 | 2 | `mailbox_count` (u16) — 0–8 |
| 35 | var | `mailboxes[mailbox_count]` — each `addr_len(u16, 1–56) ‖ onion_address(UTF-8) ‖ deposit_capability(32) ‖ envelope_secret(32)` |
| … | 2 | `display_name_len` (u16) — 0–128 |
| … | var | `introduced_display_name` — UTF-8 |
| … | 32 | `introducer_ik_pub` — MUST equal the sending contact's identity key |
| … | 8 | `timestamp` (u64) |
| … | 8 | `expires_at` (u64) — MUST be greater than `timestamp` |
| … | 64 | `introducer_signature` — `Ed25519_Sign(introducer_IK_priv, all preceding bytes)` |

### 10.7 GapRepairRequest (`0x36`)

Defined in [S07 §8.5.1](../specs/07-message-format.md).

| Offset | Size | Field |
|-------:|-----:|-------|
| 0 | 1 | `epoch_count` — 1–8 |
| 1 | var | `epochs[epoch_count]` — each `dh_pub(32) ‖ gap_count(1, 1–16) ‖ gaps[gap_count]`, each gap `start(u32) ‖ end(u32)`, inclusive |

All ranges together cover at most 100 message numbers. No bytes may follow.

### 10.8 GapRepairUnavailable (`0x37`)

Defined in [S07 §8.5.2](../specs/07-message-format.md). Exactly 40 bytes.

| Offset | Size | Field |
|-------:|-----:|-------|
| 0 | 32 | `dh_pub` |
| 32 | 4 | `start_n` (u32) |
| 36 | 4 | `end_n` (u32) — inclusive; `start_n <= end_n` |

### 10.9 GapRepairBundle (`0x38`)

Defined in [S07 §8.5.3](../specs/07-message-format.md).

| Offset | Size | Field |
|-------:|-----:|-------|
| 0 | 1 | `item_count` — 1–255 |
| 1 | var | `items[item_count]` |

`RepairedItem`:

| Offset | Size | Field |
|-------:|-----:|-------|
| 0 | 32 | `original_dh_pub` |
| 32 | 4 | `original_n` (u32) |
| 36 | 16 | `original_msg_id` |
| 52 | 8 | `original_timestamp` (u64) |
| 60 | 4 | `original_logical_seq` (u32) |
| 64 | 1 | `original_content_type` |
| 65 | 1 | `original_flags` |
| 66 | 4 | `original_content_length` (u32) |
| 70 | var | `original_content` |

No bytes may follow the last item.

### 10.10 FileChunkNack (`0x3C`)

Defined in [S11 §2.2.1 and §4.1](../specs/11-file-transfer-sanitization.md).

| Offset | Size | Field |
|-------:|-----:|-------|
| 0 | 16 | `session_id` |
| 16 | 2 | `missing_count` (u16) — 1–256 |
| 18 | 4 × N | `missing_index[missing_count]` (u32) — strictly ascending |

The body is exactly `18 + 4 × missing_count` bytes.

### 10.11 Empty-Body Subtypes

`0x02 TypingIndicator`, `0x22 RevocationNotice` and
`0x26 RotationAnnouncementRequest` have an empty body; a non-empty body is
rejected. `0x30 SessionReset` has an empty body.

## 11. Mailbox Transport Framing

Defined in [S16 §3](../specs/16-mailbox-server.md). Deposited blobs (§7) travel
inside JSON request and response bodies over HTTP through Tor.

`POST /v1/deposit` request:

| Field | Type | Content |
|-------|------|---------|
| `deposit_capability` | base64, 32 bytes | target capability |
| `blob` | base64 | the deposited blob (§7) |
| `pow_solution` | object, optional | `{ challenge: base64, nonce: u64, hash: base64 32 bytes, timestamp: u64 }` ([S16 §7](../specs/16-mailbox-server.md)) |

`POST /v1/fetch` response:

| Field | Type | Content |
|-------|------|---------|
| `messages` | array | each `{ id: string, blob: base64, deposited_at: u64, size: u32, cap_hint: base64 8 bytes (optional) }` |
| `has_more` | bool | more released blobs are waiting |

The server's default `max_blob_size_bytes` is 262,144, the largest padding
bucket.

## 12. File Transfer

Defined in [S11 §2.2.1](../specs/11-file-transfer-sanitization.md). Both
structures are Payload `content` (§8).

### 12.1 FileMetadata (`content_type = 0x10`)

| Offset | Size | Field |
|-------:|-----:|-------|
| 0 | 16 | `session_id` |
| 16 | 2 | `filename_len` (u16) — 1–255 |
| 18 | var | `filename` — UTF-8 |
| … | 8 | `total_size` (u64) — at most 268,435,456 (256 MiB) |
| … | 2 | `mime_len` (u16) — 0–127 |
| … | var | `mime_type` — UTF-8 |
| … | 4 | `chunk_count` (u32) — MUST equal `ceil(total_size / 245,760)` |
| … | 32 | `sha256` — SHA-256 of the whole sanitized file |

No bytes may follow `sha256`.

### 12.2 FileChunk (`content_type = 0x11`)

| Offset | Size | Field |
|-------:|-----:|-------|
| 0 | 16 | `session_id` |
| 16 | 4 | `chunk_index` (u32) — 0-based |
| 20 | 4 | `data_len` (u32) — at most 245,760 (`MAX_CHUNK_SIZE`) |
| 24 | `data_len` | `data` — nothing may follow |

### 12.3 FileChunkNack

See §10.10.

## 13. Client-Side Dedup Tables

Defined in [S07 §7.3](../specs/07-message-format.md) and
[S03 §5.7](../specs/03-encrypted-storage.md). Both tables live in the SQLCipher
database.

`msg_id_cache_transport` holds Payload `msg_id` values and frame `header_id`
values (`SHA256(dh_pub ‖ message_number(u32))[0:16]`).

| Column | Type | Notes |
|--------|------|-------|
| `msg_id` | BLOB (16) | primary key |
| `contact_id` | INTEGER NOT NULL | FK to `contacts`, cascade delete |
| `seen_at` | INTEGER NOT NULL | Unix seconds |

`msg_id_cache_logical` holds `logical_msg_id` values (§8).

| Column | Type | Notes |
|--------|------|-------|
| `contact_id` | INTEGER NOT NULL | FK to `contacts`, cascade delete; part of the primary key |
| `logical_msg_id` | BLOB (16) NOT NULL | part of the primary key |
| `seen_at` | INTEGER NOT NULL | Unix seconds |

Entries are kept at least 90 days.

## 14. Other At-Rest Structures

### 14.1 Sealed Database Field

Defined in [S03 §7](../specs/03-encrypted-storage.md). Secret columns of
`ratchet_sessions` (`dhs_private`, `rk`, `cks`, `ckr`) and `prekeys`
(`private_key`) are sealed inside the encrypted database.

```
row_key = HKDF-SHA256(IKM = db_key, salt = UTF8(table_name), info = row_id(i64), L = 32)
field   = nonce(24) ‖ XChaCha20-Poly1305(row_key, nonce, value, aad = "field")
```

`row_id` is the `contact_id` for `ratchet_sessions` and the 4-byte `key_id` read
as u32 for `prekeys`.

### 14.2 Sealed Disappearing-Message Content

Defined in [S12 §4](../specs/12-disappearing-messages.md). In a conversation
with a timer, the stored copy of each message's content is:

```
content_blob = nonce(24) ‖ XChaCha20-Poly1305(message_key, nonce, content, aad = msg_id(16))
```

`message_key` is a random 32-byte key per message, held in the volatile key store
until the message expires.

### 14.3 Mailbox Server Storage

The mailbox server's database schema is defined in
[S16 §4](../specs/16-mailbox-server.md). It stores deposited blobs (§7) as
received.

## 15. Constants

| Constant | Value | Defined in |
|----------|-------|------------|
| `WIRE_VERSION` | `0x01` | [S07 §2](../specs/07-message-format.md) |
| `RATCHET_HEADER_SIZE` | 72 bytes | [S07 §2.2](../specs/07-message-format.md) |
| `PAYLOAD_HEADER_SIZE` | 66 bytes | [S07 §4](../specs/07-message-format.md) |
| `ENVELOPE_OVERHEAD` | 40 bytes | [S07 §3.1](../specs/07-message-format.md) |
| `CAP_HINT_SIZE` | 8 bytes | [S07 §3](../specs/07-message-format.md) |
| `PADDING_BUCKETS` | 11 sizes, 256–262,144 | [S07 §5.1](../specs/07-message-format.md) |
| `MAX_CONTENT_SIZE` | 261,918 bytes | [S07 §5.4](../specs/07-message-format.md) |
| `MESSAGE_AAD_SIZE` | 144 bytes; 247 / 251 for `0x01` | [S07 §2.3](../specs/07-message-format.md) |
| `MAX_ACK_RANGES` | 16 | [S07 §8.1](../specs/07-message-format.md) |
| `MAX_FUTURE_SKEW_SECS` | 300 | [S07 §7.1](../specs/07-message-format.md) |
| `MAX_PAST_SKEW_SECS` | 7,776,000 (90 days) | [S07 §7.1](../specs/07-message-format.md) |
| `MIN_ENTRY_TTL` (dedup) | 7,776,000 (90 days) | [S07 §7.3](../specs/07-message-format.md) |
| `GAP_DETECT_SECS` | 600 | [S07 §8.5.4](../specs/07-message-format.md) |
| `GAP_REPAIR_MAX_RANGE` | 100 | [S07 §8.5.4](../specs/07-message-format.md) |
| `GAP_REPAIR_MIN_INTERVAL_SECS` | 3,600 | [S07 §8.5.4](../specs/07-message-format.md) |
| `MAX_SKIP` | 1,000 | [S06 §3.1](../specs/06-key-agreement-ratchet.md) |
| `MAX_SKIPPED_KEYS_PER_SESSION` | 4,000 | [S06 §3.1](../specs/06-key-agreement-ratchet.md) |
| `SKIP_KEY_EXPIRY_SECS` | 7,776,000 (90 days) | [S06 §3.1](../specs/06-key-agreement-ratchet.md) |
| OPK batch size | 200 | [S06 §5](../specs/06-key-agreement-ratchet.md) |
| SPK rotation | 7 days | [S06 §5](../specs/06-key-agreement-ratchet.md) |
| SPK grace period | 1,209,600 s (14 days) | [S06 §5](../specs/06-key-agreement-ratchet.md) |
| `MAX_HANDSHAKE_SIZE` | 2,048 bytes | [S05 §2](../specs/05-contact-establishment.md) |
| `MAILBOX_ENTRY_SIZE` | 217 bytes | [S05 §2.2](../specs/05-contact-establishment.md) |
| `MAILBOX_CERT_VALIDITY_SECS` | 15,552,000 (180 days) | [S05 §2.3](../specs/05-contact-establishment.md) |
| `MAX_FILE_SIZE` | 268,435,456 (256 MiB) | [S11 §2.1](../specs/11-file-transfer-sanitization.md) |
| `MAX_CHUNK_SIZE` | 245,760 | [S11 §2.1](../specs/11-file-transfer-sanitization.md) |
| `NACK_MAX_INDICES` | 256 | [S11 §2.1](../specs/11-file-transfer-sanitization.md) |
| `max_blob_size_bytes` (server default) | 262,144 | [S16](../specs/16-mailbox-server.md) |
| Capability retention (server) | 1–90 days, default 14 | [S16 §10](../specs/16-mailbox-server.md) |
