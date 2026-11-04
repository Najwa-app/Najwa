---
id: S07
title: Message Format & Encryption
crates: [najwa-protocol, najwa-core]
depends-on: [S01, S03, S05, S06]
---

# S07 — Message Format & Encryption

## Overview

Every message Najwa sends to a contact is wrapped twice before it reaches a
mailbox server.

The inner layer is the Double Ratchet encryption from
[S06](06-key-agreement-ratchet.md). It turns a plaintext **Payload** (sender
pseudonym, content type, flags, timestamp, identifiers and the content itself)
into a **WireMessage**. A WireMessage starts with a short cleartext prefix:
version, type, length, the 72-byte ratchet header and, for the first message of a
session, the X3DH header. The prefix is not secret, but every byte of it is part
of the AEAD associated data, so changing any header byte makes decryption fail.

The outer layer is the **deposit envelope**. The sender encrypts the whole
WireMessage again under a key derived from an `envelope_secret`. The recipient
handed that secret out together with the mailbox address and deposit capability;
the mailbox server never receives it. To the server, every deposit (real message,
acknowledgment or cover traffic) is a random-looking blob. Its only visible
property is its size, and sizes come from a fixed set of 11 buckets: the sender
pads the plaintext so the final blob lands exactly on a bucket.

```
deposited blob (one of 11 bucket sizes, 256 … 262,144 bytes)
└─ envelope: nonce(24) ‖ XChaCha20-Poly1305(outer_key, WireMessage, aad = cap_hint)
   └─ WireMessage: wire_prefix ‖ nonce(24) ‖ ciphertext ‖ tag(16)
      └─ AEAD plaintext
           0x01 / 0x02:  Payload ‖ 0x00 padding
           0x11 / 0x12:  struct_length ‖ struct ‖ 0x00 padding
```

Each Payload carries two identifiers. The transport `msg_id` is derived from the
ratchet position and the content; it recognises the same ciphertext arriving
twice (several mailboxes, retries). The `logical_msg_id` is derived from both
identity keys, the original timestamp, a per-contact sequence number and the
content; it stays the same when the same content is encrypted again later (gap
repair, re-sending history), so the receiver keeps it only once.

The recipient confirms delivery with `CumulativeAck` frames that list exact
ranges of ratchet message numbers it has decrypted and stored. The sender relies
on them: an acknowledged position counts as delivered, the sender-side
disappearing timer starts from it, and a control message is re-sent until it is
acknowledged. When a receiver sees a hole in a sender's chain that does not fill
within ten minutes, it asks for the missing positions with a gap-repair request.
The sender answers from its own durable history, re-encrypting the original
content under its current keys.

The format is built to be extended. A receiver that meets a type byte it does not
know authenticates the frame, records its chain position and drops it silently
(§10).

This spec defines byte layouts and the rules for building and checking them.
[S06](06-key-agreement-ratchet.md) defines the keys.
[S08](08-messaging-service.md) defines the send and receive pipelines that use
these formats. [S10](10-cover-traffic.md) decides when deposits happen.
[S16](16-mailbox-server.md) defines the mailbox server.

## 1. Scope

This specification defines:

- The WireMessage layout (§2), including the `0x01 Initial` prefix that carries
  the cleartext X3DH header.
- The 72-byte RatchetHeader (§2.2).
- The canonical message AAD (§2.3) and the AEAD plaintext of each message type
  (§2.4).
- The deposit envelope and `cap_hint` (§3).
- The Payload, content types, flags and `TextReplyContent` (§4).
- Padding to 11 deposited-blob buckets (§5).
- The transport `msg_id` and the endpoint-invariant `logical_msg_id` (§6).
- Timestamp validation, replay rejection and the two dedup caches (§7).
- `CumulativeAck`, read receipts, retransmission rules and the gap-repair
  structures (§8).
- Wire constants (§9) and the unknown-types receiver framework (§10).

Control-message subtypes other than gap repair are registered in
[Message Types](../reference/message-types.md) and defined by their owning specs.

## 2. WireMessage Structure

All multi-byte integers are big-endian. A WireMessage has one of two prefix
shapes. `0x01 Initial` carries the cleartext X3DH header; every other type does
not.

| Offset (`0x02`, `0x11`, `0x12`, unknown) | Offset (`0x01`) | Size | Field |
|---:|---:|---:|---|
| 0 | 0 | 1 | `version` — `0x01` |
| 1 | 1 | 1 | `message_type` — §2.1 |
| 2 | 2 | 2 | `reserved` — MUST be `0x0000` |
| 4 | 4 | 4 | `payload_length` (u32) — length of `encrypted_payload` |
| — | 8 | 2 | `x3dh_header_length` (u16) — 101 or 105 |
| — | 10 | 101 / 105 | `x3dh_header` — cleartext, [S06 §2.4](06-key-agreement-ratchet.md) |
| 8 | 111 / 115 | 72 | `ratchet_header` — §2.2 |
| 80 | 183 / 187 | `payload_length` | `encrypted_payload` = `nonce(24) ‖ ciphertext ‖ tag(16)` |

**Total size:** `80 + payload_length` bytes for `0x02`, `0x11`, `0x12`;
`183 + payload_length` (no OPK) or `187 + payload_length` (with OPK) for `0x01`.

The X3DH header layout is
`ik_pub(32) ‖ ek_pub(32) ‖ device_pub(32) ‖ spk_id(4) ‖ opk_flag(1) ‖ [opk_id(4)]`:
101 bytes with `opk_flag = 0x00`, 105 bytes with `opk_flag = 0x01`. In this
release `device_pub` equals `ik_pub`. The header travels in cleartext inside the
deposit envelope. It cannot be inside the ratchet AEAD, because the ratchet key is
derived from it; it is integrity-protected through the message AAD (§2.3).
Confidentiality against the mailbox server comes from the deposit envelope (§3).

A receiver MUST parse a WireMessage as follows and reject it on any failure:

1. At least 8 bytes are present.
2. `version` equals `0x01`. Any other value is handled by §10.
3. `reserved` is `0x0000`.
4. For `0x01`: read `x3dh_header_length` and that many header bytes. The X3DH
   header MUST be exactly 101 bytes with `opk_flag = 0x00` or exactly 105 bytes
   with `opk_flag = 0x01`.
5. Read the 72-byte ratchet header.
6. Read exactly `payload_length` bytes of `encrypted_payload`.

Senders MUST NOT append bytes after `encrypted_payload`.

### 2.1 WireMessage Types

| Code | Name | Description |
|------|------|-------------|
| `0x01` | Initial | First message of a session (X3DH). Carries the cleartext X3DH header. Also used for a session-repair Initial ([S06 §3.7.1](06-key-agreement-ratchet.md)). |
| `0x02` | Standard | Normal Double Ratchet message (`MessageType::Normal` in code). |
| `0x11` | ReadReceipt | Read receipt (§8.2). |
| `0x12` | CumulativeAck | Delivery acknowledgment (§8.1). |

Every other value is unassigned. A receiver handles it with §10.

Control messages (timer changes, mailbox updates, gap repair and the rest) are
Payloads with `content_type = 0x20` inside `0x01` or `0x02` frames.
Acknowledgments and read receipts are their own WireMessage types, not control
messages.

Cover traffic is not a WireMessage type. A cover deposit is an envelope around
`bucket − 40` random bytes under a cover envelope secret that only its creator
holds ([S10 §5](10-cover-traffic.md)). It fails envelope decryption at every
receiver and never reaches the WireMessage layer.

### 2.2 RatchetHeader (72 bytes, fixed)

| Offset | Size | Field |
|-------:|-----:|-------|
| 0 | 32 | `dh_pub` — sender's current ratchet public key (X25519) |
| 32 | 4 | `previous_chain_length` — PN (u32) |
| 36 | 4 | `message_number` — N (u32) |
| 40 | 32 | `epoch_link` — the sender's previous sending-epoch `dh_pub`, or `zeros(32)` when there is no previous sending epoch |

The ratchet header is authenticated through the AAD but not encrypted by the
ratchet. The deposit envelope hides it from the mailbox server. `epoch_link`
semantics are defined in [S06 §3.7.1](06-key-agreement-ratchet.md).

### 2.3 AEAD Encryption — canonical message AAD (normative)

For every ratchet-encrypted WireMessage the AEAD associated data is:

```
message_aad = session_ad(64) ‖ wire_prefix
```

- `session_ad` is the 64-byte X3DH associated data of the session:
  `IK_initiator_pub(32) ‖ IK_responder_pub(32)` (Ed25519 identity keys,
  [S06 §2](06-key-agreement-ratchet.md)).
- `wire_prefix` is every wire byte before `encrypted_payload`, exactly as
  transmitted:
  - `0x02`, `0x11`, `0x12`:
    `version ‖ message_type ‖ reserved ‖ payload_length ‖ ratchet_header`
    = 80 bytes, so `message_aad` is **144 bytes**.
  - `0x01`: additionally `x3dh_header_length ‖ x3dh_header` between
    `payload_length` and `ratchet_header` = 183 / 187 bytes, so `message_aad` is
    **247 / 251 bytes**.

`payload_length` inside the AAD is the length of the `encrypted_payload` being
produced: `24 + len(plaintext) + 16`.

Encryption, decryption and decryption with a stored skipped key MUST all build
this exact byte string. [S06 §3.4 / §3.5](06-key-agreement-ratchet.md) state the
same rule.

Per-message key material comes from the message key `mk` of the sending or
receiving chain ([S06 §3.3](06-key-agreement-ratchet.md)):

```
okm            = HKDF-SHA256(IKM = mk, salt = zeros(32), info = "najwa/v1/ratchet/mk", L = 80)
encryption_key = okm[0:32]
iv             = okm[64:80]
nonce          = iv ‖ zeros(8)                      // 24 bytes

(ciphertext ‖ tag) = XChaCha20-Poly1305-Encrypt(
    key       = encryption_key,
    nonce     = nonce,
    plaintext = padded_plaintext,                   // §5
    aad       = message_aad)

encrypted_payload = nonce(24) ‖ ciphertext ‖ tag(16)
```

`okm[32:64]` is derived and not used. The nonce on the wire is redundant with
the derived nonce. A receiver MUST derive the nonce from the message key and MUST
reject a frame whose first 24 bytes of `encrypted_payload` differ from it.

### 2.4 AEAD-plaintext shape by message_type (normative)

| `message_type` | AEAD plaintext | Ratchet state advances |
|----------------|----------------|------------------------|
| `0x01 Initial` | `Payload` (§4) padded per §5.2. The X3DH header is in the wire prefix, not here. | Yes: responder-side X3DH, then a normal ratchet receive. |
| `0x02 Standard` | `Payload` (§4) padded per §5.2. | Yes. |
| `0x11 ReadReceipt` | `struct_length(u16) ‖ ReadReceiptContent ‖ 0x00 fill` (§5.5, §8.2). No Payload wrapper. | Yes. |
| `0x12 CumulativeAck` | `struct_length(u16) ‖ CumulativeAck ‖ 0x00 fill` (§5.5, §8.1). No Payload wrapper. | Yes. |

`0x11`, `0x12` and unknown types can only be decrypted with an existing session.
A receiver handles any other `message_type` with §10.

## 3. Envelope AAD / Cap-Hint

Before any blob is deposited to a mailbox server, the whole WireMessage is
wrapped in an outer AEAD layer keyed from an **`envelope_secret`**.

- The `envelope_secret` is a 32-byte CSPRNG value minted by the owner of a
  deposit capability. Each receive queue (the mailbox's shared queue, each
  per-contact queue and each single-use handshake queue) has its own
  `(deposit_capability, envelope_secret)` pair.
- The secret is distributed together with the deposit capability: in each
  `MailboxEntry` of a HandshakePayload ([S05 §2.2](05-contact-establishment.md)),
  in `MailboxUpdate` (`0x20`) and in IntroductionPayload mailbox entries. All of
  these travel inside signed or ratchet-encrypted structures.
- The secret is **never sent to a mailbox server**. The server stores the
  deposit capability to route deposits, but it cannot derive the outer key.
- Cover deposits use a cover envelope secret that the creator generates and
  shares with nobody ([S10 §5](10-cover-traffic.md)).

**`cap_hint`.** The 8-byte value `SHA256(deposit_capability)[0:8]` serves two
roles: it is the envelope AAD, and the server returns it (base64) with each
fetched blob ([S16 §3.4](16-mailbox-server.md)). It adds no cryptographic
security, since the server knows the deposit capability and can compute it.
Confidentiality rests entirely on `outer_key`. Implementations MUST still use it
as the AAD, because both endpoints must build the same byte string.

**Hint collisions.** With 64-bit truncation, collisions become likely around
2³² capabilities. A receiver MUST NOT rely on the hint alone: when the hint is
missing, unknown or shared, it trial-decrypts with every pair it holds for the
queue until one succeeds or all fail.

### 3.1 Envelope Construction (Sender Side)

For each target mailbox, using that target's `(deposit_capability, envelope_secret)`:

```
1. outer_key = HKDF-SHA256(
       IKM  = envelope_secret,
       salt = "najwa/v1/deposit-envelope",
       info = "outer-key",
       L    = 32)
2. nonce     = CSPRNG(24)                         // fresh for every deposit attempt
3. aad       = SHA256(deposit_capability)[0:8]    // cap_hint
4. ct_tag    = XChaCha20-Poly1305-Encrypt(outer_key, nonce, inner_blob, aad)
5. deposited_blob = nonce(24) ‖ ct_tag
```

- For a real message, `inner_blob` is the serialized WireMessage.
- For cover traffic, `inner_blob` is `CSPRNG(bucket − ENVELOPE_OVERHEAD)` under
  the cover envelope secret, so the deposited blob is exactly `bucket` bytes.

`ENVELOPE_OVERHEAD` = 40 bytes (24 nonce + 16 tag).

A message sent to several mailboxes is enveloped separately for each target
under that target's own secret. Every retry of a frame reuses the same
WireMessage bytes with a new envelope nonce. A sender MUST NOT deposit to a target
for which it holds no envelope secret.

### 3.2 Envelope Decryption (Receiver Side)

```
1. If len(blob) < 40: fail.
2. For each (deposit_capability, envelope_secret) known for the queue being fetched,
   starting with the pair whose cap_hint matches, if any:
       outer_key  = HKDF-SHA256(envelope_secret, "najwa/v1/deposit-envelope", "outer-key", 32)
       aad        = SHA256(deposit_capability)[0:8]
       inner_blob = XChaCha20-Poly1305-Decrypt(outer_key, blob[0:24], blob[24:], aad)
       on success: parse inner_blob as a WireMessage (§2) and stop.
3. If every pair fails: discard the blob silently (cover traffic or spam).
```

A receiver MUST NOT process a blob as a WireMessage unless envelope decryption
succeeded. A queue with no usable envelope secret has no pair to try, so every
blob fetched from it is discarded. A discarded blob produces no error response and no state change; the
receiver acknowledges it to the server so it is not fetched again.

**Server knowledge.** The server links `deposit_capability` and
`fetch_capability` at registration and can compute `cap_hint`. It never holds an
`envelope_secret`, so it can neither decrypt envelopes nor tell real deposits
from cover deposits of the same size.

## 4. Payload Structure

The AEAD plaintext of `0x01` and `0x02` frames is a Payload followed by zero
padding (§5):

| Offset | Size | Field |
|-------:|-----:|-------|
| 0 | 32 | `sender_pseudonym` — sender's pairwise pseudonym for this recipient |
| 32 | 1 | `content_type` — §4.1 |
| 33 | 1 | `flags` — §4.2 |
| 34 | 8 | `timestamp` (u64) — sender's Unix seconds |
| 42 | 16 | `msg_id` — transport message ID (§6.1) |
| 58 | 4 | `logical_seq` (u32) — per-contact outbound counter |
| 62 | 4 | `content_length` (u32) |
| 66 | `content_length` | `content` — type-specific |
| … | var | `padding` — all `0x00` (§5) |

**`PAYLOAD_HEADER_SIZE = 66`** (32 + 1 + 1 + 8 + 16 + 4 + 4).

A receiver MUST reject a Payload when:

- fewer than 66 bytes are present;
- `flags` has a reserved bit set (§4.2);
- `content_length > MAX_CONTENT_SIZE` (§5.4);
- `66 + content_length` exceeds the plaintext;
- `content_type = 0x01` and `content` is not valid UTF-8;
- `content_type = 0x02` and `content` is not a valid `TextReplyContent` (§4.3);
- any byte after `content` is not `0x00`.

An unknown `content_type` is handled by §10.

**`timestamp`.** The sender's clock in Unix seconds: the system clock corrected
by the offset estimated from the Tor consensus ([S04 §7](04-transport.md)).

**`logical_seq` (normative).** A per-contact outbound counter, persisted with the
contact ([S03](03-encrypted-storage.md)). The first user-content Payload to a
contact carries 1, and each new user-content Payload carries the next value.
Control Payloads carry 0. When content is re-sent from durable history (gap
repair §8.5, `ReSendRequest` replies), the
original `timestamp` and `logical_seq` MUST be reused byte-exact; that keeps
`logical_msg_id` (§6.2) stable. Receivers MUST treat `logical_seq` as an opaque
part of `logical_msg_id`. They MUST NOT enforce monotonicity or contiguity and
MUST NOT use it to detect gaps; gap detection uses ratchet message numbers (§8.5).

### 4.1 Content Types

| Code | Type | `content` |
|------|------|-----------|
| `0x01` | Text | UTF-8 text. |
| `0x02` | TextReply | `TextReplyContent` (§4.3). |
| `0x03` | Binary | Opaque bytes. Accepted and stored; the release does not send it. |
| `0x04` | ReciprocalHandshake | The sender's serialized HandshakePayload ([S05 §2](05-contact-establishment.md), flow in [S05 §8.2](05-contact-establishment.md)). |
| `0x10` | FileMetadata | `session_id(16) ‖ filename_len(u16) ‖ filename ‖ total_size(u64) ‖ mime_len(u16) ‖ mime_type ‖ chunk_count(u32) ‖ sha256(32)` — [S11 §2.2.1](11-file-transfer-sanitization.md). |
| `0x11` | FileChunk | `session_id(16) ‖ chunk_index(u32) ‖ data_len(u32) ‖ data` — [S11 §2.2.1](11-file-transfer-sanitization.md). |
| `0x20` | Control | `subtype(1) ‖ subtype_body` — registry in [Message Types](../reference/message-types.md). |

Rules:

- `0x04 ReciprocalHandshake` is valid only inside a `0x01 Initial` frame; a
  receiver MUST reject it in any other frame. If its first content byte (the
  HandshakePayload version) is not `0x02`, the receiver handles it with §10.
  It is contact-establishment data and is not shown as a conversation message.
- `0x20 Control` Payloads carry `flags = 0x00` and `logical_seq = 0`. A control
  body that fails its subtype's parsing rules is rejected; an unknown subtype is
  handled by §10.
- Logical dedup (§6.2, §7.3) applies to every content type except `0x04` and
  `0x20`.

### 4.2 Payload Flags

| Bit | Mask | Name | Meaning |
|-----|------|------|---------|
| 0 | `0x01` | Ephemeral | Disappearing message; the conversation timer applies ([S12](12-disappearing-messages.md)). Set by the sender when the conversation timer is on at send time. |
| 1 | `0x02` | ShowDeliveryStatus | UI hint only. Transport ACKs (§8.1) never depend on it. The release does not set it. |
| 2 | `0x04` | ReadReceiptRequested | The sender asks for a read receipt (§8.2). The desktop app sets it on Text and TextReply messages. |
| 3–7 | `0xF8` | Reserved | MUST be zero. Senders MUST NOT set them; receivers MUST reject a Payload that does. |

Reply semantics live only in `content_type = 0x02` (§4.3), not in flags.

### 4.3 TextReplyContent (`content_type = 0x02`)

| Offset | Size | Field |
|-------:|-----:|-------|
| 0 | 16 | `reply_to_msg_id` — transport `msg_id` (§6.1) of the message being replied to |
| 16 | 2 | `text_length` (u16) |
| 18 | `text_length` | `text` — UTF-8 |

`content_length` MUST equal `18 + text_length` exactly; trailing bytes are
rejected. `text` MUST be valid UTF-8. A reply text is therefore at most 65,535
bytes.

## 5. Message Padding

### 5.1 Bucket Sizes — defined at the deposited-blob level (normative)

`PADDING_BUCKETS` are the **final deposited blob sizes**: the byte count the
mailbox server stores and an observer sees. There are 11 buckets:

| # | Size (bytes) |
|---|-------------:|
| 1 | 256 |
| 2 | 512 |
| 3 | 1,024 |
| 4 | 2,048 |
| 5 | 4,096 |
| 6 | 8,192 |
| 7 | 16,384 |
| 8 | 32,768 |
| 9 | 65,536 |
| 10 | 131,072 |
| 11 | 262,144 |

#### 5.1.1 Fixed overhead and padded-plaintext targets per message type

```
deposited_blob_size     = ENVELOPE_OVERHEAD(40) + wire_prefix + AEAD nonce(24) + tag(16) + padded_plaintext
fixed_overhead          = 40 + wire_prefix + 40
padded_plaintext_target = bucket − fixed_overhead
```

| Message type | `wire_prefix` | Fixed overhead | Padded-plaintext target |
|--------------|--------------:|---------------:|-------------------------|
| `0x02`, `0x11`, `0x12` | 80 | **160** | bucket − 160 |
| `0x01` without OPK | 183 | **263** | bucket − 263 |
| `0x01` with OPK | 187 | **267** | bucket − 267 |

An Initial cannot use the 256-byte bucket, because its fixed overhead exceeds 256;
the smallest Initial deposit is 512 bytes. Cover deposits use the same bucket
sizes (§3.1).

### 5.2 Padding Procedure

```
func pad_payload(payload_bytes, fixed_overhead):
    for bucket in PADDING_BUCKETS (ascending):
        if bucket <= fixed_overhead: continue
        target = bucket − fixed_overhead
        if target >= len(payload_bytes):
            return payload_bytes ‖ [0x00] * (target − len(payload_bytes))
    return Error(ContentTooLarge)        // sender MUST NOT send; split files per S11
```

Padding bytes are all `0x00`. There is no padding-length byte: `content_length`
(§4) is the authoritative content delimiter.

### 5.3 Unpadding Procedure

The receiver parses the Payload directly from the padded plaintext:

```
func parse_padded_payload(plaintext):
    header      = plaintext[0:66]                     // §4
    content_end = 66 + header.content_length
    if content_end > len(plaintext): return Error(TruncatedPayload)
    for byte in plaintext[content_end:]:
        if byte != 0x00: return Error(InvalidPadding)
    return Payload(header, plaintext[66:content_end])
```

Padding is inside the AEAD, so a non-zero padding byte means a non-canonical or
tampered plaintext and MUST be rejected. `0x11` and `0x12` use the length-prefix
rule of §5.5.

### 5.4 Maximum Content Size

```
MAX_CONTENT_SIZE = 261,918     // 262,144 − 160 (0x02 fixed overhead) − 66 (PAYLOAD_HEADER_SIZE)
```

Receivers MUST reject `content_length > MAX_CONTENT_SIZE`. For an Initial the
effective maximum is 261,815 (no OPK) or 261,811 (with OPK) bytes. A full file
chunk (`24 + MAX_CHUNK_SIZE` = 245,784 content bytes,
[S11 §2.1](11-file-transfer-sanitization.md)) fits in the 262,144 bucket, which
equals the server's default `max_blob_size_bytes`
([S16](16-mailbox-server.md)).

### 5.5 Padding for `0x11 ReadReceipt` / `0x12 CumulativeAck` (normative)

These types have no Payload and therefore no `content_length`. Their plaintext is:

```
aead_plaintext = struct_length(u16) ‖ struct_bytes ‖ 0x00 fill
```

- The sender picks the smallest bucket whose target (`bucket − 160`) holds
  `2 + struct_length` and zero-fills to that target.
- `ReadReceiptContent` (24 bytes) always fits the 256 bucket. A `CumulativeAck`
  fits the 256 bucket with up to 2 ranges, the 512 bucket with up to 8 and the
  1,024 bucket with up to 16.
- The receiver reads `struct_length`, checks that `2 + struct_length` does not
  exceed the plaintext, checks that every following byte is `0x00`
  (`InvalidPadding` otherwise), then parses the struct, whose own length rules
  (§8.1, §8.2) MUST match `struct_length` exactly.

## 6. Message ID Generation

### 6.1 Generation

```
content_hash = SHA256(content_type_byte ‖ content)

msg_id = HKDF-SHA256(
    IKM  = dh_pub(32) ‖ message_number(u32) ‖ content_hash(32),
    salt = sender_pseudonym(32),
    info = "najwa/v1/message-id",
    L    = 16)
```

`dh_pub` and `message_number` are the values of the ratchet header the frame is
sent with. Control Payloads use the same formula with `content_type_byte = 0x20`
and the full control bytes as `content`.

**Generation timing (normative).** The sender fixes the outgoing
`(dh_pub, message_number)` before building the Payload, then derives `msg_id`
from those values. Two identical texts sent in the same second therefore get
different IDs.

**Receivers treat `msg_id` as opaque** on ordinary frames and MUST NOT reject a
frame because its `msg_id` does not match the derivation. The exception is a
`GapRepairBundle` item (§8.5.3): the item carries its original `dh_pub` and
message number explicitly, and the receiver MUST verify `original_msg_id` against
them.

### 6.2 Properties

- **Deterministic** for the same content at the same ratchet position, so a
  retransmitted frame is recognised.
- **Bound to the ratchet position** (`dh_pub`, message number), so identical
  content at different positions gets different IDs.
- **Bound to the content**, so different content gets different IDs.
- **Bound to the pair of contacts** through the sender pseudonym salt.

**Logical message ID (endpoint-invariant).** A second identifier detects the
same content delivered under different transport identities: re-delivered by gap
repair (§8.5) or re-sent for a `ReSendRequest`
([S08 §10.2](08-messaging-service.md)), each time under a new ratchet position.

```
logical_msg_id = SHA256(
    min(IK_a_pub, IK_b_pub) ‖ max(IK_a_pub, IK_b_pub) ‖ 0x00 ‖   // 64 bytes, lexicographic order
    timestamp(u64)        ‖ 0x00 ‖                               // Payload.timestamp
    logical_seq(u32)      ‖ 0x00 ‖                               // Payload.logical_seq
    content_type(1)       ‖ 0x00 ‖                               // Payload.content_type
    content                                                      // Payload.content
)[0:16]
```

- `IK_a_pub`, `IK_b_pub` are the two parties' Ed25519 identity public keys,
  ordered lexicographically, so both endpoints compute the same value.
- It is computed for user content only: every content type except `0x04` and
  `0x20`.
- Sender and receiver derive the same value from the same content, independent
  of either side's local contact ID. That makes `since_logical_msg_id` in
  `ReSendRequest` meaningful to the peer.

## 7. Replay Protection

### 7.1 Timestamp Validation

| Check | Window |
|-------|--------|
| Not more than 5 minutes in the **future** | Rejects pre-dated frames. |
| Not more than 90 days in the **past** | Equals the maximum server retention ([S16 §10.1](16-mailbox-server.md)), so a receiver offline for the full retention period still accepts what the server held for it. |

```
MAX_FUTURE_SKEW_SECS = 300
MAX_PAST_SKEW_SECS   = 7,776,000          // 90 days

func validate_timestamp(ts, now):
    if ts > now + MAX_FUTURE_SKEW_SECS: return Error(TimestampOutOfRange)
    if ts < now − MAX_PAST_SKEW_SECS:   return Error(TimestampOutOfRange)
    return Ok
```

`now` is the local clock corrected by the Tor consensus offset
([S04 §7](04-transport.md)). Timestamps supplied by a mailbox server are never
used to set the clock.

**Re-delivery carve-out (normative).** Content re-delivered from durable history
carries its original timestamp, which `logical_msg_id` depends on. For
`GapRepairBundle` items (§8.5.3), `ReSendRequest` replies
([S08 §10.2](08-messaging-service.md)) and `FileChunkNack` replies
([S11 §4.1](11-file-transfer-sanitization.md)), the receiver MUST NOT reject solely
because the original timestamp is older than `MAX_PAST_SKEW_SECS`; at-most-once
delivery is enforced by logical dedup (§7.3). The future bound has no carve-out
and applies to every Payload and every bundle item.

### 7.2 Replay Rejection

Four mechanisms reject replays and duplicates:

1. **Single-use message keys.** A frame whose `(dh_pub, message_number)` is
   behind the receiving chain and has no stored skipped key fails decryption
   ([S06 §3.5](06-key-agreement-ratchet.md)).
2. **Header dedup.** Before decrypting, the receiver computes
   `header_id = SHA256(dh_pub ‖ message_number(u32))[0:16]` from the ratchet
   header. If `header_id` is in the transport cache, the frame was already
   processed: the receiver drops it without decrypting and, if that position is
   acknowledged (§8.1), queues its ACK again.
3. **Transport dedup.** After decrypting a Payload, a `msg_id` already in the
   transport cache is dropped.
4. **Logical dedup.** User content whose `logical_msg_id` is already in the
   logical cache for that contact is not stored again. The frame is still
   committed and acknowledged, so the ratchet stays in step with the sender.

### 7.3 Deduplication Cache

Two persistent caches live in the client database
([S03 §5.7](03-encrypted-storage.md)):

| Table | Key | Columns |
|-------|-----|---------|
| `msg_id_cache_transport` | `msg_id` (16 bytes) | `msg_id BLOB PRIMARY KEY`, `contact_id INTEGER NOT NULL` (FK, cascade delete), `seen_at INTEGER NOT NULL` |
| `msg_id_cache_logical` | `(contact_id, logical_msg_id)` | `contact_id INTEGER NOT NULL` (FK, cascade delete), `logical_msg_id BLOB NOT NULL`, `seen_at INTEGER NOT NULL`, `PRIMARY KEY (contact_id, logical_msg_id)` |

The transport cache holds both kinds of 16-byte transport identifier: Payload
`msg_id` values and `header_id` values (§7.2).

| Event | Transport cache | Logical cache |
|-------|-----------------|---------------|
| `0x01` / `0x02` frame committed | `header_id` and Payload `msg_id` | `logical_msg_id` (user content only) |
| `0x11` / `0x12` frame committed | `header_id` | — |
| Frame discarded under §10 | `header_id` | — |
| `GapRepairBundle` item (§8.5.3) | `original_msg_id` and the `header_id` of `(original_dh_pub, original_n)` | `logical_msg_id` |

Dedup entries MUST be written in the same storage transaction as the ratchet
state advance and the stored message ([S08 §6.3](08-messaging-service.md)).

```
MIN_ENTRY_TTL = 7,776,000      // 90 days = maximum server retention
```

A dedup entry MUST NOT be removed earlier than `MIN_ENTRY_TTL` after its
`seen_at`. Because no blob the server may still deliver can outlive its dedup
entry, a replayed or late-released blob cannot bring back a disappearing message
that was already deleted ([S12](12-disappearing-messages.md)). The release
deletes entries 91 days after `seen_at`: the server may hold a blob up to one
cleanup interval past its 90-day cap ([S16 §10.1](16-mailbox-server.md)), and
the extra day covers that ([S03 §6.4](03-encrypted-storage.md)). Deleting a
contact deletes its entries.

## 8. Delivery Confirmation

### 8.1 CumulativeAck (the only ACK format)

A recipient confirms delivery with a `message_type = 0x12` frame. A single
message is acknowledged with one range where `start_n == end_n`.

```
struct CumulativeAck {          // AEAD plaintext per §5.5
    u8       type;              // 0x12 — MUST equal WireMessage.message_type
    u8       range_count;       // 1..=16
    AckRange ranges[range_count];
}
struct AckRange {               // 40 bytes
    u8  sender_dh_pub[32];      // RatchetHeader.dh_pub of the acknowledged sending chain
    u32 start_n;                // inclusive
    u32 end_n;                  // inclusive; start_n <= end_n
}
```

The struct is exactly `2 + 40 × range_count` bytes. A receiver MUST reject a
`CumulativeAck` whose `type` is not `0x12`, whose `range_count` is 0 or above 16,
whose length differs, or that contains a range with `start_n > end_n`. The struct
has no received-at field: it would leak the receiver's clock and serves no
protocol purpose.

**Coverage rule (normative).** Every message number `n` with
`start_n <= n <= end_n` on `sender_dh_pub`'s chain MUST correspond to a frame
that was decrypted and durably committed. Acknowledging past a gap is forbidden:
a range MUST NOT span a number the receiver has not committed, so ranges are split
around gaps. A sender treats an acknowledged position as delivered, and
[S12](12-disappearing-messages.md) starts the sender-side timer from it.

**What is acknowledged.** A receiver acknowledges every committed `0x01` or
`0x02` frame, including control messages, `ReciprocalHandshake` Initials, logical
duplicates (§7.2) and positions filled by gap repair (§8.5.3), except:

- `0x11` and `0x12` frames (acknowledging them would create an endless exchange);
- frames discarded under §10;
- `SessionReset` (`0x30`) and `RevocationNotice` (`0x22`) control messages;
- frames from a contact the user has blocked.

The transport ACK does not depend on flag bit 1 (`ShowDeliveryStatus`).

**Construction.** Committing a received frame records an ACK obligation for its
`(dh_pub, n)` in the same transaction. An ACK frame takes up to 128 pending
positions for one contact, ordered by receive time and then `(dh_pub, n)`, and
merges consecutive numbers on the same chain into at most 16 ranges. Positions
left over wait for the next ACK. Committing the ACK frame clears the obligations
it carries in the same transaction.

**Scheduling.** ACK frames are deposited through the cover-traffic slot
scheduler with ACK priority ([S10 §6–§7](10-cover-traffic.md)). Under the Timing
privacy delivery mode an ACK waits for a cover slot; under Responsive the slot
wait is bypassed. To an observer an ACK deposit is an ordinary bucket-sized blob.

**Processing a received ACK.** The sender MUST validate the struct as above.
For each range it then, in one transaction: removes its outgoing frames at those
positions (ending control retransmission, §8.3), marks the user messages sent at
those positions as delivered, and starts their sender-side disappearing timers.

### 8.2 Read Receipts

A read receipt is a `message_type = 0x11` frame:

| Offset | Size | Field |
|-------:|-----:|-------|
| 0 | 16 | `msg_id` — transport `msg_id` of the message that was read |
| 16 | 8 | `timestamp` (u64) — reader's Unix seconds at display time |

`ReadReceiptContent` is exactly 24 bytes; any other length is rejected.

- A recipient sends a read receipt only for a received message whose flags have
  bit 2 (`ReadReceiptRequested`) set, and only when the message is displayed, not
  when it is decrypted. The display event is persisted and turned into a frame
  later, so a receipt survives a restart.
- Read receipts are deposited through the slot scheduler with read-receipt
  priority, like ACKs.
- On receipt, the original sender marks the message read only if it is one of its
  own sent messages to that contact with bit 2 set. Other receipts have no
  effect.
- `timestamp` is the reader's claim and is used only for display.

### 8.3 Retry Logic

Every outgoing frame is committed, with the advanced ratchet state, before its
first deposit attempt ([S08](08-messaging-service.md)). Retries reuse the same
WireMessage bytes and wrap them in a new envelope (fresh nonce) for each target.

- **Deposit failure.** If every selected mailbox fails, the sender tries up to
  `DEPOSIT_RETRIES = 2` other mailboxes of the contact, chosen in random order.
  If the frame is still not deposited, it is retried later after a random delay
  of up to `min(5 × 2^(k−1), 300)` seconds, where `k` is the number of failed
  attempts.
- **User content, ACKs and read receipts** leave the outbox after their first
  successful deposit. There is no timeout-driven re-send of deposited user
  content. Content is encrypted again only from durable history, for gap repair
  (§8.5) or a `ReSendRequest` reply. Each such re-send gets a new transport
  `msg_id`, and logical dedup (§7.3) absorbs the duplicate.

**Control-message retransmission (normative).** A control message stays in the
outbox after it is deposited. It is deposited again byte-identically (same
WireMessage, fresh envelope nonce) after a random delay of up to
`min(5 × 2^k, 3600)` seconds (`k` = earlier attempts), until an `AckRange` covers
its `(dh_pub, n)`. Header and transport dedup absorb the copies at the receiver,
and each copy is re-acknowledged.

### 8.4 SessionRepair Priority — cross-reference

Deposit priority among real messages, session-repair Initials, ACKs, read
receipts and other control messages is defined in
[S10 §6](10-cover-traffic.md).

**Reorder-vs-loss grace.** Before any repair machinery fires, receivers apply the
quarantine discipline of [S06 §3.7.1](06-key-agreement-ratchet.md)
(`REPAIR_GRACE_SECS = 600`, `EPOCH_QUARANTINE_MAX = 32`). Batched release
reorders deposits by design, and reordering MUST NOT be treated as loss.

### 8.5 Gap Repair Wire Structures

Gap repair recovers messages that were deposited and then lost in transit (the
blob expired before it was fetched, or a fetch dropped it). It is distinct from
deposit-failure retry (§8.3) and from session repair
([S06 §3.7](06-key-agreement-ratchet.md)). The detection pipeline is defined in
[S08 §6.5](08-messaging-service.md). The three structures below are control
subtypes (`content_type = 0x20`); offsets are inside `subtype_body`, after the
1-byte subtype.

**Design.** Original message keys are deleted for forward secrecy, so the sender
cannot re-send the original ciphertext. It re-encrypts the original content from
its own durable history under its **current** ratchet state. A repair therefore
separates **transport identity** (the bundle frame's own ratchet header, used for
ratchet mechanics, AEAD and transport dedup) from **logical identity** (each
item's original metadata, used for conversation placement, ordering and logical
dedup).

**Detection.** A ratchet chain numbers its messages, so receiving `n` creates a
skipped-key entry for every unseen `m < n` on that chain. An entry younger than
`GAP_DETECT_SECS` is presumed reordered. Once entries are older, the receiver
builds one request from them: positions sorted by `(dh_pub, n)`, consecutive
numbers merged into ranges, at most 8 chains, 16 ranges per chain and 100
positions in total. It sends at most one request per contact per
`GAP_REPAIR_MIN_INTERVAL_SECS`, and none while a session repair for that contact
is in progress. The responder answers at most one request per contact per
`GAP_REPAIR_MIN_INTERVAL_SECS` and drops the others unanswered
([S08 §6.5](08-messaging-service.md)), so a contact can make it re-encrypt at
most 100 positions an hour.

#### 8.5.1 GapRepairRequest (control subtype `0x36`)

```
struct GapRepairRequest {
    u8       epoch_count;              // 1..=8
    EpochGap epochs[epoch_count];
}
struct EpochGap {
    u8       dh_pub[32];               // the requester's view of the SENDER's chain
    u8       gap_count;                // 1..=16
    GapRange gaps[gap_count];
}
struct GapRange {
    u32 start;                         // first missing message number
    u32 end;                           // last missing message number, inclusive
}
```

A receiver MUST reject the request when a count is outside its range, a range
has `start > end`, the ranges cover more than `GAP_REPAIR_MAX_RANGE = 100`
message numbers in total, or bytes follow the last range.

The responder answers each requested position from its outbound repair records.
It keeps one record for each of its last 256 user-content messages to that
contact. A position is unavailable when there is no record, or when the record
holds disappearing-message content whose key has expired.

#### 8.5.2 GapRepairUnavailable (control subtype `0x37`)

The responder cannot re-deliver a range. Body: exactly 40 bytes.

| Offset | Size | Field |
|-------:|-----:|-------|
| 0 | 32 | `dh_pub` — chain identifier from the request |
| 32 | 4 | `start_n` (u32) — first unavailable message number |
| 36 | 4 | `end_n` (u32) — last unavailable message number, inclusive; `start_n <= end_n` |

The responder merges consecutive unavailable numbers on the same chain and sends
one `0x37` per range. On receipt, if the range covers at most
`GAP_REPAIR_MAX_RANGE` numbers, the requester deletes its skipped-key entries in
that range, so it stops asking for them.

#### 8.5.3 GapRepairBundle (control subtype `0x38`)

```
struct GapRepairBundle {
    u8           item_count;           // 1..=255
    RepairedItem items[item_count];
}
```

`RepairedItem` (70-byte header followed by the content):

| Offset | Size | Field |
|-------:|-----:|-------|
| 0 | 32 | `original_dh_pub` — original chain identifier |
| 32 | 4 | `original_n` (u32) — original message number |
| 36 | 16 | `original_msg_id` — original transport `msg_id` |
| 52 | 8 | `original_timestamp` (u64) |
| 60 | 4 | `original_logical_seq` (u32) |
| 64 | 1 | `original_content_type` |
| 65 | 1 | `original_flags` |
| 66 | 4 | `original_content_length` (u32) |
| 70 | var | `original_content` |

A receiver MUST reject a bundle with `item_count = 0`, a truncated item, or bytes
after the last item.

**Batching (normative).** The responder packs items in request order and starts
a new bundle when the next item would push the control content
(`subtype + item_count + items`) past `MAX_CONTENT_SIZE`, or when a bundle holds
255 items. Repairing 20 short messages therefore uses one chain position, not 20.
An item too large to fit alone is reported as unavailable (§8.5.2).

**Receiver validation (normative).** The receiver MUST reject the whole bundle if
any item:

- has an `original_content_type` that is unknown, `0x04` or `0x20`;
- has `original_logical_seq = 0`;
- would be rejected as a Payload (§4: reserved flag bits, invalid UTF-8 text,
  invalid `TextReplyContent`, content above `MAX_CONTENT_SIZE`);
- has `original_timestamp` beyond the future bound of §7.1;
- has an `original_msg_id` that differs from §6.1 computed over
  `original_dh_pub`, `original_n`, `SHA256(original_content_type ‖ original_content)`
  and the sender's pseudonym.

**Receiver processing.** For each item, in the same transaction as the bundle
frame:

1. Delete the skipped-key entry for `(original_dh_pub, original_n)`.
2. Add the `header_id` of `(original_dh_pub, original_n)` to the transport cache
   and record an ACK obligation for that position (§8.1).
3. Compute `logical_msg_id` (§6.2) from `original_timestamp`,
   `original_logical_seq`, `original_content_type` and `original_content`. If
   `original_msg_id` or `logical_msg_id` is already known, or repeats an earlier
   item of the same bundle, skip the item: the original arrived or was repaired
   already.
4. Otherwise store the message under its logical identity: `original_msg_id`,
   position `original_n` and `original_timestamp`. If the conversation timer is
   on, the stored copy is sealed as for any received message
   ([S12 §4](12-disappearing-messages.md)).

The bundle frame itself is not shown as a message. Original message keys stay
deleted; the bundle is encrypted with fresh keys by the normal ratchet.

#### 8.5.4 Constants

```
GAP_DETECT_SECS               = 600     // skipped-key age before a gap is requested
GAP_REPAIR_MAX_RANGE          = 100     // message numbers per request
GAP_REPAIR_MAX_EPOCHS         = 8       // chains per request
GAP_REPAIR_MAX_RANGES_PER_EPOCH = 16    // ranges per chain
GAP_REPAIR_MIN_INTERVAL_SECS  = 3600    // at most one request sent, and one answered, per contact per hour
REPAIRED_ITEM_HEADER_SIZE     = 70
OUTBOUND_REPAIR_RECORDS       = 256     // per contact, most recent user-content messages
```

`GAP_DETECT_SECS` equals `REPAIR_GRACE_SECS`
([S06 §3.7.1](06-key-agreement-ratchet.md)): both encode the same "reordered, not
lost" waiting period.

## 9. Wire-Format Constants

| Constant | Value | Notes |
|----------|-------|-------|
| `WIRE_VERSION` | `0x01` | §2 |
| `RATCHET_HEADER_SIZE` | 72 bytes | §2.2 |
| `MESSAGE_AAD_SIZE` | 144 bytes (`0x02`, `0x11`, `0x12`); 247 / 251 (`0x01`) | §2.3 |
| `ENVELOPE_OVERHEAD` | 40 bytes (24 nonce + 16 tag) | §3.1 |
| `CAP_HINT_SIZE` | 8 bytes | §3 |
| `PAYLOAD_HEADER_SIZE` | 66 bytes | §4 |
| `PADDING_BUCKETS` | 256, 512, 1,024, 2,048, 4,096, 8,192, 16,384, 32,768, 65,536, 131,072, 262,144 | §5.1 |
| Fixed overhead | 160 (`0x02`, `0x11`, `0x12`); 263 / 267 (`0x01`) | §5.1.1 |
| `MAX_CONTENT_SIZE` | 261,918 bytes | §5.4 |
| `READ_RECEIPT_SIZE` | 24 bytes | §8.2 |
| `AckRange` size | 40 bytes | §8.1 |
| `MAX_ACK_RANGES` | 16 | §8.1 |
| `MAX_FUTURE_SKEW_SECS` | 300 | §7.1 |
| `MAX_PAST_SKEW_SECS` | 7,776,000 (90 days) | §7.1 |
| `MIN_ENTRY_TTL` (dedup) | 7,776,000 (90 days) | §7.3 |
| `DEPOSIT_RETRIES` | 2 | §8.3 |
| `GAP_DETECT_SECS` | 600 | §8.5.4 |
| `GAP_REPAIR_MAX_RANGE` | 100 | §8.5.4 |
| `GAP_REPAIR_MAX_EPOCHS` | 8 | §8.5.4 |
| `GAP_REPAIR_MAX_RANGES_PER_EPOCH` | 16 | §8.5.4 |
| `GAP_REPAIR_MIN_INTERVAL_SECS` | 3,600 | §8.5.4 |
| `REPAIRED_ITEM_HEADER_SIZE` | 70 bytes | §8.5.3 |
| `MAX_SKIP` | 1,000 | [S06 §3.1](06-key-agreement-ratchet.md) |
| `MAX_SKIPPED_KEYS_PER_SESSION` | 4,000 | [S06 §3.1](06-key-agreement-ratchet.md) |
| `SKIP_KEY_EXPIRY_SECS` | 7,776,000 (90 days) | [S06 §3.1](06-key-agreement-ratchet.md) |

## 10. Unknown-Types Receiver Framework

*Normative; forward-compatibility contract.*

This is the single rule for a wire byte the receiver does not recognise. It
covers: the outer WireMessage `version`, `message_type`, `content_type`, a
control subtype, the HandshakePayload version inside a `ReciprocalHandshake`, and
the IntroductionPayload version inside an `Introduction` control message. Other
specs refer to this section instead of restating it.

**Unknown outer `version` (special case).** A WireMessage whose first byte is not
`0x01` cannot be parsed, because the header layout and the AAD depend on the
version. After envelope decryption the receiver MUST log a warning (offset 0 and
the value only) and discard the blob, with no ratchet operation, no dedup entry,
no ACK and no response.

**Any other unknown byte.** The receiver MUST:

1. Complete envelope decryption (§3.2).
2. Complete the AEAD decryption the frame requires, so the ratchet advances
   exactly as for a known type. An unknown `message_type` is parsed with the
   80-byte prefix (no X3DH header) and decrypted with the existing session.
3. Log a warning containing only the byte's offset and value: offset 1 for
   `message_type`, 32 for `content_type`, 66 for a control subtype or a
   HandshakePayload version, 67 for an IntroductionPayload version (offsets are
   into the WireMessage for `message_type` and into the AEAD plaintext
   otherwise).
4. Commit the ratchet advance together with a transport-cache entry for the
   frame's `header_id` (§7.2), so a retransmission is not processed twice.
5. Discard the plaintext. Do not parse further and do not surface anything to the
   application.
6. Send no error response and no ACK, do not close the session and do not start
   session repair.

A future protocol revision can therefore introduce a new byte unilaterally: older
receivers authenticate it, consume its chain position and continue.
Implementations MUST NOT add other state changes keyed on unknown types (counters,
alerts, UI), because these would be observable.

An unknown byte inside a structure that has no version field of its own is not
covered by this section. For example, a `GapRepairBundle` item with an unknown
`original_content_type` invalidates the bundle (§8.5.3).

### 10.1 Error Types

```rust
enum MessageError {
    TooShort,
    TruncatedPayload,
    EmptyMessage,
    InvalidPadding,
    ContentTooLarge { size: usize, max: usize },
    UnknownMessageType(u8),
    UnknownContentType(u8),                          // handled per §10
    UnknownControlSubtype(u8),                       // handled per §10
    UnknownNestedVersion { offset: usize, value: u8 }, // handled per §10
    UnsupportedVersion(u8),                          // outer version, handled per §10
    TimestampOutOfRange { diff: u64 },
    InvalidHeader(String),
    InvalidContent(String),
    SliceError,
    InvalidFlags(u8),
    InvalidUtf8,
}
```

The variants marked "handled per §10" are not fatal; they select the §10
behaviour. Unknown `message_type` values are carried as `MessageType::Unknown(u8)`
and reach §10 the same way.

## Security Considerations

- **What the mailbox server sees.** The deposit capability, `cap_hint`, deposit
  and fetch times and the blob size, which is one of 11 buckets. It does not see
  the ratchet header, the X3DH header, the message type or the content. Size still
  leaks something: a 256-byte deposit is never an Initial, and large file chunks
  fill the largest bucket.
- **`cap_hint` is not a secret.** It only speeds up lookup. All envelope
  confidentiality comes from `envelope_secret`.
- **Timestamps are sender claims.** They decide display order and the replay
  window, not authenticity. The read-receipt timestamp is the reader's claim.
- **The past bound is not enforced.** The reference receiver applies the §7.1
  future bound but not `MAX_PAST_SKEW_SECS`, because at the receive layer it
  cannot tell an ordinary frame from history re-delivered under the carve-out.
  Old frames are still rejected by single-use message keys and dedup (§7.2).
- **`msg_id` is chosen by the sender.** On ordinary frames receivers do not
  verify it; a dishonest sender can only confuse its own deduplication and reply
  references. Gap-repair items are verified.
- **`logical_msg_id` is not secret from the two parties.** Anyone who knows both
  identity keys and the content can compute it. It only travels inside encrypted
  Payloads.
- **ACKs are the peer's word.** A contact can claim to have received a message it
  did not, or withhold ACKs. The coverage rule makes honest ACKs exact; it cannot
  make a dishonest peer honest.
- **Gap repair costs the responder work.** A contact can request up to 100
  positions per hour. The responder re-sends only from its last 256 user-content
  records, in bundles bounded by `MAX_CONTENT_SIZE`.

## 11. Conformance Checklist

- WireMessage serialization and parsing for both prefix shapes (80-byte and
  183 / 187-byte), with the `reserved = 0x0000` check and exact X3DH header
  lengths.
- 72-byte RatchetHeader including `epoch_link`.
- Canonical AAD `session_ad(64) ‖ wire_prefix`, built by one function for
  encryption, decryption and the skipped-key path.
- Nonce derived from the message key; on-wire nonce compared on receive.
- AEAD-plaintext shape per `message_type`: Payload for `0x01` / `0x02`,
  length-prefixed struct for `0x11` / `0x12`.
- Deposit envelope: `outer_key` from `envelope_secret` with salt
  `"najwa/v1/deposit-envelope"` and info `"outer-key"`, AAD `cap_hint`, fresh
  nonce per deposit, separate envelope per target, no deposit without a secret.
- Envelope decryption by trial over the queue's pairs; silent discard on failure.
- Payload: 66-byte header, `logical_seq`, u32 `content_length`, zero-fill
  padding, rejection rules of §4.
- Seven content types; `0x04` only in an Initial; `TextReplyContent` with exact
  length and UTF-8.
- Flag bits 0–2; reserved bits rejected on send and receive.
- 11 deposited-blob buckets with fixed overheads 160 / 263 / 267; zero-fill pad;
  `content_length`-authoritative parse; `MAX_CONTENT_SIZE = 261,918`.
- §5.5 length-prefix rule for `0x11` / `0x12`.
- Transport `msg_id` from the transmitted header and content hash; opaque on
  ordinary receive; verified for gap-repair items.
- Endpoint-invariant `logical_msg_id` for user content.
- Per-contact `logical_seq` starting at 1, 0 for control, original value reused on
  re-delivery.
- Future-timestamp rejection (+300 s) for Payloads and bundle items.
- Header dedup before decryption; transport and logical dedup committed
  atomically with the ratchet state; entries kept at least 90 days.
- `CumulativeAck`: 1–16 ranges, exact coverage, no ranges across gaps, no ACK of
  `0x11` / `0x12`, §10 discards, `0x22`, `0x30` or blocked contacts; obligations
  recorded and cleared transactionally.
- Read receipts only for messages with bit 2 set, sent on display, applied only to
  own messages that requested them.
- Same-frame retry with fresh envelope nonces; control frames retransmitted until
  acknowledged.
- Gap repair: request construction and limits, one answered request per contact
  per `GAP_REPAIR_MIN_INTERVAL_SECS`, 256 outbound repair records,
  `0x37` range collapsing, `0x38` batching under `MAX_CONTENT_SIZE`, full
  receiver validation and logical dedup.
- §10 framework for outer version, `message_type`, `content_type`, control
  subtype and nested version bytes, with `header_id` dedup and no ACK.
- HKDF labels as listed in [HKDF Strings](../reference/hkdf-strings.md).
