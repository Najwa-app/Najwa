# Message Types

This is the single registry of numeric codes on the Najwa wire. Each entry names
the spec section that defines it. Byte layouts are collected in
[Wire Formats](wire-formats.md).

"Sent" means a release client emits the code. "Accepted" means a release client
parses and acts on it when received. A code that is accepted but not sent is
still part of the protocol a peer may use.

Unknown codes in the WireMessage `version`, `message_type`, `content_type`,
control subtype and the nested version bytes of §6 are handled by the
[unknown-types receiver framework](../specs/07-message-format.md) (S07 §10).

## 1. WireMessage Version (`WireMessage.version`, 1 byte)

| Code | Name | Sent | Accepted | Defined in |
|------|------|:----:|:--------:|------------|
| `0x01` | `WIRE_VERSION` | yes | yes | [S07 §2](../specs/07-message-format.md) |
| any other | unassigned — rejected | | | |

## 2. WireMessage Type (`WireMessage.message_type`, 1 byte)

| Code | Name | Sent | Accepted | Defined in |
|------|------|:----:|:--------:|------------|
| `0x01` | Initial | yes | yes | [S07 §2](../specs/07-message-format.md), [S06 §2.4](../specs/06-key-agreement-ratchet.md) |
| `0x02` | Standard | yes | yes | [S07 §2](../specs/07-message-format.md) |
| `0x11` | ReadReceipt | yes | yes | [S07 §8.2](../specs/07-message-format.md) |
| `0x12` | CumulativeAck | yes | yes | [S07 §8.1](../specs/07-message-format.md) |
| any other | unassigned — rejected | | | |

Cover traffic has no WireMessage type: a cover blob fails envelope decryption at
every receiver ([S10](../specs/10-cover-traffic.md)).

## 3. Content Types (`Payload.content_type`, 1 byte)

| Code | Type | Sent | Accepted | Defined in |
|------|------|:----:|:--------:|------------|
| `0x01` | Text | yes | yes | [S07 §4.1](../specs/07-message-format.md) |
| `0x02` | TextReply | yes | yes | [S07 §4.3](../specs/07-message-format.md) |
| `0x03` | Binary | no | yes | [S07 §4.1](../specs/07-message-format.md) |
| `0x04` | ReciprocalHandshake | yes | yes, only in an Initial | [S07 §4.1](../specs/07-message-format.md), [S05 §8.2](../specs/05-contact-establishment.md) |
| `0x10` | FileMetadata | yes | yes | [S11 §2.2.1](../specs/11-file-transfer-sanitization.md) |
| `0x11` | FileChunk | yes | yes | [S11 §2.2.1](../specs/11-file-transfer-sanitization.md) |
| `0x20` | Control | yes | yes | [S07 §4.1](../specs/07-message-format.md); subtypes in §5 |
| any other | unassigned — rejected | | | |

## 4. Payload Flags (`Payload.flags`, 1 byte)

| Bit | Mask | Name | Sent | Defined in |
|-----|------|------|:----:|------------|
| 0 | `0x01` | Ephemeral | yes, when the conversation timer is on | [S07 §4.2](../specs/07-message-format.md), [S12](../specs/12-disappearing-messages.md) |
| 1 | `0x02` | ShowDeliveryStatus | no (accepted; UI hint only) | [S07 §4.2](../specs/07-message-format.md) |
| 2 | `0x04` | ReadReceiptRequested | yes, on Text and TextReply | [S07 §4.2](../specs/07-message-format.md), [S07 §8.2](../specs/07-message-format.md) |
| 3–7 | `0xF8` | unassigned — rejected | | [S07 §4.2](../specs/07-message-format.md) |

## 5. Control Subtypes (first byte of `content` when `content_type = 0x20`)

Bodies follow the subtype byte. Layouts are in
[Wire Formats §10](wire-formats.md).

| Subtype | Name | Body | Sent | Accepted | Defined in |
|--------:|------|------|:----:|:--------:|------------|
| `0x01` | TimerChange | `timer_secs(u32) ‖ set_at(u64)`, 12 bytes | yes | yes | [S12 §2.3](../specs/12-disappearing-messages.md) |
| `0x02` | TypingIndicator | empty | no | yes | [S08 §6.4](../specs/08-messaging-service.md) |
| `0x05` | ReSendRequest | `mode(1) ‖ mode_body` (24 or 16 bytes) | no | yes | [S08 §10.2](../specs/08-messaging-service.md) |
| `0x20` | MailboxUpdate | 1–8 × `MailboxEntry` (217 bytes each, long-term) | yes | yes | [S05 §12](../specs/05-contact-establishment.md) |
| `0x21` | IdentityRotation | `RotationAnnouncement`, 200 bytes | no | yes | [S02 §18](../specs/02-identity-key-protection.md) |
| `0x22` | RevocationNotice | empty | yes, on Delete contact | yes | [S08 §6.4, §7.1](../specs/08-messaging-service.md) |
| `0x25` | Introduction | one IntroductionPayload (version `0x02`) | no | yes | [S05 §11](../specs/05-contact-establishment.md) |
| `0x26` | RotationAnnouncementRequest | empty | no | yes (no action) | [S02 §18](../specs/02-identity-key-protection.md) |
| `0x30` | SessionReset | empty | no | yes | [S08 §7.2](../specs/08-messaging-service.md) |
| `0x31` | SessionRepairInit | `reason(1) ‖ failed_dh_pub(32) ‖ failed_epoch_link(32)`, inside an Initial | yes | yes | [S06 §3.7.1](../specs/06-key-agreement-ratchet.md) |
| `0x36` | GapRepairRequest | `epoch_count(1) ‖ epochs` | yes | yes | [S07 §8.5.1](../specs/07-message-format.md) |
| `0x37` | GapRepairUnavailable | `dh_pub(32) ‖ start_n(u32) ‖ end_n(u32)`, 40 bytes | yes | yes | [S07 §8.5.2](../specs/07-message-format.md) |
| `0x38` | GapRepairBundle | `item_count(1) ‖ RepairedItem…` | yes | yes | [S07 §8.5.3](../specs/07-message-format.md) |
| `0x3C` | FileChunkNack | `session_id(16) ‖ missing_count(u16) ‖ missing_index(u32)…` | yes, for missing parts of a quiet received file | yes; the named parts are re-sent | [S11 §4.1](../specs/11-file-transfer-sanitization.md) |
| any other | unassigned — rejected | | | | |

## 6. Nested Enumerations

| Field | Values | Defined in |
|-------|--------|------------|
| HandshakePayload `version` (first byte of a `0x04` content) | `0x02`; any other: unassigned — rejected | [S05 §2](../specs/05-contact-establishment.md) |
| IntroductionPayload `version` (first byte after subtype `0x25`) | `0x02`; any other: unassigned — rejected | [S05 §11](../specs/05-contact-establishment.md) |
| `MailboxEntry.capability_type` | `0x01` single-use handshake capability, `0x02` long-term capability | [S05 §2.2](../specs/05-contact-establishment.md) |
| X3DH header `opk_flag` | `0x00` no one-time prekey, `0x01` one-time prekey used; any other: rejected | [S06 §2.4](../specs/06-key-agreement-ratchet.md) |
| `SessionRepairInit.reason` | `0x01` MissedEpochBoundary, `0x02` TooManySkipped | [S06 §3.7.1](../specs/06-key-agreement-ratchet.md) |
| `ReSendRequest.mode` | `0x01` since a logical message ID (24-byte body), `0x02` time range (16-byte body); any other: rejected | [S08 §10.2](../specs/08-messaging-service.md) |
| `CumulativeAck.type` | `0x12` | [S07 §8.1](../specs/07-message-format.md) |
| Identity record `version` / `mode` / `kdf_alg` / `aead_alg` | `0x03` / `0x01` standard / `0x01` Argon2id / `0x01` XChaCha20-Poly1305 | [S02 §7](../specs/02-identity-key-protection.md) |
| Recovery record `phrase_length` | `12` or `24` | [S02 §13](../specs/02-identity-key-protection.md) |

## 7. Error Codes

Error codes are not wire values. The FFI error codes are listed in the
[API Reference](api-reference.md).
