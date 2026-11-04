# Protocol specifications

These documents specify the Najwa protocol and the behavior of its reference
implementation in this repository. They cover the desktop app (`apps/local-web`
and the Rust crates it uses) and the `najwa-mailbox` server. Each spec is
normative for the release it ships with: the conformance checklist at the end of
each spec lists what the reference implementation does.

## Conventions

- The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are used as in
  RFC 2119.
- Multi-byte integers in Najwa structures are big-endian unless a layout says
  otherwise. Third-party file formats (S11) keep their own byte order.
- `‖` is byte concatenation. Lengths are in bytes.
- Spec numbers (`S01`) and section numbers (`§2.3`) are stable identifiers.
  Source code cites them. A section titled "Reserved" holds a number that is not
  used in this release. Numbers S09, S14 and S15 are not assigned.
- The crate list in each spec's front matter names the crates that implement it.

## Specifications

| Spec | Title | Implemented in | Depends on |
| --- | --- | --- | --- |
| [S01](specs/01-crypto-primitives.md) | Cryptographic primitives, key hierarchy, pairwise pseudonyms | `najwa-crypto` | — |
| [S02](specs/02-identity-key-protection.md) | Identity and key protection, unlock, recovery kit | `najwa-identity` | S01 |
| [S03](specs/03-encrypted-storage.md) | Encrypted local storage, schema, crash consistency | `najwa-storage`, `najwa-core`, `najwa-ffi` | S01, S02, S06, S07, S08, S12 |
| [S04](specs/04-transport.md) | Tor transport, isolation, bridges | `najwa-transport`, `najwa-protocol`, `najwa-ffi` | S01 |
| [S05](specs/05-contact-establishment.md) | Invitations, mailbox certificates, prekeys, reciprocal setup | `najwa-protocol`, `najwa-core`, `najwa-ffi` | S01, S02, S04, S06, S07, S16 |
| [S06](specs/06-key-agreement-ratchet.md) | X3DH key agreement and the Double Ratchet | `najwa-protocol`, `najwa-core` | S01, S03, S05, S07, S16 |
| [S07](specs/07-message-format.md) | Wire messages, deposit envelope, padding, IDs, acknowledgements | `najwa-protocol`, `najwa-core` | S01, S03, S05, S06 |
| [S08](specs/08-messaging-service.md) | Send and receive pipelines, retries, deduplication, repair | `najwa-core`, `najwa-storage` | S03–S07, S10, S12, S16 |
| [S10](specs/10-cover-traffic.md) | Delivery modes and cover traffic | `najwa-core`, `najwa-ffi` | S04, S07, S08, S16 |
| [S11](specs/11-file-transfer-sanitization.md) | File sanitization and resumable transfer | `najwa-sanitize`, `najwa-protocol`, `najwa-core`, `najwa-storage`, `najwa-ffi` | S03, S04, S06–S08, S10, S12, S16 |
| [S12](specs/12-disappearing-messages.md) | Disappearing-message timers | `najwa-core`, `najwa-storage` | S03, S07, S08, S13 |
| [S13](specs/13-privacy-hardening.md) | Locking, erasure, memory and log hygiene | `najwa-privacy`, `najwa-ffi`, `najwa-web` | S02–S04, S08, S10, S12, S17 |
| [S16](specs/16-mailbox-server.md) | Mailbox server API, capabilities, proof of work, retention | `najwa-mailbox`, `najwa-protocol` | S01, S04–S07 |
| [S17](specs/17-ffi-bindings.md) | C ABI and native integration contract | `najwa-ffi` | S02–S04, S08, S10, S12, S13 |
| [S18](specs/18-test-vectors.md) | Conformance test vectors | `najwa-crypto`, `najwa-identity`, `najwa-protocol`, `najwa-core`, `najwa-sanitize` | S01–S03, S05–S08, S11 |

`najwa-web` is the package name of `apps/local-web`. Each spec's front matter
is authoritative for its crate list and dependencies.

Supporting registries:

- [Wire formats](reference/wire-formats.md): byte layout of every structure.
- [Message types](reference/message-types.md): message types, content types, flags, control subtypes.
- [HKDF strings](reference/hkdf-strings.md): every key-derivation and domain-separation label.
- [Keys](reference/keys.md): every key and secret, with derivation, storage, lifetime and erasure.

## Format versions

Format versions identify compatibility. They are independent of the app version
(`0.1.0`, set in the workspace `Cargo.toml`). Changing any of them breaks
compatibility with existing peers or profiles.

| Format | Identifier | Defined in |
| --- | --- | --- |
| Wire message | `version = 0x01` | [S07 §2](specs/07-message-format.md) |
| Handshake payload (invitation) | `HANDSHAKE_VERSION = 0x02` | [S05](specs/05-contact-establishment.md) |
| Invitation link | `najwa://contact?data=` + Base64URL (no padding) | [S05](specs/05-contact-establishment.md) |
| Identity record | `VERSION = 0x03`, 192 bytes | [S02](specs/02-identity-key-protection.md) |
| Recovery record | 105 bytes, unversioned, AEAD-authenticated | [S02 §13.0](specs/02-identity-key-protection.md) |
| Passphrase KDF | Argon2id, version `0x13` | [S02](specs/02-identity-key-protection.md) |
| Client database | SQLCipher, `schema_version = 2` | [S03 §5.1](specs/03-encrypted-storage.md) |
| Mailbox database | SQLite, schema version 2 | [S16](specs/16-mailbox-server.md) |
| Mailbox HTTP API | path prefix `/v1/` | [S16](specs/16-mailbox-server.md) |
| Key-derivation labels | `najwa/v1/…` and the other registered labels | [HKDF strings](reference/hkdf-strings.md) |

## Using the specifications

- To implement a peer, read S01, S02, S05, S06, S07, S08 and S16 in that order,
  with the registries, then check your implementation against S18.
- To review security, start with the [threat model](understanding/threat-model.md)
  and the [security properties](security/properties.md); each property links to
  the spec section that defines it.
- To change the protocol, follow [Contributing](../CONTRIBUTING.md#protocol-and-format-changes):
  update the spec, the registries and the vectors together.
