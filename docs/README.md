# Najwa documentation

Najwa is a desktop one-to-one messenger. A native service on your computer holds
the identity, keys, Tor client and encrypted database, and serves the interface
to your browser on loopback. Messages are end-to-end encrypted and delivered
through independent store-and-forward mailboxes reached over Tor.

Start with the guide for your role.

## Using Najwa

| Document | Contents |
| --- | --- |
| [Getting started](getting-started.md) | Install, create an identity, add a mailbox, invite a contact, send files |
| [FAQ](understanding/faq.md) | Offline delivery, invitations, recovery, files, locking, updates |
| [How it works](understanding/how-it-works.md) | The whole system in plain language |
| [Release status](../RELEASE-READINESS.md) | Supported platforms, what was validated, known limitations |

## Security

| Document | Contents |
| --- | --- |
| [Threat model](understanding/threat-model.md) | Adversaries, what each can learn or do, assumptions and non-goals |
| [Security properties](security/properties.md) | Each guarantee, its assumptions and the spec that defines it |
| [Cryptographic rationale](security/crypto-rationale.md) | Why each primitive and parameter was chosen |
| [Supply chain](security/supply-chain.md) | How packages are built and how to verify them |
| [Dependency assessment](security/dependencies.md) | Dated review of third-party dependencies and advisories |
| [Reporting a vulnerability](../SECURITY.md) | Private disclosure process |

## Protocol specification

The [specification index](SPECS-VERSION.md) lists the protocol specifications,
their scope and the format versions they define. Read them in this order:

| Spec | Topic |
| --- | --- |
| [S01](specs/01-crypto-primitives.md) | Cryptographic primitives, key derivation, pairwise pseudonyms |
| [S02](specs/02-identity-key-protection.md) | Identity, passphrase and device factor, unlock, recovery |
| [S05](specs/05-contact-establishment.md) | Invitations, mailbox certificates, prekeys, reciprocal setup |
| [S06](specs/06-key-agreement-ratchet.md) | X3DH key agreement and the Double Ratchet |
| [S07](specs/07-message-format.md) | Wire messages, envelopes, padding, IDs, acknowledgements |
| [S08](specs/08-messaging-service.md) | Send and receive pipelines, retries, deduplication, repair |
| [S16](specs/16-mailbox-server.md) | Mailbox server API, capabilities, proof of work, retention |
| [S04](specs/04-transport.md) | Tor transport, isolation, bridges |
| [S10](specs/10-cover-traffic.md) | Delivery modes and cover traffic |
| [S03](specs/03-encrypted-storage.md) | Encrypted local storage and crash consistency |
| [S11](specs/11-file-transfer-sanitization.md) | File sanitization and resumable transfer |
| [S12](specs/12-disappearing-messages.md) | Disappearing-message timers |
| [S13](specs/13-privacy-hardening.md) | Locking, erasure, memory and log hygiene |
| [S17](specs/17-ffi-bindings.md) | C ABI and native integration contract |
| [S18](specs/18-test-vectors.md) | Conformance test vectors |

## Reference

| Document | Contents |
| --- | --- |
| [Wire formats](reference/wire-formats.md) | Byte layout of every on-wire and at-rest structure |
| [Message types](reference/message-types.md) | Registry of message types, content types, flags and control subtypes |
| [HKDF strings](reference/hkdf-strings.md) | Registry of key-derivation and domain-separation labels |
| [Keys](reference/keys.md) | Every key and secret: derivation, storage, lifetime, erasure |
| [API reference](reference/api-reference.md) | Local HTTP API, C ABI and mailbox HTTP API |
| [Glossary](reference/glossary.md) | Terms used across the documentation |

## Running a mailbox

| Document | Contents |
| --- | --- |
| [Quick start](server/quick-start.md) | One-command mailbox install on Ubuntu 26.04 |
| [Deployment](server/deployment.md) | Host, Tor onion service and mailbox setup |
| [Operations](server/operations.md) | Monitoring, backup and restore, key handling, retirement, incidents |
| [Public mailbox list](../MAILBOXES.md) | Mailboxes offered to anyone, and how to add yours |
| [Development mailbox](../scripts/deployment/ONION-DEVELOPMENT.md) | A local Tor mailbox for testing |

## Developing Najwa

| Document | Contents |
| --- | --- |
| [Architecture](development/architecture.md) | Crates, data flow, lifecycle and the spec-to-code map |
| [Building](development/building.md) | Prerequisites, build and packaging commands |
| [Testing](development/testing.md) | Test levels and how to run them |
| [Contributing](../CONTRIBUTING.md) | How to propose changes |
