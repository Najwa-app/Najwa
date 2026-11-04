# Changelog

Versions follow the workspace version in `Cargo.toml`. Protocol and storage
format versions are listed separately in the
[specification index](docs/SPECS-VERSION.md#format-versions).

## 0.1.0 — 2026-10-29 (public beta)

First public beta. See [release status](RELEASE-READINESS.md) for platform
support, validation and known limitations.

### App

- Native local service that serves the interface to your browser on
  `127.0.0.1:1421`, with Tor built in. Packages for Windows and Linux (x64),
  and an untested preview for macOS (Apple silicon and Intel), each with a
  SHA-256 file, built by CI and attached to the GitHub release.
- Identity protected by a passphrase (at least 12 characters and hard to guess)
  and a hardware device factor: TPM 2.0 on Windows and Linux, Secure Enclave on
  macOS. OS key storage only after explicit, per-identity approval.
- Recovery kit of 24 words and an encrypted recovery file; passphrase change;
  recovery after a forgotten passphrase.
- Automatic lock after 5 minutes of inactivity (adjustable from 1 to 60 minutes),
  lock on page close and when the computer locks, switches user or sleeps,
  **Keep unlocked** for long transfers, and **Quit Najwa**.
- Local profile erasure.

### Contacts and messaging

- Signed invitations as a link or QR code, valid for 48 hours; safety-number
  verification; local rename, block and unblock; delete, which also sends an
  encrypted notice that removes the conversation from the other person's Najwa.
- End-to-end encryption with X3DH and the Double Ratchet.
- Up to eight mailboxes with a selectable primary; durable send queue across
  restarts, automatic retries, and queued, deposited, delivered and read states.
- Message search, quoted replies, read receipts and per-conversation
  disappearing-message timers.
- Sanitized file transfer in resumable parts, up to 256 MiB; images are
  re-encoded as WebP; lost parts are requested again. Files of 10 MB or less
  are recommended.
- Delivery modes: Responsive (default) and Timing privacy, with cover traffic.
  Tor bridges with bundled pluggable transports.

### Mailbox server

- `najwa-mailbox`: capability-based store-and-forward server for Tor onion
  services, with proof of work, quotas, configurable release timing and a 90-day
  retention cap. Docker and systemd deployment files.
- One-command installer for Ubuntu 26.04 that hardens the server and sets up
  Tor, the keys and the service, with a 15-minute quick start.
- A public list of mailboxes ([MAILBOXES.md](MAILBOXES.md)) that operators add to
  by pull request; the project's beta mailbox is the first entry.

### Compatibility with earlier preview builds

- **Update mailboxes and apps together.** Prekey upload now requires the
  queue's fetch capability; an older app cannot refresh its prekeys on an
  updated mailbox.
- **Mailbox configuration.** `batching.enabled`, `logging.directory` and
  `logging.rotate_days` are removed, and unknown keys are refused: delete those
  lines before upgrading. A missing configuration file is an error.
- **Mailbox files.** The systemd unit now sets `UMask=0077`. On an existing
  install, run `chmod 0600 /var/lib/najwa-mailbox/mailbox.db*` once.
- **Operator attestation.** The signed format is now
  `najwa-operator-attestation-v2` with length-prefixed fields.
- **C ABI.** Message status `5` means retrying; `4` means failed after retries.
- **Profiles.** Existing profiles gain new tables and columns automatically on
  open; the schema version stays 2. New passphrases must pass the strength check;
  existing passphrases still unlock.

### Documentation

- Protocol specifications S01–S18 with conformance checklists and test vectors,
  plus registries of wire formats, message types, key-derivation labels and keys.
- User, operator, developer and security guides.
