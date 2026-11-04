# Security properties

This document lists the security properties of the desktop release. Each entry
states the property, the mechanism that provides it, the assumptions it needs,
its limits, and the specification section that defines it. The
[threat model](../understanding/threat-model.md) describes the adversaries and
non-goals; read the two together. Najwa has not had an independent security
audit.

## Global assumptions

Every property below assumes:

- an authentic build (see [supply chain](supply-chain.md));
- no adversary controls the computer, the browser or its extensions while the
  profile is unlocked;
- Ed25519, X25519, XChaCha20-Poly1305, HKDF-SHA256, SHA-256, HMAC-SHA256 and
  Argon2id meet their security goals (see [cryptographic rationale](crypto-rationale.md)
  and [S01 §2](../specs/01-crypto-primitives.md));
- Tor onion services provide location hiding and self-authenticating addresses.

Properties that depend on more say so.

## End-to-end message protection

### Confidentiality

- **Property.** Only the two endpoints of a session can read a message.
- **Mechanism.** X3DH establishes the session; the Double Ratchet derives a
  fresh message key for every message; content is encrypted with
  XChaCha20-Poly1305. The algorithm suite is fixed, with no negotiation.
- **Assumptions.** The contact's identity key belongs to the intended person
  (see [Contact authentication](#contact-authentication)).
- **Limits.** An endpoint that is compromised while unlocked exposes plaintext.
  Message history stored on either computer is readable to anyone who unlocks
  that profile.
- **Defined in.** [S06 §2–§3](../specs/06-key-agreement-ratchet.md),
  [S07 §2](../specs/07-message-format.md).

### Integrity and context binding

- **Property.** A modified, truncated or re-targeted message is rejected.
- **Mechanism.** AEAD over the payload, with the wire header, ratchet header
  and session associated data bound as additional data. The deposit envelope is
  a second AEAD layer.
- **Limits.** Parser and state-machine correctness remain part of the attack
  surface.
- **Defined in.** [S07 §2.3](../specs/07-message-format.md),
  [S07 §3](../specs/07-message-format.md).

### Forward secrecy

- **Property.** Capturing a session's current state does not decrypt messages
  that were sent earlier and already processed.
- **Mechanism.** Symmetric chain keys advance after every message and message
  keys are deleted after use. Keys kept for out-of-order messages are bounded
  (1,000 skipped keys per chain, 4,000 per session) and expire.
- **Limits.** Retained skipped keys can decrypt the messages they were kept for.
  Forward secrecy covers captured traffic, not the stored conversation history.
- **Defined in.** [S06 §3.3–§3.8](../specs/06-key-agreement-ratchet.md).

### Post-compromise recovery

- **Property.** After a passive attacker loses access to a session's state,
  messages sent after the next round trip are secure again.
- **Mechanism.** A Diffie-Hellman ratchet step with fresh key pairs whenever
  the speaking direction changes.
- **Assumptions.** The attacker does not keep access to the endpoint and does
  not alter traffic in the meantime.
- **Defined in.** [S06 §3.6](../specs/06-key-agreement-ratchet.md).

### Replay and duplicate rejection

- **Property.** A captured or redelivered message is not processed twice.
- **Mechanism.** Deterministic message IDs, a persistent deduplication cache,
  and a timestamp window of 90 days in the past and 5 minutes in the future.
- **Defined in.** [S07 §6–§7](../specs/07-message-format.md).

### Length hiding

- **Property.** Mailboxes and observers see a blob's size bucket, not its exact
  length.
- **Mechanism.** Every deposited blob is padded to one of eleven sizes from
  256 bytes to 256 KiB.
- **Limits.** The bucket and the number of blobs still show roughly how much
  was sent; a file is visible as many parts.
- **Defined in.** [S07 §5](../specs/07-message-format.md).

## Contact establishment

### Invitation authenticity

- **Property.** An invitation that verifies was created by the holder of the
  identity key it names, has not been altered, and has not expired.
- **Mechanism.** An Ed25519 signature over the payload with a domain-separation
  prefix, an expiry check, and an identity-key signature on each mailbox
  certificate that binds a mailbox-specific key to the identity.
- **Limits.** A valid signature does not show that the key belongs to the
  intended person.
- **Defined in.** [S05 §2, §4](../specs/05-contact-establishment.md).

### Contact authentication

- **Property.** Two users who compare safety numbers over an independent
  channel can detect a substituted invitation.
- **Mechanism.** The safety number is the first 16 bytes of SHA-256 over both
  identity public keys in sorted order, shown as eight groups of four
  hexadecimal digits. The user marks the contact verified after comparing; the
  app shows the verification state.
- **Assumptions.** The comparison channel is not controlled by the attacker.
- **Limits.** Until the numbers are compared, the contact is authenticated only
  to whoever supplied the invitation.
- **Defined in.** [S05 §9](../specs/05-contact-establishment.md).

### Prekey integrity and downgrade detection

- **Property.** A mailbox cannot substitute prekeys or silently force a weaker
  key agreement by withholding one-time prekeys.
- **Mechanism.** The bundle's key must equal the mailbox-specific key from the
  invitation. The signed prekey and a signed manifest of the one-time prekey
  pool are verified against that key, and a bundle without a manifest is
  rejected. Prekey fetches on an invitation capability are idempotent.
- **Limits.** The mailbox can still refuse to serve the bundle.
- **Defined in.** [S06 §2.2, §2.5, §4.2](../specs/06-key-agreement-ratchet.md),
  [S16 §3.6–§3.7](../specs/16-mailbox-server.md).

### Single-use invitation capability

- **Property.** One invitation capability establishes at most one contact.
- **Mechanism.** The creator's app processes the first valid introduction on a
  one-time capability, discards later ones, and deactivates the capability. The
  server expires it after 48 hours.
- **Limits.** Anyone holding the invitation can use it before the intended
  person does. Each exported invitation has its own capability; the app reuses
  one only for a retry of a request that failed before export.
- **Defined in.** [S05 §5](../specs/05-contact-establishment.md),
  [S16 §2.2–§2.3](../specs/16-mailbox-server.md).

## Mailboxes and network

### Mailbox content-blindness

- **Property.** A mailbox operator cannot decrypt stored blobs.
- **Mechanism.** Each blob is wrapped in an envelope keyed from an envelope
  secret that is shared only with the depositor and never registered with the
  server, around the end-to-end encrypted message.
- **Limits.** Whoever holds a deposit capability and its envelope secret, such
  as the holder of an unused invitation, can deposit.
- **Defined in.** [S07 §3](../specs/07-message-format.md).

### Account-free addressing

- **Property.** A mailbox learns no identity key, name or account.
- **Mechanism.** Mailboxes address storage by random 32-byte deposit and fetch
  capabilities. Registration carries the capabilities, a proof of work and
  settings, nothing more.
- **Limits.** The operator sees the capability pairs, their types and how they
  are used (see the [threat model](../understanding/threat-model.md#4-mailbox-operator)).
- **Defined in.** [S16 §2](../specs/16-mailbox-server.md).

### Cross-mailbox key unlinkability

- **Property.** Operators of different mailboxes cannot link one user's
  registrations by key.
- **Mechanism.** At each mailbox the app signs with a key derived by HKDF from
  the identity key and the mailbox's onion address. Capabilities are
  independent random values.
- **Limits.** Timing and volume correlation across mailboxes remain possible.
- **Defined in.** [S05 §3](../specs/05-contact-establishment.md),
  [S02 §2.2](../specs/02-identity-key-protection.md).

### Network location hiding

- **Property.** Neither the mailbox nor the contact learns the user's network
  address, and network observers do not learn which mailboxes are used.
- **Mechanism.** All mailbox traffic uses Tor onion services through the
  embedded Arti client. The transport rejects any destination that is not a v3
  onion address, so there is no clearnet fallback. Circuits are isolated by
  purpose: one-shot circuits for deposits (cover deposits included), per-mailbox
  circuits for polling, per-mailbox cover circuits for cover polling. Bridges
  (plain, obfs4, Snowflake) are supported, and Najwa never switches back to
  direct Tor on its own.
- **Limits.** Tor's own limits apply, including correlation by an observer of
  both ends. In Responsive mode the parts of one file share one circuit.
- **Defined in.** [S04 §2, §4, §5.4, §6, §11](../specs/04-transport.md).

### Send-timing protection

- **Property.** In Timing privacy mode, the deposit rate does not change with
  user activity while the cover scheduler runs.
- **Mechanism.** The cover scheduler emits deposits on a randomized schedule
  (about one every 30 seconds by default). A real deposit waits for the next
  slot and replaces the cover deposit. Cover traffic continues while the
  profile is locked.
- **Limits.** Responsive mode, the default, deposits immediately. If the
  scheduler is not running, sends go out at once in either mode. Polling of
  real capabilities is not paced in either mode and stops while locked. The
  shipped mailbox configuration has no release hold.
- **Defined in.** [S10 §6, §11](../specs/10-cover-traffic.md),
  [S16 §6](../specs/16-mailbox-server.md).

### Mailbox abuse resistance

- **Property.** Registration, deposit and prekey flooding cost the attacker
  work and are bounded per capability.
- **Mechanism.** Proof of work of at least 20 bits for registration, adaptive
  proof of work for deposits and prekey fetches, per-capability rate limits,
  storage quotas and a 256 KiB blob limit. Clients also limit incoming messages
  per contact.
- **Limits.** A resourced attacker can still exhaust a server, and an operator
  can refuse service.
- **Defined in.** [S16 §7–§9](../specs/16-mailbox-server.md),
  [S08 §8.2](../specs/08-messaging-service.md).

### Bounded retention on compliant servers

- **Property.** A compliant mailbox does not keep blobs indefinitely.
- **Mechanism.** Acknowledged blobs are deleted at once. Fetched but
  unacknowledged blobs expire after the operator's retention period (14 days by
  default). Unfetched blobs expire after 90 days at most. Capabilities unused
  for 30 days are deleted with their blobs.
- **Assumptions.** The operator runs unmodified server code. Nothing stops a
  malicious operator from keeping copies.
- **Defined in.** [S16 §10](../specs/16-mailbox-server.md).

## Local protection

### Identity key at rest

- **Property.** The identity key cannot be recovered from the profile without
  both the passphrase and the device factor.
- **Mechanism.** A key-encryption key is derived with HKDF from an Argon2id hash
  of the passphrase and a 32-byte device factor. The device factor is wrapped by
  the TPM 2.0 (Windows, Linux) or the Secure Enclave (macOS). OS key storage is
  used only after explicit, per-identity user approval, and the app shows when
  it is in use.
- **Assumptions.** The passphrase has adequate entropy; at least 12 characters
  are enforced.
- **Limits.** With approved OS key storage, an attacker with access to the OS
  account can extract the device factor and guess the passphrase offline at
  Argon2id cost.
- **Defined in.** [S02 §3, §4, §6, §17](../specs/02-identity-key-protection.md).

### Online guessing resistance

- **Property.** Passphrase guessing on the device is slow and bounded.
- **Mechanism.** Unlock attempts back off exponentially; ten consecutive
  failures lock the profile out. The attempt counter is stored with an
  HMAC keyed by the device factor, and a missing or tampered counter counts as
  locked out. The counter resets 24 hours after the last attempt. All failure
  causes return the same error.
- **Defined in.** [S02 §9–§11](../specs/02-identity-key-protection.md).

### Recovery

- **Property.** A user who holds both parts of the recovery kit can restore the
  identity without the passphrase or the device.
- **Mechanism.** 24 BIP-39 words derive the key that decrypts a 105-byte
  recovery record holding the identity key. On the original profile the words
  alone suffice, because the record is stored there.
- **Limits.** A complete kit is as powerful as the identity itself. Replacing
  the kit does not revoke an earlier complete kit. Recovery restores the
  identity, not contacts or history.
- **Defined in.** [S02 §13](../specs/02-identity-key-protection.md).

### Local database encryption

- **Property.** Contacts, sessions and messages on disk are unreadable without
  the unlocked identity.
- **Mechanism.** SQLCipher with a key derived from the identity key, plus
  per-field encryption of sensitive columns. The app refuses a main database
  file with a plaintext SQLite header.
- **Defined in.** [S02 §4.2](../specs/02-identity-key-protection.md),
  [S03 §2–§4, §7](../specs/03-encrypted-storage.md).

### Local service access control

- **Property.** Only browser pages served by the local service, holding its
  per-run token, can call its API.
- **Mechanism.** The service binds to `127.0.0.1` and checks the exact `Host`,
  the `Origin` and `Sec-Fetch-Site` headers, a 32-byte session token and, for
  every POST, the content type. Responses carry a restrictive Content Security
  Policy and frame denial. A browser receives the token through a launch link,
  or through a 30-day cookie limited to the bootstrap endpoint. Neither unlocks
  the profile. On Linux the profile directory is mode `0700`.
- **Limits.** Software running as the same OS user can read the token from the
  profile and act through the API while the profile is unlocked.
- **Defined in.** [Local web service](../../apps/local-web/README.md),
  [desktop client](../../crates/najwa-ffi/DESKTOP.md).

### Locking and key zeroization

- **Property.** A locked profile holds no identity, session or database keys in
  memory.
- **Mechanism.** Lock cancels running operations, persists disappearing-message
  keys encrypted, closes the database, and zeroizes the identity key, ratchet
  state and database key. The service locks after the idle limit (5 minutes by
  default, 1 to 60 minutes), when the page closes, and when the OS locks the
  session, switches user or sleeps, and enforces the idle limit itself. If lock
  cannot confirm that key handles are cleared, the app reports an error state
  instead of locked.
- **Limits.** Cover traffic keeps running while locked. The OS lock is best
  effort: a sleep that starts before the lock finishes keeps the keys in memory
  until wake, and a Linux desktop that sends no lock signal is not observed.
  Plaintext already shown in the browser is outside the service's control.
- **Defined in.** [S13 §8](../specs/13-privacy-hardening.md),
  [S01 §6.1](../specs/01-crypto-primitives.md).

### Durable delivery

- **Property.** Restarts and lost responses do not reuse a message key, lose a
  received message or show a message twice.
- **Mechanism.** The message, the new ratchet state and the queued encrypted
  frame commit in one transaction before any network send. A received message
  and its state commit in one transaction before the mailbox is told to delete
  it. Transport and logical deduplication are separate.
- **Limits.** **Deposited** means the mailbox accepted the blob. A server
  accepts deposits to unknown or deleted capabilities in the same way and
  stores nothing.
- **Defined in.** [S06 §3.11](../specs/06-key-agreement-ratchet.md),
  [S08 §5, §6.3](../specs/08-messaging-service.md),
  [S07 §8.1](../specs/07-message-format.md).

### Local erasure

- **Property.** After erasure, the profile's identity and data cannot be
  recovered with the passphrase or the device factor.
- **Mechanism.** A durable marker is written first. The service then deletes
  the device factor from the TPM or OS key storage and overwrites and deletes
  the profile files. An interrupted erasure blocks unlock until it completes.
- **Limits.** Overwriting is best effort on SSDs and copy-on-write file systems.
  Exported recovery kits, downloads, OS backups, mailbox copies and contacts'
  copies are untouched. Mailbox capabilities are deactivated only when erasing
  an unlocked profile, best effort within 20 s; mailboxes that could not be
  reached, and all of them for a locked profile, keep accepting deposits.
- **Defined in.** [S13 §11](../specs/13-privacy-hardening.md),
  [S02 §17.6](../specs/02-identity-key-protection.md).

## Content handling

### File sanitization

- **Property.** Files leave the sender's computer without embedded metadata.
- **Mechanism.** The type is detected from magic bytes, not the file name.
  JPEG, PNG, GIF, BMP and TIFF images are decoded and re-encoded as WebP, which
  discards their containers. WebP, MP4, MOV, MP3, FLAC and WAV are rewritten by
  streaming cleaners. PDF, DOCX, ODT and OGG are cleaned in memory, and the
  in-memory path ends with a verification pass. Unknown types and HEIC are
  refused. File names are sanitized.
- **Limits.** Visible content is unchanged. Sanitization runs on the sender's
  side; the receiver checks size and SHA-256 integrity but does not re-check
  for metadata, so a modified sender can deliver anything. Decoders for complex
  formats remain an attack surface.
- **Defined in.** [S11 §2.5, §5–§8](../specs/11-file-transfer-sanitization.md).

### Disappearing messages

- **Property.** Cooperating apps delete timed messages from local storage after
  the timer.
- **Mechanism.** A per-conversation timer of at least 30 seconds, synchronized
  by an encrypted control message; sending pauses until the contact
  acknowledges a change. Sent messages count from delivery, received messages
  from display. Content is protected by volatile keys that are destroyed at
  expiry, and a background task deletes expired rows.
- **Limits.** A modified or hostile peer can keep anything. Screenshots and
  copies are out of reach. Deletion on SSDs is best effort.
- **Defined in.** [S12 §2–§6](../specs/12-disappearing-messages.md).

## Limitations

These gaps apply to this release in addition to the per-property limits:

- **Contact-route counting.** The app polls all of its capabilities on a mailbox
  together, over one circuit, with no dummy capabilities. The operator can
  therefore count a user's contact routes on that mailbox and see when the app
  is unlocked.
- **Receiver-side file checks.** Received files are not checked for metadata
  before download.
- **Read receipts.** They are always sent and cannot be disabled.
- **Invitation slot sharing.** Invitations created before the first is answered
  share one single-use capability.
- **No recall or revocation.** Sent messages and complete recovery kits cannot
  be revoked.
- **Classical cryptography only.** Nothing is protected against a future
  quantum adversary.

## How to review

Check the fixed-input vectors in [S18](../specs/18-test-vectors.md), the
domain-separation labels in [HKDF strings](../reference/hkdf-strings.md), the
byte layouts in [wire formats](../reference/wire-formats.md), and the key
lifecycle in the [key inventory](../reference/keys.md). Exercise parser bounds,
transaction boundaries, lock cancellation and restart. Verify the final
artifact against [supply chain](supply-chain.md), and read the
[dependency assessment](dependencies.md) and [testing guide](../development/testing.md).
