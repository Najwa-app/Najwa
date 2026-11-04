# Glossary

Terms used across the Najwa documentation. Each entry is a short definition with
a pointer to the section that specifies it; the spec is normative where the two
differ.

## A

**AAD (associated authenticated data).** Data an AEAD authenticates without
encrypting. Najwa binds each ciphertext to its context this way: the message AAD
is the session's associated data followed by the WireMessage prefix
([S07 §2.3](../specs/07-message-format.md)); the deposit-envelope AAD is the
[cap hint](#c).

**Absorption.** Real traffic (messages, acknowledgements, receipts) takes the
place of a scheduled cover slot instead of adding traffic on top of it, under
[Timing privacy](#d). [S10 §6](../specs/10-cover-traffic.md).

**AEAD.** Authenticated encryption with associated data. Najwa uses
XChaCha20-Poly1305 everywhere. [S01 §2](../specs/01-crypto-primitives.md).

**Argon2id.** The memory-hard function that derives a key from the passphrase.
The app targets 512 MiB, halving down to a 64 MiB floor on smaller machines, and
calibrates iterations to at least one second.
[S02 §6](../specs/02-identity-key-protection.md).

**Auto-lock.** The service locks the identity after a period without activity:
5 minutes by default, adjustable from 1 to 60 minutes. Closing the page also
requests a lock. [S13](../specs/13-privacy-hardening.md).

## B

**BIP-39.** The word list used to write down the recovery seed. The app
generates 24 words. See [recovery kit](#r). [S02 §13](../specs/02-identity-key-protection.md).

**Bridge.** An unlisted Tor entry relay, optionally behind a pluggable transport,
for networks that block Tor. Up to eight bridge lines can be configured.
[S04 §11](../specs/04-transport.md).

## C

**Capability.** A random 32-byte bearer token that grants one kind of access to
a mailbox. A *deposit capability* lets the holder store blobs in a queue; the
matching *fetch capability* lets the owner retrieve them. The server stores
capabilities but associates no identity with them.
[S16 §2.1](../specs/16-mailbox-server.md).

**Cap hint.** `SHA-256(deposit capability)[0..8]`. It labels fetched blobs so the
receiver can find the right envelope secret quickly, and it is the AAD of the
deposit envelope. [S07 §3](../specs/07-message-format.md#3-envelope-aad--cap-hint).

**Circuit isolation.** Using separate Tor circuits for unrelated operations, so
a relay or mailbox cannot link them by circuit. [S04 §4](../specs/04-transport.md).

**Cover traffic.** Envelope-wrapped random blobs, the same sizes as real
deposits, deposited to dedicated cover capabilities at randomized (exponential)
intervals, together with cover polls. It makes real activity harder to pick out;
it does not defeat a global observer. [S10](../specs/10-cover-traffic.md).

**CumulativeAck.** The acknowledgement message (`message_type 0x12`). It lists
the ranges of message numbers the receiver has decrypted and stored.
[S07 §8.1](../specs/07-message-format.md).

## D

**Delivery mode.** *Responsive* (default) deposits real messages immediately.
*Timing privacy* makes them wait for a cover deposit slot and uses a fresh circuit
for each file part; it is slower. [S10 §14](../specs/10-cover-traffic.md).

**Deposit.** Storing an encrypted blob in a contact's mailbox queue. A message is
*deposited* when the mailbox accepts it; the sender may then close the app.
[S08 §5.2](../specs/08-messaging-service.md).

**Deposit envelope.** The outer encryption layer around every deposited blob.
Its key is derived from the queue's [envelope secret](#e), which the mailbox never
receives, so the operator cannot open it or tell real messages from cover.
[S07 §3](../specs/07-message-format.md).

**Device factor (DKM).** 32 bytes of device key material, sealed by the TPM
(Windows, Linux) or Secure Enclave (macOS), or by OS key storage after explicit
approval. Together with the passphrase it forms the 2-of-2 protection of the
identity key. [S02 §17](../specs/02-identity-key-protection.md).

**DH ratchet.** The Diffie-Hellman half of the Double Ratchet. Each change of
speaker introduces fresh DH output, which gives
[post-compromise security](#p). [S06 §3.6](../specs/06-key-agreement-ratchet.md).

**Double Ratchet.** The session algorithm after X3DH: a symmetric chain ratchet
derives a new key per message, and a DH ratchet refreshes the chains.
[S06 §3](../specs/06-key-agreement-ratchet.md).

## E

**Ed25519.** The signature scheme for identity keys, per-mailbox keys,
certificates and prekey signatures. [S01 §2](../specs/01-crypto-primitives.md).

**Envelope secret.** A 32-byte secret per receive queue, shared with contacts
alongside the deposit capability but never sent to the mailbox. It keys the
[deposit envelope](#d). [S07 §3](../specs/07-message-format.md).

**Ephemeral key (disappearing messages).** A random per-message key that
encrypts the stored content of a disappearing message. Destroying it at expiry
makes the stored ciphertext unreadable. [S12 §4](../specs/12-disappearing-messages.md).

**Ephemeral key pair (X3DH).** A fresh X25519 pair the initiator creates for one
X3DH run and then discards. [S06 §2.2](../specs/06-key-agreement-ratchet.md).

**Epoch link.** The 32-byte field at offset 40 of the ratchet header: the
sender's previous sending-epoch DH public key, or zeros if there is none. It lets
a receiver detect a missed epoch. [S06 §3.9](../specs/06-key-agreement-ratchet.md),
[S07 §2.2](../specs/07-message-format.md).

## F

**Forward secrecy.** Compromise of current keys does not reveal earlier
messages, because message keys and used one-time prekeys are deleted.
[S06](../specs/06-key-agreement-ratchet.md). Locally stored history is a
separate matter; see the [threat model](../understanding/threat-model.md).

## G

**Gap repair.** Recovery of messages a receiver knows it missed: a
`GapRepairRequest` (`0x36`) is answered with a `GapRepairBundle` (`0x38`) or
`GapRepairUnavailable` (`0x37`). [S07 §8.5](../specs/07-message-format.md),
[S08 §6.5](../specs/08-messaging-service.md).

## H

**Handshake payload.** The signed structure inside an invitation: identity key,
mailbox entries with certificates, invitation deposit capabilities and envelope
secrets, display name and expiry. Version `0x02`, 116 to 2,048 bytes. Prekeys are
not included; they are fetched from the mailbox.
[S05 §2](../specs/05-contact-establishment.md).

**HKDF.** HKDF-SHA256 (RFC 5869), used for all key derivation. Every label is in
the [HKDF registry](hkdf-strings.md). [S01 §3](../specs/01-crypto-primitives.md).

## I

**Identity key (IK).** The Ed25519 key pair that is a user's identity. The private
key never leaves the device except inside the recovery kit.
[S02 §2](../specs/02-identity-key-protection.md).

**Identity record.** The 192-byte file holding the encrypted identity key:
magic `NAJWA\0\0\0`, version `0x03`, Argon2id parameters, salt, nonce, ciphertext
and checksum. [S02 §7](../specs/02-identity-key-protection.md).

**Invitation.** A signed handshake payload shared as a `najwa://contact?data=`
link or as a QR code (prefix `NAJWA:`, zlib and Base45, with a CRC-32). Its
receive queue lasts 48 hours. Use one invitation per contact.
[S05 §5–§7](../specs/05-contact-establishment.md).

## K

**KEK (key-encryption key).** The key that encrypts the identity key, derived
from the Argon2id passphrase output and the device factor.
[S02 §4](../specs/02-identity-key-protection.md).

**Key inventory.** Every key and secret, with how it is made, stored and erased:
[Keys](keys.md).

## L

**Logical message ID.** A 16-byte ID derived from both identity keys, the
timestamp, a per-contact sequence number, the content type and the content. It
stays the same when a message is re-encrypted, which makes deduplication work
across repair. [S07 §6.2](../specs/07-message-format.md).

## M

**Mailbox.** A store-and-forward server (`najwa-mailbox`) reachable as a Tor v3
onion service. It holds encrypted blobs per capability until the owner fetches
and acknowledges them, and deletes them after at most 90 days. A profile can use
up to eight mailboxes. [S16](../specs/16-mailbox-server.md).

**Mailbox certificate.** A 200-byte certificate in which the identity key signs a
[per-mailbox signing key](#p), so contacts can check that prekeys on that mailbox
belong to the identity. [S05 §2.3](../specs/05-contact-establishment.md).

**Message key.** A single-use key from the chain ratchet that encrypts exactly
one message. [S06 §3.3](../specs/06-key-agreement-ratchet.md).

**msg_id.** The 16-byte transport message ID, derived from the final ratchet
header and a hash of the content. It changes when a message is re-encrypted.
Compare [logical message ID](#l). [S07 §6.1](../specs/07-message-format.md).

## O

**One-time prekey (OPK).** A single-use X25519 public key on the mailbox, consumed
by one X3DH run. The app keeps up to 200 per receive queue and tops up below 50.
[S06 §2.5](../specs/06-key-agreement-ratchet.md).

**Operator attestation.** A statement signed with the mailbox operator's key and
served at `/v1/attestation`. It is self-reported.
[S16 §3.10](../specs/16-mailbox-server.md).

## P

**Padding bucket.** One of 11 fixed sizes, from 256 to 262,144 bytes, that every
deposited blob is padded to exactly. [S07 §5](../specs/07-message-format.md).

**Pairwise pseudonym.** A 32-byte identifier unique to one contact relationship,
carried inside encrypted payloads. It differs per relationship, so it does not
link a user across contacts. [S01 §8.2](../specs/01-crypto-primitives.md).

**Per-mailbox signing key.** An Ed25519 key derived from the identity key and the
mailbox's onion address. Each mailbox sees a different key, so colluding operators
cannot link a user by key. [S05 §3](../specs/05-contact-establishment.md).

**Post-compromise security.** After a key compromise ends, new DH ratchet steps
restore confidentiality without user action.
[S06 §3](../specs/06-key-agreement-ratchet.md).

**Prekey bundle.** The public keys a mailbox serves for X3DH: the per-mailbox
signing key, a signed prekey with its signature, one-time prekeys, and a signed
manifest that lets clients detect withheld one-time prekeys.
[S06 §4](../specs/06-key-agreement-ratchet.md).

**Primary mailbox.** The mailbox listed first in new invitations. Changing it
does not change invitations already shared.
[S08 §9.5](../specs/08-messaging-service.md).

**Profile.** The local directory holding one identity's records and encrypted
database. [S03 §11](../specs/03-encrypted-storage.md).

**Proof of work.** SHA-256 puzzles, counted in leading zero bits, that a mailbox
requires for every registration, every deposit to an invitation queue, and other
deposits above a per-capability rate. [S16 §7](../specs/16-mailbox-server.md).

## R

**Ratchet header.** The 72-byte header of each WireMessage: the sender's DH public
key, previous chain length, message number and [epoch link](#e). It is
authenticated, not encrypted, and the deposit envelope hides it from the mailbox.
[S07 §2.2](../specs/07-message-format.md).

**Read receipt.** A `message_type 0x11` message sent when a message has been shown
in the focused conversation. [S07 §8.2](../specs/07-message-format.md).

**Recovery kit.** 24 recovery words plus a 105-byte encrypted recovery file. Both
are needed to restore the identity on another device or after losing the device
factor. The kit does not contain contacts or messages.
[S02 §13](../specs/02-identity-key-protection.md).

**Responsive.** The default [delivery mode](#d).

**Root key.** The top key of the Double Ratchet state, advanced at each DH
ratchet step. [S06 §3](../specs/06-key-agreement-ratchet.md).

## S

**Safety number.** 32 hex characters in 8 groups of 4, from the SHA-256 of both
sorted identity keys. Both parties see the same value; comparing it through a
trusted channel detects a substituted key.
[S05 §9](../specs/05-contact-establishment.md).

**Session repair.** Re-establishing a broken ratchet session with a fresh X3DH
exchange (`SessionRepairInit`). [S06 §3.7.1](../specs/06-key-agreement-ratchet.md).

**Signed prekey (SPK).** A medium-term X25519 key signed by the per-mailbox key,
rotated every 7 days and accepted for 14 more.
[S06 §5](../specs/06-key-agreement-ratchet.md).

**Skipped message key.** A key kept for a message that has not arrived yet, so it
can be decrypted out of order: at most 1,000 per chain step and 4,000 per
session, expiring after 90 days. [S06 §3.7](../specs/06-key-agreement-ratchet.md).

**SQLCipher.** The encrypted SQLite build that stores the local database.
[S03](../specs/03-encrypted-storage.md).

## T

**Timing privacy.** The paced [delivery mode](#d).

**Tor.** The anonymity network all Najwa traffic uses. The app embeds the Arti
client; mailboxes are v3 onion services. [S04](../specs/04-transport.md).

## W

**WireMessage.** The encrypted message format: version `0x01`, message type,
reserved bytes, payload length, an X3DH header for `0x01 Initial` messages, the
ratchet header and the AEAD payload. It is wrapped in a deposit envelope before
deposit. [S07 §2](../specs/07-message-format.md).

## X

**X25519.** The Diffie-Hellman function used by X3DH, the DH ratchet and pairwise
pseudonyms. [S01 §2](../specs/01-crypto-primitives.md).

**X3DH.** The initial key agreement: three or four DH computations over identity,
signed prekey, ephemeral and optional one-time keys produce the secret that starts
the Double Ratchet. [S06 §2](../specs/06-key-agreement-ratchet.md).

**XChaCha20-Poly1305.** Najwa's AEAD: 32-byte key, 24-byte nonce, 16-byte tag.
[S01 §2](../specs/01-crypto-primitives.md).
