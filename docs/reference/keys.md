# Key Inventory

This page lists every key and secret the release creates or holds: what it is,
how it is made, where it lives, how long it lives and when it is erased. The
derivations are defined in [S01 §8.1](../specs/01-crypto-primitives.md), and the
exact label bytes are in the [label registry](hkdf-strings.md). Each entry links
to the spec section that owns the key.

"Profile directory" is the per-profile data directory of the local service.
"Locked" means the identity is not unlocked: the service holds no identity
seed, no database key and no session keys in memory. While locked it still holds
what cover traffic and fetch-only polling need: the onion address of each
mailbox, the fetch capabilities of the user's receive queues and dummy queues,
and the cover and dummy deposit capabilities with the cover envelope secret
([S13 §8.3](../specs/13-privacy-hardening.md), [S10 §11](../specs/10-cover-traffic.md)).

## Summary

| Key or secret | Size | Lifetime | At rest |
|---------------|------|----------|---------|
| [Identity seed](#identity-key) | 32 B Ed25519 seed | Life of the profile | Identity record, encrypted under the KEK; locked memory while unlocked |
| [`K_pwd`, KEK](#passphrase-derived-keys) | 32 B each | One unlock, create or password change | Never stored |
| [Device factor](#device-factor) | 32 B | One identity-record generation | OS key store, wrapped by TPM or Secure Enclave |
| [Recovery seed](#recovery-kit) | 32 B, 24 words | Until the user destroys the kit | Not stored by the app |
| [`K_recovery`](#recovery-kit) | 32 B | One create or recover operation | Never stored |
| [Database key](#database-key-and-field-keys) | 32 B | Life of the profile | Never stored; derived on unlock into locked memory |
| [Per-row field keys](#database-key-and-field-keys) | 32 B | One read or write | Never stored |
| [Per-mailbox signing key](#per-mailbox-signing-keys) | Ed25519 | While the mailbox is used | Never stored; derived on demand |
| [Signed prekey](#signed-prekeys) | X25519 | 7 days + 14-day grace | Database, field-encrypted |
| [One-time prekeys](#one-time-prekeys) | X25519 | Until used, then 7 days | Database, field-encrypted |
| [X3DH ephemeral](#x3dh-ephemeral-key-and-shared-secret) | X25519 | One session start; reused as the first ratchet key | Ratchet state |
| [X3DH shared secret `SK`](#x3dh-ephemeral-key-and-shared-secret) | 32 B | One session start | Never stored |
| [Root, chain and DH ratchet keys](#ratchet-keys) | 32 B each | Replaced every DH step or message | Database, field-encrypted |
| [Message keys](#message-keys-and-skipped-keys) | 32 B → 80 B | One message | Never stored |
| [Skipped message keys](#message-keys-and-skipped-keys) | 32 B | Until used or 90 days | Database |
| [Deposit and fetch capabilities](#mailbox-capabilities-and-envelope-secrets) | 32 B each | Until the contact or profile is removed | Database; also held by the mailbox; fetch capabilities also in memory while locked |
| [Envelope secret](#mailbox-capabilities-and-envelope-secrets) | 32 B | Same as its deposit capability | Database; never sent to a mailbox |
| [Envelope outer key](#mailbox-capabilities-and-envelope-secrets) | 32 B | One deposit or decrypt | Never stored |
| [Disappearing-message keys](#disappearing-message-keys) | 32 B | Until the message expires | Memory while unlocked; database, wrapped, while locked |
| [File-transfer secrets](#file-transfer-secrets) | 16–32 B | One transfer or download | Database |
| [Local service tokens](#local-service-tokens) | 32 B | One process, or 30 days | Profile directory files |
| [Mailbox server keys](#mailbox-server-keys) | Ed25519 | Operator-managed | Server files |

## Identity key

- **Algorithm and size.** Ed25519. The stored secret is the 32-byte seed
  (`IK_seed`); the 32-byte public key `IK_pub` is the user's identity.
- **Generated.** `IK_seed = CSPRNG(32)` when a profile is created. Recovery on a
  new device decrypts the same seed from the recovery record.
- **Stored.** Encrypted in the 192-byte identity record `identity.najwa` in the
  profile directory: `enc_ik = XChaCha20-Poly1305(KEK, nonce, IK_seed,
  AAD_identity)`, with a random 24-byte nonce and an 85-byte AAD that binds the
  record header, `salt_p` and `IK_pub`
  ([S02 §7.1, §8.1](../specs/02-identity-key-protection.md)). The record is
  replaced atomically.
- **Used for.** Signing the HandshakePayload and MailboxCertificates
  ([S05 §4](../specs/05-contact-establishment.md)); DH in X3DH and in pairwise
  pseudonyms through its X25519 form ([S01 §3.3, §8.2](../specs/01-crypto-primitives.md));
  deriving the database key and the per-mailbox signing keys.
- **In memory.** While unlocked, one copy in locked memory, shared by the
  identity manager, the messaging service and the local service
  ([S01 §6.2](../specs/01-crypto-primitives.md)). If the OS refuses the lock, it
  stays in pageable memory. Every derivation that copies the seed zeroizes the
  copy.
- **Lifetime and rotation.** The life of the profile. This release does not
  rotate its own identity key.
- **Erased.** Dropped and zeroized from memory on lock. The record is deleted by
  local profile erasure ([S13 §10](../specs/13-privacy-hardening.md)).

## Passphrase-derived keys

- **Algorithm and size.** `K_pwd`: Argon2id v1.3, 32 bytes. KEK: HKDF-SHA256,
  32 bytes.
- **Derived.**
  `K_pwd = Argon2id(NFC(passphrase), salt_p, m, t, p)` with the 32-byte random
  `salt_p` and the calibrated parameters stored in the record;
  `KEK = HKDF(IKM = K_pwd, salt = DKM, info = "najwa/v1/kek", 32)`
  ([S02 §4.1](../specs/02-identity-key-protection.md),
  [S01 §3.8](../specs/01-crypto-primitives.md)).
- **Stored.** Never. Only `salt_p` and the Argon2 parameters are in the record.
- **Lifetime.** One create, unlock or password change. The parameters are
  calibrated when a record is created (512 MiB target, at least about one
  second per derivation) and kept across password changes.
- **Rotation.** A password change writes a new record with a new `salt_p` and
  nonce under the same device factor
  ([S02 §12](../specs/02-identity-key-protection.md)).
- **Erased.** The passphrase bytes after Argon2id; `K_pwd` and the HKDF PRK after
  KEK derivation; the KEK after the record is encrypted or decrypted.

## Device factor

- **Algorithm and size.** 32 random bytes (`DKM`), the second factor of the
  2-of-2 unlock ([S02 §3](../specs/02-identity-key-protection.md)).
- **Generated.** `CSPRNG(32)` for every new identity-record generation:
  profile creation and recovery. A password change keeps the existing value.
- **Stored.** In the OS key store, under a name derived from the record's salt:
  `Najwa/DKM/record/<hex(salt_p)>` ([S02 §17](../specs/02-identity-key-protection.md)).
  The release build requires hardware protection:
  - **Windows.** A Credential Manager entry holds `"NJWTPM01" ‖
    RSA-OAEP-SHA256(binding ‖ DKM)` under a non-exportable RSA-2048 key created
    in the TPM 2.0 by the Microsoft Platform Crypto Provider and named
    `Najwa.DKM.v2.<hex(SHA256(entry name))>`.
  - **Linux.** A Secret Service entry (service `com.najwa.identity`) holds the
    hex of `"NJWLTP01" ‖ len ‖ TPM public ‖ TPM private` for a TPM 2.0 sealed
    object containing `binding ‖ DKM`, reachable only through `/dev/tpmrm0`.
  - **macOS.** A Keychain entry holds `binding ‖ DKM` encrypted with ECIES to a
    Secure Enclave P-256 key tagged `com.najwa.identity.enclave.v2.` ‖
    `SHA256(entry name)`.
  - **Approved OS storage.** When no hardware key store works and the user
    explicitly approves software storage for this identity generation, the OS
    key store entry `Najwa/DKM/record/approved-software/<hex(salt_p)>` holds
    `"NJWAPR01" ‖ binding ‖ DKM` (72 bytes). The device factor is then protected
    only by the OS user account.

  Each `binding` is a 32-byte SHA-256 over a fixed label and the entry name (or,
  for approved storage, `salt_p ‖ IK_pub`), so a wrapped value cannot be moved
  to another entry ([registry §5](hkdf-strings.md#5-hash-and-mac-labels)).
- **Also keys.** The HMAC tags on the attempt counter
  (`identity.counter.<hex(salt_p)>`, label `attempt-counter`) and the stored
  Argon2 timing reference (`identity.timing.<hex(salt_p)>`, label
  `last-successful-argon-time`) ([S02 §9–§10](../specs/02-identity-key-protection.md)).
  A missing or invalid counter tag locks unlocking out.
- **Lifetime.** One identity-record generation. When a password change or
  recovery commits a new record, the previous generation's entry and TPM key
  are deleted.
- **Erased.** Zeroized in memory after each use. Deleted from the key store,
  together with its TPM or Secure Enclave key, when its generation is replaced
  and by local profile erasure.
- **Loss.** If the hardware key is lost (new TPM, reinstalled OS), the record
  cannot be unlocked. Approving software storage does not bypass a lost
  hardware factor. The recovery kit is the only way back.

## Recovery kit

- **Algorithm and size.** `recovery_seed`: 32 random bytes, shown as 24 BIP-39
  English words. `K_recovery`: HKDF-SHA256, 32 bytes. Recovery record: 105 bytes
  (`IK_pub ‖ nonce_recovery(24) ‖ enc_ik_recovery(48) ‖ phrase_length`).
- **Generated.** At profile creation, and again when the user replaces the kit.
  The recovery seed is independent of the identity seed.
  `K_recovery = HKDF(IKM = recovery_seed, salt = IK_pub, info =
  "najwa/v1/recovery", 32)` encrypts `IK_seed` with AAD
  `"najwa/v1/recovery" ‖ IK_pub` ([S02 §13](../specs/02-identity-key-protection.md)).
- **Stored.** The words are never written by the app. They stay in memory,
  zeroized on drop, until the user confirms they have saved them, the profile
  locks, or the operation is superseded. The record is stored as
  `identity.recovery` next to the identity record and can be exported as a file
  while the words are displayed.
- **Use.** On a new device, the user imports the record into an empty profile
  and enters the words. Recovery decrypts `IK_seed`, checks that it yields
  `IK_pub`, and creates a new identity record with a new passphrase, new device
  factor and fresh Argon2 calibration. It then requires a fresh signed prekey
  and one-time prekey pool before accepting Initial messages
  ([S02 §13.2](../specs/02-identity-key-protection.md)).
- **Lifetime and rotation.** The words and record are valid for as long as the
  identity exists. Replacing the kit overwrites `identity.recovery`; it does not
  revoke copies of an earlier kit. Any earlier record together with its words
  still recovers the identity.
- **Erased.** `recovery_seed`, `K_recovery` and the working copy of `IK_seed` are
  zeroized after each create or recover. `identity.recovery` is deleted by local
  profile erasure. Paper copies and exported files are outside the app's reach.

## Database key and field keys

- **Algorithm and size.** 32-byte keys from HKDF-SHA256.
- **Derived.**
  `db_key = HKDF(IKM = IK_seed, salt = "najwa-sqlcipher-key", info =
  "najwa/v1/sqlcipher-key", 32)` on every unlock
  ([S03 §3](../specs/03-encrypted-storage.md)). `db_key` is the SQLCipher raw
  key for `najwa.db` (passed as `x'<hex>'`, so SQLCipher applies no password
  KDF). Per-row field keys:
  `row_key = HKDF(IKM = db_key, salt = table name, info = row id (8 bytes BE), 32)`
  for the `ratchet_sessions` and `prekeys` tables
  ([S03 §7](../specs/03-encrypted-storage.md)).
- **Stored.** Never. While unlocked, `db_key` is held once, in locked memory
  shared by every database handle, and zeroized on drop
  ([S01 §6.2](../specs/01-crypto-primitives.md)). Row keys exist only for one
  read or write.
- **Protects.** The whole database (SQLCipher page encryption and
  authentication), plus a second AEAD layer (AAD `field`) on ratchet secrets and
  prekey private keys. It also wraps disappearing-message keys while locked.
- **Lifetime.** The database key changes only if the identity seed changes,
  which this release never does.
- **Erased.** On lock. Deleted rows are overwritten by SQLCipher
  (`secure_delete = ON`, [S03 §4.2](../specs/03-encrypted-storage.md)); the
  database file is removed by local profile erasure.

## Per-mailbox signing keys

- **Algorithm and size.** Ed25519.
- **Derived.** `seed = HKDF(IKM = IK_seed, salt = UTF8(onion_address), info =
  "najwa/v1/mailbox-signing-key", 32)`, then `Ed25519_Generate(seed)`
  ([S05 §3](../specs/05-contact-establishment.md)). Each mailbox sees a
  different, unlinkable public key.
- **Stored.** Never. It is derived again whenever it is needed.
- **Used for.** Signing signed prekeys and prekey manifests
  ([S06 §2.2, §4.2](../specs/06-key-agreement-ratchet.md)). The identity key
  signs a MailboxCertificate binding the derived public key to the identity for
  180 days ([S05 §4.2](../specs/05-contact-establishment.md)).
- **Lifetime.** As long as the identity uses that mailbox.
- **Erased.** The seed and key are zeroized after each use.

## Signed prekeys

- **Algorithm and size.** X25519 key pair; 4-byte random id.
- **Generated.** `CSPRNG` by the prekey manager, one per mailbox and receiving
  capability, signed with the per-mailbox signing key over
  `"najwa/v1/spk/" ‖ spk_pub ‖ spk_id ‖ timestamp`
  ([S06 §4.2, §5](../specs/06-key-agreement-ratchet.md)).
- **Stored.** Private key in the `prekeys` table, field-encrypted. Public key and
  signature uploaded to the mailbox.
- **Lifetime and rotation.** Rotated every 7 days. The previous key stays
  usable for incoming Initial messages for a 14-day grace period, then is
  deleted. A recovered identity generates a fresh one and refuses Initials that
  name a pre-recovery id.
- **Also.** The responder's first ratchet sending key is a copy of the signed
  prekey that the Initial used ([S06 §3.2](../specs/06-key-agreement-ratchet.md)).
- **Erased.** Deleted from the database when the grace period ends.

## One-time prekeys

- **Algorithm and size.** X25519 key pairs; 4-byte random ids, never reused.
- **Generated.** `CSPRNG` in batches of 200 when fewer than 50 unused keys
  remain on a mailbox ([S06 §5](../specs/06-key-agreement-ratchet.md)). The
  uploaded set is committed by a signed manifest.
- **Stored.** Private keys in the `prekeys` table, field-encrypted. Public keys
  on the mailbox, which hands out each one once.
- **Lifetime.** Single use. After an Initial consumes one, the private key is
  kept 7 days for late duplicates and then deleted. Every id ever issued is
  recorded so it is never issued again. Recovery retires the whole pool and
  uploads a new one with new ids.
- **Erased.** Deleted from the database 7 days after use, on expiry, or on
  retirement.

## X3DH ephemeral key and shared secret

- **Algorithm and size.** `EK`: X25519 key pair. `SK`: 32 bytes.
- **Generated.** `EK` fresh for every session the user starts.
  `SK = HKDF(IKM = DH1 ‖ DH2 ‖ DH3 [‖ DH4], salt = zeros(32), info =
  "najwa/v1/x3dh/" ‖ X_IK_A_pub ‖ X_IK_B_pub, 32)`
  ([S06 §2.2](../specs/06-key-agreement-ratchet.md)).
- **Stored.** `EK_pub` travels in the Initial message header. `EK_priv` becomes
  the initiator's first ratchet sending key and is stored with the ratchet state
  until the first DH ratchet step replaces it. `SK` is never stored.
- **Erased.** The DH concatenation and `SK` are zeroized once the ratchet is
  initialized; `EK_priv` as described under ratchet keys.

## Ratchet keys

- **Algorithm and size.** Root key `RK`, sending and receiving chain keys
  `CKs`/`CKr`: 32 bytes each. DH ratchet key pair: X25519.
- **Derived.** `(RK', CK) = HKDF(IKM = DH_out, salt = RK, info =
  "najwa/v1/ratchet/rk", 64)` on each DH ratchet step; `CK' = HMAC_SHA256(CK,
  0x02)` on each message. A new DH key pair is generated at every DH ratchet
  step ([S06 §3.3, §3.6](../specs/06-key-agreement-ratchet.md)).
- **Stored.** Per contact in `ratchet_sessions`; the DH private key, `RK`,
  `CKs` and `CKr` are field-encrypted
  ([S03 §5.4](../specs/03-encrypted-storage.md)).
- **Lifetime.** A chain key lives for one message; a root key and DH key pair
  for one DH epoch. The session lives until the contact is deleted or the
  session is reset or repaired. Blocking a contact keeps its session.
- **Erased.** Replaced values are zeroized in memory and overwritten in the
  database. Deleting a contact deletes its session.

## Message keys and skipped keys

- **Algorithm and size.** `MK` = `HMAC_SHA256(CK, 0x01)`, 32 bytes, expanded to
  `enc_key(32) ‖ auth_key(32) ‖ iv(16)` with
  `HKDF(IKM = MK, salt = zeros(32), info = "najwa/v1/ratchet/mk", 80)`. The
  nonce is `iv ‖ zeros(8)`; `auth_key` is not used.
- **Lifetime.** One message. The key and its expansion are zeroized right after
  encryption or decryption.
- **Skipped keys.** When messages arrive out of order, the keys for the gap are
  stored in `skipped_keys`, protected by SQLCipher, with the sending chain's
  public key and the message number. At most 1000 per chain step and 4000 per
  session, oldest evicted first ([S06 §3.7–§3.8](../specs/06-key-agreement-ratchet.md)).
  A skipped key survives a failed trial decryption and is deleted only after
  the message authenticates.
- **Erased.** On use, after 90 days (matching mailbox retention), by eviction,
  or with the contact.

## Mailbox capabilities and envelope secrets

- **Algorithm and size.** `deposit_capability`, `fetch_capability` and
  `envelope_secret`: 32 random bytes each. Outer key: 32 bytes from HKDF.
- **Generated.** By the receiving side, with `CSPRNG`: one set per own mailbox,
  one per contact per mailbox at contact acceptance, and one short-lived set per
  shared invitation ([S05 §2.2, §5, §8](../specs/05-contact-establishment.md)).
  Each own mailbox also gets a cover set and nine dummy fetch and deposit pairs
  with no envelope secret of their own, never shared with anyone
  ([S10 §5, §5.1](../specs/10-cover-traffic.md)).
- **Distributed.** The fetch and deposit capabilities are registered with the
  mailbox. The deposit capability and its envelope secret go to the contact
  inside the signed handshake or a ratchet-encrypted MailboxUpdate. The envelope
  secret is never sent to a mailbox.
- **Outer key.** `outer_key = HKDF(IKM = envelope_secret, salt =
  "najwa/v1/deposit-envelope", info = "outer-key", 32)` for every deposit and
  every fetched blob ([S07 §3](../specs/07-message-format.md)). The mailbox holds
  the deposit capability but not the envelope secret, so it cannot open
  envelopes.
- **Stored.** In the `mailboxes`, `contact_mailbox_caps`,
  `ephemeral_handshake_caps` and `dummy_capabilities` tables, protected by
  SQLCipher. The outer key is never stored; it is zeroized after each deposit or
  fetched blob.
- **In memory while locked.** The fetch plan keeps the onion address and the
  fetch capability of every receive queue and registered dummy queue, taken just
  before the database closes, so polling continues fetch-only. The cover
  snapshot keeps the cover pair, the cover envelope secret and the active dummy
  deposit capabilities. No envelope secret of a real queue is kept. Both are
  zeroized when the messaging runtime is destroyed: erase, bridge change or quit
  ([S13 §8.3](../specs/13-privacy-hardening.md)).
- **Lifetime and rotation.** Invitation capabilities expire on the mailbox
  48 hours after creation and authorize a single Initial message.
  Per-contact capabilities are not rotated in this release; they live until the
  contact is deleted or the profile is erased.
- **Erased.** Deleting a contact deletes its capability rows locally; it does
  not deactivate them on the mailbox. The contact's own deposit capability and
  envelope secret stay in `revocation_frames` with its pending
  RevocationNotice until the first deposit, at most 90 days
  ([S08 §7.1](../specs/08-messaging-service.md)). Erasing an unlocked profile
  first asks each mailbox, once per receiving capability (cover and dummy queues
  included) and within 20 s, to deactivate it, then deletes all of them locally; the result lists the
  mailboxes reached and not reached. Erasing a locked profile deletes them
  locally only.

## Disappearing-message keys

- **Algorithm and size.** 32 random bytes per message
  ([S12 §4](../specs/12-disappearing-messages.md)).
- **Generated.** `CSPRNG(32)` when a disappearing message is stored. The content
  is stored as `nonce(24) ‖ XChaCha20-Poly1305(key, nonce, plaintext, AAD =
  msg_id)`.
- **Stored.** In memory while unlocked. On lock, each live key is wrapped with
  the database key (random nonce, AAD `volatile-key`) into `volatile_keys`, and
  the memory copy is zeroized. On unlock, the live keys are unwrapped into memory
  and the table is cleared in the same transaction.
- **Lifetime.** Until the message's disappear time.
- **Erased.** At expiry the key is removed from memory and its row deleted.
  Without the key the stored ciphertext cannot be read, even if the
  best-effort content overwrite fails. Deleting the contact or the message
  removes the key. A crash while unlocked loses the in-memory keys; the affected
  messages then read as expired.

## File-transfer secrets

File content has no dedicated key. Each chunk is sent as an ordinary
ratchet-encrypted message ([S11 §2](../specs/11-file-transfer-sanitization.md)).

- **Transfer ids.** 16 random bytes per transfer.
- **Upload staging.** Uploaded parts are stored in `browser_transfer_parts`
  inside the encrypted database.
- **Download grants.** A download link carries a 32-byte random token (64 hex
  characters). Only `SHA256(token)` is stored, in `browser_download_grants`.
- **Circuit isolation key.** A responsive-mode file transfer derives a 32-byte
  Tor isolation key with the label `najwa-responsive-file-circuit-v1\0` over the
  contact, transfer and capability ([S04 §4](../specs/04-transport.md)). It is
  not stored.
- **Erased.** With the transfer or contact rows, and by profile erasure.

## Local service tokens

The local service authenticates the browser UI with random tokens
([local service](../../apps/local-web/README.md)).

- **Session token.** 32 random bytes (hex) per service process. Required on API
  requests. Written to `web-instance.json` in the profile directory while the
  service runs so a second launch can hand over to it, and on Linux and macOS
  to the `0600` launch page `web-launch.html`; both files are removed on exit.
- **Browser access grant.** 32 random bytes (hex) with a 30-day lifetime, stored
  in `browser-access.json` in the profile directory. It lets a browser reopen
  the locked profile; it never unlocks the identity. A new grant replaces an
  expired one.
- **Erased.** The session token disappears with the process. The grant is
  zeroized in memory on drop. Both files are deleted by profile erasure.

## Mailbox server keys

- **Operator signing key.** Optional Ed25519 key loaded from a seed file or an
  inline hex seed in the server configuration. It signs operator attestations
  and batching attestations ([S16 §5–§6](../specs/16-mailbox-server.md)). The
  operator manages its lifetime.
- **Onion service key.** Held by the server's Tor instance
  (`HiddenServiceDir`, [S16 §11](../specs/16-mailbox-server.md)).
- **Stored capabilities.** The server stores fetch and deposit capabilities as
  registered, until deactivation, expiry or retirement.

## Erasure events

| Event | What is erased |
|-------|----------------|
| Lock | Identity seed, database key and all session keys leave memory; disappearing-message keys are wrapped into the database and zeroized |
| Message key use | The message key and its expansion |
| Disappearing-message expiry | The message key and its ciphertext |
| Contact deletion | Session state, skipped keys, capabilities, disappearing-message keys and messages for that contact |
| Password change | The previous identity record, its device-factor entry and its counter files |
| Recovery kit replacement | The previous `identity.recovery` on this device |
| Local profile erasure ([S13 §10](../specs/13-privacy-hardening.md)) | If unlocked, a best-effort mailbox deactivation of every receiving capability first (20 s bound); then the current device-factor entry and its TPM or Secure Enclave key; then every file in the profile directory (overwritten, then deleted): identity record, recovery record, database and token files |

Zeroization and deletion reduce what remains on the device. They cannot reach
recovery kits stored elsewhere, OS backups, the contact's copy of the
conversation, or earlier blocks on flash and copy-on-write file systems.

Every `CSPRNG` on this page is the OS generator ([S01 §5.1](../specs/01-crypto-primitives.md)).
Crash dumps of the local service are suppressed ([S01 §6.3](../specs/01-crypto-primitives.md)).
While unlocked, the identity seed and the database key are locked against
paging when the OS allows it; other keys held in memory are not, so they can
reach swap, and all of them can reach the hibernation file
([S01 §6.2](../specs/01-crypto-primitives.md)).
