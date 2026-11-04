---
id: S03
title: Encrypted Storage
crates: [najwa-storage, najwa-core, najwa-ffi]
depends-on: [S01, S02, S06, S07, S08, S12]
---

# S03 — Encrypted Storage

## Overview

Najwa keeps everything it knows about conversations in one encrypted database
per profile: contacts, Double Ratchet sessions, prekeys, mailbox capabilities,
messages, delivery queues and file-transfer progress. The database is a
SQLCipher file. Every page on disk is encrypted and authenticated, and the key
is derived from the identity key, so the database can be read only while the
identity is unlocked ([S02](02-identity-key-protection.md)).

The native local service owns the profile directory. The browser never chooses
file paths and never receives keys. Inside the directory the files have
distinct roles: the identity record holds the passphrase-protected identity key,
the device-key factor lives in the operating system's key store or TPM, and the
database holds everything else (§11). Opening the same profile with a newer
program version reuses the same files. Changing browsers does not create a new
identity.

Storage is where crash safety is decided. A network action must never get ahead
of the local state needed to interpret it:

- **Send.** Before a frame goes to a mailbox, the advanced sending ratchet, the
  message row and the exact wire bytes commit in one transaction. After a crash
  the same bytes are deposited again. Encryption is never re-run at an old
  ratchet position, which would reuse keys.
- **Receive.** A frame is authenticated and decrypted first. The ratchet
  advance, skipped keys, the stored message, the dedup marks and every control
  effect then commit in one transaction. Only after that commit is the blob
  acknowledged for deletion at the mailbox. A crash can never leave a dedup
  mark for a message that was not stored, or an advanced chain without its
  message.

Work that outlives a browser request (contact setup, receive-route
announcements, read receipts, attachment preparation) is written to the
database before success is reported, and resumes after unlock or restart.
Mailbox acknowledgement, peer delivery confirmation and read receipts are
separate events with separate records.

Only one process may operate a profile at a time, and only one owner may use a
ratchet state. Copying a live profile, or running a copy next to the original,
breaks these guarantees (§12).

SQLCipher protects content, not metadata. File names, sizes, timestamps and WAL
bookkeeping stay visible to anyone with access to the disk.

## 1. Scope

This specification defines:

- the SQLCipher configuration and the database key derivation (§2, §3);
- open-time hardening and the at-rest tripwire (§4);
- the client schema, version `2`, including every table, index and trigger (§5);
- the storage interface, its atomic commit boundaries, crash consistency and
  WAL handling (§6);
- per-row field encryption of ratchet and prekey secrets (§7);
- schema initialisation and version checking (§8);
- the on-disk profile layout (§11).

Lock-time key handling and local profile erasure are specified in
[S13](13-privacy-hardening.md). Disappearing-message key handling is specified
in [S12](12-disappearing-messages.md). The mailbox server's database is
specified in [S16](16-mailbox-server.md).

## 2. Technology

| Property | Value |
|----------|-------|
| Library | SQLCipher 4.10.0 (community edition) on SQLite 3.50.4, OpenSSL crypto provider (vendored) |
| Rust binding | `rusqlite` 0.38 with the `bundled-sqlcipher-vendored-openssl` feature |
| Page cipher | AES-256-CBC with a fresh random 16-byte IV for every page write |
| Page authentication | HMAC-SHA256 over each page |
| Page size | 4096 bytes; each page reserves 48 bytes (16-byte IV + 32-byte HMAC) |
| File salt | 16 random bytes at the start of the main database file |
| Key input | Raw 256-bit key (§3); SQLCipher's passphrase KDF is not run |
| Page-HMAC key | Derived by SQLCipher: PBKDF2-HMAC-SHA256, 2 iterations, over the raw key, salt = file salt with every byte XOR `0x3A` |
| `kdf_iter` | 256000 (configured file parameter; not applied to a raw key) |

## 3. Database Key Derivation

```
db_key = HKDF-SHA256(
    IKM    = identity_seed,            // 32-byte Ed25519 private seed of the unlocked identity (S02)
    salt   = "najwa-sqlcipher-key",    // 19 bytes: 6E616A77612D73716C6369706865722D6B6579
    info   = "najwa/v1/sqlcipher-key", // 22 bytes: 6E616A77612F76312F73716C6369706865722D6B6579
    length = 32
)
```

Requirements:

- `db_key` MUST be derived only from an unlocked identity and MUST be held in a
  zeroizing buffer for its whole lifetime. The release holds one copy, in
  locked memory shared by every database handle ([S01 §6.2](01-crypto-primitives.md)).
- `db_key` MUST be handed to SQLCipher as raw key data through `sqlite3_key`:
  the 67-byte ASCII string `x'` ‖ lowercase-hex(`db_key`) ‖ `'`, built in a
  zeroizing buffer. It MUST NOT be passed in SQL text (`PRAGMA key`), which
  leaves copies in ordinary heap strings.
- SQLCipher uses raw key data of exactly 64 hex digits directly as the page
  encryption key and derives the page-HMAC key from it (§2).
- `db_key` is a deterministic function of the identity seed. It does not change
  when the passphrase changes, and the release has no database rekey operation.
- `db_key` is dropped when the profile locks ([S13 §8.2](13-privacy-hardening.md))
  and when it is erased ([S13 §10](13-privacy-hardening.md)).

The derivation is `derive_sqlcipher_key` in `crates/najwa-ffi/src/lib.rs`. Every
path that attaches an identity to storage uses it: `DesktopClient::attach_identity`
and the C ABI `najwa_create` / `najwa_unlock` ([S17 §4.1](17-ffi-bindings.md)).

## 4. Database Initialization

### 4.1 Open Procedure

```
func open_database(path, db_key):
    path  = absolute(path)                         // canonical parent directory + file name
    gate  = lock_exclusive(path || ".gate")        // serialises opens across handles and processes
    lease = lock_shared(path || ".lease")          // held for the lifetime of the connection
    ensure_lock_quota()                            // once per process (S01 §6.2)
    conn  = sqlite3_open(path)                     // busy timeout 5000 ms (rusqlite default)
    sqlite3_key(conn, "x'" || hex(db_key) || "'")  // §3
    PRAGMA cipher_page_size       = 4096
    PRAGMA kdf_iter               = 256000
    PRAGMA cipher_hmac_algorithm  = HMAC_SHA256
    PRAGMA cipher_kdf_algorithm   = PBKDF2_HMAC_SHA256
    PRAGMA cipher_memory_security = ON
    PRAGMA secure_delete          = ON
    PRAGMA journal_mode           = WAL
    PRAGMA synchronous            = FULL
    PRAGMA temp_store             = MEMORY
    PRAGMA foreign_keys           = ON
    init_schema(conn)                              // §8: first read; a wrong key fails here
    verify_hardening(conn, path)                   // §4.2, §4.3
    release gate
    return (conn, lease)
```

- The four cipher pragmas MUST be set identically on every open, after keying
  and before the first read. A file written with other values cannot be read.
- A wrong key or a damaged file fails at the first read inside `init_schema`.
  The open then fails and publishes no state.
- While a profile is unlocked, one process holds two connections to
  `najwa.db`: the application state's handle and the messaging service's
  handle. Each `SqliteStorage` serialises its own use through a mutex, and the
  mutex is never held across an `await`. SQLite's WAL locking coordinates the
  two connections.

### 4.2 Hardening Pragmas

These MUST be set on every open:

| Pragma | Value | Reason |
|--------|-------|--------|
| `cipher_page_size` | `4096` | File-format parameter |
| `kdf_iter` | `256000` | File-format parameter; not applied to a raw key |
| `cipher_hmac_algorithm` | `HMAC_SHA256` | Page authentication |
| `cipher_kdf_algorithm` | `PBKDF2_HMAC_SHA256` | Derives the page-HMAC key |
| `cipher_memory_security` | `ON` | SQLCipher wipes the memory it frees and locks its buffers in RAM where the OS allows; the first open raises the process's locked-memory quota so the locks succeed ([S01 §6.2](01-crypto-primitives.md)) |
| `secure_delete` | `ON` | Freed page content is overwritten with zeros |
| `journal_mode` | `WAL` | Readers do not block the writer; WAL frames hold encrypted pages (§6.3) |
| `synchronous` | `FULL` | The WAL is synced at every commit (§6.2) |
| `temp_store` | `MEMORY` | Temporary tables and indexes never reach disk |
| `foreign_keys` | `ON` | The cascading deletes in §5 depend on it |

After schema initialisation `verify_hardening` re-reads `temp_store` (MUST be
`2`, meaning MEMORY) and `journal_mode` (MUST be `wal`) and fails the open
otherwise.

### 4.3 At-rest Encryption Verification

After schema initialisation the open reads the first 16 bytes of the main
database file:

- If they equal `SQLite format 3\0` (`53514C69746520666F726D6174203300`), the
  file was written without encryption. The open MUST fail with
  `StorageError::WalNotEncrypted`.
- Otherwise the check passes. A file that does not exist yet passes.

A SQLCipher file starts with its random 16-byte salt, so the plaintext header
never appears on a correctly keyed database. The check is a tripwire, not a
proof of encryption. The keyed read in `init_schema` and the configuration in
§4.2 provide the rest of the boundary.

The WAL file MUST NOT be tested for plaintext. SQLCipher encrypts WAL frame
contents but writes the 32-byte WAL header and the 24-byte frame headers in the
standard SQLite format, so a healthy encrypted WAL starts with the ordinary WAL
magic `0x377F0682` or `0x377F0683`. The tripwire is
`hardening::verify_wal_encryption` in `crates/najwa-storage/src/hardening.rs`;
despite its name, it inspects only the main database file, and it reads at most
16 bytes.

### 4.4 Temporary File Cleanup

Plaintext database content MUST NOT be written to temporary files.
`temp_store = MEMORY` (§4.2) meets this for SQLite: no `etilqs_*` files are
created. The library function `hardening::cleanup_temp_files(dir)` zero-fills
and removes `*.tmp`, `*-journal` and `*etilqs_*` files in a directory. The
release does not call it: it matches by suffix alone and follows symlinks when
it zero-fills, so in a profile directory the user chose (`najwa-web --profile`)
it could overwrite other programs' files, including another database's hot
journal. With `temp_store = MEMORY` and WAL, Najwa itself leaves no such files.

## 5. Database Schema

The schema is the file `crates/najwa-storage/schema.sql`, created by §8. All
tables live in the one encrypted database. There are no group, channel, feed or
linked-device tables.

Conventions: times are Unix seconds unless a column is marked milliseconds.
Byte lengths are enforced by the schema only where a `CHECK` appears; otherwise
the code writes the stated length. Foreign keys are enforced (§4.2).

| Table | § | Purpose |
|-------|---|---------|
| `db_meta` | 5.1 | Schema version |
| `contacts` | 5.2 | One row per peer |
| `ratchet_sessions` | 5.4 | Double Ratchet state per contact |
| `skipped_keys` | 5.5 | Out-of-order message keys |
| `messages` | 5.6 | Conversation history and outgoing message rows |
| `msg_id_cache_transport`, `msg_id_cache_logical` | 5.7 | Replay and duplicate suppression |
| `prekeys` | 5.8 | Signed and one-time prekeys |
| `mailboxes` | 5.9 | This profile's own mailbox routes |
| `contact_mailbox_caps` | 5.10 | Per-contact capabilities |
| `remote_mailbox_health` | 5.11 | Delivery health of peers' mailboxes |
| `volatile_keys` | 5.13 | Disappearing-message keys saved at lock |
| `identity_history` | 5.14 | Peer identity rotations |
| `onion_pins` | 5.15 | Unused |
| `settings` | 5.16 | Key/value records |
| `outgoing_frames`, `outbound_message_positions`, `revocation_frames` | 5.17 | Outbound queue |
| `received_frames`, `inbound_work` | 5.18 | Accepted frames, pending ACKs, deferred work |
| `outbound_repair_records`, `outbound_history` | 5.19 | Re-send sources for repair |
| `ephemeral_handshake_caps` | 5.20 | Invitation receive capabilities |
| `pending_introductions` | 5.21 | Received introductions |
| `epoch_quarantine` | 5.22 | Frames held for a later ratchet epoch |
| `prekey_used_ids` | 5.23 | Every prekey ID ever issued |
| `browser_transfers`, `browser_transfer_parts`, `browser_download_grants` | 5.24 | File-transfer staging and download tickets |
| `dummy_capabilities` | 5.26 | Dummy receive queues that pad polls |

### 5.1 Metadata

```sql
CREATE TABLE IF NOT EXISTS db_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
-- row written by init_schema (§8):
-- ('schema_version', '2')
```

`schema_version` is the TEXT value `2`. It identifies this schema for
compatibility checks; it is not a product version.

### 5.2 Contacts

```sql
CREATE TABLE IF NOT EXISTS "contacts" (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pseudonym BLOB NOT NULL,
    their_ik_pub BLOB NOT NULL,
    their_device_pub BLOB NOT NULL,
    our_pseudonym BLOB NOT NULL,
    display_name TEXT,
    avatar_hash BLOB,
    created_at INTEGER NOT NULL,
    last_message_at INTEGER,
    verified INTEGER DEFAULT 0,
    blocked INTEGER DEFAULT 0,
    next_outbound_seq INTEGER NOT NULL DEFAULT 0,
    UNIQUE(their_ik_pub, their_device_pub)
);
CREATE INDEX IF NOT EXISTS idx_contacts_pseudonym ON contacts(pseudonym);
CREATE INDEX IF NOT EXISTS idx_contacts_ik ON contacts(their_ik_pub);
CREATE INDEX IF NOT EXISTS idx_contacts_last_message ON contacts(last_message_at DESC);
```

| Column | Meaning |
|--------|---------|
| `pseudonym` | 32 bytes: the peer's pairwise pseudonym for this relationship. Indexed, not unique. |
| `their_ik_pub` | 32 bytes: the peer's Ed25519 identity public key. Updated in the receive transaction when an authenticated identity rotation is applied (§5.14). |
| `their_device_pub` | 32 bytes: written with the peer's identity public key. The release keeps exactly one row per peer. |
| `our_pseudonym` | 32 bytes: this profile's pairwise pseudonym for the peer. |
| `display_name` | Local name chosen by the user. |
| `avatar_hash` | Unused (NULL). |
| `verified` | `1` after the user confirms the safety number. |
| `blocked` | `1` while the user blocks the contact. Blocking pauses work and keeps history. |
| `next_outbound_seq` | Last `logical_seq` issued to this contact ([S07 §4](07-message-format.md)). Incremented with a single `UPDATE … RETURNING`; the first message gets `1`. At `4294967295` the update matches no row and the send fails instead of wrapping. |

Lookups: by row ID; by `pseudonym` (first matching row); by `their_ik_pub`; and
by `(their_ik_pub, their_device_pub)`, which returns at most one row.

Deleting a contact runs in one transaction. It removes the contact's volatile
keys, the contact row (cascading to every table with a `contact_id` foreign key)
and the contact's `settings` entries (§5.16). A delete that notifies the peer
first moves its undeposited RevocationNotice frame into `revocation_frames`
(§5.17) in the same transaction.

### 5.3 Session Associated Data

There is no session-AD table. The 64-byte X3DH associated data
(`IK_A ‖ IK_B`, [S06 §2](06-key-agreement-ratchet.md)) for a contact is stored in
`settings` under the key `session_ad:{contact_id}`. It is written in the
transaction that first commits the session (§6.1) and deleted with the contact
and on a session reset.

### 5.4 Double Ratchet State

```sql
CREATE TABLE IF NOT EXISTS ratchet_sessions (
    contact_id INTEGER PRIMARY KEY,
    dhs_private BLOB,
    dhs_public BLOB,
    dhr BLOB,
    rk BLOB,
    cks BLOB,
    ckr BLOB,
    ns INTEGER DEFAULT 0,
    nr INTEGER DEFAULT 0,
    pn INTEGER DEFAULT 0,
    established_at INTEGER NOT NULL,
    last_activity INTEGER NOT NULL,
    prev_dhs_pub BLOB,
    FOREIGN KEY (contact_id) REFERENCES contacts(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_ratchet_sessions_dhr ON ratchet_sessions(dhr);
```

| Column | Content |
|--------|---------|
| `dhs_private` | Our current DH ratchet private key, field-encrypted (§7): 72 bytes |
| `dhs_public` | Our current DH ratchet public key, 32 bytes |
| `dhr` | The peer's current DH ratchet public key, 32 bytes; indexed for lookup by ratchet key |
| `rk`, `cks`, `ckr` | Root, sending-chain and receiving-chain keys, each field-encrypted (§7): 72 bytes |
| `ns`, `nr`, `pn` | Ratchet counters ([S06 §3.1](06-key-agreement-ratchet.md)) |
| `prev_dhs_pub` | Our previous sending-epoch public key, 32 bytes, sent as `epoch_link`; `NULL` before the first DH step ([S06 §3.10](06-key-agreement-ratchet.md)) |

Rows are written with `INSERT OR REPLACE`, only inside the transactions of §6.1.
A received session reset or revocation deletes the row in its receive
transaction. The in-memory record type zeroizes its four secret fields when it
is dropped.

### 5.5 Skipped Message Keys

```sql
CREATE TABLE IF NOT EXISTS skipped_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    contact_id INTEGER NOT NULL,
    dh_pub BLOB NOT NULL,
    message_number INTEGER NOT NULL,
    message_key BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    FOREIGN KEY (contact_id) REFERENCES contacts(id) ON DELETE CASCADE,
    UNIQUE (contact_id, dh_pub, message_number)
);
CREATE INDEX IF NOT EXISTS idx_skipped_expires ON skipped_keys(expires_at);
```

| Constant | Value | Source |
|----------|-------|--------|
| `MAX_SKIP` | 1000 keys per chain step | `najwa-protocol/src/ratchet/state.rs` |
| `MAX_SKIPPED_KEYS_PER_SESSION` | 4000 (oldest evicted first) | same |
| `SKIP_KEY_EXPIRY_SECS` | 7776000 (90 days) | same |

- `message_key` is the raw 32-byte message key, protected by SQLCipher only.
- `expires_at = created_at + SKIP_KEY_EXPIRY_SECS`.
- Every ratchet commit (§6.1) replaces the contact's whole set: it deletes all of
  the contact's rows and inserts the current in-memory set. The stored set
  therefore mirrors the in-memory store, including eviction and expiry. Expired
  keys of a contact leave the table at that contact's next ratchet commit, and
  the retention pass (§6.4) deletes every row past `expires_at`, so a contact
  that never sends again does not keep its keys.
- A skipped key MUST NOT be written before AEAD verification of the frame that
  created it succeeds ([S06 §3.11](06-key-agreement-ratchet.md)).
- A received `ForgetSkipped` effect deletes a `(dh_pub, start..=end)` range in the
  receive transaction.

### 5.6 Messages

```sql
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    contact_id INTEGER NOT NULL,
    msg_id BLOB NOT NULL UNIQUE,
    direction INTEGER NOT NULL,
    content_type INTEGER NOT NULL,
    flags INTEGER DEFAULT 0,
    content BLOB NOT NULL,
    file_path TEXT,
    timestamp INTEGER NOT NULL,
    received_at INTEGER,
    read_at INTEGER,
    status INTEGER DEFAULT 0,
    retry_count INTEGER DEFAULT 0,
    last_retry_at INTEGER,
    reply_to_msg_id BLOB,
    disappear_timer INTEGER,
    disappear_at INTEGER,
    encrypted_blob BLOB,
    group_id BLOB,
    sender_display_name TEXT,
    origin_timestamp_ms INTEGER,
    retry_wire_blob BLOB,
    FOREIGN KEY (contact_id) REFERENCES contacts(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_messages_contact ON messages(contact_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_messages_status ON messages(status) WHERE status < 2;
CREATE INDEX IF NOT EXISTS idx_messages_msg_id ON messages(msg_id);
CREATE INDEX IF NOT EXISTS idx_messages_disappear ON messages(disappear_at)
    WHERE disappear_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_messages_group ON messages(group_id, timestamp DESC)
    WHERE group_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_browser_file_progress
    ON messages(contact_id, direction, substr(content,1,16), substr(content,17,4), status)
    WHERE content_type=11 AND disappear_timer IS NULL;
CREATE INDEX IF NOT EXISTS idx_browser_file_metadata
    ON messages(contact_id, direction, substr(content,1,16))
    WHERE content_type=10 AND disappear_timer IS NULL;
```

| Column | Meaning |
|--------|---------|
| `msg_id` | 16-byte transport message ID ([S07 §6](07-message-format.md)); unique |
| `direction` | `0` received, `1` sent |
| `content_type` | Local code (table below) |
| `flags` | Payload flags ([S07 §4.2](07-message-format.md)) |
| `content` | Payload content. For a disappearing message (`disappear_timer` not NULL) this is the sealed form `nonce(24) ‖ XChaCha20-Poly1305(ephemeral_key, nonce, content, AAD = msg_id)` ([S12 §4](12-disappearing-messages.md)) |
| `file_path` | Unused (NULL). Attachment bytes stay inside the database |
| `timestamp` | Sender timestamp, Unix seconds |
| `received_at` | Receive time, Unix seconds (received rows) |
| `read_at` | First display time, Unix **milliseconds** (received rows) |
| `status` | Status code (table below) |
| `retry_count`, `last_retry_at` | Sent rows: failed deposit attempts; time in seconds. Received `FileMetadata` rows: `FileChunkNack`s sent (`5` once the receiver stopped asking); time of the file's last stored part or request, in seconds ([S11 §4.1](11-file-transfer-sanitization.md)) |
| `reply_to_msg_id` | 16-byte `msg_id` quoted by a reply |
| `disappear_timer` | Timer in seconds, an unsigned 32-bit value read back unchanged up to `4,294,967,295` ([S12 §2.4](12-disappearing-messages.md)); NULL for an ordinary message |
| `disappear_at` | Deletion deadline, Unix **milliseconds**; NULL until the timer starts |
| `encrypted_blob`, `group_id`, `sender_display_name`, `origin_timestamp_ms` | Unused (NULL). `idx_messages_group` therefore indexes no rows |
| `retry_wire_blob` | Sent rows: the exact wire bytes for retry; cleared at the first successful deposit |

Local content-type codes differ from the wire bytes:

| Code | Name | Wire byte ([S07 §4.1](07-message-format.md)) |
|------|------|------|
| 0 | Text | `0x01` |
| 8 | TextReply | `0x02` |
| 9 | Binary | `0x03` |
| 10 | FileMetadata | `0x10` |
| 11 | FileChunk | `0x11` |
| 12 | ReciprocalHandshake | `0x04` |
| 13 | Control | `0x20` |

Codes 1–7 exist in the storage enum and are never written. An unknown code reads
back as Text.

| Status | Meaning |
|--------|---------|
| 0 | Pending: queued, not yet deposited |
| 1 | Sent: deposited at a mailbox |
| 2 | Delivered: the peer's ACK covers the frame |
| 3 | Read: the peer's read receipt arrived |
| 4 | Failed: the last deposit attempt failed; still retried |
| 5 | Permanently failed or retired: never retried |

Deleting a message, or overwriting its `content`, fires the triggers of §5.25.

### 5.7 Message ID Deduplication Cache

```sql
CREATE TABLE IF NOT EXISTS msg_id_cache_transport (
    msg_id     BLOB    PRIMARY KEY,
    contact_id INTEGER NOT NULL,
    seen_at    INTEGER NOT NULL,
    FOREIGN KEY (contact_id) REFERENCES contacts(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_msg_cache_transport_seen ON msg_id_cache_transport(seen_at);

CREATE TABLE IF NOT EXISTS msg_id_cache_logical (
    contact_id     INTEGER NOT NULL,
    logical_msg_id BLOB    NOT NULL,
    seen_at        INTEGER NOT NULL,
    PRIMARY KEY (contact_id, logical_msg_id),
    FOREIGN KEY (contact_id) REFERENCES contacts(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_msg_cache_logical_seen ON msg_id_cache_logical(seen_at);
```

`msg_id_cache_transport` holds two kinds of 16-byte ID, both globally unique:

- the transport `msg_id` of every received message ([S07 §6.1](07-message-format.md)):
  `HKDF-SHA256(IKM = dh_pub(32) ‖ n(4, BE) ‖ SHA-256(content_type ‖ content),
  salt = sender_pseudonym, info = "najwa/v1/message-id", L = 16)`;
- the authenticated header ID of every accepted frame, including controls and
  repaired positions: `SHA-256(dh_pub(32) ‖ n(4, BE))[0:16]`.

`msg_id_cache_logical` holds the endpoint-invariant logical ID
([S07 §6.2](07-message-format.md)), which survives re-encryption during session
repair:

```
logical_msg_id = SHA-256(
    min(IK_a, IK_b) ‖ max(IK_a, IK_b) ‖ 0x00 ‖   // 32-byte Ed25519 keys, bytewise order
    timestamp(8, BE) ‖ 0x00 ‖
    logical_seq(4, BE) ‖ 0x00 ‖
    content_type(1) ‖ 0x00 ‖
    content
)[0:16]
```

Rules:

- A frame whose header ID is already cached MUST NOT be processed again. It may
  be acknowledged again.
- A message whose transport ID, or whose `(contact_id, logical_msg_id)`, is
  cached MUST NOT be stored again. The ratchet commit for that frame still
  proceeds.
- Marks MUST be written only inside the receive transaction (§6.1).
- Entries MUST be kept for at least `MIN_ENTRY_TTL_SECS = 7776000` (90 days).
  The retention pass (§6.4) deletes rows whose `seen_at` is more than 91 days
  old: a mailbox may hold a blob for up to one cleanup interval past its 90-day
  cap ([S16 §10.1](16-mailbox-server.md)), and the extra day covers that. Rows
  also leave with their contact. The pruning helper `cleanup_old_msg_ids`
  clamps its cutoff so that no entry younger than 90 days is removed.

### 5.8 Prekeys

```sql
CREATE TABLE IF NOT EXISTS prekeys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_id BLOB NOT NULL UNIQUE CHECK(length(key_id) = 4),
    key_type INTEGER NOT NULL,
    private_key BLOB NOT NULL,
    public_key BLOB NOT NULL,
    signature BLOB,
    created_at INTEGER NOT NULL,
    expires_at INTEGER,
    used INTEGER DEFAULT 0,
    used_at INTEGER,
    mailbox_id INTEGER,
    fetch_scope BLOB,
    FOREIGN KEY (mailbox_id) REFERENCES mailboxes(id)
);
CREATE INDEX IF NOT EXISTS idx_prekeys_type ON prekeys(key_type, used);
CREATE INDEX IF NOT EXISTS idx_prekeys_mailbox ON prekeys(mailbox_id);
```

| Column | Meaning |
|--------|---------|
| `key_id` | 4 random bytes |
| `key_type` | `0` SPK (signed prekey), `1` OPK (one-time prekey) |
| `private_key` | X25519 private key, field-encrypted (§7, row ID = `key_id` as a big-endian u32): 72 bytes |
| `public_key` | 32 bytes |
| `signature` | SPK signature, 64 bytes; NULL for OPKs |
| `expires_at` | NULL for current keys. When an SPK is replaced, set to the end of its grace period |
| `used`, `used_at` | OPK consumption. Set in the receive transaction that accepts the Initial message using it |
| `mailbox_id`, `fetch_scope` | The mailbox and 32-byte receiving-capability scope the key was published for |

A prekey batch commits in one transaction ([S06 §5](06-key-agreement-ratchet.md)):

1. Reject the batch unless the SPK has type 0, every OPK has type 1, and every
   key is fresh (`used = 0`, 32-byte private and public keys).
2. Reject the batch if the unused, unexpired OPKs for `(mailbox_id, fetch_scope)`
   plus the new OPKs would exceed 200.
3. For each key: insert its `key_id` into `prekey_used_ids` (§5.23), then insert
   the key. Inserts never replace an existing key, so private material needed
   by an Initial in flight is never overwritten. A colliding `key_id` fails the
   batch.
4. If the batch has an SPK, set `expires_at = grace_end` on the previous current
   SPK of the same mailbox and scope.
5. Set the `prekeys:dirty:{hex(fetch_scope)}` setting.

Prekey recovery after an identity restore runs in one transaction: it copies
every `key_id` into `prekey_used_ids`, deletes all prekeys and their
publication settings, and records the recovery generation in
`prekeys:prepared`.

### 5.9 Mailboxes

```sql
CREATE TABLE IF NOT EXISTS "mailboxes" (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    onion_address TEXT NOT NULL UNIQUE,
    fetch_capability BLOB NOT NULL,
    deposit_capability BLOB NOT NULL,
    cover_deposit_capability BLOB,
    cover_fetch_capability BLOB,
    priority INTEGER DEFAULT 1,
    last_success INTEGER,
    last_failure INTEGER,
    failure_count INTEGER DEFAULT 0,
    messages_stored INTEGER DEFAULT 0,
    quota_limit INTEGER,
    enabled INTEGER DEFAULT 1,
    created_at INTEGER NOT NULL,
    last_seen_id TEXT,
    envelope_secret BLOB,
    cover_envelope_secret BLOB,
    cover_registered_at INTEGER
);
```

One row per mailbox this profile receives on ([S16](16-mailbox-server.md)).

| Column | Meaning |
|--------|---------|
| `onion_address` | v3 onion address, 56 characters, without `.onion` |
| `fetch_capability`, `deposit_capability`, `envelope_secret` | The profile's own 32-byte capabilities and envelope secret for this mailbox |
| `cover_deposit_capability`, `cover_fetch_capability`, `cover_envelope_secret` | Dedicated cover-traffic capabilities ([S10 §5](10-cover-traffic.md)) |
| `cover_registered_at` | When the cover capabilities were registered |
| `last_success`, `last_failure`, `failure_count`, `enabled` | Health of this mailbox (§5.11) |
| `priority`, `messages_stored`, `quota_limit`, `last_seen_id` | Unused by the release (default values) |

Capabilities and envelope secrets are protected by SQLCipher only. The
`desktop:mailbox:{id}` setting records whether the mailbox's registration
succeeded, and `desktop:primary` names the primary mailbox.

### 5.10 Per-Contact Mailbox Capabilities

```sql
CREATE TABLE IF NOT EXISTS contact_mailbox_caps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    contact_id INTEGER NOT NULL,
    mailbox_id INTEGER NOT NULL,
    deposit_capability BLOB NOT NULL,
    their_deposit_capability BLOB,
    created_at INTEGER NOT NULL,
    revoked_at INTEGER,
    fetch_capability BLOB,
    their_envelope_secret BLOB,
    envelope_secret BLOB,
    capability_type INTEGER NOT NULL DEFAULT 2,
    expires_at INTEGER,
    registered_at INTEGER,
    FOREIGN KEY (contact_id) REFERENCES contacts(id) ON DELETE CASCADE,
    FOREIGN KEY (mailbox_id) REFERENCES mailboxes(id),
    UNIQUE (contact_id, mailbox_id, deposit_capability)
);
```

| Column | Meaning |
|--------|---------|
| `deposit_capability` | 32 bytes: the capability this contact uses to deposit to us on `mailbox_id` |
| `fetch_capability`, `envelope_secret` | 32 bytes each: our fetch capability and envelope secret for that route |
| `their_deposit_capability`, `their_envelope_secret` | 32 bytes each: the contact's primary route, used to send to them |
| `capability_type` | `2` long-term per-contact capability; `1` ephemeral ([S05 §5](05-contact-establishment.md)) |
| `expires_at` | NULL for long-term capabilities |
| `registered_at` | NULL until the mailbox confirms registration. An unregistered capability MUST NOT be advertised to the contact |
| `revoked_at` | Set when the route is revoked |

These rows are created in the contact-establishment transaction (§6.1). The
contact's complete list of routes is stored as JSON in the
`contact_target:{id}` and `contact_targets:{id}` settings.

### 5.11 Mailbox Health Tracking

Health of the profile's own mailboxes lives in `mailboxes` (§5.9): a success
sets `last_success` and resets `failure_count`; a failure sets `last_failure`
and increments `failure_count`. `enabled` is the user's or the failover
logic's on/off switch ([S08 §9.3](08-messaging-service.md)).

Health of peers' mailboxes:

```sql
CREATE TABLE IF NOT EXISTS remote_mailbox_health (
    onion TEXT PRIMARY KEY,
    failures INTEGER NOT NULL DEFAULT 0,
    enabled INTEGER NOT NULL DEFAULT 1
);
```

- A successful deposit sets `failures = 0`. A failed one increments `failures`,
  saturating at 4294967295. Both set `enabled = 1`: the release never pauses a
  peer's mailbox automatically, and delivery workers keep retrying.
- An explicit user retry deletes the row.
- At unlock, once per profile (marker setting `desktop:auto-retry-v1`), routes
  paused after five or more failures are enabled again: remote rows with
  `failures >= 5`, and own mailboxes with `failure_count >= 5` whose
  registration succeeded.

### 5.13 Volatile Keys (Disappearing Messages)

```sql
CREATE TABLE IF NOT EXISTS volatile_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    msg_id BLOB NOT NULL UNIQUE,
    encrypted_key BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_volatile_keys_expires ON volatile_keys(expires_at)
    WHERE expires_at IS NOT NULL;
```

While the profile is unlocked, each disappearing message's 32-byte ephemeral
key lives only in memory ([S12 §4](12-disappearing-messages.md)) and this table is
empty. At lock the in-memory keys are saved here; at unlock they are moved back
to memory.

```
encrypted_key = nonce(24) ‖ XChaCha20-Poly1305(
    key   = db_key,
    nonce = nonce,                      // 24 random bytes
    pt    = ephemeral_key(32),
    aad   = "volatile-key"              // 12 bytes: 766F6C6174696C652D6B6579
)                                       // 72 bytes in total
```

- `msg_id` is the message's 16-byte transport ID. `expires_at` is the message's
  `disappear_at` (Unix milliseconds), kept in step by the `message_key_deadline`
  trigger (§5.25). `created_at` is in seconds.
- **Lock** (`replace_volatile_keys`, one transaction): delete every row, then
  insert one row per cached key whose message still exists, still has a timer,
  and has not expired.
- **Unlock** (`take_live_volatile_keys`, one transaction, before storage is
  published to any other operation or the transport starts): delete rows with
  `expires_at <= now_ms`; read the rows whose message is still a live
  disappearing message; delete every row; return what was read for decryption
  into memory.
- Deleting a message deletes its key (`message_secrets_deleted`).

### 5.14 Identity History

```sql
CREATE TABLE IF NOT EXISTS identity_history (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    contact_id  INTEGER NOT NULL,
    old_ik_pub  BLOB NOT NULL,
    new_ik_pub  BLOB NOT NULL,
    rotated_at  INTEGER NOT NULL,
    reason      TEXT,
    FOREIGN KEY (contact_id) REFERENCES contacts(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_identity_history_contact ON identity_history(contact_id);
```

When a peer's authenticated identity rotation is received, the receive
transaction updates `contacts.their_ik_pub` from the old to the new key (failing
the whole transaction if the stored key differs from the old key) and inserts a
row with `reason = 'rotation'`.

### 5.15 Onion Address Pinning (TOFU)

```sql
CREATE TABLE IF NOT EXISTS onion_pins (
    onion_address TEXT PRIMARY KEY,
    expected_key_hash BLOB NOT NULL,
    first_seen INTEGER NOT NULL,
    last_verified INTEGER NOT NULL,
    pin_count INTEGER DEFAULT 1
);
```

The schema creates this table. The release neither reads nor writes it. A v3
onion address already commits to the service's public key.

### 5.16 Settings

```sql
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value BLOB NOT NULL,
    updated_at INTEGER NOT NULL
);
```

A general key/value store inside the encrypted database. Values written through
`set_setting` are JSON; the others are raw bytes as listed.

| Key | Value |
|-----|-------|
| `session_ad:{contact}` | Raw 64-byte X3DH associated data (§5.3) |
| `disappear_timer:{contact}` | Raw 44 bytes: `secs(4, BE) ‖ set_at(8, BE) ‖ setter(32)`; `secs = 0` means off ([S12 §2.2](12-disappearing-messages.md)) |
| `pending_timer:{contact}` | Raw 8 bytes: the `outgoing_frames.id` (i64, BE) carrying the latest local timer change |
| `contact_target:{contact}`, `contact_targets:{contact}` | JSON: the contact's primary route and full route list |
| `contact_handshake:{contact}` | Raw signed handshake payload received from the contact |
| `desktop:reciprocal:{contact}`, `desktop:announced:{contact}`, `desktop:announced-current:{contact}`, `desktop:announced-v2:{contact}:{digest}` | Contact-setup and receive-route announcement obligations |
| `desktop:read-receipt:{contact}:{hex msg_id}` | A pending read-receipt intent, consumed by the send transaction that carries it |
| `desktop:attachment-job:{contact}:{…}` | Raw: `cursor(4, BE) ‖ job data`; at most 4 jobs |
| `desktop:invite:{mailbox}` | JSON: ID of the invitation capability a failed or cancelled request left for retry on a mailbox (§5.20); deleted on export |
| `desktop:invite-wire:{capability}` | JSON `1`: marks an invitation capability whose format the release can reuse; deleted on export |
| `desktop:mailbox:{id}`, `desktop:primary` | JSON: mailbox registration flag; primary mailbox |
| `desktop:responsive` | JSON bool: delivery mode ([S10](10-cover-traffic.md)); set to `true` on first attach if absent |
| `desktop:local-preferences` | JSON `{"lockTimeoutSeconds": u32, "bridges": [string]}` ([S13 §8](13-privacy-hardening.md)) |
| `desktop:auto-retry-v1` | Marker (§5.11) |
| `prekeys:{kind}:{hex scope}`, `prekeys:prepared`, `prekeys:complete` | Prekey publication state (§5.8) |

### 5.17 Outbound Queue

```sql
CREATE TABLE IF NOT EXISTS outgoing_frames (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    contact_id INTEGER NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
    message_id INTEGER REFERENCES messages(id) ON DELETE CASCADE,
    wire BLOB NOT NULL,
    dh_pub BLOB NOT NULL CHECK(length(dh_pub)=32),
    n INTEGER NOT NULL,
    requires_ack INTEGER NOT NULL,
    is_replay INTEGER NOT NULL DEFAULT 0,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt INTEGER NOT NULL DEFAULT 0,
    deposited_at INTEGER,
    UNIQUE(contact_id,dh_pub,n)
);

CREATE TABLE IF NOT EXISTS outbound_message_positions (
    contact_id INTEGER NOT NULL,
    dh_pub BLOB NOT NULL CHECK(length(dh_pub) = 32),
    message_number INTEGER NOT NULL,
    msg_id BLOB NOT NULL,
    PRIMARY KEY (contact_id, dh_pub, message_number),
    FOREIGN KEY (contact_id) REFERENCES contacts(id) ON DELETE CASCADE,
    FOREIGN KEY (msg_id) REFERENCES messages(msg_id) ON DELETE CASCADE
);
```

Each `outgoing_frames` row is one encrypted frame, ready for deposit, at ratchet
position `(dh_pub, n)`. `message_id` is NULL for control frames. `is_replay = 1`
marks a re-deposit of an existing message at a new position. A frame is
eligible while it has no message, or while it is a replay or its message has
status other than 2, 3 or 5, and its message has not expired.

After a deposit attempt (`finish_outgoing`, one transaction):

- **Success:** the message moves to status 1 and its `retry_wire_blob` is
  cleared. A frame with `requires_ack = 0` is deleted. A frame with
  `requires_ack = 1` stays, with `deposited_at` set to the first success time,
  until the peer's ACK covering `(dh_pub, n)` deletes it in a receive
  transaction.
- **Failure:** the message moves to status 4, `retry_count` and `attempts`
  increase (saturating at 4294967295), and `next_attempt` is rescheduled. There
  is no finite retry budget; the same bytes are retried until deposit, ACK or
  expiry.

`outbound_message_positions` maps every position at which a message was sent to
its `msg_id`, so a peer's ACK range reaches the right messages after the repair
buffer (§5.19) has been pruned.

```sql
CREATE TABLE IF NOT EXISTS revocation_frames (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    wire BLOB NOT NULL,
    targets BLOB NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
);
```

A `revocation_frames` row is a deleted contact's RevocationNotice
([S08 §7.1](08-messaging-service.md)). It has no `contact_id`: the contact
delete moves the undeposited frame's `wire` here in the same transaction, with
`targets`, the contact's deposit routes as a JSON list of
`[onion, deposit_capability, envelope_secret]`. The first successful deposit
deletes the row; a failure increases `attempts` and reschedules
`next_attempt`, or deletes the row once it is older than 90 days.

### 5.18 Received Frames and Inbound Work

```sql
CREATE TABLE IF NOT EXISTS received_frames (
    header_id BLOB PRIMARY KEY CHECK(length(header_id)=16),
    contact_id INTEGER NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
    dh_pub BLOB NOT NULL CHECK(length(dh_pub)=32),
    n INTEGER NOT NULL,
    ack_required INTEGER NOT NULL,
    ack_pending INTEGER NOT NULL,
    received_at INTEGER NOT NULL,
    UNIQUE(contact_id,dh_pub,n)
);

CREATE TABLE IF NOT EXISTS inbound_work (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    contact_id INTEGER NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
    body BLOB NOT NULL,
    cursor INTEGER NOT NULL DEFAULT 0
);
```

- `received_frames` has one row per accepted frame, keyed by its header ID
  (§5.7). `ack_pending` starts equal to `ack_required`. The send transaction
  that carries an ACK covering the frame clears it; a duplicate of an
  ACK-requiring frame sets it again. ACK ranges are built from at most 128
  pending rows into at most 16 ranges ([S08 §6](08-messaging-service.md)).
- `inbound_work` holds work created by a receive transaction and carried out
  after it commits. `cursor` makes the work resumable; the row is deleted when
  the work completes.

### 5.19 Outbound Repair History

```sql
CREATE TABLE IF NOT EXISTS outbound_repair_records (
    contact_id       INTEGER NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
    dh_pub           BLOB    NOT NULL CHECK(length(dh_pub) = 32),
    message_number   INTEGER NOT NULL,
    msg_id           BLOB    NOT NULL CHECK(length(msg_id) = 16),
    timestamp        INTEGER NOT NULL,
    logical_seq      INTEGER NOT NULL,
    content_type     INTEGER NOT NULL,
    flags            INTEGER NOT NULL,
    content          BLOB    NOT NULL,
    content_sealed   INTEGER NOT NULL DEFAULT 0,
    created_at       INTEGER NOT NULL,
    PRIMARY KEY (contact_id, dh_pub, message_number)
);
CREATE INDEX IF NOT EXISTS idx_outbound_repair_created
    ON outbound_repair_records (contact_id, created_at DESC);

CREATE TABLE IF NOT EXISTS outbound_history (
    message_id INTEGER PRIMARY KEY REFERENCES messages(id) ON DELETE CASCADE,
    contact_id INTEGER NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
    logical_id BLOB NOT NULL CHECK(length(logical_id)=16),
    logical_seq INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_outbound_history_logical ON outbound_history(contact_id,logical_id);
```

- `outbound_repair_records` keeps the payload fields of recent sent messages by
  ratchet position, so session and gap repair can re-encrypt the same logical
  content with the original `timestamp` and `logical_seq`
  ([S06 §3.7.1](06-key-agreement-ratchet.md), [S08 §6.5](08-messaging-service.md)).
  The newest 256 records per contact are kept; older ones are deleted in the
  send transaction.
- For a disappearing message the record MUST hold the message's sealed content,
  never plaintext; `content_sealed = 1` marks it.
- `outbound_history` maps each sent message that has a repair record to its
  `logical_msg_id` and `logical_seq`, for answering re-send requests.
- Deleting a message, or overwriting its content, deletes both kinds of row
  (§5.25).

### 5.20 Ephemeral Handshake Capabilities

```sql
CREATE TABLE IF NOT EXISTS ephemeral_handshake_caps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mailbox_id INTEGER NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
    deposit_capability BLOB NOT NULL UNIQUE CHECK(length(deposit_capability) = 32),
    fetch_capability BLOB NOT NULL UNIQUE CHECK(length(fetch_capability) = 32),
    envelope_secret BLOB NOT NULL UNIQUE CHECK(length(envelope_secret) = 32),
    capability_type INTEGER NOT NULL DEFAULT 1 CHECK(capability_type = 1),
    expires_at INTEGER NOT NULL,
    registered_at INTEGER,
    accepted_at INTEGER,
    deactivated_at INTEGER,
    created_at INTEGER NOT NULL,
    CHECK(expires_at > created_at)
);
CREATE INDEX IF NOT EXISTS idx_ephemeral_handshake_caps_active
    ON ephemeral_handshake_caps(mailbox_id, expires_at)
    WHERE registered_at IS NOT NULL AND deactivated_at IS NULL;
```

One row per invitation receive route ([S05 §5](05-contact-establishment.md)). The
desktop client creates each row with three fresh random 32-byte values and
`expires_at = created_at + EPHEMERAL_CAP_TTL_SECS` (172800 s, 48 hours). A
capability MUST NOT be advertised before `registered_at` is set. The receive
transaction that accepts the first Initial message through it sets
`accepted_at`; the update requires the row to be registered, not yet accepted
and not deactivated, and the whole receive transaction fails otherwise.

### 5.21 Pending Introductions

```sql
CREATE TABLE IF NOT EXISTS pending_introductions (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    introducer_contact_id   INTEGER NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
    introduced_ik_pub       BLOB    NOT NULL CHECK(length(introduced_ik_pub) = 32),
    introduced_display_name TEXT    NOT NULL,
    introducer_ik_pub       BLOB    NOT NULL CHECK(length(introducer_ik_pub) = 32),
    payload_blob            BLOB    NOT NULL,
    is_anonymous            INTEGER NOT NULL DEFAULT 0,
    status                  INTEGER NOT NULL DEFAULT 0,
    created_at              INTEGER NOT NULL,
    expires_at              INTEGER NOT NULL,
    resolved_at             INTEGER
);
CREATE INDEX IF NOT EXISTS idx_pending_intro_status ON pending_introductions(status);
CREATE INDEX IF NOT EXISTS idx_pending_intro_introducer
    ON pending_introductions(introducer_contact_id);
```

A received introduction control is stored by its receive transaction, unless a
pending row (`status = 0`) for the same `introduced_ik_pub` already exists.
Status codes: `0` pending, `1` accepted, `2` rejected, `3` expired. The
retention pass (§6.4) sets pending rows past `expires_at` to `3`, so an expired
introduction no longer blocks a new one for the same person.

### 5.22 Epoch Quarantine

```sql
CREATE TABLE IF NOT EXISTS epoch_quarantine (
    blob_hash      BLOB PRIMARY KEY,
    blob           BLOB NOT NULL,
    quarantined_at INTEGER NOT NULL
);
```

Holds raw received blobs that belong to a ratchet epoch the receiver cannot
process yet ([S08 §6](08-messaging-service.md)). `blob_hash` is SHA-256 of the
blob. At most `EPOCH_QUARANTINE_MAX = 32` frames are held; further frames are
not quarantined.

### 5.23 Retired Prekey IDs

```sql
CREATE TABLE IF NOT EXISTS prekey_used_ids (
    key_id BLOB PRIMARY KEY CHECK(length(key_id)=4)
);
```

Every prekey ID ever issued. Rows are never deleted, so a retired or recovered
prekey ID is never reused (§5.8).

### 5.24 Browser File Transfers

```sql
CREATE TABLE IF NOT EXISTS browser_transfers (
    id TEXT PRIMARY KEY CHECK(length(id)=32),
    contact_id INTEGER NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
    fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32),
    manifest BLOB NOT NULL,
    size INTEGER NOT NULL CHECK(size BETWEEN 1 AND 268435456),
    received INTEGER NOT NULL DEFAULT 0,
    state INTEGER NOT NULL DEFAULT 0,
    cursor INTEGER NOT NULL DEFAULT 0,
    metadata BLOB,
    error TEXT,
    created_at INTEGER NOT NULL,
    UNIQUE(contact_id,fingerprint)
);
CREATE TABLE IF NOT EXISTS browser_transfer_parts (
    transfer_id TEXT NOT NULL REFERENCES browser_transfers(id) ON DELETE CASCADE,
    kind INTEGER NOT NULL CHECK(kind IN (0,1)),
    part INTEGER NOT NULL CHECK(part>=0),
    data BLOB NOT NULL CHECK(length(data)<=1048576),
    PRIMARY KEY(transfer_id,kind,part)
);
CREATE TABLE IF NOT EXISTS browser_download_grants (
    digest BLOB PRIMARY KEY CHECK(length(digest)=32),
    contact_id INTEGER NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
    message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL
);
DROP INDEX IF EXISTS idx_browser_file_parts;
```

All upload and prepared bytes stay inside SQLCipher. No plaintext staging file
and no browser credential is written ([S11](11-file-transfer-sanitization.md)).

| Item | Rule |
|------|------|
| `id` | 32 hex characters |
| `manifest` | At most 32768 bytes |
| `size` | 1 to 268435456 bytes (256 MiB) |
| `metadata` | At most 4096 bytes |
| Part `kind` | `0` uploaded source part, `1` prepared output part; each at most 1048576 bytes |
| `state` | `0` uploading, `1` uploaded (sealed when `received = size`), `2` prepared, `3` sent, `4` failed |
| Concurrency | At most 4 active jobs: transfers with `state < 3` plus `desktop:attachment-job:*` settings |
| Creation | Only for an existing, unblocked contact. A finished or failed transfer with the same `(contact, fingerprint)` is replaced; an active one is returned |
| Cleanup | Source parts are deleted when output is finished; all parts are deleted on completion or failure. Cancellation is allowed in states 0 and 4 |
| Download grant | `digest = SHA-256(ticket)`, where the ticket is the 64-character lowercase-hex form of 32 random bytes. `expires_at = now + 3600`. Expired grants are deleted when the next grant is created |

### 5.25 Triggers

```sql
CREATE TRIGGER IF NOT EXISTS message_key_deadline AFTER UPDATE OF disappear_at ON messages
BEGIN
    UPDATE volatile_keys SET expires_at=NEW.disappear_at WHERE msg_id=NEW.msg_id;
END;
CREATE TRIGGER IF NOT EXISTS message_secrets_deleted AFTER DELETE ON messages
BEGIN
    DELETE FROM volatile_keys WHERE msg_id=OLD.msg_id;
    DELETE FROM outbound_repair_records WHERE msg_id=OLD.msg_id;
END;
CREATE TRIGGER IF NOT EXISTS message_repair_overwritten AFTER UPDATE OF content ON messages
BEGIN
    DELETE FROM outbound_repair_records WHERE msg_id=OLD.msg_id;
END;
CREATE TRIGGER IF NOT EXISTS message_outbox_overwritten AFTER UPDATE OF content ON messages
BEGIN
    DELETE FROM outgoing_frames WHERE message_id=NEW.id;
    DELETE FROM outbound_history WHERE message_id=NEW.id;
END;
```

Overwriting a message's content is the first step of secure deletion
([S12 §5](12-disappearing-messages.md)). These triggers guarantee that a wiped
message leaves no key, no repair copy, no queued frame and no re-send source.

### 5.26 Dummy Capabilities

```sql
CREATE TABLE IF NOT EXISTS dummy_capabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mailbox_id INTEGER NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
    fetch_capability BLOB NOT NULL UNIQUE CHECK(length(fetch_capability) = 32),
    deposit_capability BLOB NOT NULL UNIQUE CHECK(length(deposit_capability) = 32),
    registered_at INTEGER
);
```

Self-owned queues that pad real polls ([S08 §6.1.1](08-messaging-service.md),
[S10 §5.1](10-cover-traffic.md)). The provisioning loop creates nine rows per
mailbox with random 32-byte values and sets `registered_at` once the server accepts
the pair. Only registered rows are polled or deposited to. Row order (`id`) is the
order in which dummies join a mailbox's poll pool. A dummy has no envelope secret.
An existing profile gains the table on its next open (§8).

## 6. Storage Trait Interface

The messaging core talks to storage through the async trait `CoreStorage`
(`crates/najwa-core/src/storage.rs`). `SqliteStorage` implements it in
`crates/najwa-core/src/bridge.rs` by calling the synchronous `najwa-storage`
methods; the disappearing-message manager uses `DisappearingStorage`
([S12 §7](12-disappearing-messages.md)) the same way. `CoreStorage` covers:

- contacts, pseudonyms, the per-contact outbound sequence and capabilities;
- ratchet state, session AD and skipped keys;
- the atomic commits of §6.1;
- the outbound queue, ACK ranges, received frames and inbound work;
- transport and logical dedup;
- mailboxes, mailbox health and ephemeral handshake capabilities;
- prekeys;
- disappearing-message timers, deadlines and volatile keys;
- identity history, pending introductions and the epoch quarantine;
- WAL checkpoint.

### 6.1 Durability and Transaction Requirements

The ratchet state-commit invariants of [S06 §3.11](06-key-agreement-ratchet.md)
land here.

**One-transaction receive (I3).** `commit_incoming` runs these steps in one
transaction, after the frame has been authenticated and decrypted:

1. If the frame's header ID is already in `msg_id_cache_transport`, stop and
   commit nothing.
2. Write the ratchet state (§5.4) and replace the contact's skipped keys (§5.5).
3. For an Initial message: write `session_ad:{contact}`, mark the consumed OPK
   used, and mark the ephemeral handshake capability accepted (§5.20).
4. If the frame carries a message and neither its transport ID nor its logical
   ID is cached, insert the message.
5. Mark the transport ID, the logical ID and the header ID as seen (§5.7).
6. Insert the `received_frames` row (§5.18).
7. Apply every control effect: timer change, settings, peer identity rotation
   and history, session reset, revocation (deletes the contact), introduction,
   additional messages, skipped-key range removal, repaired position, inbound
   work, delivery confirmation (ACK ranges delete queued frames and advance
   message status; a read receipt sets status 3).

Any failure rolls the whole transaction back. The blob MUST be acknowledged to
the mailbox only after this transaction commits.

**Persist-before-send (I2).** `commit_outgoing` runs these steps in one
transaction, after encryption and before any transport call:

1. If the frame carries a read receipt, consume its intent setting; fail if it
   is gone.
2. Write the advanced ratchet state and skipped keys.
3. Write `session_ad:{contact}` when establishing a session.
4. For a new message: insert the message with `retry_wire_blob = wire`, insert
   its position (§5.17), insert its repair record and history row (§5.19), and
   prune repair records to 256. For a replay: verify the message is a live sent
   message and insert the new position.
5. Insert the `outgoing_frames` row with the exact wire bytes.
6. Clear `ack_pending` for the ranges this frame acknowledges.
7. For a timer change: write `disappear_timer:{contact}` and
   `pending_timer:{contact}`. A timer below 30 seconds is rejected.

The transport sends only bytes read from `outgoing_frames`, or from
`revocation_frames` after their contact is deleted (§5.17). After a restart,
queued frames are deposited again unchanged; `ratchet_encrypt` is never re-run
for them.

**Other atomic operations.** Each of these is one transaction:

| Operation | Effect |
|-----------|--------|
| `commit_contact_establishment` | Contact row, `contact_target`, `contact_targets` and `contact_handshake` settings, and the local capabilities. A duplicate identity fails with `AlreadyExists` and leaves nothing behind |
| `commit_prekey_batch`, `prepare_prekey_recovery` | §5.8 |
| `finish_outgoing` | Message status and frame update after a deposit attempt (§5.17) |
| `retire_undeposited_contact_setup` | Retires a contact-setup message that was never deposited and deletes its frames; a concurrent deposit wins |
| `replace_volatile_keys`, `take_live_volatile_keys` | §5.13 |
| `delete_contact` | §5.2 |
| Display marking | `read_at` and timer start for displayed received messages |
| Transfer state changes | §5.24 |
| `init_schema` | §8 |

### 6.2 Crash Consistency

- Every connection uses `synchronous = FULL` in WAL mode. A transaction is
  durable once `COMMIT` returns: the WAL is synced at every commit.
- A crash leaves either the complete state before a transaction or the complete
  state after it.
- Schema creation is one transaction. An interrupted first open leaves no
  partial schema, and the next open completes it.
- Files outside the database (identity record, recovery record, browser grant,
  instance record) are written atomically: write a randomly named temporary
  file, sync it, rename it over the target, then sync the directory where the
  platform allows ([S02](02-identity-key-protection.md)).
- Local erasure persists its intent before deleting anything
  ([S13 §10](13-privacy-hardening.md)).

### 6.3 WAL Behavior

- The database runs in WAL mode next to two companion files, `najwa.db-wal` and
  `najwa.db-shm`. WAL frames contain encrypted page images. The WAL header and
  frame headers (page numbers, commit sizes, salts, checksums) and the `-shm`
  index are plaintext bookkeeping.
- Older page images stay in the WAL until a checkpoint copies them back and the
  WAL is reset. SQLite's automatic checkpoint runs at its default threshold.
- `wal_checkpoint` runs `PRAGMA wal_checkpoint(TRUNCATE)` and fails unless the
  result reports `busy = 0` and every WAL frame checkpointed.
- The lock procedure checkpoints after saving volatile keys, so a locked
  profile leaves an empty WAL ([S13 §8.2](13-privacy-hardening.md)). If the
  checkpoint cannot complete, the lock fails and keys stay in memory.
- Secure deletion of disappearing messages checkpoints after overwriting
  content ([S12 §5](12-disappearing-messages.md)).

### 6.4 Retention Pass

`SqliteStorage::run_retention_cleanup` bounds the tables that receive traffic
keeps adding to:

| Table | Removed |
|-------|---------|
| `msg_id_cache_transport`, `msg_id_cache_logical` | `seen_at` older than 91 days (§5.7) |
| `skipped_keys` | `expires_at < now`, that is 90 days after `created_at` (§5.5) |
| `pending_introductions` | none; pending rows past `expires_at` become `status = 3` (§5.21) |

The cleaner that `najwa-ffi` starts at unlock ([S12 §6](12-disappearing-messages.md))
runs it on its first tick after unlock and then once an hour, so it runs only
while the profile is unlocked.
The pass runs on the cleaner task, not on the receive path; each statement
holds the connection lock only while it runs.

## 7. Per-Row Field Encryption (Defense-in-Depth)

The most sensitive columns carry a second layer of encryption inside SQLCipher:

| Table | Columns | `row_id` |
|-------|---------|----------|
| `ratchet_sessions` | `dhs_private`, `rk`, `cks`, `ckr` | `contact_id` |
| `prekeys` | `private_key` | `key_id` read as a big-endian u32 |

```
row_key = HKDF-SHA256(
    IKM    = db_key,
    salt   = UTF-8(table_name),           // "ratchet_sessions" or "prekeys"
    info   = row_id as i64, 8 bytes, BE,
    length = 32
)
nonce  = CSPRNG(24)
stored = nonce(24) ‖ XChaCha20-Poly1305(row_key, nonce, plaintext, AAD = "field")
                                          // AAD: 5 bytes, 6669656C64
plaintext = XChaCha20-Poly1305-Decrypt(row_key, stored[0:24], stored[24:], AAD = "field")
```

- A 32-byte secret is stored as 72 bytes.
- Every write seals with a fresh random nonce.
- A field that fails to decrypt MUST fail the read. There is no plaintext
  fallback.
- Decrypted values are held in zeroizing buffers and moved into record types
  that zeroize on drop.
- Other secrets (skipped message keys, capabilities, envelope secrets, session
  AD, repair records) are protected by SQLCipher alone. Disappearing-message
  content and volatile keys have their own encryption (§5.6, §5.13).

Because every `row_key` derives from `db_key`, this layer does not protect
against a party that holds `db_key`. It confines a raw copy of a single field to
the row it came from: a sealed value moved to another row or table fails
authentication.

## 8. Schema Initialisation

There is one schema, version `2`. `init_schema` runs inside every open (§4.1):

```
func init_schema(conn):
    BEGIN IMMEDIATE
    if table db_meta exists:
        v = SELECT value FROM db_meta WHERE key = 'schema_version'
        if v exists and v != '2':
            ROLLBACK; fail "database schema version {v} is not supported"
    execute schema.sql                         // every statement IF NOT EXISTS
    if outgoing_frames has no column deposited_at:
        ALTER TABLE outgoing_frames ADD COLUMN deposited_at INTEGER
    if outbound_repair_records has no column content_sealed:
        ALTER TABLE outbound_repair_records ADD COLUMN content_sealed INTEGER NOT NULL DEFAULT 0
        DELETE repair records with no matching message
        for repair records of disappearing messages:
            content = the message's sealed content; content_sealed = 1
    if ratchet_sessions has no column prev_dhs_pub:
        ALTER TABLE ratchet_sessions ADD COLUMN prev_dhs_pub BLOB
    INSERT OR IGNORE INTO db_meta VALUES ('schema_version', '2')
    UPDATE volatile_keys SET expires_at = disappear_at of its message,
        for messages with disappear_at set
    COMMIT
```

- A database stamped with any other version MUST be refused. It MUST NOT be read
  as if compatible.
- Supported changes are additive and MUST keep existing profiles readable.
- Any failure rolls back all DDL and data changes of the call.
- `schema.sql` is the normative DDL for §5.

## 9. Reserved

## 10. Rust Crate Dependencies

| Crate | Purpose |
|-------|---------|
| `najwa-crypto` | HKDF-SHA256, XChaCha20-Poly1305, SHA-256, CSPRNG |
| `rusqlite` 0.38 (`bundled-sqlcipher-vendored-openssl`) | SQLCipher binding |
| `serde`, `serde_json` | Settings values |
| `zeroize` | Key and plaintext buffers |
| `fs2` | `.gate` and `.lease` file locks |
| `tempfile` | Temporary staging files |
| `thiserror`, `tracing` | Errors and diagnostics |

## 11. On-Disk Profile Layout

The profile directory defaults to `profile` inside the per-user application data
directory:

| Platform | Default path |
|----------|--------------|
| Windows | `%LOCALAPPDATA%\Najwa\Najwa Web\data\profile` |
| Linux | `$XDG_DATA_HOME/najwaweb/profile` (default `~/.local/share/najwaweb/profile`) |
| macOS | `~/Library/Application Support/org.Najwa.Najwa-Web/profile` |

`--profile DIRECTORY` selects another directory. On Unix the service sets the
directory mode to `0700` at startup.

| Path | Content | Protection |
|------|---------|-----------|
| `owner.lock` | Empty. Exclusive OS file lock held by the running service; a second instance cannot open the profile | — |
| `identity.najwa` | Identity record ([S02 §7](02-identity-key-protection.md)); its public key is readable | Passphrase + device key |
| `identity.recovery` | Recovery record | Recovery words |
| `identity.counter.<key id>`, `identity.timing.<key id>` | Unlock-attempt counter and Argon2 timing ([S02 §10](02-identity-key-protection.md)) | HMAC with the device key |
| `identity.tmp.<16 hex>` | Transient atomic-write file | As the target |
| `prekey-recovery-<64 hex ik_pub>` | 32 random bytes: prekey-recovery generation marker. The name contains the identity public key | None |
| `najwa.db` | SQLCipher database (§5) | SQLCipher |
| `najwa.db-wal`, `najwa.db-shm` | WAL and WAL index (§6.3) | Pages encrypted; headers plaintext |
| `najwa.db.gate`, `najwa.db.lease` | Empty lock files (§4.1) | — |
| `browser-access.json` | `{"token", "expires_at"}`: the 30-day browser grant ([S13 §19](13-privacy-hardening.md)); mode `0600` on Unix | None |
| `web-instance.json` | `{"port", "session", "token"}` while the service runs; removed at exit | Directory permissions |
| `web-launch.html` | Linux and macOS only: redirect page to the tokenized launch URL ([S13 §19](13-privacy-hardening.md)); replaced on each launch, removed at exit | Mode `0600`, directory permissions |
| `wipe.pending` | Present only while an erasure is incomplete ([S13 §10](13-privacy-hardening.md)) | Identity-record encryption |
| `tor/cache/`, `tor/state/` | Arti directory cache and state ([S04](04-transport.md)) | None |

The device-key factor is not in the directory. It lives in the OS key store
under the name `Najwa/DKM/record/<key id>`, sealed by the TPM or Secure Enclave
where available ([S02 §17](02-identity-key-protection.md)).

## 12. Security Considerations

- **Metadata.** SQLCipher hides content, not the existence of the profile, file
  sizes, modification times, WAL bookkeeping, the Tor state directory or the
  identity public key (readable in the identity record and in the
  `prekey-recovery-*` file name).
- **One key for the life of the identity.** `db_key` derives from the identity
  seed and never rotates. Changing the passphrase does not change it. Anyone who
  obtains the identity seed (an unlocked process, or the recovery words plus the
  recovery record) can decrypt every copy of the database, including old copies
  in backups, snapshots or file-sync tools.
- **Raw key.** SQLCipher's passphrase KDF is not used; the key is a 256-bit
  HKDF output, so `kdf_iter` adds no work for an attacker.
- **Secrets under SQLCipher only.** Skipped message keys, capabilities, envelope
  secrets and the content of ordinary messages are readable by anyone holding
  `db_key`.
- **Copies and restores.** Running a copy of a profile, or reverting a profile
  to an older copy, reuses ratchet state, prekeys and dedup state. That can
  break forward secrecy, accept replays the newer state would reject, and
  desynchronise sessions. One profile MUST be operated by one service at a time
  (`owner.lock`). A copy of the directory is not a supported backup; the
  recovery kit restores the identity, not the history
  ([S02 §13](02-identity-key-protection.md)).
- **Deletion inside the file.** `secure_delete` zeroes freed pages and the lock
  checkpoint empties the WAL, but SSD wear levelling, copy-on-write file
  systems, file-system journals and OS snapshots can keep older encrypted pages.
  These remain decryptable with `db_key`.
- **Growth.** Dedup caches hold about 91 days of received frames (§6.4).
  `received_frames` and `identity_history` are never pruned; they grow with the
  number of frames received over the profile's life.

## 13. Conformance Checklist

- SQLCipher keyed through `sqlite3_key` with raw key data built in a zeroizing
  buffer; `db_key` derived per §3.
- Cipher pragmas and hardening pragmas of §4.2 set on every open, after keying
  and before the first read.
- `synchronous = FULL` and `foreign_keys = ON` on every connection.
- `verify_hardening` checks `temp_store`, `journal_mode` and the main-file
  plaintext header after schema initialisation; the WAL header is not tested.
- `.gate` exclusive lock during open; `.lease` shared lock for the connection's
  lifetime.
- Schema of §5 created from `schema.sql` in one transaction; version `2`
  stamped; any other stored version refused; additive repairs of §8 applied.
- Single-transaction receive (I3) and persist-before-send (I2) per §6.1;
  mailbox acknowledgement only after the receive commit; deposits only from
  `outgoing_frames`, or from `revocation_frames` for a deleted contact's
  RevocationNotice (§5.17).
- Skipped keys replaced per contact in every ratchet commit and never written
  before AEAD verification.
- Two dedup caches with transport, header and logical IDs; nothing younger than
  90 days removed.
- Retention pass of §6.4 on the first cleaner tick after unlock and hourly
  while unlocked: dedup rows older than 91 days, expired skipped keys, expired
  pending introductions.
- Field encryption of `dhs_private`, `rk`, `cks`, `ckr` and prekey
  `private_key` per §7, with fail-closed decryption.
- Volatile keys saved only at lock, taken back at unlock in one transaction
  that discards expired keys first (§5.13).
- Triggers of §5.25 remove keys, repair copies, queued frames and re-send
  sources when a message is deleted or overwritten.
- Prekey batches insert-only, OPK pool ≤ 200 per mailbox scope, prekey IDs
  never reused.
- `wal_checkpoint(TRUNCATE)` fails when blocked; the lock procedure uses it.
- Secret-bearing record types (`RatchetState`, `SkippedKey`, `Prekey`) zeroize on
  drop and never print secret bytes through `Debug`.
