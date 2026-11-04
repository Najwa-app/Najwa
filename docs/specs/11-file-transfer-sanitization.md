---
id: S11
title: File Transfer & Media Sanitization
crates: [najwa-sanitize, najwa-protocol, najwa-core, najwa-storage, najwa-ffi]
depends-on: [S03, S04, S06, S07, S08, S10, S12, S16]
---

# S11 — File Transfer & Media Sanitization

## Overview

Najwa sends a file as a sequence of ordinary one-to-one messages. Before any
byte of the file leaves the device, the native service rewrites it to remove
identifying metadata: camera GPS coordinates, author names, editing software,
creation dates and similar fields. A file that the service cannot clean is
refused. It is never sent as-is.

A transfer has four stages:

1. **Local staging.** The browser UI reads the selected file in 1 MiB parts,
   hashes each part with SHA-256, and uploads the parts over loopback into the
   profile's encrypted store ([S03](03-encrypted-storage.md)). Saved parts
   survive a lock or restart. Selecting the same file again skips the parts
   already saved.
2. **Preparation.** The native service sanitizes the staged file. Decodable
   images (JPEG, PNG, GIF, BMP, TIFF) are decoded to pixels and re-encoded as
   WebP, which discards the original container and everything in it. WebP,
   video, audio and document files are rewritten with their metadata removed.
   HEIC and unrecognized files are refused. The sanitized output is split into
   parts of 245,760 bytes and described by a `FileMetadata` record that carries
   the file name, size, MIME type, part count and SHA-256 hash.
3. **Delivery.** The metadata record and each part become separate encrypted
   pairwise messages, content types `0x10` and `0x11`
   ([S07](07-message-format.md)). They enter the ordinary outbox
   ([S08](08-messaging-service.md)) behind chat and control traffic, and each
   is deposited at the recipient's mailbox like any other message.
4. **Reception and download.** The recipient stores each part as it arrives,
   in any order. If parts stop arriving while some are missing, the recipient
   asks the sender to re-send them (`FileChunkNack`, §4.1). When every part is
   present, a download request checks each
   part and the SHA-256 hash of the whole file, then issues a one-hour,
   single-file download link. The browser fetches it with resumable HTTP range
   requests.

The maximum file size is 256 MiB; the UI labels it "256 MB". The UI
recommends 10 MB or less, because every part is a separate deposit over Tor: a
10 MB file needs 42 deposits and a 256 MiB file needs 1,094. Sending a file
requires the conversation's disappearing-message timer to be off.

The delivery mode ([S10](10-cover-traffic.md)) decides how parts reach the
mailbox. In the default Responsive mode, the parts of one file sent to one
mailbox share an isolated Tor circuit ([S04](04-transport.md)). In Timing
privacy mode, each deposit waits for a cover slot and uses a fresh circuit.

## 1. Scope

This specification defines:

- size limits and part constants (§2.1);
- the byte-exact `FileMetadata` (`0x10`), `FileChunk` (`0x11`) and
  `FileChunkNack` (control subtype `0x3C`) layouts (§2.2.1);
- splitting, assembly and filename rules (§2.3–§2.6);
- persisted progress (§3);
- outbound queueing, part validation, retransmission and retention (§4);
- the sanitization pipeline, file type detection, per-format processing and
  verification (§5–§8);
- integration with messaging: send and receive flows, the disappearing-timer
  rule, local staging and resume, circuit policy, download, the single-request
  path and error codes (§9).

Message envelopes, the payload header and padding buckets are in
[S07](07-message-format.md). Outbox, acknowledgement and repair rules are in
[S08](08-messaging-service.md). Mailbox quotas and retention are in
[S16](16-mailbox-server.md).

## 2. File Chunking

### 2.1 Constants

| Constant | Value | Defined in | Meaning |
|---|---|---|---|
| `MAX_FILE_SIZE` | 268,435,456 (256 MiB) | `najwa-protocol` `message::file_transfer`; `najwa-core` `filetransfer` | Largest `total_size` a sender emits or a receiver accepts |
| `MAX_TRANSFER` | 268,435,456 | `najwa-storage` `transfers` | Largest staged upload and largest sanitized output |
| `MAX_CHUNK_SIZE` | 245,760 | `najwa-protocol` `message::file_transfer` | Data bytes per wire part |
| `UPLOAD_PART` | 1,048,576 | `najwa-storage` `transfers` | Browser upload part size |
| `MAX_BROWSER_FILE` | 8,388,608 | `najwa-ffi` `desktop_files` | Input and output limit of the single-request path (§9.7) |
| `NACK_MAX_INDICES` | 256 | `najwa-protocol` `message::file_transfer` | Maximum indices in one `FileChunkNack` |
| `NACK_MIN_INTERVAL_SECS` | 600 | `najwa-protocol` `message::file_transfer` | Quiet period before a receiver's first `FileChunkNack` for a file, doubled for each later one; a sender answers at most one per file and contact per interval (§4.1) |
| `NACK_MAX_ATTEMPTS` | 4 | `najwa-protocol` `message::file_transfer` | `FileChunkNack`s per received file before the file is reported failed (§4.1) |
| Filename bound | 255 bytes | §2.2.1 | Maximum `filename_len` |
| MIME bound | 127 bytes | §2.2.1 | Maximum `mime_type_len` |
| Sanitizer buffer | 65,536 bytes | `najwa-sanitize` `stream` | Copy buffer of the streamed formats (§5.6) |
| Download grant lifetime | 3,600 s | `najwa-storage` `transfers` | Validity of a download link (§9.6) |
| `ORPHAN_PART_BYTES` | 268,461,688 | `najwa-storage` `transfers` | Stored part bodies per contact without received metadata: the 1,093 bodies of one 256 MiB file (§4.3) |
| `ORPHAN_PART_SECS` | 604,800 (7 days) | `najwa-storage` `transfers` | Age after which a part without received metadata is deleted (§4.3) |
| Recommended size | 10 MB | UI text | Guidance only; not enforced |

`chunk_count(total_size) = ceil(total_size / MAX_CHUNK_SIZE)`. A 0-byte file has
0 parts. The app never sends one: staging rejects a size of 0.

The 256 MiB limit is enforced at each stage:

- the UI refuses a file of 0 bytes or more than 256 × 1,048,576 bytes;
- staging rejects a manifest size of 0 or above `MAX_TRANSFER`, and the
  `browser_transfers.size` column carries `CHECK(size BETWEEN 1 AND 268435456)`;
- the sanitizer rejects an input above 268,435,456 bytes and an in-memory
  output above that size, and the output writer refuses to grow past
  `MAX_TRANSFER`;
- preparation rejects an empty or oversized output with `file_too_large`;
- `FileMetadata` parsing rejects `total_size > MAX_FILE_SIZE`; display reports
  metadata above `MAX_TRANSFER` as unsupported, and download refuses it.

### 2.2 Records

```rust
struct FileMetadata {          // content_type 0x10
    session_id: [u8; 16],      // transfer identifier, 16 CSPRNG bytes
    filename: String,          // display hint, never a path (§2.5)
    total_size: u64,           // bytes of the sanitized file
    mime_type: String,         // FileType::mime_type() of the sanitized output (§6.1)
    chunk_count: u32,          // chunk_count(total_size)
    sha256_hash: [u8; 32],     // SHA-256 of the whole sanitized file
}

struct FileChunkWire {         // content_type 0x11
    session_id: [u8; 16],
    index: u32,                // 0-based part index
    data: Vec<u8>,             // at most MAX_CHUNK_SIZE bytes
}

struct FileChunkNack {         // control subtype 0x3C
    session_id: [u8; 16],
    missing_indices: Vec<u32>, // 1..=256 entries, strictly ascending
}
```

The sender's service generates the 16-byte transfer identifier when staging
begins (§9.4). The same bytes are the wire `session_id`; their lowercase hex
form names the local staging record.

### 2.2.1 Wire Layouts (normative, byte-exact)

All integers are big-endian. Strings are UTF-8 with a u16 byte-length prefix.
Each body below is the `content` field of the S07 payload;
[S07 §4.1](07-message-format.md) registers the content-type bytes and
[Message Types](../reference/message-types.md) registers the control subtype.
[Wire Formats](../reference/wire-formats.md) indexes these layouts; this
section is authoritative.

**`FileMetadata` — `content_type = 0x10`.** With `n = filename_len` and
`m = mime_type_len`, the body is `64 + n + m` bytes:

| Offset | Size | Field | Rule |
|---|---|---|---|
| 0 | 16 | `session_id` | |
| 16 | 2 | `filename_len` | 1 ≤ n ≤ 255 |
| 18 | n | `filename` | valid UTF-8 |
| 18 + n | 8 | `total_size` | ≤ `MAX_FILE_SIZE` |
| 26 + n | 2 | `mime_type_len` | m ≤ 127 |
| 28 + n | m | `mime_type` | valid UTF-8 |
| 28 + n + m | 4 | `chunk_count` | = chunk_count(`total_size`) |
| 32 + n + m | 32 | `sha256_hash` | |

A parser MUST reject: a body shorter than 64 bytes; a field that runs past the
end of the body; `filename_len > 255`; an empty filename; invalid UTF-8 in
either string; `total_size > MAX_FILE_SIZE`; `mime_type_len > 127`; a
`chunk_count` other than chunk_count(`total_size`); any byte after
`sha256_hash`.

Example with an illustrative hash: session `00 01 … 0f`, filename `a.webp`,
1,000 bytes, `image/webp`, one part. The body is 80 bytes:

```
00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f   session_id
00 06 61 2e 77 65 62 70                           filename_len = 6, "a.webp"
00 00 00 00 00 00 03 e8                           total_size = 1000
00 0a 69 6d 61 67 65 2f 77 65 62 70               mime_type_len = 10, "image/webp"
00 00 00 01                                       chunk_count = 1
<32 bytes: SHA-256 of the 1,000-byte sanitized file>
```

**`FileChunk` — `content_type = 0x11`.** The body is `24 + data_len` bytes:

| Offset | Size | Field | Rule |
|---|---|---|---|
| 0 | 16 | `session_id` | |
| 16 | 4 | `index` | |
| 20 | 4 | `data_len` | ≤ 245,760 |
| 24 | `data_len` | `data` | |

A parser MUST reject a body shorter than 24 bytes, `data_len > MAX_CHUNK_SIZE`,
or a body length other than `24 + data_len`. A full part body is 245,784
bytes. With the S07 payload header it pads into the 262,144-byte bucket
([S07 §5](07-message-format.md)).

**`FileChunkNack` — control subtype `0x3C`.** The body of a
`content_type = 0x20` control message is `19 + 4 × missing_count` bytes:

| Offset | Size | Field | Rule |
|---|---|---|---|
| 0 | 1 | subtype | `0x3C` |
| 1 | 16 | `session_id` | |
| 17 | 2 | `missing_count` | 1 ≤ count ≤ 256 |
| 19 | 4 × count | `missing_index_0 … missing_index_{count−1}` | u32 each, strictly ascending |

A parser MUST reject a count of 0, a count above `NACK_MAX_INDICES`, any other
body length, and indices that are not strictly ascending. Semantics: §4.1.

Test vectors for these layouts: [S18](18-test-vectors.md).

### 2.3 Chunking Procedure

```
func split(sanitized, transfer_id, original_name, output_type) -> (FileMetadata, parts):
    size  = len(sanitized)                          // 1 ≤ size ≤ MAX_TRANSFER
    count = ceil(size / MAX_CHUNK_SIZE)
    for i in 0 .. count:
        parts[i] = sanitized[i·MAX_CHUNK_SIZE .. min((i+1)·MAX_CHUNK_SIZE, size)]
    meta = FileMetadata {
        session_id:  transfer_id,
        filename:    output_filename(original_name, output_type),   // §2.5
        total_size:  size,
        mime_type:   output_type.mime_type(),                       // §6.1
        chunk_count: count,
        sha256_hash: SHA-256(sanitized),
    }
    return (meta, parts)
```

Every part except the last is exactly `MAX_CHUNK_SIZE` bytes; the last holds
the remainder. In the staged path the sanitizer writes its output directly as
stored parts of `MAX_CHUNK_SIZE` bytes, so stored output part `i` is wire part
`i` (§9.1).

### 2.4 Assembly Procedure

Assembly returns a `Result`. No step may panic, because stored parts come from
a remote peer.

```
func assemble(contact, direction, meta) -> Result<stream of bytes>:
    if meta.total_size > MAX_TRANSFER: return Err(file_too_large)
    hasher = SHA-256()
    for i in 0 .. meta.chunk_count:
        rows = stored FileChunk bodies for (contact, direction, meta.session_id, index i)
        if rows is empty: return Err(file_unavailable)
        if any row is longer than 24 + MAX_CHUNK_SIZE or two rows differ:
            return Err(invalid_file)
        part = FileChunkWire.parse(rows[0])?                     // §2.2.1
        expected = min(MAX_CHUNK_SIZE, meta.total_size − i·MAX_CHUNK_SIZE)
        if part.session_id ≠ meta.session_id or part.index ≠ i or len(part.data) ≠ expected:
            return Err(invalid_file)
        hasher.update(part.data)
        yield part.data
    if hasher.finalize() ≠ meta.sha256_hash: return Err(invalid_file)
```

Identical duplicate rows are normal (a re-sent part) and are absorbed. The
service holds one part in memory at a time.

### 2.5 Filename Sanitization

The `filename` field is a display hint. It is never a path. A receiver MUST NOT
pass it to a filesystem API as a path or as part of one. When a file is saved,
the saving agent chooses the location and the sanitized name is at most the
leaf component. Downloads are offered with `Content-Disposition: attachment`
(§9.6).

A sender MUST apply `sanitize_filename` before encoding `FileMetadata`. A
receiver MUST apply it to every received name before display or use,
regardless of what the sender did.

```
func sanitize_filename(name) -> String:
    name = the last component of name after splitting on '/' and '\'
    remove every Unicode Cc control character
    remove U+200E, U+200F, U+202A–U+202E, U+2066–U+2069, U+061C,
           U+200B–U+200D and U+FEFF                // bidi and zero-width controls
    trim trailing '.' and ' ', then leading whitespace
    if name ∈ {"", ".", ".."}: name = "unnamed"
    stem = ASCII-uppercase(name up to the first '.')
    if stem ∈ {CON, PRN, AUX, NUL, COM1–COM9, LPT1–LPT9}: name = "_" + name
    truncate name to at most 255 bytes on a UTF-8 character boundary
    return name
```

The desktop service also applies `display_filename` to the staged upload name
on send, and to every name it displays or offers for download:

```
func display_filename(name) -> String:
    name = the last component of name after splitting on '/' and '\'
    remove Unicode Cc control characters and the characters < > : " | ? *
    remove U+200B–U+200F, U+202A–U+202E, U+2066–U+2069, U+061C and U+FEFF
    keep the first 120 characters
    trim leading and trailing ' ' and '.'
    if name is empty: return "attachment"
    stem = ASCII-uppercase(name up to the first '.', without trailing ' ')
    if stem ∈ {CON, PRN, AUX, NUL, COM1–COM9, LPT1–LPT9}: name = "_" + name
    return name
```

When the sanitized output type is WebP, the sender replaces the text after the
last `.` with `webp`, or appends `.webp` if the name has no `.`. The final
filename MUST be 1 to 255 bytes so that it encodes in `FileMetadata`. The
sender truncates the base name, on a UTF-8 character boundary, so that it fits
together with the extension; the desktop service applies the same truncation
to every name it encodes (`metadata_filename`).

### 2.6 Interruption by Session Repair

File parts are ordinary user messages. They follow the same session-repair
([S06 §3.7.1](06-key-agreement-ratchet.md)), gap-repair
([S08 §6.5](08-messaging-service.md)) and re-send
([S08 §10.2](08-messaging-service.md)) rules as text. An unacknowledged part is
re-sent under the current session, and the receiver's logical-ID
deduplication ([S07 §7.3](07-message-format.md)) absorbs copies it already
holds. A transfer has no session-bound state beyond its `session_id`, so
repair neither interrupts nor restarts it. Re-sent parts carry byte-identical
bodies: assembly (§2.4) absorbs identical duplicates and rejects conflicting
ones.

---

## 3. Transfer Progress

Progress is persisted in the profile's encrypted store and survives lock and
restart.

**Sender staging record.** `browser_transfers` holds one row per staged upload:

| Column | Meaning |
|---|---|
| `id` | 32 lowercase hex characters; the hex form of `session_id` |
| `contact_id` | Recipient contact; deleting the contact deletes the row |
| `fingerprint` | SHA-256 of the serialized upload manifest (§9.4) |
| `manifest` | Manifest JSON, at most 32,768 bytes |
| `size` | Declared upload size, 1 to 268,435,456 |
| `received` | Bytes of verified upload parts stored |
| `state` | Phase, below |
| `cursor` | Next wire message to emit (§9.1) |
| `metadata` | Encoded `FileMetadata` once prepared, at most 4,096 bytes |
| `error` | Failure code when `state = 4` |

| `state` | Phase reported | Meaning |
|---|---|---|
| 0 | `uploading` | Accepting upload parts |
| 1 | `preparing` | Upload sealed; sanitization pending or running |
| 2 | `queued` | Sanitized parts and metadata stored; wire messages being emitted |
| 3 | not listed | Every wire message emitted; staged parts deleted |
| 4 | `failed` | Preparation refused the file; staged parts deleted |

`browser_transfer_parts(transfer_id, kind, part, data)` holds the staged bytes:
`kind = 0` is an upload part of at most 1 MiB, `kind = 1` is a sanitized output
part of `MAX_CHUNK_SIZE` bytes (the last may be shorter).

The staging view returned to the UI is
`{id, filename, size, uploaded, phase, parts, error}`. `parts` lists the stored
upload part indices while `state = 0` and is empty otherwise. The list
operation returns at most 8 records with `state ≠ 3`, failed records last.

**Message-level progress.** For each `FileMetadata` message the service reports
`{filename, size, chunks, availableChunks, depositedChunks, complete, supported, failed}`:

- `availableChunks`: distinct part indices stored for that `session_id` and
  direction;
- `depositedChunks`: distinct part indices whose message status is deposited,
  delivered or read;
- `supported`: `total_size ≤ MAX_TRANSFER` and the metadata row has no
  disappearing timer;
- `complete`: `supported` and `availableChunks = chunk_count`;
- `failed`: an incoming, `supported`, incomplete file whose missing-part
  requests are exhausted (§4.1).

**Receiver request state.** A received `FileMetadata` row also records its
missing-part requests (§4.1): `retry_count` is the number of `FileChunkNack`s
sent, or `NACK_MAX_ATTEMPTS + 1` once the receiver stopped asking, and
`last_retry_at` is the time of the file's last stored part or request.

A metadata row that fails to parse (§2.2.1) is reported as an unavailable file:
`{filename: "Unavailable file", size: 0, chunks: 0, availableChunks: 0,
depositedChunks: 0, complete: false, supported: false, failed: false}`. The
other messages of the list are unaffected (§4.4).

The UI shows "N of M parts deposited" for an outgoing file until every part is
deposited, and "N of M parts received" for an incoming file until it is
complete, followed by "the rest did not arrive" when it is `failed`. A complete
count does not prove integrity; the hash is checked at download (§2.4).

---

## 4. Outbound Queue and Part Handling

### 4.1 Retransmission and `FileChunkNack`

Lost or late parts are recovered by the generic mechanisms of §2.6 (outbox
frames are retried until the peer acknowledges them, gap repair re-sends
specific messages, and `ReSendRequest` re-sends history) and by
`FileChunkNack`, the file's own request for its missing parts. Each re-sends the
stored part body byte for byte. `FileChunkNack` also covers what gap repair
cannot: a lost last part, which leaves no later message on its chain to reveal
the gap, and parts older than the sender's 256 outbound repair records.

**Receiver.** A received `FileMetadata` row without a disappearing timer, from
an unblocked contact, is *watched* until the receiver stops asking (§3). Its
*attempts* are the `FileChunkNack`s sent for it. Its *last activity* is the
latest of its own receive time, the receive commit of a stored part of the file
(§4.3) and its last `FileChunkNack`. The file is *quiet* once
`now − last activity ≥ NACK_MIN_INTERVAL_SECS << attempts`: 10, 20, 40, 80 and
160 minutes. While the profile is unlocked, the desktop file worker (§4.2)
checks for quiet files at most once a minute:

```
for each watched file that is quiet:
    missing = indices in 0 .. chunk_count without a stored part, ascending,
              at most NACK_MAX_INDICES of them
    if missing is empty, the metadata does not parse (§2.2.1),
       or attempts = NACK_MAX_ATTEMPTS:
        stop watching the file                    // retry_count = NACK_MAX_ATTEMPTS + 1
    else:
        queue FileChunkNack{session_id, missing} in the outbox
        on failure (no session, timer change pending, …): retry on a later check
        attempts += 1
    last activity = now
```

A file the receiver stopped asking for while parts were missing is reported
`failed` (§3), about 5 hours 10 minutes (31 × 600 s) after its last part. Parts
that arrive later still complete it.

**Sender.** A valid `0x3C` from an unblocked contact is committed as durable
inbound work, like `ReSendRequest` ([S08 §6.4](08-messaging-service.md)), and
answered by `drain_inbound_work`:

```
for each index in missing_indices, in order, from the work cursor:
    part = the stored sent FileChunk row of this contact for (session_id, index),
           without a disappearing timer, with its outbound history entry
    if none: continue        // unknown file, index past the file, another
                             // contact's file, or a deleted part
    on the first part found:
        if a FileChunkNack for (contact, session_id) was answered less than
           NACK_MIN_INTERVAL_SECS ago: drop the request
        record the answer time
    re-send the part with its original timestamp, logical_seq and flags under
        the current ratchet, as a new outbox frame of the existing row (S08 §10.2)
```

The re-sent frame is a file frame, so the delivery mode's pacing and circuit
policy apply (§9.5, [S10 §9](10-cover-traffic.md)). Re-sends use outbound tokens
([S08 §8.1](08-messaging-service.md)); when none are left the work stays queued
and resumes at its cursor. A re-send refused for another reason, for example a
disappearing timer turned on since the file was sent, is skipped; the receiver
asks again after its next quiet period. Answer times are kept in memory and
start empty after a restart. The receiver's logical-ID deduplication absorbs a
part that arrives twice.

A malformed `0x3C` body is rejected as a malformed control message
([S08 §6.4](08-messaging-service.md)).

### 4.2 Flow Control and Priority

- One worker emits wire messages for all staged transfers. It runs about once
  per second while the profile is unlocked, and a second pass cannot start
  while one is running. The same worker requests missing parts of received
  files (§4.1).
- Per pass, the worker emits at most 16 wire messages per transfer, and stops
  emitting while 64 or more outgoing frames await their first deposit.
- At most 4 unfinished transfers exist across all contacts: staged records in
  states 0–2 plus single-request jobs (§9.7). Beginning a fifth fails with
  `storage_unavailable`.
- Outbox pages hold at most 64 frames and order frames of file messages after
  every other frame, so chat, receipts and control traffic are not delayed
  behind a file ([S08](08-messaging-service.md)).

### 4.3 Parts Arriving Before Metadata

Mailbox delivery can reorder messages, so parts may arrive before their
`FileMetadata`. Every received part is committed as its own message row in the
same transaction as its ratchet advance, whether or not the metadata has
arrived. Assembly (§2.4) selects parts by `session_id`, so arrival order does
not matter.

A receiver MUST bound the storage it commits to parts that belong to no
received `FileMetadata` (*orphan parts*). In the same transaction, before it
stores an unsealed received part, the service:

1. deletes the contact's orphan parts received more than `ORPHAN_PART_SECS`
   (7 days) ago;
2. stores the part if a received `FileMetadata` row for the contact has the
   part's `session_id`, and records now as that file's last activity (§4.1);
3. otherwise stores it only if the contact's stored orphan part bodies plus
   this body total at most `ORPHAN_PART_BYTES`, the 1,093 part bodies of one
   256 MiB file.

A refused part is still committed (ratchet, dedup marks, acknowledgement); it
is only not stored, so its file stays incomplete. Sealed parts (S12) are not
counted: they expire with their timer.

### 4.4 Part Validation

A receiver MUST validate `FileMetadata` (§2.2.1) and every part before using
them:

1. The part body parses as `FileChunkWire` (§2.2.1).
2. `index < chunk_count`.
3. `len(data) = MAX_CHUNK_SIZE` for every index except the last; the last holds
   `total_size − (chunk_count − 1) · MAX_CHUNK_SIZE` bytes.
4. All stored bodies for one `(session_id, index)` are byte-identical. A
   differing copy makes the file `invalid_file`.
5. The SHA-256 of the assembled bytes equals `sha256_hash`.

On receipt, the service parses every `FileMetadata` and `FileChunk` body with
the §2.2.1 rules, in the direct receive path and for repaired items of a
`GapRepairBundle`. A body that fails is committed like any frame (ratchet,
dedup marks, acknowledgement) but never stored as a message row. The service
parses metadata again when it displays a file and applies all five checks when
it assembles one; the progress count of §3 counts distinct stored indices
without parsing them. A stored record that fails validation, for example one
stored by an older build, MUST be treated as an unavailable file (§3) and MUST
NOT affect other messages.

### 4.5 Sender-Side Retention

The sender keeps each emitted part as an outgoing message row whose body is the
sanitized plaintext part, next to the metadata row, in the encrypted store.
These rows answer re-send and gap-repair requests and let the sender download
its own file. They follow the ordinary message lifecycle (S08).

Staged bytes are deleted at fixed points:

- unsanitized upload parts (`kind = 0`) when preparation succeeds;
- every staged part when the last wire message is emitted (`state = 3`), when
  preparation fails (`state = 4`), or when the record is removed;
- the record and its parts when the contact is deleted.

Unsanitized bytes are never sent and never kept for retransmission.

---

## 5. Metadata Sanitization Pipeline

### 5.1 Main Pipeline

Sanitization is mandatory and has no user setting. It runs on the sender, in
the native service, before the bytes are split and encrypted. Two entry points
share the per-format rules of §7:

- `sanitize_seekable(input, output)` — file-backed. Preparation of staged
  uploads uses it.
- `sanitize_file(bytes, settings)` — in memory. The single-request path (§9.7)
  uses it, and `sanitize_seekable` delegates to it for formats without a
  streaming sanitizer.

```
func sanitize_seekable(input, output) -> Result<FileType>:
    size = length(input)
    if size == 0 or size > 268,435,456: return Err(InvalidFormat)
    kind = detect_file_type(first min(64, size) bytes of input)       // §6.2
    match kind:
        Unknown, Heic -> return Err(UnsupportedType)
        Wav           -> stream_riff(WAV_KEEP)                        // §7.15
        WebP          -> stream_riff(WEBP_KEEP)                       // §7.12
        Mp3           -> stream_mp3()                                 // §7.7
        Flac          -> stream_flac()                                // §7.9
        Mp4, Mov      -> stream_video()                               // §7.3
        otherwise     -> bytes  = read the whole input
                         result = sanitize_file(bytes, default settings)?
                         if len(result.sanitized_bytes) > 268,435,456:
                             return Err(InvalidFormat)
                         write result.sanitized_bytes
                         return result.output_type
    v = verify_seekable(output, kind)                                 // §8
    if not v.passed: return Err(VerificationFailed)
    return kind

func sanitize_file(bytes, settings) -> Result<SanitizationResult>:
    t = detect_file_type(bytes)                                       // §6.2
    (out, output_type) = match t:
        WebP                      -> (strip_webp(bytes), WebP)        // §7.12
        Jpeg, Png, Gif, Bmp, Tiff -> (convert_to_webp(bytes), WebP)   // §7.16
        Heic                      -> return Err(UnsupportedType)      // §7.14
        Mp4, Mov                  -> (strip_video(bytes), t)          // §7.3
        Pdf                       -> (strip_pdf(bytes), t)            // §7.4
        Docx                      -> (strip_docx(bytes), t)           // §7.5
        Odt                       -> (strip_odt(bytes), t)            // §7.6
        Mp3, Ogg, Flac, Wav       -> (strip_audio(bytes, t), t)       // §7.7–§7.9, §7.15
        Unknown                   -> return Err(UnsupportedType)
    v = verify_no_metadata(out, output_type)                          // §8
    if not v.passed and settings.strict_verification:
        return Err(VerificationFailed)
    return SanitizationResult {
        sanitized_bytes: out, original_type: t, output_type,
        fields_removed, re_encoded: (output_type == WebP and t ≠ WebP),
        size_before: len(bytes), size_after: len(out),
    }
```

A file that cannot be processed MUST be refused; no path passes the original
bytes through. The output type, not the input type, determines the MIME type
and the verifier: a converted image is labelled `image/webp` and verified as
WebP.

### 5.2 Settings

```rust
struct SanitizationSettings {
    strict_verification: bool,   // default: true
}
```

Every production caller uses the default. No setting disables sanitization or
image conversion.

### 5.3 Error Types

```rust
enum SanitizeError {
    InvalidFormat(String),         // malformed or undecodable input; output too large
    VerificationFailed { residual_count: usize, findings: Vec<String> },
    UnsupportedType(String),       // Unknown or HEIC
    Other(String),                 // I/O failure of the file-backed input or output
}
```

A read that ends before the structure the file declares (a truncated or
malformed file) is `InvalidFormat`, not `Other`, because retrying cannot fix
it. Preparation maps `Other` to `storage_unavailable`, which leaves the record
in `state = 1` for a later pass. Every other error becomes `unsupported_file`
and fails only that record (`state = 4`); the pass continues with the next
record. The single-request path maps every error to `unsupported_file`.

### 5.4 Determinism

Every sanitizer MUST be deterministic: with the same sanitizer build, the same
input bytes produce the same output bytes. No sanitizer embeds a library
version string, the current time or a random value in its output.
Consequences:

- ZIP-based formats are rewritten with stored entries, the original entry
  order, zero DOS time and date, no extra fields and no comments (§7.5). Entry
  modification times are document metadata and do not survive.
- An emptied PDF Info value is exactly the empty literal string `()` (§7.4).
- WAV and file-backed WebP use closed keep-lists (§7.12, §7.15). No stripper
  decides heuristically whether a chunk is safe.
- Sanitizing an already sanitized PDF, DOCX, ODT or WebP file returns the same
  bytes.

### 5.5 Thumbnails and Previews

Neither side generates or transmits a thumbnail or preview of a file. An
implementation that adds previews MUST generate them only from sanitized bytes,
and MUST pass any transmitted preview through §5.1 as a new file.

### 5.6 Memory Use

In the file-backed path:

- WAV, WebP, MP3, FLAC, MP4 and MOV are streamed through a 65,536-byte buffer
  that is zeroized when dropped, and their output is verified (§8) with reads
  of at most 65,536 bytes. The staging layer holds one stored part at a
  time: an upload part of up to 1 MiB, or an output part of up to 245,760
  bytes.
- JPEG, PNG, GIF, BMP, TIFF, PDF, DOCX, ODT and OGG are read whole into a
  zeroizing buffer (up to 256 MiB) and processed in memory. Image decoding uses
  the decoder's default allocation limit of 512 MiB for pixel data. ZIP
  inflation is capped at 512 MiB of declared uncompressed data.

The single-request path processes every format in memory, with inputs of at
most 8 MiB. Preparation processes one file at a time.

---

## 6. File Type Detection

### 6.1 `FileType`

```rust
enum FileType {
    Jpeg, Png, Gif, Bmp, WebP, Tiff, Heic,   // images
    Mp4, Mov,                                // video
    Pdf, Docx, Odt,                          // documents
    Mp3, Ogg, Flac, Wav,                     // audio
    Unknown,
}
```

| Type | `mime_type()` | Processing | Output type | File-backed memory |
|---|---|---|---|---|
| `Jpeg` | `image/jpeg` | Convert (§7.1, §7.16) | WebP | Whole file |
| `Png` | `image/png` | Convert (§7.2, §7.16) | WebP | Whole file |
| `Gif` | `image/gif` | Convert (§7.10, §7.16) | WebP | Whole file |
| `Bmp` | `image/bmp` | Convert (§7.11, §7.16) | WebP | Whole file |
| `WebP` | `image/webp` | Strip (§7.12) | WebP | Streamed |
| `Tiff` | `image/tiff` | Convert (§7.13, §7.16) | WebP | Whole file |
| `Heic` | `image/heic` | Refused (§7.14) | — | — |
| `Mp4` | `video/mp4` | Strip (§7.3) | MP4 | Streamed |
| `Mov` | `video/quicktime` | Strip (§7.3) | MOV | Streamed |
| `Pdf` | `application/pdf` | Strip (§7.4) | PDF | Whole file |
| `Docx` | `application/vnd.openxmlformats-officedocument.wordprocessingml.document` | Strip (§7.5) | DOCX | Whole file |
| `Odt` | `application/vnd.oasis.opendocument.text` | Strip (§7.6) | ODT | Whole file |
| `Mp3` | `audio/mpeg` | Strip (§7.7) | MP3 | Streamed |
| `Ogg` | `audio/ogg` | Strip (§7.8) | OGG | Whole file |
| `Flac` | `audio/flac` | Strip (§7.9) | FLAC | Streamed |
| `Wav` | `audio/wav` | Strip (§7.15) | WAV | Streamed |
| `Unknown` | `application/octet-stream` | Refused | — | — |

### 6.2 Magic-Byte Detection

Detection reads only leading bytes; the file extension is never consulted. The
checks run in this order and the first match wins:

```
func detect_file_type(d) -> FileType:
    if len(d) < 4: return Unknown
    if d[0..3] == FF D8 FF:                                 return Jpeg
    if len(d) ≥ 8 and d[0..8] == 89 50 4E 47 0D 0A 1A 0A:   return Png
    if len(d) ≥ 6 and d[0..6] ∈ {"GIF87a", "GIF89a"}:       return Gif
    if d[0..2] == "BM":                                     return Bmp
    if len(d) ≥ 12 and d[0..4] == "RIFF" and d[8..12] == "WEBP": return WebP
    if d[0..4] ∈ {49 49 2A 00, 4D 4D 00 2A}:                return Tiff
    if d[0..4] == "fLaC":                                   return Flac
    if d[0..4] == "OggS":                                   return Ogg
    if len(d) ≥ 12 and d[0..4] == "RIFF" and d[8..12] == "WAVE": return Wav
    if len(d) ≥ 5 and d[0..5] == "%PDF-":                   return Pdf
    if d[0..4] == 50 4B 03 04:                              return zip_subtype(d)
    if d[0..3] == "ID3":                                    return Mp3
    if d[0] == FF and (d[1] & E0) == E0:                    return Mp3
    if len(d) ≥ 12 and d[4..8] == "ftyp":
        brand = d[8..12]
        if brand ∈ {"heic", "heix", "mif1"}:                return Heic
        if brand == "qt  ":                                 return Mov
        return Mp4
    return Unknown

func zip_subtype(d) -> FileType:
    w = d[0 .. min(len(d), 4096)]
    if w contains "word/" or "[Content_Types].xml":         return Docx
    if w contains "mimetype" or "opendocument":             return Odt
    return Unknown
```

The file-backed path passes only the first 64 bytes to `detect_file_type`, so a
ZIP package is recognized there only when the distinguishing name lies in that
window. Every OOXML package (word processing, spreadsheet, presentation) is
detected as `Docx`, and every ODF package as `Odt`; the transmitted MIME type
then names the word-processing format.

### 6.3 Helpers

```
is_image(t)    = t ∈ {Jpeg, Png, Gif, Bmp, WebP, Tiff, Heic}
is_video(t)    = t ∈ {Mp4, Mov}
is_audio(t)    = t ∈ {Mp3, Ogg, Flac, Wav}
is_document(t) = t ∈ {Pdf, Docx, Odt}
mime_type(t)   = the string in the §6.1 table
```

---

## 7. Per-Format Processing

### 7.1 JPEG

Converted to WebP (§7.16). All APPn segments (EXIF, XMP, ICC, IPTC, Photoshop),
COM segments and embedded EXIF thumbnails are discarded with the container.

### 7.2 PNG

Converted to WebP (§7.16). Text chunks (`tEXt`, `iTXt`, `zTXt`), `eXIf`,
`iCCP`, `tIME` and every other ancillary chunk are discarded with the
container.

### 7.3 MP4 / MOV

The file-backed sanitizer keeps every byte offset unchanged. It overwrites
metadata boxes in place instead of removing them, so the `mdat` media data and
all `stco`/`co64` chunk offsets remain valid without rewriting:

```
func stream_video(input, output, end, depth):
    if depth ≥ 64: reject
    while position < end:
        start = position
        if end − start < 8: reject
        read size32 (u32) and type (4 bytes)
        len = match size32:
                0 -> end − start                   // box extends to the end
                1 -> read u64 largesize            // 16-byte header
                n -> n
        if len < header length or len > end − start: reject
        if type ∈ {moof, mfra, mvex}: reject       // fragmented files are refused
        if type ∈ {udta, meta, uuid, XMP_, CTIM, free, skip}:
            write the header with type replaced by "free"
            write (len − header length) zero bytes
        else:
            write the header unchanged
            if type ∈ {moov, trak, mdia, minf, stbl, edts, dinf}:
                stream_video(children, start + len, depth + 1)
            elif type ∈ {mvhd, tkhd, mdhd}:
                read version (1 byte) and flags (3 bytes)
                dates = 8 bytes if version = 0, 16 bytes if version = 1; otherwise reject
                if payload < 4 + dates: reject
                write version and flags, then `dates` zero bytes  // creation and modification time
                copy the rest of the payload
            else:
                copy the payload unchanged
```

The output has the same length as the input.

The in-memory sanitizer (single-request path) removes boxes instead:

- `udta`, `meta`, `uuid`, `XMP_` and `CTIM` boxes are removed at the top level
  and inside `moov`, `trak`, `mdia`, `minf`, `stbl`, `edts` and `dinf`; other
  boxes, including `free` and `skip`, are copied unchanged.
- `moof` and `mfra` at the top level and `mvex` inside a container are
  rejected. Nesting is limited to 64 levels.
- `mvhd`, `tkhd` and `mdhd` creation and modification times are zeroed as above.
- Container sizes are recomputed as 32-bit values; a container whose size does
  not fit in 32 bits is rejected.
- Every `stco` and `co64` entry is remapped through the `mdat` payload it
  pointed into in the input. An entry outside every `mdat` payload, a malformed
  offset table, or a 32-bit overflow is rejected.

### 7.4 PDF

```
func strip_pdf(data):
    doc = parse(data)                       // reject unparseable, encrypted, or catalog-less documents
    if trailer has /Info:
        info = dereference(/Info)           // reject if not a dictionary
        clean = new dictionary
        for key in info:
            if key ∈ {Author, Creator, Producer, Title, Subject, Keywords, CreationDate, ModDate}:
                clean[key] = ()             // empty literal string
        replace the Info object with clean  // every other Info key is dropped
    for every object, recursively (depth limit 128; deeper input is rejected):
        replace a stream whose /Type is /Metadata with null
        remove the /Metadata key from every dictionary
    remove /Prev, /XRefStm, /ID, /Type, /W, /Index, /Length, /Filter, /DecodeParms from the trailer
    delete every object unreachable from the trailer
    write a single revision with a classic cross-reference table
```

The rewrite discards incremental-update history, unreachable objects, XMP
packets (compressed or not) and the trailer `/ID` file identifier.

### 7.5 DOCX

A DOCX file is a ZIP archive. The sanitizer parses it, empties the metadata
elements in `docProps/core.xml` and `docProps/app.xml`, and rewrites the whole
archive.

Emptied elements, matched by local name in any namespace: `dc:creator`,
`dc:title`, `dc:subject`, `dc:description`, `cp:lastModifiedBy`, `cp:revision`,
`dcterms:created`, `dcterms:modified`.

**ZIP reading.** The reader locates the end-of-central-directory record within
the last 65,557 bytes and walks the central directory. For each entry it reads
the data through the entry's local header. It MUST reject:

- an encrypted entry (general-purpose flag bit 0);
- a Zip64 marker (`0xFFFFFFFF` compressed or uncompressed size);
- a compression method other than 0 (stored) or 8 (DEFLATE);
- a stored entry whose compressed and uncompressed sizes differ;
- a DEFLATE entry whose inflated size differs from its declared size;
- a cumulative declared uncompressed size above 536,870,912 bytes;
- any truncated or missing header or data.

**XML rewriting.** A target member MUST be valid UTF-8 without NUL bytes. A
declared encoding other than UTF-8 or US-ASCII, a DOCTYPE, a malformed
attribute, nesting deeper than 128 levels, unbalanced tags, or anything other
than exactly one root element is rejected. For each target element that has
content, every descendant event (text, CDATA, comments, processing
instructions, child elements) is removed; the start tag, its attributes and the
end tag remain. Self-closing target elements are unchanged.

**ZIP writing.** Entries are written in central-directory order:

| Record | Fields |
|---|---|
| Local header | `50 4B 03 04`, version needed 20, flags 0, method 0, time 0, date 0, CRC-32, compressed size = uncompressed size, name length, extra length 0, name, data |
| Central directory | `50 4B 01 02`, version made by 20, version needed 20, flags 0, method 0, time 0, date 0, CRC-32, sizes, name length, extra length 0, comment length 0, disk 0, internal attributes 0, external attributes 0, local header offset, name |
| End of central directory | `50 4B 05 06`, disk 0, directory disk 0, entry count twice, directory size, directory offset, comment length 0 |

Every entry is stored uncompressed. The archive is rewritten even when no
element changed, because entry timestamps are metadata.

### 7.6 ODT

Same ZIP and XML rules as §7.5. The target member is `meta.xml`, and the
emptied elements are `meta:initial-creator`, `dc:creator`, `meta:creation-date`,
`dc:date`, `meta:editing-cycles`, `meta:editing-duration` and `meta:generator`.
Original entry order is kept, so the ODF `mimetype` entry stays first and
stored.

### 7.7 MP3

```
func stream_mp3(input, size):
    start = 0; end = size
    while end − start ≥ 10 and bytes[start .. start+3] == "ID3":     // leading ID3v2 tags, stacked
        tag = syncsafe(bytes[start+6 .. start+10])                   // any byte ≥ 0x80: reject
        total = 10 + tag + (10 if bytes[start+5] & 0x10 else 0)      // footer-present flag
        if total > end − start: reject
        start += total
    loop:                                                            // trailing tags, any order
        before = end
        if end − start ≥ 128 and bytes[end−128 .. end−125] == "TAG": // ID3v1
            end −= 128
        if end − start ≥ 32 and bytes[end−32 .. end−24] == "APETAGEX":   // APEv2 footer
            tag_size = u32 LE at end−20; flags = u32 LE at end−12
            total = tag_size + (32 if flags & 0x80000000 else 0)     // header present
            if total < 32 or total > end − start: reject
            end −= total
        if end − start ≥ 20 and bytes[end−10 .. end−7] == "3DI":     // appended ID3v2.4
            total = 20 + syncsafe(bytes[end−4 .. end])
            if total > end − start or bytes[end−total .. end−total+3] ≠ "ID3": reject
            end −= total
        if end == before: break
    if start ≥ end: reject
    copy bytes[start .. end]
    reject if the copied range contains "APETAGEX" anywhere, or "3DI" in its last 160 bytes
```

The in-memory stripper removes the same tags but stops scanning at a malformed
or overlapping tag instead of rejecting; the verifier (§8) then rejects any
residue.

### 7.8 OGG

Both paths process OGG in memory:

1. Parse the whole file as Ogg pages. Each page starts with `OggS`, has stream
   structure version 0, a complete 27-byte header, a segment table and a body
   within the file. Any other byte sequence rejects the file.
2. Reassemble packets per logical stream (serial number) from the lacing
   values; a segment shorter than 255 bytes ends a packet. A packet still open
   at the end of the file rejects the file.
3. For a packet that starts with `03 "vorbis"` (Vorbis comment header) or
   `"OpusTags"`: parse the vendor length (u32 LE), the vendor string, the
   comment count (u32 LE) and each comment (u32 LE length and bytes). A
   Vorbis comment header MUST end with a framing byte whose bit 0 is set. If
   the vendor string is empty and the count is 0, leave the packet unchanged.
   Otherwise overwrite it in place with `signature ‖ 00000000 ‖ 00000000`,
   followed by `01` for Vorbis, then zero bytes up to the original packet
   length. A packet shorter than this replacement rejects the file.
4. Recompute the CRC of every page that was overwritten: CRC-32 with polynomial
   `0x04C11DB7`, initial value 0, no reflection and no final XOR, computed with
   the CRC field set to zero.

Audio pages and the page layout are unchanged.

### 7.9 FLAC

```
func stream_flac(input, size):
    require bytes[0..4] == "fLaC"; write "fLaC"
    loop:
        if fewer than 4 bytes remain: reject
        header = 1 byte (bit 7: last block; bits 0–6: type) + 24-bit BE length
        if length exceeds the remaining bytes: reject
        if type ∈ {4 (VORBIS_COMMENT), 6 (PICTURE)}: skip the block
        else: write the header with the last-block bit cleared, then the block body
        if the last-block bit was set: break
    if no block was written: reject
    set the last-block bit on the last written block
    copy the remaining bytes (audio frames) unchanged
```

STREAMINFO, PADDING, APPLICATION, SEEKTABLE, CUESHEET and unknown block types
are kept.

### 7.10 GIF

Converted to WebP (§7.16). Comment, plain-text and application extensions,
including XMP and ICC blocks, are discarded with the container. Only the first
frame of an animation is kept.

### 7.11 BMP

Converted to WebP (§7.16). Embedded colour profiles and bytes outside the pixel
array are discarded with the container.

### 7.12 WebP

WebP is the output format of image conversion. A WebP input is cleaned in place
rather than converted.

```
func stream_riff(input, size, keep):
    header = 12 bytes; riff_end = u32 LE header[4..8] + 8
    require header[0..4] == "RIFF", header[8..12] == form type, 12 ≤ riff_end ≤ size
    write header
    pos = 12
    while pos < riff_end:
        if riff_end − pos < 8: reject
        fourcc, len = 8-byte chunk header; padded = len + (len & 1)
        if pos + 8 + padded > riff_end: reject
        if fourcc ∈ keep:
            write the chunk header
            if fourcc == "VP8X":
                if len < 10: reject
                write (flags byte & ~0x2C)       // clear ICC 0x20, EXIF 0x08, XMP 0x04
                copy padded − 1 bytes
            else:
                copy padded bytes
        else:
            skip padded bytes
        pos += 8 + padded
    rewrite the RIFF size field as output length − 8
    // bytes after riff_end are not copied

WEBP_KEEP = {"VP8 ", "VP8L", "VP8X", "ALPH", "ANIM", "ANMF"}
```

Every other chunk, including `EXIF`, `XMP ` and `ICCP`, is dropped.

The in-memory stripper (single-request path) walks chunks to the end of the
data, drops `EXIF`, `XMP ` and `ICCP`, clears the same VP8X flags, keeps every
other chunk and recomputes the RIFF size. A truncated chunk is rejected.

### 7.13 TIFF

Converted to WebP (§7.16). EXIF, GPS, XMP, IPTC, Photoshop and ICC tags,
sub-IFDs and every image after the first are discarded with the container.

### 7.14 HEIC

Refused with `UnsupportedType` ("convert to JPEG/WebP before sending"). The
image decoder in use has no HEIC support, and a HEIC file is never sent with
its metadata intact.

### 7.15 WAV

`stream_riff` (§7.12) with form type `WAVE` and the closed keep-list:

```
WAV_KEEP = {"fmt ", "data", "fact", "cue ", "plst", "smpl"}
```

Every other chunk is removed, including `LIST` of any type (`INFO`, `adtl`),
`bext`, `iXML`, `axml`, `ID3 ` and unknown chunks. Kept chunks are copied in
their original order, byte for byte; audio samples are never decoded. Bytes
after the RIFF end are dropped and the RIFF size is recomputed. The in-memory
stripper applies the same rules.

### 7.16 Structural Image Conversion

```
func convert_to_webp(data) -> Result<bytes>:
    image = decode(data)       // first frame or page only; reject on failure
    return encode_webp_lossless(image.pixels)
```

- Decoding uses the `image` crate with its JPEG, PNG, GIF, BMP, TIFF and WebP
  decoders and default limits, including a 512 MiB allocation cap. A file that
  does not decode is refused with `InvalidFormat`.
- Decoding to pixels discards the whole source container. The encoder writes a
  WebP file from the pixels alone, so no source container byte can reach the
  output, whether or not a parser recognized it.
- The encoder writes lossless WebP (VP8L) at 8 bits per channel, keeping alpha.
  Higher bit depths are reduced. The output carries no ICC, EXIF or XMP chunk.
- The output is verified as WebP (§8). If it exceeds 268,435,456 bytes, the
  file is refused.

---

## 8. Verification Pass

```
func verify_no_metadata(data, file_type) -> VerificationResult { passed, residual_findings }
    // passed ⇔ residual_findings is empty
```

The sanitized output MUST pass `verify_no_metadata` (for streamed output,
`verify_seekable`) for its output type before it is split into parts. A file
that fails is refused (`VerificationFailed`).

| Type | A finding is reported for |
|---|---|
| WebP | A header other than `RIFF`…`WEBP`; a RIFF size beyond the data; a chunk overrunning the RIFF end; an `EXIF`, `XMP ` or `ICCP` chunk; a `VP8X` chunk with any of the flags `0x2C` set; bytes after the RIFF end |
| MP4, MOV | A parse failure of the in-memory stripper (§7.3), or anything it would remove: a `udta`, `meta`, `uuid`, `XMP_` or `CTIM` box, or a nonzero `mvhd`/`tkhd`/`mdhd` date |
| PDF | A parse failure or encryption; an Info key outside the eight of §7.4 or a non-empty Info value; a `/Metadata` key or a stream of `/Type /Metadata` anywhere |
| DOCX, ODT | An unparseable archive; an entry that is not stored, carries a nonzero DOS time or date, or has extra fields; content inside a target element (§7.5, §7.6); unparseable target XML |
| MP3 | `ID3` at offset 0; `TAG` at length − 128; `APETAGEX` anywhere; `3DI` in the last 160 bytes |
| OGG | A parse failure (§7.8 steps 1–2); a comment packet with a vendor string or comments |
| FLAC | A `VORBIS_COMMENT` (4) or `PICTURE` (6) metadata block |
| WAV | A parse failure; a chunk outside `WAV_KEEP`; bytes after the RIFF end |
| JPEG | Any `FF E1`–`FF EF` or `FF FE` byte pair; the bytes `Exif 00` |
| PNG | Any of the byte strings `tEXt`, `iTXt`, `zTXt`, `eXIf`, `iCCP`, `tIME` |
| GIF | A malformed block structure; a comment, plain-text, or non-animation application extension; bytes after the trailer |
| BMP | A declared file size other than the data length; the bytes `Exif 00`; a V5 header with a linked or embedded colour profile, or nonzero profile fields |
| TIFF, HEIC, Unknown | Always: these types have no verifier |

Sanitized output is always WebP, MP4, MOV, PDF, DOCX, ODT, MP3, OGG, FLAC or
WAV. The JPEG, PNG, GIF, BMP, TIFF and HEIC rows apply only when the verifier
is called on such data directly.

```
func verify_seekable(input, file_type) -> Result<VerificationResult>
```

`verify_seekable` applies the same rules to a file-backed file. For WAV, WebP,
MP3, FLAC, MP4 and MOV it walks the file with reads of at most 65,536 bytes; a
structure the walk cannot follow is a finding, and the MP4/MOV walk does not
check chunk-offset tables, which carry no metadata. TIFF, HEIC and Unknown
give their fixed finding without reading the file. Every other type is read
whole, at most 268,435,456 bytes, and passed to `verify_no_metadata`.
`sanitize_seekable` runs it on the output of the streamed formats (§5.1).

The receiver runs `verify_seekable` on every reassembled file before it offers
the download, for the type that `detect_file_type` gives the file's first 64
bytes (§6.2), not the declared MIME type, because a modified sender can skip
sanitization. A finding does not refuse the download: the grant reports
`metadataWarning: true` (§9.6) and the UI warns the user that the file may
still contain metadata.

---

## 9. Integration with Messaging

### 9.1 Send Flow

```
UI:
    refuse a file of 0 bytes or more than 256 × 1,048,576 bytes
    hashes = [lowercase hex SHA-256 of each 1 MiB part]
    record = transfers.begin(contact, {name, size, hashes})          // §9.4
    for each part index not in record.parts:
        POST /api/transfer-part/{record.id}/{index}                   // §9.4
    transfers.finish(record.id)                                       // state 0 → 1

Worker pass (profile unlocked; one pass at a time; §4.2):
    for each staging record with state ≠ 3 (at most 8, failed last, then oldest first):
        if the contact is missing or blocked: skip
        if state == 1:
            prepare(record)
            on unsupported_file, file_too_large or invalid_file: state = 4, delete parts; continue
            on any other error: end the pass
        if state ≠ 2: continue
        meta = FileMetadata.parse(record.metadata)                    // §2.2.1
        on a parse failure: state = 4 (invalid_file), delete parts; continue
        repeat at most 16 times:
            if 64 or more outgoing frames await first deposit: stop
            if a sent message for (session_id, cursor) does not exist:
                cursor == 0 → enqueue content_type 0x10, body = meta
                cursor = k ≥ 1 → enqueue content_type 0x11,
                                 body = FileChunkWire{session_id, index k−1, output part k−1}
                if enqueue fails: stop
            cursor += 1
            if cursor > meta.chunk_count: state = 3, delete staged parts; stop
            persist cursor

func prepare(record):
    delete the record's output parts
    kind = sanitize_seekable(upload parts → output parts of MAX_CHUNK_SIZE)   // §5.1
    size = output length; require 1 ≤ size ≤ MAX_TRANSFER, else file_too_large
    hash = SHA-256 over the output parts
    name = display_filename(manifest.name), WebP rename if kind == WebP,
           base truncated to fit 255 bytes                                  // §2.5
    meta = FileMetadata{record.session_id, name, size, kind.mime_type(),
                        chunk_count(size), hash}
    store meta; state = 2; cursor = 0; delete the upload parts
```

The existence check before each enqueue makes emission idempotent across a
crash between enqueueing a message and persisting the cursor. Enqueueing
encrypts the message with the pairwise ratchet and adds it to the durable
outbox ([S08 §5](08-messaging-service.md)); the outbox retries the deposit
until the mailbox accepts it and the peer acknowledges it.

A lock cancels a running preparation. Preparation then restarts from the
beginning on the next pass after unlock; it does not resume part-way through a
file. Uploading, emission and deposit resume from their persisted positions.

### 9.2 Receive Flow

```
on a decrypted payload with content_type 0x10 or 0x11 (S08 §6.3):
    if the body fails its §2.2.1 parse: commit the frame, store no row (§4.4)
    if it is an orphan part over the §4.3 bound: commit the frame, store no row
    store the body as a received FileMetadata or FileChunk message row,
        in the same transaction as the ratchet advance; a stored part with
        received metadata also records the file's last activity (§4.3)
    if the conversation timer is on: the row is sealed (S12) and the file is unsupported

worker (unlocked, at most once a minute): FileChunkNack for quiet incomplete files (§4.1)
on a FileChunkNack: queue durable inbound work; re-send the named parts (§4.1)
on display:  for each FileMetadata row, parse it (§2.2.1) and report progress (§3)
on download: assemble and verify (§2.4), check for metadata (§8), then grant (§9.6)
```

The receiver does not re-run sanitization; it only checks for metadata and
warns (§8). Received parts are never decoded, rendered or opened by the app.

### 9.3 Disappearing-Messages Interplay ([S12](12-disappearing-messages.md))

1. Beginning a staged upload MUST fail with `file_timer_unsupported` while the
   conversation timer is on or a timer change is pending. The single-request
   path applies the same rule, and its worker skips jobs for such a contact.
2. Turning the timer on MUST fail with `file_preparing` while the contact has a
   staged record in states 0–2 or a single-request job.
3. File rows with a disappearing timer are excluded from the file-frame circuit
   policy (§9.5), from progress counts and from download.
4. A file row stored under a timer (for example, when a timer change crosses a
   transfer) is reported as unsupported and cannot be downloaded. It expires
   under S12 like any sealed row.
5. Download refuses a metadata row whose expiry time has passed.

### 9.4 Browser Upload Staging and Resume

**Control requests.** `POST /api/transfers` with a JSON body of at most 32,768
bytes:

```
{ "session": <identity session>, "generation": <u64>,
  "action": { "kind": "begin",    "contact": <id>, "manifest": <manifest> }
          | { "kind": "list",     "contact": <id> }
          | { "kind": "finish",   "id": <transfer id> }
          | { "kind": "cancel",   "contact": <id>, "id": <transfer id> }
          | { "kind": "download", "contact": <id>, "message": <message id> } }
```

The service validates the identity session and generation before and after
each operation. Unknown fields are rejected.

**Manifest.** `{name, size, hashes}` with unknown fields rejected:

- `name`: at most 255 bytes;
- `size`: 1 to `MAX_TRANSFER`;
- `hashes`: exactly `ceil(size / UPLOAD_PART)` strings of 64 hex characters.
  Entry `i` is the lowercase hex SHA-256 of bytes
  `[i · UPLOAD_PART, min((i+1) · UPLOAD_PART, size))`.

A manifest that fails these checks is refused with `file_too_large`. Begin also
requires a contact whose setup is complete (`contact_pending` otherwise), the
timer rule of §9.3, an unblocked contact and a free queue slot (§4.2).

**Resume.** The record key is `fingerprint = SHA-256(serialized manifest JSON)`.
If a record for the same contact and fingerprint is in states 0–2, begin
returns it, and its `parts` field tells the UI which parts to skip. A record
for the same fingerprint in state 3 or 4 is replaced. Resuming therefore needs
the same name, size and part contents; a different file with the same name
cannot reuse saved parts.

**Part upload.** `POST /api/transfer-part/{id}/{part}` with
`Content-Type: application/octet-stream`, a body of at most 1 MiB, and the
headers `X-Najwa-Session` (launch token), `X-Najwa-Identity` and
`X-Najwa-Generation`. The service:

1. requires a known record (`file_unavailable` otherwise);
2. requires `SHA-256(body)` in lowercase hex to equal `hashes[part]`
   (`invalid_file` otherwise);
3. requires the record in state 0, its contact unblocked,
   `part · UPLOAD_PART < size` and
   `len(body) = min(size − part · UPLOAD_PART, UPLOAD_PART)`;
4. treats an existing part with identical bytes as success without change, and
   refuses an existing part with different bytes;
5. stores the part and adds its length to `received`, in one transaction.

**Finish** moves the record from state 0 to 1 only when `received = size`.
**Cancel** deletes a record in state 0 or 4 together with its parts; a record
that is preparing or queued cannot be cancelled. A storage-layer refusal in
steps 3–4, in finish or in cancel is reported as `storage_unavailable`.

**UI retry.** The UI retries a request that fails with `service_unavailable`,
`service_restarted` or `busy`, after `min(1000 · 2^attempt, 10000)` ms. Any
other error stops the upload. Pausing aborts the upload; stored parts remain.

### 9.5 Delivery Mode and Circuits

A *file frame* is an outgoing frame whose message is a sent `FileMetadata` or
`FileChunk` row without a disappearing timer. Other frames always deposit on
one-shot circuits.

**Responsive mode** (the default; cover-slot bypass on, [S10](10-cover-traffic.md)).
Each deposit attempt of a file frame uses the circuit isolation
`CircuitIsolation::FileTransfer(isolation)` with

```
isolation = SHA-256( "najwa-responsive-file-circuit-v1" ‖ 0x00
                   ‖ contact_id                     (u64 BE)
                   ‖ session_id                     (16 bytes)
                   ‖ their_deposit_capability       (32 bytes)
                   ‖ their_envelope_secret          (32 bytes)
                   ‖ mailbox_onion                  (UTF-8, no length prefix) )
```

Deposits of one file to one contact through one mailbox capability share a Tor
circuit. Different files, contacts or mailboxes never share one. The reuse key
`"file:" ‖ hex(isolation)` is distinct from the per-contact, per-mailbox and
cover keys. A shared circuit is retired 600 s after creation, or after
`circuit_timeout_secs` (default 60 s) without use while no request is in
flight ([S04](04-transport.md)).

**Timing privacy mode** (bypass off). Each deposit attempt waits for a cover
slot ([S10](10-cover-traffic.md)) and uses a one-shot circuit.

The mode is read immediately before every deposit attempt, so a mode change
applies to parts already queued.

### 9.6 Download

**Grant creation** (`{kind: "download", contact, message}`):

1. The message MUST be a `FileMetadata` row of that contact, without a
   disappearing timer and not expired. Otherwise `file_unavailable`.
2. Assemble and hash every part (§2.4). Any failure refuses the grant.
3. Run `verify_seekable` on the assembled file, one part in memory at a time
   (§8). A finding sets `metadataWarning`; it does not refuse the grant.
4. Generate `token` = 32 CSPRNG bytes as 64 lowercase hex characters. Store
   `SHA-256(token as ASCII)` with the contact, the message and
   `expires_at = now + 3,600 s`. Delete expired grants in the same transaction.
5. Return `{url: "/api/download/<token>", filename: display_filename(meta.filename), size, metadataWarning}`.

The UI accepts only a URL matching `^/api/download/[a-f0-9]{64}$` and starts a
native browser download. When `metadataWarning` is true it also shows a warning
that the file may still contain metadata.

**`GET /api/download/{token}`:**

- The route is exempt from the session header, because a native download
  cannot set one. Every other loopback check (Host, Origin, Sec-Fetch-Site)
  applies.
- The profile MUST be unlocked. An unknown or expired grant, or a locked
  profile, returns 404.
- Response headers: `Content-Type: application/octet-stream`;
  `Content-Disposition: attachment; filename="attachment"; filename*=UTF-8''<name>`,
  where every byte of the name other than `A–Z a–z 0–9 - . _` is percent-encoded;
  `Accept-Ranges: bytes`; `ETag: "<sha256_hash in lowercase hex>"`;
  `Content-Length`.
- A single range `bytes=a-b`, `bytes=a-` or `bytes=-n` returns 206 with
  `Content-Range`. `If-Range` is honoured only when it equals the ETag; a
  mismatch returns the whole file. An unsatisfiable or multi-part range
  returns 416 with `Content-Range: bytes */<size>`.
- The body streams one part at a time. For each part, the service re-checks
  the grant and the §2.4 structural rules, and confirms that the unlocked
  identity session observed at the start of the request is still current. A
  lock or an expired grant ends the stream with an error.

Grants live in the profile's encrypted database and survive restarts until they
expire. Deleting the message or the contact deletes its grants.

### 9.7 Single-Request Path

`POST /api/attachment` accepts a whole file of at most `MAX_BROWSER_FILE`
(8 MiB) as an `application/octet-stream` body, with the headers
`X-Najwa-Identity`, `X-Najwa-Generation`, `X-Najwa-Contact` and
`X-Najwa-Filename` (base64 of the UTF-8 name). The service:

1. applies the contact and timer checks of §9.4 and §9.3;
2. runs `sanitize_file` in memory (§5.1);
3. names the file `sanitize_filename(display_filename(name))` with the WebP
   rename (§2.5);
4. refuses a sanitized output above 8 MiB with `file_too_large`;
5. stores a job under the settings key
   `desktop:attachment-job:<contact id>:<session_id hex>` with the value
   `cursor (u32 BE) ‖ metadata_len (u32 BE) ‖ FileMetadata ‖ sanitized bytes`.

A worker emits up to 4 wire messages per job per pass, in the order of §9.1,
and deletes the job once the cursor passes `chunk_count`. A job whose value
does not parse, for example one an older build stored with a name over 255
bytes, is deleted unsent so that it cannot block later jobs. The `download_file`
operation returns `{filename, data}`, with `data` the base64 of an assembled,
hash-checked file of at most 8 MiB. The desktop UI uses the staged path
(§9.4, §9.6) for every file.

### 9.8 Error Codes

| Code | Raised when |
|---|---|
| `file_too_large` | Size 0 or above a limit; a manifest that fails §9.4; an empty or oversized sanitized output |
| `unsupported_file` | Unknown or refused type; malformed or truncated input; verification failure |
| `file_timer_unsupported` | Upload begun while the conversation timer is on or a change is pending |
| `file_preparing` | Timer enabled while a transfer for the contact is unfinished |
| `contact_pending` | Contact setup is not complete |
| `invalid_file` | Upload part hash mismatch; malformed stored manifest, metadata or part; conflicting part copies or hash mismatch at download; a staged record whose stored metadata does not parse (it fails, `state = 4`) |
| `file_unavailable` | Unknown transfer; missing part; message is not a downloadable file; unknown or expired grant |
| `storage_unavailable` | Any storage-layer error or refusal: full queue, blocked contact, part outside the declared size, early finish, cancel of a preparing or queued record; an I/O failure while preparing, which the next pass retries |
| `locked` | The profile locked during the operation |
| `not_connected` | The messaging service is not running; emission waits |

---

## 10. Rust Crate Dependencies

| Crate | Dependency | Use |
|---|---|---|
| `najwa-sanitize` | `image` 0.25 (default features off; `jpeg`, `png`, `gif`, `bmp`, `tiff`, `webp`) | Image decoding and lossless WebP encoding (§7.16) |
| `najwa-sanitize` | `lopdf` 0.42 (default features off) | PDF parsing and rewriting (§7.4) |
| `najwa-sanitize` | `quick-xml` 0.41 | Metadata XML rewriting (§7.5) |
| `najwa-sanitize` | `flate2` | DEFLATE inflation and ZIP CRC-32 (§7.5) |
| `najwa-sanitize` | `zeroize`, `thiserror`, `tracing` | Buffer wiping, errors, logging |
| `najwa-core`, `najwa-ffi` | `sha2` | File and part hashes |

The full dependency inventory and its review policy are in
[Dependencies](../security/dependencies.md) and
[Supply Chain](../security/supply-chain.md).

---

## Security Considerations and Limitations

- **What sanitization removes.** It removes the container metadata listed in
  §7. It does not change what a file shows or says: faces, landmarks, visible
  text, document body text, comments and tracked changes with their authors,
  revision identifiers, embedded files, PDF annotations, page thumbnails and
  scripts, and steganographic content all pass through. Some metadata outside
  the listed elements also remains: DOCX `docProps/app.xml` fields such as
  company and template, `docProps/custom.xml`, ODT title, subject, keywords and
  user-defined fields, MP4 handler and encoder names, FLAC APPLICATION blocks
  and bytes after the last metadata block, and the length of an emptied OGG
  comment packet.
- **Image conversion side effects.** Converted images are lossless WebP and can
  be larger than the source. Animation keeps only the first frame, a
  multi-page TIFF keeps only its first page, colour profiles are dropped so
  colours can shift, EXIF orientation is not applied so a photo can arrive
  rotated, and depth is reduced to 8 bits per channel.
- **The receiver trusts the sender's client.** Sanitization runs only on the
  sender. A modified client can send unsanitized bytes. The receiver runs the
  §8 verifier and warns, but it does not clean the file, and the verifier
  finds only the metadata listed in §8. The app never renders a received
  file; it offers it as an `application/octet-stream` attachment.
- **Size and linkage are observable.** Every full part fills a 262,144-byte
  deposit, so the number of deposits reveals the file size to within about
  240 KiB to the mailbox operator and to anyone who can count deposits. In
  Responsive mode, observers of the shared circuit can also link the parts of
  one file to one another.
- **Delivery is not guaranteed.** The recipient's mailbox quota, retention and
  proof-of-work policy ([S16](16-mailbox-server.md)) apply to every part. A
  large file can be refused or expire before collection. Recovery relies on
  outbox retries, gap repair, missing-part requests and the sender's stored
  history.
- **Missing-part requests (§4.1).** A receiver asks only for parts of a file
  whose metadata arrived; a file whose metadata is lost is recovered only by
  gap repair or `ReSendRequest`. One request names at most 256 parts, so a file
  missing more needs several quiet periods, and it is reported failed after
  four requests. The receiver cannot tell a lost part from one the sender has
  not sent yet: a sender that stays offline more than about five hours in the
  middle of a file leaves it marked failed until the remaining parts arrive,
  and a part still in the sender's outbox when a request arrives is deposited
  twice. A sender answers one request per file and contact per 10 minutes and
  re-sends only parts it still stores, so the answer to a request that arrives
  within 10 minutes of an answered one, or after the sender deleted the file,
  is the receiver's next request or nothing. A contact can make the sender
  re-send up to 256 parts (about 60 MiB) of each file it was sent, once per
  10 minutes per file; `ReSendRequest` already allows re-sending all history.
  The sender's answer times reset at restart.
- **Work needs an unlocked profile.** Upload, preparation, emission, deposit,
  collection and download run only while the profile is unlocked. Preparation
  restarts from the beginning after a lock or restart.
- **Memory.** In the file-backed path, whole-file formats (§5.6) hold up to
  256 MiB of input in memory, plus decoded pixels for images. The receiver's
  metadata check (§8) holds up to 256 MiB for a received file of those types,
  and one part for the streamed types.
- **Filenames.** A filename is a sender-chosen hint. §2.5 removes bidi and
  zero-width controls, so a right-to-left override cannot reverse the visible
  extension, and prefixes Windows device names. A name can still imitate a
  trusted name or extension with look-alike characters or a long run of
  spaces before the real extension.
- **Parts without metadata.** A contact can make the recipient store up to
  `ORPHAN_PART_BYTES` (256 MiB plus part headers) of parts that belong to no
  received metadata. Orphan parts older than 7 days are deleted when that
  contact's next part arrives, so a contact that stops sending can leave up to
  that bound in place. Parts over the bound are dropped, so a file whose
  metadata is delayed past the bound or the 7 days stays incomplete (§4.3).
- **Download links.** A download URL is a bearer token. It is valid for one
  hour, only through the loopback service, and only while the profile is
  unlocked. It should not be shared.

---

## 11. Conformance Checklist

- `FileMetadata` (`0x10`), `FileChunk` (`0x11`) and `FileChunkNack` (`0x3C`)
  encoders and parsers follow §2.2.1 byte for byte, including every
  parser rejection.
- `chunk_count = ceil(total_size / MAX_CHUNK_SIZE)`; every part except the last
  is exactly `MAX_CHUNK_SIZE` bytes (§2.3).
- The 256 MiB limit holds at the UI, staging, sanitizer, preparation, parsing
  and download (§2.1).
- Assembly checks session, index, exact length and duplicate consistency for
  every part and the SHA-256 of the whole file, without panicking (§2.4).
- The single-request path applies `sanitize_filename` (§2.5); the staged path
  applies `display_filename` and the WebP rename. Both remove bidi and
  zero-width controls, prefix Windows device names, and truncate the base name
  so that the encoded name is at most 255 bytes.
- Staging records, part stores and states are persisted and survive restart;
  progress is reported per §3.
- A received incomplete file gets a `FileChunkNack` for its first 256 missing
  parts only after `NACK_MIN_INTERVAL_SECS << attempts` without a part or
  request, at most `NACK_MAX_ATTEMPTS` times, only while unlocked; then it is
  reported `failed`. A sender answers a valid one from durable inbound work by
  re-sending only that contact's stored parts of that file, with their logical
  identity, at most once per file and contact per `NACK_MIN_INTERVAL_SECS`,
  through the outbox and the file circuit policy (§3, §4.1).
- Emission is limited to 16 messages per transfer per pass and pauses at 64
  undeposited frames; at most 4 unfinished transfers; file frames sort after
  other frames (§4.2).
- Parts are committed independently of metadata arrival; stored orphan parts
  are bounded by `ORPHAN_PART_BYTES` per contact and deleted after
  `ORPHAN_PART_SECS` (§4.3).
- Received `FileMetadata` and `FileChunk` bodies are parsed on receipt, and a
  malformed one is committed without a message row; a stored metadata row that
  does not parse lists as an unavailable file without failing the list (§3,
  §4.4).
- A truncated or malformed upload fails only its own record; a record or job
  whose stored metadata does not parse is failed or deleted, and the worker
  continues with the next one (§5.3, §9.1, §9.7).
- Unsanitized upload parts are deleted when preparation succeeds; all staged
  parts are deleted on completion, failure or removal (§4.5).
- Sanitization is mandatory with no disabling setting; unknown types and HEIC
  are refused; no path passes original bytes through (§5.1, §5.2).
- `sanitize_file` verifies against the output type and refuses on a finding;
  `sanitize_seekable` does the same for streamed output with
  `verify_seekable` (§5.1, §8).
- Grant creation runs `verify_seekable` on the received file for its detected
  type and reports `metadataWarning` without refusing the download (§8, §9.6).
- ZIP rewrites are stored, ordered, timestamp-free and extra-field-free; PDF
  Info values are `()`; WAV and file-backed WebP use closed keep-lists;
  WebP, DOCX and PDF sanitization is idempotent (§5.4).
- No thumbnails or previews are generated or sent (§5.5).
- WAV, WebP, MP3, FLAC, MP4 and MOV stream through a 64 KiB buffer in the
  file-backed path, including their verification (§5.6).
- Magic-byte detection follows the order of §6.2.
- Per-format processing follows §7.1–§7.16: image conversion to lossless WebP;
  in-place MP4/MOV metadata blanking with date zeroing and fragmented-file
  refusal; structural PDF rewrite; DOCX/ODT element emptying with strict ZIP and
  XML parsing; stacked and trailing MP3 tag removal; OGG comment replacement
  with CRC recomputation; FLAC VORBIS_COMMENT and PICTURE removal; WAV keep-list.
- Upload parts are checked against the manifest hashes, sizes and existing
  bytes; resume is keyed by manifest fingerprint (§9.4).
- Uploads fail while the timer is on or pending; enabling the timer fails while
  a transfer is unfinished (§9.3).
- Responsive file frames use the §9.5 isolation token; Timing privacy file
  frames wait for a cover slot and use one-shot circuits; the mode is read
  before each attempt.
- Download grants are random 256-bit tokens stored as SHA-256 digests, expire
  after 3,600 s, are issued only after a full hash check, and stream with
  single-range support, ETag and If-Range (§9.6).
- Tests: per-format stripping and verification, determinism and idempotence
  fixtures, streamed-versus-in-memory equivalence for WAV, MP3, FLAC and WebP,
  refusal of streamed output with leftover metadata, the receiver's
  metadata warning,
  bounded read sizes, malformed-container refusal, upload resume after
  restart, conflicting part rejection, grant survival across restart and
  refusal after lock, Responsive circuit separation by file, contact and
  mailbox, and missing-part recovery: no request inside the quiet period, the
  re-sent part completing a hash-checked file, unknown and other contacts'
  files ignored, the sender's and receiver's per-file limits and the attempt
  bound.
