---
id: S06
title: Key Agreement & Double Ratchet
crates: [najwa-protocol, najwa-core]
depends-on: [S01, S03, S05, S07, S16]
---

# S06 — Key Agreement & Double Ratchet

## Overview

Every conversation is a pairwise session built in two steps.

**X3DH** lets one person start a session with someone who is offline. The
responder publishes a *prekey bundle* to each of its receive queues on a mailbox:
a signed prekey (SPK), a pool of one-time prekeys (OPKs) and a signed manifest
listing them. The initiator fetches a bundle, verifies it with the responder's
certified per-mailbox signing key ([S05 §3](05-contact-establishment.md)),
combines three or four Diffie-Hellman results with HKDF, and sends an Initial
message. The responder repeats the same DH operations with its private keys and
derives the same secret.

The **Double Ratchet** then encrypts every message with a fresh key. A
symmetric chain gives each message its own key; a DH ratchet step on every
change of speaker mixes in new randomness. Old keys are deleted, so a stolen
device cannot read past traffic, and the session heals after a compromise once a
new DH step happens.

The rest of this document fixes the exact inputs, the order of state changes,
and the rules that keep a session consistent under loss, reordering, crashes and
forged frames. The ratchet never changes state for a frame that fails
authentication. Outgoing state is saved before a frame leaves the device, and
retries resend the saved bytes.

The release runs one device per identity. The device key equals the identity
key (§7).

## 1. Scope

This specification defines:

- X3DH initiation and response, with 4-DH and a signed 3-DH fallback.
- Prekey-bundle manifest verification and the OPK-withholding rule.
- The cleartext X3DH header carried in Initial messages.
- Double Ratchet initialisation, key derivation, sending, receiving and the DH
  ratchet step.
- Skipped message keys and their limits.
- Epoch-link validation.
- Session repair and the reorder quarantine.
- State-commit invariants.
- The prekey-bundle wire object, SPK and manifest signatures.
- Prekey generation, rotation, replenishment, maintenance, per-queue scoping and
  publication after identity recovery.

Pairwise pseudonym derivation is defined in [S01 §8](01-crypto-primitives.md).
The WireMessage framing is in [S07 §2](07-message-format.md).

## 2. X3DH Key Agreement

### 2.1 Participants

The initiator (Alice) has:

- `IK_A` — her Ed25519 identity key pair.
- `EK_A` — a fresh X25519 ephemeral key pair.

The responder (Bob) publishes, per receive queue:

- `mailbox_ik_pub_B` — his per-mailbox signing key, certified in his signed
  `MailboxEntry` ([S05 §2.3](05-contact-establishment.md)).
- `SPK_B` — his X25519 signed prekey, signed by `mailbox_ik_priv_B`.
- `OPK_B` — at most one X25519 one-time prekey per fetch.

Alice already holds Bob's real identity key `IK_B` from his signed
HandshakePayload. DH always uses the real identity keys. Signature checks on
prekey material always use the mailbox key.

### 2.2 Initiator Computation

```
x3dh_initiate(contact):
  For each remote target of the contact, in stored order:
   1. Fetch: POST /v1/prekey/fetch with the target's deposit capability
      (S16 §3.7), on a circuit isolated per prospective contact (S04 §4.1.1).
      On a 429 carrying a proof-of-work challenge, solve it bound to the deposit
      capability with blob_hash = 32 zero bytes, and retry once.
      A transport or server error moves to the next target.
   1a. Signer and manifest:
      - The bundle's mailbox_ik_pub MUST equal the mailbox_ik_pub of the
        contact's signed MailboxEntry for that onion. If no entry is stored, it
        MUST equal IK_B. A mismatch is InvalidSignature.
      - The manifest MUST be present (ManifestInvalid otherwise).
      - Verify the manifest signature (§4.3) against mailbox_ik_pub, with spk_id
        taken from the served bundle.
      - opk_ids MUST have at most 200 entries, MUST have exactly opk_count
        entries, MUST be strictly ascending, and SHA-256 over them (§4.3) MUST
        equal opk_id_set_hash.
      - Every served OPK id MUST appear in opk_ids.
      Any failure is ManifestInvalid: move to the next target.
   1b. 3-DH acceptance (downgrade detection):
      - If opk_count > 0 and the bundle carries no OPK: OpkWithheld. The mailbox
        is withholding OPKs; move to the next target.
      - 3-DH is acceptable only with a signed opk_count == 0.
      - An OPK and its id are both present or both absent (ManifestInvalid).
   1c. SPK signature: verify (§4.2) against mailbox_ik_pub. On failure (or a
      signer mismatch in 1a) fetch once more from the same target; a second
      failure aborts the whole initiation with InvalidSignature.
   2. EK_A = X25519 key pair from the CSPRNG.
   3. X_IK_A = Ed25519→X25519(IK_A private); X_IK_B = Ed25519→X25519(IK_B).
   4. DH1 = X25519(X_IK_A_priv, SPK_B)
      DH2 = X25519(EK_A_priv,  X_IK_B)
      DH3 = X25519(EK_A_priv,  SPK_B)
      DH4 = X25519(EK_A_priv,  OPK_B)          // only if an OPK was served
      Each DH output MUST be contributory (not all-zero); a low-order public key
      aborts with CryptoError.
      DH = DH1 || DH2 || DH3 [|| DH4]           // 96 or 128 bytes
   5. SK = HKDF-SHA256(
        IKM  = DH,
        salt = 32 zero bytes,
        info = "najwa/v1/x3dh/" || X_IK_A_pub || X_IK_B_pub,   // 14 + 32 + 32 = 78 bytes
        L    = 32)
   6. AD = IK_A_pub || IK_B_pub                 // Ed25519, 64 bytes
   7. Zeroize DH, every DH output and converted private keys. Keep EK_A's private
      key only to initialise the ratchet (§3.2).
   8. Header = { identity_key: IK_A_pub, ephemeral_key: EK_A_pub,
                 device_key: IK_A_pub, spk_id, opk_id? }       (§2.4)
  If every target fails, return the last error.
```

Every bundle the initiator accepts proves that the mailbox did not strip OPKs to
force 3-DH: a mailbox cannot produce a signed `opk_count == 0` for a pool that
had keys, and a positive count with no OPK is rejected. The manifest's
`opk_count` reflects the pool at upload time. When the server refuses to serve
the last OPK (§2.5), a responder whose manifest still lists keys is briefly
unreachable on that queue rather than silently downgraded. Replenishment keeps
the pool above that boundary in normal operation.

A responder that repeatedly serves a signed `opk_count == 0` to the same
initiator MUST be surfaced to the user.

### 2.3 Responder Computation

The responder processes an Initial (WireMessage type `0x01`) as follows. Nothing
is persisted until step 10.

```
x3dh_respond(initial):
  0. Transport dedup: header_id = SHA-256(ratchet dh_pub || n as u32 BE)[0:16].
     A seen header_id is dropped and re-acknowledged; it MUST NOT touch any
     session.
  0a. If prekey publication after identity recovery is incomplete (§5.8), refuse
     the Initial as a transient error; the blob is not acknowledged.
  1. Parse the X3DH header (§2.4).
  2. SPK = local SPK with this spk_id, unused, not past its expires_at (the
     rotation grace). Missing → NoSignedPrekey.
  3. If the header names an OPK: the local OPK with that id, unused and not past
     its expires_at. Missing → NoSignedPrekey. It is NOT consumed yet.
     OPK presence MUST match the header flag.
  4. DH1 = X25519(SPK_B_priv,  X_IK_A)
     DH2 = X25519(X_IK_B_priv, EK_A)
     DH3 = X25519(SPK_B_priv,  EK_A)
     DH4 = X25519(OPK_B_priv,  EK_A)            // if an OPK was named
     Each output MUST be contributory.
  5. SK = same HKDF as §2.2 step 5, info = "najwa/v1/x3dh/" || X_IK_A_pub || X_IK_B_pub
     (initiator first on both sides).
  6. AD = IK_A_pub || IK_B_pub (initiator first).
  7. state = init_bob(SK, SPK_B) (§3.2); decrypt the first frame (§3.5) with
     message_aad = AD || wire_prefix. Failure rejects the Initial.
  8. Resolve the contact from the plaintext's sender pseudonym (first 32 bytes
     of the Payload, S07 §4):
     - If a contact matches (ik_pub, device_pub) from the header and it is not
       the pseudonym's contact: PseudonymMismatch.
     - The header's identity_key MUST equal the pseudonym contact's pinned
       identity key.
     - No contact for the pseudonym and content_type 0x04: the reciprocal
       handshake path of S05 §8.2.
     - Otherwise: UnknownPseudonym.
  9. Session guard (invariant I4):
     - No session: proceed.
     - Session without a receiving chain (our own Initial is unanswered): this is
       a crossing Initial. Compare our current DHs public key (our EK_A) with the
       incoming EK_A as unsigned 32-byte strings. Ours larger: drop the incoming
       Initial (KeepLocalSession). Otherwise adopt the incoming session.
     - Established session: accept only if the Payload is a SessionRepairInit
       (control 0x31, §3.7.1); otherwise drop it as a duplicate. Redundant copies
       of an Initial delivered over several mailboxes MUST NOT replace an
       advanced session.
  10. Commit atomically (§3.11 I3): ratchet state, session AD, OPK marked used,
      invitation queue marked accepted (S05 §5.2), message and dedup marks.
```

Consuming the OPK only inside the commit means a forged or replayed Initial
cannot burn it. Once committed, a second Initial naming the same OPK fails at
step 3.

### 2.4 Initial Message Embedding

The X3DH header travels in cleartext inside the WireMessage, before the ratchet
ciphertext. It cannot sit inside the ratchet AEAD: the responder needs it to
derive the key that AEAD uses. The deposit envelope keeps it hidden from the
mailbox ([S07 §3](07-message-format.md)). Binding every wire byte before the
ciphertext into the AEAD associated data (§3.4) makes any header change fail
decryption.

```
WireMessage 0x01 (Initial), see S07 §2:
  version(1) || type(1) = 0x01 || reserved(2) || payload_length(4, BE) ||
  x3dh_header_len(2, BE) || x3dh_header || ratchet_header(72) ||
  nonce(24) || ciphertext || tag(16)

X3DH header:
  Offset 0    identity_key   32   IK_A_pub (Ed25519)
  Offset 32   ephemeral_key  32   EK_A_pub (X25519)
  Offset 64   device_key     32   device signing key (= IK_A_pub, §7)
  Offset 96   spk_id          4   SPK id as sent by the server (u32 BE)
  Offset 100  opk_flag        1   0x00 no OPK, 0x01 OPK present
  Offset 101  opk_id          4   present only when opk_flag = 0x01
  Length: 101 bytes without OPK, 105 with OPK; 103 or 107 with the length prefix.
```

Parsers MUST reject an `opk_flag` other than `0x00` or `0x01`, and a header
whose length does not equal 101 or 105 to match the flag.

A session-repair Initial is an ordinary type `0x01` frame whose Payload is a
control message with subtype `0x31` (§3.7.1). The AEAD plaintext of every
Initial is the standard Payload ([S07 §4](07-message-format.md)); the X3DH
header is not repeated inside it.

### 2.5 OPK Management and Exhaustion Resistance

Without an OPK, X3DH falls back to three DH operations and the SPK is the only
medium-term key. The pool rules keep that case rare and detectable.

| Constant | Value | Meaning |
|----------|-------|---------|
| `OPK_BATCH_SIZE` | 200 | Target pool per receive queue, and the local maximum |
| `OPK_REPLENISH_THRESHOLD` | 50 | Top up to 200 when fewer unused OPKs remain |
| `OPK_LOW_ALERT_THRESHOLD` | 50 | User-visible notice |
| `OPK_CRITICAL_ALERT_THRESHOLD` | 10 | Urgent warning |
| `SPK_ROTATION_DAYS` | 7 | Rotate the SPK once it is 604,800 s old |
| `SPK_GRACE_PERIOD_SECS` | 1,209,600 | Accept a retired SPK for 14 days |
| Server prekey-fetch ceiling | 10 per minute per deposit capability | [S16 §8](16-mailbox-server.md) |
| Server prekey-fetch PoW threshold | above 5 per minute per deposit capability | 8–20-bit challenge, [S16 §7.2](16-mailbox-server.md) |
| Server OPK quota | 200 per capability | [S16 §9](16-mailbox-server.md) |

The client MUST show a notice when a queue's unused OPKs fall below 50 and an
urgent warning below 10.

The server MUST:

- never serve the last OPK: when one or none remains, serve the bundle without
  an OPK;
- return the bundle with the manifest exactly as uploaded;
- report `opk_low` in `/v1/status` when the pool holds 50 or fewer OPKs.

Rate limits are per capability. The mailbox runs behind an onion service and
cannot see circuits.

### 2.5.1 OPK Exhaustion Attack Resistance

- Fetching requires a valid deposit capability, and fetches are bounded per
  capability with adaptive proof-of-work above 5 per minute.
- On an invitation queue (type `0x01`) the first fetch consumes at most one OPK
  and every later fetch returns the same cached response, so re-fetching cannot
  drain the pool.
- The server never serves the last OPK.
- Hourly reconciliation and replenishment (§5.6) refill the pool before it runs
  low in normal use.
- The signed manifest (§2.2 step 1a) makes a forced 3-DH downgrade detectable.

### 2.6 X3DH Data Types

```
struct X3DHPrekeyBundle {
  identity_key: Ed25519Public,          // real IK_B (DH input)
  mailbox_ik_pub: Option<Ed25519Public>,// signer of SPK and manifest
  signed_prekey: X25519Public,
  signed_prekey_id: [u8; 4],
  signed_prekey_signature: Ed25519Signature,
  signed_prekey_timestamp: u64,
  one_time_prekey: Option<X25519Public>,
  one_time_prekey_id: Option<[u8; 4]>,
}

struct X3DHHeader {
  identity_key: Ed25519Public,          // IK_A_pub
  ephemeral_key: X25519Public,          // EK_A_pub
  device_key: Ed25519Public,            // = IK_A_pub (§7)
  signed_prekey_id: [u8; 4],
  used_one_time_prekey_id: Option<[u8; 4]>,
}

struct X3DHResult {                     // zeroized on drop
  shared_secret: [u8; 32],              // SK
  ephemeral_seed: [u8; 32],             // EK_A private (initiator only)
  header: X3DHHeader,
  associated_data: [u8; 64],            // IK_A_pub || IK_B_pub
}
```

### 2.7 Error Types

```
enum X3DHError {
  InvalidSignature,         // SPK signature or signer mismatch: abort
  ManifestInvalid,          // missing/invalid manifest, OPK flag mismatch
  OpkWithheld,              // signed opk_count > 0, no OPK served
  KeyConversionFailed(String),
  KeyDerivationFailed(String),
  CryptoError(CryptoError), // includes non-contributory DH
}
```

The service layer adds `NoSignedPrekey` (responder lacks the named SPK or OPK),
`PseudonymMismatch`, `UnknownPseudonym`, `DuplicateMessage` and
`KeepLocalSession` ([S08](08-messaging-service.md)).

## 3. Double Ratchet

### 3.1 State

```
struct RatchetState {
  DHs: X25519KeyPair,            // our current ratchet key pair
  DHr: Option<X25519Public>,     // their current ratchet public key
  RK: [u8; 32],                  // root key
  CKs: Option<[u8; 32]>,         // sending chain key
  CKr: Option<[u8; 32]>,         // receiving chain key
  Ns: u32,                       // next sending message number
  Nr: u32,                       // next expected receiving number
  PN: u32,                       // length of our previous sending chain
  prev_DHs_pub: Option<[u8; 32]>,// our previous sending-epoch public key
  MKSKIPPED: Map<(dh_pub[32], n: u32), SkippedKey>,
}

struct SkippedKey {
  message_key: [u8; 32],
  created_at: u64,               // expires at created_at + SKIP_KEY_EXPIRY_SECS
}
```

| Constant | Value | Meaning |
|----------|-------|---------|
| `MAX_SKIP` | 1,000 | Most keys skipped in one chain for one frame |
| `MAX_SKIPPED_KEYS_PER_SESSION` | 4,000 | Stored skipped keys per session; oldest evicted first |
| `SKIP_KEY_EXPIRY_SECS` | 7,776,000 | 90 days, matching mailbox retention ([S16 §10.1](16-mailbox-server.md)) |
| `REPAIR_GRACE_SECS` | 600 | Quarantine time before a frame is treated as lost (§3.7.1) |
| `EPOCH_QUARANTINE_MAX` | 32 | Frames held in the reorder quarantine, per profile |
| `MAX_REPAIR_RETRIES` | 3 | Repair attempts before local teardown (§3.7.1) |

All secret fields are zeroized when the state is dropped.

### 3.2 Initialisation

Alice (initiator), after §2.2:

```
DHs = EK_A                       // the authenticated X3DH ephemeral
DHr = SPK_B
(RK, CKs) = KDF_RK(SK, X25519(EK_A_priv, SPK_B))
CKr = None; Ns = Nr = PN = 0; prev_DHs_pub = None; MKSKIPPED = {}
```

Using `EK_A` as the first sending ratchet key binds the ratchet to the X3DH
handshake.

Bob (responder), at §2.3 step 7:

```
DHs = SPK_B
DHr = None
RK  = SK
CKs = CKr = None; Ns = Nr = PN = 0; prev_DHs_pub = None; MKSKIPPED = {}
```

Bob's first decryption performs his first DH ratchet step (§3.5). After it he
holds a sending chain and `prev_DHs_pub = SPK_B_pub`.

### 3.3 Key-Derivation Functions

```
KDF_RK(rk, dh_out):
  prk    = HKDF-Extract(salt = rk, IKM = dh_out)
  out    = HKDF-Expand(prk, info = "najwa/v1/ratchet/rk", L = 64)
  return (out[0:32] = new RK, out[32:64] = chain key)

KDF_CK(ck):
  mk     = HMAC-SHA256(ck, 0x01)        // message key
  new_ck = HMAC-SHA256(ck, 0x02)        // next chain key
  return (new_ck, mk)

derive_message_keys(mk):
  out = HKDF-SHA256(IKM = mk, salt = 32 zero bytes,
                    info = "najwa/v1/ratchet/mk", L = 80)
  enc_key  = out[0:32]                  // XChaCha20-Poly1305 key
  auth_key = out[32:64]                 // reserved, unused
  iv       = out[64:80]
  nonce    = iv || 8 zero bytes         // 24-byte XChaCha20 nonce
```

The nonce is a function of the message key, so each key encrypts exactly one
plaintext (invariant I2 keeps it that way across crashes).

### 3.4 Sending a Message

**Canonical message AAD.** Encryption and decryption build the same byte string
for every ratchet frame:

```
message_aad = session_ad(64) || wire_prefix
```

`session_ad` is the X3DH `AD` (`IK_A_pub || IK_B_pub`, initiator first, fixed for
the session). `wire_prefix` is every wire byte before the nonce:

```
Standard 0x02, ReadReceipt 0x11, CumulativeAck 0x12:
  version(1) || type(1) || reserved(2) || payload_length(4) || ratchet_header(72)
  = 80 bytes; message_aad = 144 bytes
Initial 0x01:
  version(1) || type(1) || reserved(2) || payload_length(4) ||
  x3dh_header_len(2) || x3dh_header(101 or 105) || ratchet_header(72)
  = 183 or 187 bytes; message_aad = 247 or 251 bytes
```

`payload_length` is the length of `nonce || ciphertext || tag`. The same
definition applies to the skipped-key path. [S07 §2.3](07-message-format.md)
states the same construction.

```
ratchet_encrypt(state, plaintext, session_ad, wire_meta):
  1. CKs MUST be present (NoSendingChain); Ns + 1 MUST NOT overflow.
  2. (CKs', mk) = KDF_CK(CKs)
  3. header = { dh_pub: DHs.public, pn: PN, n: Ns,
                epoch_link: prev_DHs_pub or 32 zero bytes }
  4. (enc_key, _, iv) = derive_message_keys(mk); nonce = iv || 0^8
  5. wire_prefix from wire_meta, header and payload_length = len(plaintext) + 40
  6. ct||tag = XChaCha20-Poly1305_Encrypt(enc_key, nonce, plaintext,
                                          session_ad || wire_prefix)
  7. encrypted_payload = nonce || ct || tag
  8. Commit CKs = CKs', Ns = Ns + 1. Zeroize mk and the derived keys.
```

Sending never performs a DH step. A responder can send once its first received
frame has created a sending chain.

**Message IDs.** The transport `msg_id` is derived from the sending chain's
`(DHs.public, Ns)` that the header carries ([S07 §6.1](07-message-format.md)).
Receivers MUST NOT verify the derivation.

**Retries.** The advanced sending state and the frame are committed before the
frame reaches the network (I2). A retry deposits the stored bytes again; it
never re-runs `ratchet_encrypt`.

### 3.5 Receiving a Message

Decryption follows **derive → verify → commit** (I1). Steps 2–6 compute a plan
against a read-only view of the state. Only step 8 changes it.

```
ratchet_decrypt(state, header, encrypted_payload, session_ad, wire_prefix):
  0. Delete skipped keys with created_at <= now - SKIP_KEY_EXPIRY_SECS.
  1. Skipped-key path. If (header.dh_pub, header.n) is in MKSKIPPED: decrypt with
     that key (step 7). On success remove the entry and return. On failure return
     DecryptionFailed and keep the entry for the genuine frame.
  2. If header.dh_pub == DHr (same epoch):
       if n < Nr: DecryptionFailed (consumed, not skipped)
       if n - Nr > MAX_SKIP: TooManySkipped
       derive keys Nr .. n-1 into pending skipped entries keyed (DHr, i)
       (CKr', mk) at n; Nr' = n + 1
     Otherwise (new epoch, including DHr = None) continue at step 3.
  3. Epoch-link validation. header.epoch_link MUST be 32 zero bytes or equal DHr.
     Otherwise return MissedEpochBoundary.
  4. If pn - Nr > MAX_SKIP: TooManySkipped. If CKr exists, derive keys Nr .. pn-1
     of the old chain into pending entries keyed (old DHr, i).
  5. Speculative DH step (§3.6) against header.dh_pub, producing
     (RK', CKr0, DHs', CKs', PN' = Ns, prev' = DHs.public).
  6. From CKr0 derive keys 0 .. n-1 into pending entries keyed (header.dh_pub, i),
     with the MAX_SKIP bound; (CKr', mk) at n; Nr' = n + 1.
  7. Verify: encrypted_payload MUST be at least 40 bytes; its first 24 bytes MUST
     equal the nonce derived from mk; then
     XChaCha20-Poly1305_Decrypt(enc_key, nonce, ct||tag, session_ad || wire_prefix).
     Any failure returns DecryptionFailed with the state unchanged.
  8. Commit: apply the plan (DH step results if any, CKr, Nr), insert the pending
     skipped keys with created_at = now, then evict the oldest skipped keys while
     more than MAX_SKIPPED_KEYS_PER_SESSION remain.
```

A non-contributory DH in step 5 fails with `CryptoError` and changes nothing.
The caller commits the new state in the receive transaction (I3).

### 3.6 DH Ratchet Step

On receive the step runs on the plan (§3.5 step 5) and reaches the state only at
the commit:

```
dh_ratchet_step(state, received_dh_pub):
  prev       = DHs.public
  PN         = Ns
  Ns         = 0
  Nr         = 0
  DHr        = received_dh_pub
  (RK, CKr)  = KDF_RK(RK, X25519(DHs_priv, DHr))
  DHs        = new X25519 key pair from the CSPRNG
  (RK, CKs)  = KDF_RK(RK, X25519(DHs_priv, DHr))
  prev_DHs_pub = prev
```

Every frame in a sending epoch carries the same `epoch_link`: the sender's
previous epoch key. If the first frame of an epoch is lost, any later frame of
that epoch still bridges the gap.

### 3.7 Skip Message Keys

Skipping is all-or-nothing. The bound is checked before any key is derived. Keys
go into a pending list that reaches `MKSKIPPED` only at the §3.5 commit.

```
skip(chain_key, from, until, dh_pub, pending):
  if until - from > MAX_SKIP: return TooManySkipped     // nothing derived
  for i in from .. until-1:
    (chain_key, mk) = KDF_CK(chain_key)
    pending.append(((dh_pub, i), mk))
```

The 4,000-key session cap bounds memory and storage when a peer forces many
near-`MAX_SKIP` gaps across epochs.

### 3.7.1 Session Recovery on Ratchet Failure

The mailbox releases deposits in batches and copies travel through several
mailboxes, so frames arrive out of order. The error model separates **reordered**
frames, which decrypt once the intervening frames arrive, from **lost** epochs,
which never will.

**Quarantine.** A Standard frame that fails with `MissedEpochBoundary`, or for
which no session matches (`NoMatchingSession`, for example a Standard that
overtook its Initial), is quarantined:

1. Identify the frame by SHA-256 of the decrypted inner WireMessage. A frame
   already quarantined is not added twice.
2. If fewer than `EPOCH_QUARANTINE_MAX` frames are held, store the frame and its
   arrival time durably in the local quarantine
   ([S08 §6.3](08-messaging-service.md)), keep it in memory, and acknowledge the
   server copy. The ratchet state is untouched.
3. If the quarantine is full, a `MissedEpochBoundary` frame goes straight to
   repair; any other frame fails.
4. On the first poll after start-up, reload stored frames once, keeping their
   original arrival times.
5. At the end of every poll, retry each held frame through the full receive
   path:
   - decrypts: deliver it and delete the stored copy;
   - still `MissedEpochBoundary` and held for `REPAIR_GRACE_SECS` or longer: start
     repair (reason `0x01`) and delete the copy;
   - still `NoMatchingSession` after `REPAIR_GRACE_SECS`: delete the copy; there is
     no authenticated peer to repair with;
   - transient storage error or rate limit: keep it;
   - any other error: delete the copy.

`TooManySkipped` starts repair at once (reason `0x02`): the gap provably exceeds
`MAX_SKIP`.

**Repair.** For contact *C*, with the failing frame's `dh_pub` and `epoch_link`.
*C* is the contact whose session the header names: its `DHr` equals `dh_pub`
(same epoch) or a non-zero `epoch_link` (next epoch). Trial decryption makes
every other session fail on a frame that is not its own, so only the named
session's error counts ([S08 §4.4](08-messaging-service.md)).

```
repair(C, reason, failed_dh_pub, failed_epoch_link):
  1. retry_count[C] += 1 (in memory).
  2. If retry_count[C] > MAX_REPAIR_RETRIES:
       mark C's repair failed;
       delete C's ratchet state and session AD locally;
       send nothing.
     The next outgoing message to C starts a fresh X3DH.
  3. Otherwise:
       run a fresh X3DH (§2.2) against C's current prekey bundle;
       build an Initial whose Payload is control subtype 0x31:
         reason(1) || failed_dh_pub(32) || failed_epoch_link(32)     // 65 bytes
         reason: 0x01 MissedEpochBoundary, 0x02 TooManySkipped
       commit the new candidate session with the outbox frame (I2); it replaces
       C's session;
       deliver it with the Paranoid strategy: every remote target of C, in random
       order (S08 §9.1).
     If the X3DH or the commit fails, C's current session stays in place and the
     next qualifying failure tries again.
```

`SessionReset (0x30)` is a different, bidirectional signal
([S08 §7.2](08-messaging-service.md)). Repair MUST NOT send it, because it would
make the peer delete its own working state.

**Receiving a repair.** A `SessionRepairInit` arrives in an Initial and is
accepted over an established session (§2.3 step 9). The receiver's session is
replaced by the new one in the commit. The receiver clears its own repair
tracking for that contact. The initiator clears its tracking when the next frame
from *C* commits: the old session is gone, so that frame is *C* answering in the
new one, normally its ACK of the repair Initial. Decoders accept a `0x31` body of
at least 65 bytes and ignore trailing bytes.

**Crossing repairs.** If both sides start repair at once, each holds an
unanswered Initial. The larger `EK_A` wins under the crossing rule of §2.3 step 9.

### 3.7.2 Repair and Queued Traffic

- Frames committed under a replaced session keep their stored bytes. The peer
  can decrypt them only while it still holds the old session.
- Gap-repair requests ([S07 §8.5](07-message-format.md)) to a contact are
  suppressed while a repair for it is in progress.
- Logical-message dedup ([S07 §6.2](07-message-format.md)) absorbs content that
  arrives twice under different sessions.

### 3.8 Skipped Key Cleanup

Expired skipped keys are removed at the start of every decryption (§3.5 step 0)
and are not loaded from storage. Every send or receive commit rewrites the
contact's stored skipped keys from the current state, so expired rows are
deleted at the contact's next commit. Rows of contacts that stay silent are
deleted by the storage retention pass, which removes every row past
`expires_at = created_at + SKIP_KEY_EXPIRY_SECS` on the first cleaner tick
after unlock and hourly while unlocked ([S03 §6.4](03-encrypted-storage.md)).

### 3.9 Ratchet Header (72 bytes)

| Offset | Size | Field |
|--------|------|-------|
| 0 | 32 | `dh_pub` — sender's current ratchet public key (X25519) |
| 32 | 4 | `pn` — previous sending-chain length, u32 BE |
| 36 | 4 | `n` — message number in the current chain, u32 BE |
| 40 | 32 | `epoch_link` — sender's previous sending-epoch public key, or 32 zero bytes |

The sender writes zeros only when it has no previous sending epoch. Receivers
MUST accept zeros. The authoritative WireMessage layout is
[S07 §2.2](07-message-format.md).

### 3.10 Persistence

The ratchet state is stored per contact in `ratchet_sessions`
([S03 §5.4](03-encrypted-storage.md)): `dhs_private`, `dhs_public`, `dhr`, `rk`,
`cks`, `ckr`, `ns`, `nr`, `pn`, `prev_dhs_pub`. The secret columns (`dhs_private`,
`rk`, `cks`, `ckr`) are additionally sealed per row ([S03 §7](03-encrypted-storage.md)).
`prev_DHs_pub` MUST be persisted with the state, in the same write, so that
`epoch_link` survives a reload. A row written before the column existed reads
`None` and sends zeros until its next DH step.

Skipped keys live in the `skipped_keys` table
([S03 §5.5](03-encrypted-storage.md)), keyed by contact, `dh_pub` and message
number, with `created_at` and `expires_at`. They are loaded into the state with
it, excluding expired rows, and written back in the same transaction as the
state.

The session AD is stored beside the state ([S03 §5.3](03-encrypted-storage.md)).

### 3.11 State-Commit Invariants

These invariants are normative for every implementation. They exist because
desynchronization under loss recurs wherever state changes before verification
or is saved after transmission.

**I1 — derive → verify → commit.** No ratchet-state change (`CKr`, `Nr`, DH
state, `MKSKIPPED`) happens before the AEAD tag verifies. Skipped-key lookup is
non-destructive: the key is removed only after its frame decrypts. Skipping is
all-or-nothing. A forged frame carrying a current `(dh_pub, n)` therefore cannot
burn the genuine message's key.

**I2 — persist before send.** The advanced sending state, the outgoing frame
and the outgoing message row commit in one transaction before the frame reaches
the network. After a restart, saved frames are pending same-bytes retries. Only
session repair or gap repair re-encrypts content, under logical-message dedup. A
crash between encryption and deposit can never produce two plaintexts under one
`(key, nonce)`.

**I3 — atomic receive.** The ratchet state, skipped keys, message, dedup marks
and any control effects commit in one storage transaction. For an Initial the
same transaction also stores the session AD, marks the OPK used and marks an
invitation queue accepted. The commit completes before the blob is included in
`/v1/acknowledge`. The client acknowledges a blob only when:

- its processing reached durable persistence; or
- it was a definitive discard (dedup hit, envelope decryption failed for every
  local queue, unknown type after its chain position is committed, or a
  permanent processing error); or
- it was copied durably into the local quarantine (§3.7.1).

Transient failures (storage errors, rate limits, incomplete prekey recovery) are
not acknowledged; the server copy is retried.

**I4 — Initial handling.** Transport dedup runs before any session state from
an Initial is persisted (§2.3 step 0). An Initial for an established session is
ignored unless it carries `SessionRepairInit`. Crossing Initials resolve by the
larger `EK_A` (§2.3 step 9).

### 3.12 Error Types

```
enum RatchetError {
  NoSendingChain,
  NoReceivingChain,
  NoDHR,
  TooManySkipped { limit: u32, requested: u32 },  // repair at once (§3.7.1)
  MissedEpochBoundary,                            // quarantine first (§3.7.1)
  DecryptionFailed,
  EncryptionFailed,
  CorruptedState,                                 // counter overflow, bad state
  InvalidHeader(String),
  KeyDerivationFailed(String),
  CryptoError(CryptoError),                       // includes non-contributory DH
}
```

## 4. Prekey Bundle

### 4.1 Wire Format

A prekey bundle is a JSON object. Byte fields are standard Base64 with padding.
The upload and fetch request envelopes are in
[S16 §3.6 and §3.7](16-mailbox-server.md).

| Field | JSON type | Content |
|-------|-----------|---------|
| `mailbox_ik_pub` | string | Base64 of the 32-byte per-mailbox signing key. Servers also accept the name `identity_key` on upload |
| `signed_prekey` | string | Base64 of the 32-byte X25519 SPK |
| `signed_prekey_id` | number | SPK id: its 4 bytes read as a big-endian u32 |
| `signed_prekey_signature` | string | Base64 of the 64-byte signature (§4.2) |
| `signed_prekey_timestamp` | number | SPK creation time, Unix seconds |
| `one_time_prekeys` | array | Upload: every unused OPK of the queue. Fetch: at most one. Each item is `{ "id": u32, "key": Base64(32 bytes) }`. The server omits the field when it serves none; clients MUST read an absent field as an empty list, which §2.2 step 1b then judges |
| `manifest` | object | §4.3 |

`manifest` object:

| Field | JSON type | Content |
|-------|-----------|---------|
| `opk_id_set_hash` | string | Base64 of the 32-byte set hash |
| `opk_count` | number | u32 |
| `opk_ids` | array of number | The ids, strictly ascending, at most 200 |
| `timestamp` | number | Manifest creation time, Unix seconds |
| `signature` | string | Base64 of the 64-byte signature |

Prekey ids are 4 CSPRNG bytes. Ids are insert-only per profile: a collision rolls
back the whole batch, and ids stay reserved after their keys are deleted.

### 4.2 SPK Signature

```
spk_message   = "najwa/v1/spk/" || spk_pub(32) || spk_id(4) || spk_timestamp(8, BE)
                                                                 // 13 + 44 = 57 bytes
spk_signature = Ed25519_Sign(mailbox_ik_priv, spk_message)
```

The signer is the per-mailbox derived key of the queue's mailbox
([S05 §3](05-contact-establishment.md)), never the identity key. Initiators
verify it with the `mailbox_ik_pub` from the certified entry.

### 4.3 Manifest Signature

```
opk_id_set_hash   = SHA-256( u32_BE(id_1) || … || u32_BE(id_k) )  // ids ascending
manifest_message  = spk_id(4) || opk_id_set_hash(32) || opk_count(4, BE) ||
                    timestamp(8, BE)                               // 48 bytes
manifest_signature = Ed25519_Sign(mailbox_ik_priv, manifest_message)
```

`spk_id` is the bundle's SPK id. The manifest lists every OPK in the upload, so
`opk_count` equals the number of OPKs uploaded. Every upload carries a freshly
signed manifest. The mailbox stores and returns it without verifying it.

## 5. Prekey Manager

### 5.1 Normative Parameters

```
OPK_BATCH_SIZE            = 200       // per receive queue
OPK_REPLENISH_THRESHOLD   = 50
OPK_LOW_ALERT_THRESHOLD   = 50
OPK_CRITICAL_ALERT_THRESHOLD = 10
SPK_ROTATION_DAYS         = 7         // rotate when age >= 604,800 s
SPK_GRACE_PERIOD_SECS     = 1209600   // 14 days
OPK_USED_CLEANUP_DAYS     = 7         // delete used OPKs after 7 days
SERVED_OPK_RETENTION_SECS = 1209600   // 14 days, §5.6 reconciliation
MAINTENANCE_INTERVAL_SECS = 3600      // per receive queue
```

The replenishment and alert thresholds are independent values that happen to be
equal.

### 5.2 `PrekeyManager`

One manager instance serves one receive queue. It holds the identity key, the
queue's derived mailbox signing key, the queue's mailbox configuration, a
storage scope and a publisher:

```
PrekeyManager::new(identity, storage, publisher, mailbox)  // derives mailbox_ik
generate_initial_bundle()   // SPK + 200 OPKs, committed, returns upload bundle
rotate_signed_prekey()      // §5.4
replenish_if_needed(threshold) -> count
mark_opk_used(id)
get_opk(id) -> unused OPK
get_current_spk()
get_spk(id) -> SPK not past expires_at
maintenance()               // §5.6 steps 3–6
```

The publisher uploads through `POST /v1/prekey/upload` with the queue's deposit
capability and, as owner proof, its fetch capability
([S16 §3.6](16-mailbox-server.md)). In the app each upload first waits for a
control slot from the cover scheduler ([S10](10-cover-traffic.md)).

### 5.3 `PrekeyStorage` Trait

```
trait PrekeyStorage {
  commit_bundle(spk: Option<SignedPrekey>, opks: [OneTimePrekey], grace_end: u64)
      // Atomic: insert the new SPK/OPKs and set expires_at = grace_end on the
      // previous current SPK. Insert-only ids; a collision rolls back the batch.
  list_unused_opks() -> [StoredOpk]          // in this queue's publication pool
  save_signed_prekey(spk)
  get_current_spk() -> Option<StoredSpk>
  get_spk_by_id(id) -> Option<StoredSpk>
  expire_spk(id, expires_at)
  delete_expired_spks(before) -> u32
  save_one_time_prekeys(opks)
  count_unused_opks(mailbox_id) -> u32
  mark_opk_used(id)
  get_opk_by_id(id) -> Option<StoredOpk>
  delete_used_opks(before) -> u32
  list_mailboxes() -> [MailboxConfig]
}
```

The production implementation scopes every call to one mailbox and one fetch
capability (§5.7). Private keys in `StoredSpk` and `StoredOpk` are zeroized on
drop. The local pool for a scope never exceeds 200 unused OPKs.

### 5.4 SPK Rotation Procedure

```
rotate_signed_prekey():
  1. new SPK = X25519 key pair from the CSPRNG; id = 4 CSPRNG bytes.
  2. signature = Ed25519_Sign(mailbox_ik_priv, spk_message(pub, id, now)) (§4.2).
  3. commit_bundle(new SPK, [], grace_end = now + SPK_GRACE_PERIOD_SECS):
     the previous SPK gets expires_at = grace_end in the same transaction.
  4. Upload the current bundle: new SPK, every unused OPK, fresh manifest.
  5. Until expires_at the responder still accepts Initials naming the old SPK.
  6. Maintenance deletes SPKs whose expires_at has passed, with their private keys.
```

**Fetch snapshot consistency.** The server stores the SPK, its signature, its
timestamp and the manifest as one record, so a fetch returns them from the same
upload ([S16 §3.7](16-mailbox-server.md)).

**Initiator retry.** An initiator whose fetched bundle fails SPK verification
fetches once more from the same target. A second failure is a hard
`InvalidSignature`, not a retry loop (§2.2 step 1c).

### 5.5 OPK Replenishment

```
replenish_if_needed(threshold):
  unused = count of unused OPKs in the publication pool
  if unused < threshold:
    needed = OPK_BATCH_SIZE - unused
    commit_bundle(None, generate(needed), now + SPK_GRACE_PERIOD_SECS)
    upload the current bundle
    return needed
  return 0
```

Every upload (initial, rotation, replenishment, retry) carries a manifest
re-signed over the current unused set (§4.3).

### 5.6 Maintenance Schedule

Maintenance runs at the start of every poll, for every receive queue: the
mailbox's own queue, each registered per-contact queue and each active invitation
queue ([S05 §5](05-contact-establishment.md)). It also runs when an invitation is
created, when a mailbox is added and after contact setup registers new queues
([S05 §8](05-contact-establishment.md) step 11).

```
maintain(queue):
  0. Skip an invitation queue that is already accepted.
     Skip the queue if it ran within MAINTENANCE_INTERVAL_SECS and has no
     pending upload.
  1. If an upload is pending, retry that exact pool first (go to step 3).
  2. Otherwise, if the queue was maintained before, reconcile with the server:
     POST /v1/status (S16 §3.8) returns prekey_ids; their number MUST equal
     prekey_count. Every listed id MUST be an unused, unretired OPK of this scope;
     otherwise stop with an error. Unused local OPKs the server no longer lists
     were served: they leave the publication pool and their private keys are
     kept until now + SERVED_OPK_RETENTION_SECS.
  3. Delete SPKs past expires_at; delete used OPKs used more than 7 days ago.
  4. No current SPK: generate_initial_bundle and upload it.
     SPK age >= 7 days: rotate (§5.4).
  5. replenish_if_needed(OPK_REPLENISH_THRESHOLD) (§5.5).
  6. Upload the current bundle.
  7. Record the run time.
```

A pending-upload flag commits atomically with new keys or inventory changes and
clears after a successful upload. Each network call (status, upload) waits for
its own control slot.

### 5.7 Receive-Queue Scopes

Each receive queue has an independent SPK and OPK pool, even when several queues
share a mailbox onion. Reusing an OPK across server pools would break
consume-once semantics. The scope is the pair (mailbox, fetch capability). The
mailbox signing key is per onion, so queues on one mailbox share a signer.

The responder looks up an SPK or OPK by id alone. Ids are unique per profile
(§4.1).

### 5.8 Identity Recovery

A recovered identity no longer has the private keys behind the prekeys its
mailboxes still serve. Prekey publication restarts before any Initial is
accepted:

1. Before installing recovered key material, the identity layer writes a fresh
   random 32-byte generation to `prekey-recovery-<hex identity key>` beside the
   identity record. The record and the encrypted database share the profile
   directory.
2. At the next maintenance, if that generation is not recorded as prepared, the
   client in one transaction reserves every existing prekey id, deletes all local
   prekeys, clears the per-queue maintenance markers and records the generation
   as prepared.
3. Every invitation queue is deactivated on its server and marked locally. A type
   `0x01` queue authorizes one Initial for its whole life and is not reset.
4. Every other queue runs maintenance with a fresh SPK and pool, uploaded as an
   owner-authorized replacement: the upload sets `replace_opks` = `true`, and
   the server removes stored OPKs that are not in the upload
   ([S16 §3.6](16-mailbox-server.md)). Historical ids stay reserved on the server
   too.
5. When every queue has succeeded, the generation is recorded as complete.
   Retries reuse the same fresh local keys.

Until completion, Initials are refused as a transient error (§2.3 step 0a) and
stay on the server. The obligation survives restarts and password changes.

## 6. Rust Crate Dependencies

| Crate | Purpose |
|-------|---------|
| `najwa-crypto` | Ed25519, X25519, Ed25519→X25519, HKDF, HMAC, XChaCha20-Poly1305, SHA-256, CSPRNG |
| `najwa-storage` | Ratchet, skipped-key, prekey and quarantine persistence |
| `serde` / `serde_json` | Prekey-bundle JSON |
| `base64` 0.22 | Base64 fields |
| `rand` 0.8 | `OsRng` for ephemeral keys |
| `zeroize` | Secret cleanup |
| `async-trait` | `PrekeyStorage`, publisher |

## 7. Single-Device Operation

One identity has one device. The device signing key is the identity key:

- An initiator sets the X3DH header's `device_key` to `IK_A_pub`.
- A contact's stored device key equals its identity key
  ([S03 §5.2](03-encrypted-storage.md)).
- A responder looks contacts up by `(ik_pub, device_pub)` from the header
  (§2.3 step 8).

A header whose `device_key` differs from its `identity_key` matches no stored
contact by identity. It is then accepted only through the pseudonym match and
the pinned-key check of §2.3 step 8.

## 8. Security Considerations

- **Forward secrecy and healing.** Chain keys move forward one way, and message
  keys are deleted after use. Skipped keys are the exception: they stay for up to
  90 days, or until evicted, so the late message can still be read.
- **3-DH.** Without an OPK, compromise of the SPK private key within its lifetime
  plus grace exposes sessions started against it. The signed manifest prevents a
  mailbox from forcing this silently.
- **Identity binding.** The AD binds both identity keys into every AEAD tag, and
  DH1 and DH2 authenticate both parties. The pinned-key check of §2.3 step 8 stops
  anyone who learns a contact's pairwise pseudonym (for example from one leaked
  plaintext) from replacing that contact's session with one keyed to another
  identity.
- **Repair is not authentication.** A `SessionRepairInit` is accepted only
  inside a fresh X3DH that authenticates the sender's identity key.
- **Limitations.**
  - A `MissedEpochBoundary` frame names no session (its `dh_pub` and
    `epoch_link` match no `DHr`), so §3.7.1 cannot tell which contact sent it.
    The client reports it as `NoMatchingSession`: it is quarantined and discarded
    after `REPAIR_GRACE_SECS` without starting repair. Only `TooManySkipped`
    starts repair.
  - Repair progress is kept in memory only, so a restart forgets the retry
    count, and teardown removes both directions of the session.

## 9. Conformance Checklist

- X3DH initiator: signer binding, mandatory manifest with witness checks,
  OPK-withholding rejection, signed-zero 3-DH only, single refetch on SPK
  signature failure, contributory DH, exact HKDF inputs, AD order (§2.2).
- X3DH responder: transport dedup first, SPK and OPK lookup with grace, OPK
  consumed only in the commit, crossing and repair guard (§2.3).
- Cleartext X3DH header of 101/105 bytes with strict flag and length checks,
  device key equal to the identity key (§2.4, §7).
- Server never serves the last OPK; idempotent fetch on invitation queues (§2.5).
- Initialisation with `EK_A` as the first sending key (§3.2).
- `KDF_RK`, `KDF_CK`, 80-byte message-key expansion, IV-derived nonce (§3.3).
- Canonical `message_aad` on encrypt, decrypt and the skipped-key path (§3.4).
- Plan-then-commit decryption, non-destructive skipped keys, nonce check,
  epoch-link check, `MAX_SKIP` before derivation, 4,000-key cap with oldest-first
  eviction, 90-day expiry (§3.5–§3.8).
- Quarantine bounded at 32 frames, durable and reloaded after restart, 600-second
  grace (§3.7.1).
- `SessionRepairInit` accepted over an established session; `SessionReset` never
  sent by repair; repair started only for the session the header names and
  cleared when the contact's next frame commits (§3.7.1).
- `prev_DHs_pub` persisted with the state (§3.10).
- Invariants I1–I4 (§3.11).
- Prekey-bundle JSON, SPK signature, manifest signature (§4).
- Per-queue prekey pools: 200-key target, replenishment below 50, 7-day SPK
  rotation, 14-day grace, 7-day used-OPK cleanup, hourly reconciliation with
  served-key retention, pending-upload retry (§5).
- Recovery publication gate with owner-authorized replacement (§5.8).
