---
id: S01
title: Cryptographic Primitives
crates: [najwa-crypto]
depends-on: []
---

# S01 — Cryptographic Primitives

## Overview

This spec defines the cryptographic building blocks every other part of Najwa
uses: the fixed algorithm suite, the API contract of each primitive, canonical
byte encoding, random-number generation, handling of secrets in memory,
constant-time rules, the key hierarchy, and pairwise pseudonyms.

Najwa uses one fixed cipher suite. There is no algorithm negotiation on the
wire, no "best available" fallback and no caller-pluggable primitive. Changing
a primitive requires a new protocol version, never a runtime choice. A single
suite removes downgrade attacks and keeps the surface small enough to audit.

All primitives live in `najwa-crypto`. No other crate implements a
cryptographic primitive; they call this crate. Signatures use Ed25519, key
agreement uses X25519 on the same curve family, so an identity key can be used
for both after a standard conversion. Symmetric encryption is
XChaCha20-Poly1305 everywhere. Keys are derived with HKDF-SHA256, and every
derivation carries its own label so a key made for one purpose can never be
mistaken for a key made for another. The passphrase is stretched with
Argon2id.

Everything descends from one 32-byte identity seed. The seed is the Ed25519
private key. It is encrypted at rest under a key derived from the passphrase
and a device factor ([S02](02-identity-key-protection.md)), and it also yields
the database key, the per-mailbox signing keys and the pairwise pseudonyms.
Session keys come from X3DH and the Double Ratchet
([S06](06-key-agreement-ratchet.md)). §8 gives the whole tree; the
[key inventory](../reference/keys.md) follows each key from creation to
erasure, and the [label registry](../reference/hkdf-strings.md) lists every
domain-separation string with its exact bytes.

The suite is classical. Najwa does not use post-quantum primitives and does not
build its own cryptography: every algorithm is a published construction with
reference implementations in the RustCrypto and dalek libraries. The reasons
for each choice are in [Cryptographic Rationale](../security/crypto-rationale.md).

## 1. Normative Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are
interpreted as described in [RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119).

## 2. Algorithm Suite

The suite is fixed. Implementations MUST NOT negotiate algorithms or accept
substitutes.

| Purpose | Algorithm | Reference | Sizes |
|---------|-----------|-----------|-------|
| Signatures | Ed25519 | [RFC 8032](https://datatracker.ietf.org/doc/html/rfc8032) | 32-byte seed, 32-byte public key, 64-byte signature |
| Key agreement | X25519 | [RFC 7748](https://datatracker.ietf.org/doc/html/rfc7748) | 32-byte private key, 32-byte public key, 32-byte shared secret |
| Authenticated encryption | XChaCha20-Poly1305 | [draft-irtf-cfrg-xchacha](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha) | 32-byte key, 24-byte nonce, 16-byte tag |
| Key derivation | HKDF-SHA256 | [RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869) | 32-byte PRK, 1–8160-byte output |
| Passphrase hashing | Argon2id v1.3 | [RFC 9106](https://datatracker.ietf.org/doc/html/rfc9106) | 32-byte output |
| Hashing | SHA-256 | FIPS 180-4 | 32-byte output |
| MAC | HMAC-SHA256 | [RFC 2104](https://datatracker.ietf.org/doc/html/rfc2104) | 32-byte output |

### 2.1 Algorithm Identifiers (Stored in Identity Records)

The identity record ([S02 §7.1](02-identity-key-protection.md)) stores one-byte
algorithm identifiers:

```
KDF_ALG_ARGON2ID           = 0x01
AEAD_ALG_XCHACHA20POLY1305 = 0x01
Reserved: 0x00, 0x02–0xFF in each category
```

Both bytes are bound into the identity-record AAD
([S02 §8.1](02-identity-key-protection.md)).

### 2.2 Platform and Storage Primitives

The components below use cryptography outside the message suite. The database
and device-factor primitives protect data at rest on one device and never appear
in Najwa messages. Tor uses its own suite for transport.

| Component | Primitive | Spec |
|-----------|-----------|------|
| Local database | SQLCipher 4 page encryption (AES-256 with HMAC-SHA256 page authentication), keyed with a raw 32-byte key from §8.1 | [S03](03-encrypted-storage.md) |
| Device factor wrapping, Windows | RSA-2048 OAEP-SHA256 key generated inside the TPM 2.0 by the Microsoft Platform Crypto Provider | [S02 §17](02-identity-key-protection.md) |
| Device factor wrapping, Linux | TPM 2.0 sealed keyed-hash object | [S02 §17](02-identity-key-protection.md) |
| Device factor wrapping, macOS | Secure Enclave P-256 key, ECIES (cofactor X9.63 SHA-256, AES-GCM) | [S02 §17](02-identity-key-protection.md) |
| Tor | Arti's own suite | [S04](04-transport.md) |

## 3. Key Types and Primitive APIs

### 3.1 Ed25519

```
SEED_LENGTH       = 32 bytes
PUBLIC_KEY_LENGTH = 32 bytes
SIGNATURE_LENGTH  = 64 bytes
```

**Generation:**

```
seed = CSPRNG(32)
(priv, pub) = Ed25519_Generate(seed)
```

The private key is derived deterministically from the seed. Implementations
MUST store the 32-byte seed, not the expanded private key. Everywhere this
document set writes `IK_priv` or `IK_seed` for an Ed25519 key, it means this
seed.

**Signing:**

```
signature = Ed25519_Sign(priv, message)   // 64 bytes, deterministic
```

**Verification:**

```
valid = Ed25519_Verify(pub, message, signature)
```

Decoding a public key that is not a valid compressed Edwards point MUST fail.
Verification MUST fail for any signature that does not verify; callers MUST NOT
act on the message in that case.

### 3.2 X25519

```
PRIVATE_KEY_LENGTH   = 32 bytes
PUBLIC_KEY_LENGTH    = 32 bytes
SHARED_SECRET_LENGTH = 32 bytes
```

**Generation:**

```
priv = CSPRNG(32)          // clamped by X25519
pub  = X25519_BasePoint(priv)
```

**Diffie-Hellman:**

```
shared = X25519(my_priv, their_pub)
if shared is non-contributory (all zero):
    FAIL InvalidPublicKey
```

A peer public key of low order yields an all-zero shared secret. The DH
operation MUST reject it as an ordinary error, never a panic, so a hostile peer
key cannot abort the receive task. The check MUST be constant-time.

### 3.3 Ed25519 ↔ X25519 Conversion

Ed25519 and X25519 use the same curve in different coordinates. Identity keys
take part in X3DH and in pseudonym derivation through this conversion.

**Public key conversion:**

```
point = decompress(ed25519_pub)
if point is invalid:        FAIL KeyConversionFailed
if point is of small order: FAIL KeyConversionFailed
x25519_pub = to_montgomery(point)
```

**Private key conversion:**

```
h = SHA512(ed25519_seed)
s = h[0..32]
s[0]  &= 248
s[31] &= 127
s[31] |= 64
x25519_priv = s
```

Requirements:

- Public conversion MUST use the birational map provided by `curve25519-dalek`.
  Implementations MUST NOT implement field or curve arithmetic themselves.
- Invalid encodings and small-order points MUST fail the conversion. This keeps
  an attacker-chosen contact identity key from reaching the DH step.
- Private conversion MUST equal the RFC 8032 secret-scalar derivation shown
  above, so that `X25519_BasePoint(x25519_priv) == x25519_pub` for every key
  pair. Intermediate hash output MUST be zeroized.

### 3.4 XChaCha20-Poly1305

```
KEY_LENGTH   = 32 bytes
NONCE_LENGTH = 24 bytes
TAG_LENGTH   = 16 bytes
```

**Encryption:**

```
ciphertext_with_tag = XChaCha20Poly1305_Encrypt(key, nonce, plaintext, aad)
// length = len(plaintext) + 16
```

**Decryption:**

```
plaintext = XChaCha20Poly1305_Decrypt(key, nonce, ciphertext_with_tag, aad)
// error on authentication failure
```

Requirements:

- A nonce MUST NOT repeat under one key. Every AEAD use in Najwa meets this in
  one of two ways:
  - **Random nonce**: 24 bytes from the OS CSPRNG (§5). Used for the identity
    record, recovery record, deposit envelope, per-row fields, volatile keys
    and disappearing-message content. The 192-bit nonce space makes random
    nonces safe.
  - **Derived nonce**: the ratchet derives a fresh 16-byte IV from each
    single-use message key and appends 8 zero bytes
    ([S06 §3.3](06-key-agreement-ratchet.md)). Each message key encrypts
    exactly one message.
- Decryption MUST NOT return partial plaintext on failure.
- Tag comparison MUST be constant-time.

**Blob format (when the nonce travels with the ciphertext):**

```
encrypted_blob = nonce(24) || ciphertext || tag(16)
overhead       = 40 bytes
```

Inputs shorter than 40 bytes MUST be rejected before decryption.

### 3.5 HKDF-SHA256

```
PRK = HKDF_Extract(salt, IKM)          // 32 bytes
OKM = HKDF_Expand(PRK, info, length)   // length ≤ 8160
OKM = HKDF(IKM, salt, info, length)    // Extract then Expand
```

An empty salt is equivalent to a salt of 32 zero bytes (RFC 5869 §2.2). The
PRK MUST be zeroized after Expand.

**Domain separation.** Every derivation, every AEAD use with a fixed context and
every signature or hash over a fixed context uses its own label. Most labels
start with `najwa/v1/`; a few local-only labels are bare strings. The
[label registry](../reference/hkdf-strings.md) lists every label the release
uses, with its exact bytes, and [S18 §18](18-test-vectors.md) pins them.

- Labels are ASCII, used without a terminating NUL unless the registry shows one.
- A label ending in `/` is a prefix; the full `info` is the prefix followed by the
  per-call suffix, and the whole concatenation is the `info`.
- Implementations MUST NOT introduce a label that is not in the registry, and
  MUST NOT reuse one label for two purposes.
- The `v1` in a label is a format version. It MUST NOT change without a
  protocol version change.

### 3.6 SHA-256

```
hash = SHA256(message)   // 32 bytes
```

Used for: the identity-record checksum ([S02 §7.3](02-identity-key-protection.md)),
`cap_hint = SHA256(deposit_capability)[0:8]` ([S07 §3](07-message-format.md)),
the content hash inside the message id and the logical message id
([S07 §6](07-message-format.md)), the OPK id-set commitment in the prekey
manifest ([S06 §2.2](06-key-agreement-ratchet.md)), file integrity
([S11](11-file-transfer-sanitization.md)), proof-of-work
([S16 §7](16-mailbox-server.md)), and the domain-labelled binding hashes listed
in the registry.

### 3.7 HMAC-SHA256

```
mac = HMAC_SHA256(key, message)   // 32 bytes
```

Used for: the Double Ratchet chain step `KDF_CK`
([S06 §3.3](06-key-agreement-ratchet.md)), and the tags on the unlock attempt
counter and on the stored Argon2 timing reference, both keyed with the device
factor ([S02 §9–§10](02-identity-key-protection.md)). MAC verification MUST be
constant-time.

### 3.8 Argon2id

```
VERSION        = 0x13 (v1.3)
TYPE           = Argon2id
TAG_LENGTH     = 32 bytes
SALT_LENGTH    = 32 bytes
MIN_MEMORY_KIB = 65536     // 64 MiB, hard floor
MAX_MEMORY_KIB = 4194304   // 4 GiB
MIN_ITERATIONS = 3
MAX_ITERATIONS = 100
MIN_PARALLELISM = 1
MAX_PARALLELISM = 16
DESKTOP_TARGET_KIB = 524288   // 512 MiB
CALIBRATION_TARGET_MS = 1000
```

**Derivation:**

```
K_pwd = Argon2id(
    password    = UTF8(NFC(password)),   // empty password rejected
    salt        = salt,                  // 32 bytes from CSPRNG
    memory      = m_cost,                // KiB
    iterations  = t_cost,
    parallelism = p,
    tag_length  = 32
)
```

Parameters outside the bounds above MUST be rejected before any memory is
allocated. The Argon2 working memory MUST be allocated fallibly, so an
allocation failure is an error and not an abort, and it MUST be zeroized on
every exit path, including errors and unwinding.

**Calibration** runs when an identity record is created (new identity or
recovery) and its result is stored in the record
([S02 §6](02-identity-key-protection.md)):

```
1. parallelism = clamp(available CPU cores, 1, 16)
2. memory = DESKTOP_TARGET_KIB
3. Run Argon2id once at (memory, 3, parallelism).
   If the memory cannot be allocated:
       if memory > MIN_MEMORY_KIB: memory = max(memory / 2, MIN_MEMORY_KIB); repeat step 3
       else: FAIL — the device does not meet the minimum
4. iterations = 3
5. loop:
       time one Argon2id run at (memory, iterations, parallelism)
       if elapsed ≥ CALIBRATION_TARGET_MS or iterations ≥ 100: stop
       iterations += 1
6. Store (memory, iterations, parallelism) and the salt in the identity record.
```

Calibration never lowers the work below one second on the calibrating device,
except when 100 iterations are reached first. A slower derivation raises the
attacker's guessing cost and is accepted; a faster one is not. A device that
cannot allocate 64 MiB for Argon2 MUST NOT create an identity.

Unlock and password change use the parameters stored in the record.

## 4. Canonical Encoding

Unless a spec says otherwise:

- Integers are unsigned and big-endian.
- Fixed-length byte arrays carry no length prefix.
- Variable-length fields carry an explicit length prefix whose width the owning
  spec defines.
- There is no implicit padding between fields.
- Parsers MUST reject wire structures with invalid lengths or trailing bytes.
- Strings are UTF-8. Passwords are NFC-normalized before use.

## 5. Secure Random Number Generation

### 5.1 CSPRNG Requirements

All random bytes used as key material, nonces, salts, capabilities, tokens or
identifiers MUST come from the operating system CSPRNG:

| Platform | Source |
|----------|--------|
| Linux | `getrandom(2)` (falls back to `/dev/urandom`) |
| Windows | `BCryptGenRandom` (falls back to `RtlGenRandom`) |
| macOS | `getentropy` |
| Rust | `rand::rngs::OsRng`, through `najwa_crypto::random` |

`najwa_crypto::random::{random_bytes, random_bytes_vec, fill_random}` are the
single auditable entry points. Key generation that takes a generator
(`X25519KeyPair::generate`, `Ed25519KeyPair::generate`) is passed
`rand::rngs::OsRng`: the X3DH ephemeral key, prekeys and ratchet keys.
`scripts/check-os-rng.sh` fails if a userspace generator (§5.3) appears in
production code outside the files reviewed as non-security.

### 5.2 Entropy Verification

Before any secret state is loaded, `najwa_crypto::initialize()` MUST run and
MUST succeed:

```
disable_core_dumps()                // §6.3; on failure: refuse to start
test = CSPRNG(32)                   // through the fallible API
if the CSPRNG returns an error or test == zeros(32):
    refuse to start (EntropyUnavailable)
```

The desktop service, the C ABI and the mailbox server call `initialize()` at
startup and fail closed on error.

### 5.3 Prohibited PRNGs

The following MUST NOT be used for security-relevant values:

- Mersenne Twister and other non-cryptographic generators
- Linear congruential generators
- `rand::rngs::StdRng` or any generator seeded from a non-OS source
- `Math.random` (JavaScript)
- Any generator seeded from predictable inputs (PID, time)

Non-security randomness (scheduling jitter, shuffling of send order) MAY use
`rand::thread_rng`.

## 6. Secure Memory Handling

### 6.1 Zeroization Policy

Secret material MUST be overwritten as soon as it has served its purpose.
Dropping or freeing memory is not enough.

As a backstop for copies held inside dependencies, the native service and the
mailbox server MUST install `najwa_crypto::memory::ZeroizingAllocator` as the
global allocator. It zeroes every block before releasing it, and `realloc`
always moves the block so the old copy is zeroed. It does not replace the
explicit zeroization below: a live buffer is not freed, and the allocator
cannot reach memory outside the heap.

| Material | When zeroized |
|----------|---------------|
| Passphrase bytes | Immediately after Argon2id |
| `K_pwd` | After KEK derivation |
| HKDF PRK | After HKDF-Expand |
| KEK | After the identity record is encrypted or decrypted |
| Device factor (DKM) | After KEK derivation and tag computation |
| Identity seed | On lock, on profile erasure, and after every derivation that copies it |
| Recovery seed and `K_recovery` | After the recovery record is created or opened |
| Database key | On lock |
| Message keys and their expansion | Immediately after encrypt or decrypt |
| Deposit-envelope outer key ([S07 §3.1](07-message-format.md)) | Immediately after envelope encrypt or decrypt |
| Chain and root keys | When the ratchet replaces them, and when ratchet state is dropped |
| Skipped message keys | On use, or at expiry ([S06 §3.8](06-key-agreement-ratchet.md)) |
| Old ratchet DH private keys | When a DH ratchet step replaces them |
| Volatile disappearing-message keys | On expiry and on lock after persistence ([S12 §4](12-disappearing-messages.md)) |
| Argon2 working memory | On every exit path |

In Rust, secret types implement `Zeroize` and zeroize on drop
(`ZeroizeOnDrop`, `Zeroizing<T>`, or an explicit `Drop`). Secret types MUST NOT
print their contents through `Debug`.

### 6.2 Memory Locking

Memory holding long-lived secrets SHOULD be locked against paging to swap
(`mlock(2)` on Linux and macOS, `VirtualLock` on Windows).

While a profile is unlocked, the release locks two secrets: the identity seed
and the database key. Each is held once, in a
`najwa_crypto::memory::GuardedMemory` region: an allocation of whole pages,
page-aligned, that holds nothing else, so locking or unlocking it never affects
another value. On drop the region is zeroed, then unlocked and freed; lock
drops both (§6.1).

- **Identity seed.** Held as an ed25519-dalek `SigningKey`, which stores only
  the seed and the public key, zeroizes the seed on drop, and expands it for
  each signature into a value that is also zeroized on drop. The identity
  manager, the messaging service and the local service share the one region:
  a clone of `Ed25519KeyPair` shares the key and copies nothing.
- **Database key.** Derived straight into its region. Every SQLCipher handle of
  the profile shares that region instead of keeping its own copy.

If the OS refuses the lock (`RLIMIT_MEMLOCK` too low, or the Windows
working-set quota used up), the secret stays in its region in pageable memory
and everything else works as before: unlock and startup do not fail. A warning
is logged, and `najwa_crypto::memory::unlocked_region_count()` reports how many
live regions are unlocked, so an application can show it (the local service
discards library logs, [S13 §18](13-privacy-hardening.md)). On platforms other
than Windows, Linux and macOS nothing is locked.

SQLCipher locks and wipes its own buffers (`cipher_memory_security = ON`,
[S03 §4.2](03-encrypted-storage.md)). On Windows they draw on the same
working-set quota; the two regions above are locked before the database opens.

**Lock quota.** The default limits leave little to lock: on Windows the
default minimum working set lets a process lock only about 150 KB, and beyond
that most SQLCipher buffer locks fail with `ERROR_WORKING_SET_QUOTA` (1453).
`najwa_crypto::memory::ensure_lock_quota()` raises the limit once per process,
best effort. Every SQLCipher open calls it before the connection is created, and
`initialize()` calls it at startup, so the local service, the mailbox server and
test binaries all get it.

- **Windows.** `SetProcessWorkingSetSizeEx` sets a minimum working set of
  64 MiB (and a maximum of at least that), with
  `QUOTA_LIMITS_HARDWS_MIN_DISABLE | QUOTA_LIMITS_HARDWS_MAX_DISABLE`. The
  minimum bounds what `VirtualLock` may lock; because both limits are soft,
  Windows can still trim unlocked pages when memory is short. Nothing changes
  if the minimum is already at least 64 MiB. Raising it needs
  `SeIncreaseWorkingSetPrivilege`, which Windows grants to Users; the call
  succeeds from a standard medium-integrity token where that privilege is
  present but not enabled. Measured on the storage tests: the unit suite, which
  opens many databases in parallel, locks every buffer at 64 MiB and has about
  6 000 refused locks at 32 MiB; the integration suite locks every buffer at
  16 MiB.
- **Linux and macOS.** The soft `RLIMIT_MEMLOCK` is raised to the hard limit.
  The hard limit is not raised (that needs privilege), so locks beyond it, for
  example past a common 8 MiB hard limit on Linux, still fail.

A failure is logged and changes nothing else: memory that cannot be locked
stays pageable, as above.

Not covered: session state (ratchet, skipped, prekey and message keys), the
per-mailbox signing keys and transient copies made during a derivation are
zeroized on drop but stay in ordinary, pageable memory. Locking does not keep a
secret out of the hibernation file: hibernation writes all of memory, locked
pages included.

### 6.3 Core Dump Prevention

The process MUST prevent core dumps before it loads secrets:

| Platform | Mechanism |
|----------|-----------|
| Linux | `prctl(PR_SET_DUMPABLE, 0)` and `RLIMIT_CORE = 0` |
| macOS | `RLIMIT_CORE = 0` |
| Windows | Crash dumps of the process MUST be suppressed: `WerAddExcludedApplication(<executable file name>, FALSE)`, plus `SetErrorMode(SEM_FAILCRITICALERRORS \| SEM_NOGPFAULTERRORBOX)` |

Failure to apply the mechanism MUST abort startup (§5.2). The local service
calls `initialize()` at startup, before it reads the browser token or the
identity record; the mailbox server does the same before it loads its
configuration.

On Windows, `initialize()` sets the error mode only. The WER exclusion is
registered by the application, right after `initialize()`, through
`najwa_crypto::memory::exclude_from_error_reporting()`: the value persists per
executable name, so library callers and test binaries MUST NOT create it. An
application that embeds Najwa through the C ABI on Windows MUST register its
own exclusion.

The Windows exclusion is a per-user registry value
(`HKCU\Software\Microsoft\Windows\Windows Error Reporting\ExcludedApplications`)
keyed by the executable's file name, so it needs no administrator rights,
persists after exit and covers any executable of that name run by the user.
WER is configured rather than an in-process exception filter because a Rust
abort (`__fastfail`) bypasses in-process filters. That the exclusion also
stops administrator-configured `LocalDumps` is not verified.

### 6.4 Secret Memory Pages

Where the platform allows it, pages holding secrets SHOULD also be excluded
from dumps (`madvise(MADV_DONTDUMP)` on Linux).

## 7. Constant-Time Requirements

Operations on secret data MUST run in time independent of secret values.

### 7.1 Operations That MUST Be Constant-Time

| Operation | Requirement |
|-----------|-------------|
| AEAD tag verification | Library constant-time comparison |
| MAC verification | `constant_time_eq` |
| Comparison of keys, tags or secret tokens | `constant_time_eq`, never `==` |
| Passphrase check | Never compared directly; Argon2id and AEAD authenticate it |
| Public key check after unlock | `constant_time_eq` ([S02 §9](02-identity-key-protection.md)) |
| Ed25519 signing and verification | `ed25519-dalek` |
| X25519 and the non-contributory check | `x25519-dalek` Montgomery ladder |
| Pseudonym lookup | Indexed lookup, not a linear scan with early exit |

### 7.2 Rust Implementation

```rust
use subtle::ConstantTimeEq;

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}
```

A length mismatch returns early; lengths are public.

## 8. Key Hierarchy and Pairwise Pseudonyms

### 8.1 Key Hierarchy

The tree below shows every key the release derives and how. The
[key inventory](../reference/keys.md) gives storage, lifetime and erasure for
each one, and the [label registry](../reference/hkdf-strings.md) gives the exact
bytes of each label.

```
Identity seed IK_seed (32 B, CSPRNG) — the Ed25519 private key
 │
 ├── IK (Ed25519): signs the HandshakePayload and MailboxCertificates (S05 §4)
 ├── X25519 form of IK (§3.3): DH1/DH2 in X3DH (S06 §2), pairwise pseudonyms (§8.2)
 │
 ├── Protected at rest by passphrase + device factor (S02 §4):
 │     K_pwd = Argon2id(NFC(passphrase), salt_p, stored params)
 │     KEK   = HKDF(IKM = K_pwd, salt = DKM, info = "najwa/v1/kek", 32)
 │     enc_ik = XChaCha20Poly1305(KEK, nonce, IK_seed, AAD_identity)
 │
 ├── Recovery kit (S02 §13):
 │     recovery_seed = CSPRNG(32), shown as 24 BIP-39 words
 │     K_recovery = HKDF(IKM = recovery_seed, salt = IK_pub, info = "najwa/v1/recovery", 32)
 │     enc_ik_recovery = XChaCha20Poly1305(K_recovery, nonce, IK_seed, "najwa/v1/recovery" || IK_pub)
 │
 ├── Database key (S03 §3):
 │     db_key = HKDF(IKM = IK_seed, salt = "najwa-sqlcipher-key", info = "najwa/v1/sqlcipher-key", 32)
 │       ├── SQLCipher raw key
 │       ├── row_key = HKDF(IKM = db_key, salt = UTF8(table), info = row_id (u64 BE), 32)  (S03 §7)
 │       └── wraps volatile disappearing-message keys, AAD "volatile-key"           (S12 §4)
 │
 ├── Per-mailbox signing key, one per mailbox (S05 §3):
 │     seed = HKDF(IKM = IK_seed, salt = UTF8(onion_address), info = "najwa/v1/mailbox-signing-key", 32)
 │     (mailbox_ik_priv, mailbox_ik_pub) = Ed25519_Generate(seed)
 │       └── signs SPKs ("najwa/v1/spk/" || …) and prekey manifests (S06 §2.2, §4.2)
 │
 └── Pairwise pseudonyms, one pair per contact (§8.2)

Session keys (S06)
 ├── Signed prekey SPK, one-time prekeys OPK, X3DH ephemeral EK: X25519, CSPRNG
 ├── SK = HKDF(IKM = DH1 || DH2 || DH3 [|| DH4], salt = zeros(32),
 │             info = "najwa/v1/x3dh/" || X_IK_A_pub || X_IK_B_pub, 32)
 ├── KDF_RK: (RK', CK) = HKDF(IKM = DH_out, salt = RK, info = "najwa/v1/ratchet/rk", 64) split 32/32
 ├── KDF_CK: MK = HMAC_SHA256(CK, 0x01); CK' = HMAC_SHA256(CK, 0x02)
 └── enc_key(32) || auth_key(32) || iv(16) = HKDF(IKM = MK, salt = zeros(32), info = "najwa/v1/ratchet/mk", 80)
       nonce = iv || zeros(8); auth_key is not used

Mailbox keys (S05, S07)
 ├── deposit_capability, fetch_capability, envelope_secret: 32 B each, CSPRNG
 ├── outer_key = HKDF(IKM = envelope_secret, salt = "najwa/v1/deposit-envelope", info = "outer-key", 32)
 └── cap_hint  = SHA256(deposit_capability)[0:8]

Message identifiers (S07 §6)
 └── msg_id = HKDF(IKM = dh_pub || n (u32 BE) || content_hash, salt = sender_pseudonym,
                   info = "najwa/v1/message-id", 16)

Disappearing messages (S12 §4)
 └── per-message content key: 32 B, CSPRNG, AAD = msg_id
```

`X_IK_A_pub` and `X_IK_B_pub` are the X25519 forms of the X3DH initiator's and
responder's identity keys, in that order on both sides.

### 8.2 Pairwise Pseudonyms

A pairwise pseudonym is a 32-byte value that names one party to one contact.
Each pair of contacts shares exactly two pseudonyms, one per party. Both sides
compute the same two values from their identity keys; nobody else can. A
pseudonym is never an identity key and does not reveal one.

**Derivation.** Given my identity key pair and the contact's Ed25519 public key:

```
x_my_priv   = Ed25519_to_X25519_Private(IK_my_seed)        // §3.3
x_their_pub = Ed25519_to_X25519_Public(IK_their_pub)       // §3.3; fails on invalid or small-order keys
shared      = X25519(x_my_priv, x_their_pub)               // §3.2; fails if non-contributory

(lower, higher) = sort(IK_my_pub, IK_their_pub)             // canonical order, below
salt = lower || higher                                      // 64 bytes

P_initiator = HKDF(IKM = shared, salt, info = "najwa/v1/pairwise-pseudonym/initiator", 32)
P_responder = HKDF(IKM = shared, salt, info = "najwa/v1/pairwise-pseudonym/responder", 32)

if IK_my_pub < IK_their_pub:
    my_pseudonym = P_initiator; their_pseudonym = P_responder
else:
    my_pseudonym = P_responder; their_pseudonym = P_initiator
```

**Canonical ordering.** Every key sort and comparison in the derivation, both the
role assignment and the salt order, MUST be unsigned bytewise lexicographic
comparison (memcmp order) of the 32-byte **Ed25519** public keys. The X25519
forms exist only inside the DH and MUST NOT be used for ordering. Two
implementations that sort on different forms derive different pseudonyms and
reject each other's first message. The same ordering rule applies to the safety
number ([S05 §9.2](05-contact-establishment.md)) and the logical message id
([S07 §6](07-message-format.md)).

The role words `initiator` and `responder` name positions in this ordering
only. They are unrelated to who started the X3DH session.

The X25519 DH is symmetric and the ordering is canonical, so both parties
derive the same `(P_initiator, P_responder)`. The `info` is exactly 37 bytes
(the 28-byte prefix `najwa/v1/pairwise-pseudonym/` plus the 9-byte role word);
the ordered keys are the salt, never part of the `info`.

**Lifetime and storage.** Both pseudonyms are derived once, when a contact is
accepted ([S05 §8](05-contact-establishment.md)), and stored with the contact
row: `our_pseudonym` and `pseudonym` (theirs), with an index on `pseudonym`
([S03 §5.2](03-encrypted-storage.md)). They are not recomputed per message and
are deleted with the contact.

**Use on send.** Every payload carries the sender's own pseudonym in
`Payload.sender_pseudonym` ([S07 §4](07-message-format.md)). The pseudonym is
inside the ratchet-encrypted payload, so mailboxes and network observers never
see it.

**Verification on receive.** The receiver MUST check the pseudonym before it
commits any state change from the message:

1. For an Initial message (`0x01`), the receiver looks up the contact by
   `sender_pseudonym` using the index. If the contact found differs from the
   contact identified by the X3DH header's identity key, the message MUST be
   rejected (`PseudonymMismatch`). An unknown pseudonym is accepted only for a
   reciprocal handshake ([S05 §8.2](05-contact-establishment.md)); otherwise
   the message MUST be rejected (`UnknownPseudonym`).
2. For every ratchet-decrypted payload, `sender_pseudonym` MUST equal the stored
   `pseudonym` of the contact whose session decrypted it. A mismatch MUST be
   rejected (`PseudonymMismatch`) and the pending ratchet advance MUST be
   discarded.

**What a pseudonym protects.** Two contacts of the same person see different
pseudonyms for that person, so they cannot match identities by comparing
pseudonyms. An outsider who holds neither identity key cannot link a pseudonym
to a person. Carrying a pseudonym instead of `IK_pub` keeps the identity key out
of every message payload.

**What it does not protect.**

- The peer. A contact learns your identity key at contact establishment.
  Pseudonyms hide you from outsiders, not from the people you talk to.
- Collusion. Two contacts who compare notes out of band can confirm they know
  the same person.
- Traffic analysis. Pseudonyms live inside encrypted payloads. Timing and size
  at the mailbox layer are handled by padding, cover traffic and circuit
  isolation ([S07 §5](07-message-format.md), [S10](10-cover-traffic.md),
  [S04 §4](04-transport.md)).

## 9. Notation Reference

| Notation | Description |
|----------|-------------|
| `CSPRNG(n)` | n bytes from the OS CSPRNG (§5) |
| `UTF8(s)` | UTF-8 encoding of string s |
| `NFC(s)` | Unicode NFC normalization of s |
| `SHA256(m)` | SHA-256 of m |
| `HMAC_SHA256(key, m)` | HMAC-SHA256 of m under key |
| `Ed25519_Generate(seed)` | Ed25519 key pair from a 32-byte seed |
| `Ed25519_Sign(priv, m)` | Ed25519 signature over m |
| `Ed25519_Verify(pub, m, sig)` | Ed25519 verification |
| `Ed25519_to_X25519_Public(pub)` | §3.3 public conversion |
| `Ed25519_to_X25519_Private(seed)` | §3.3 private conversion |
| `X25519(priv, pub)` | X25519 Diffie-Hellman |
| `X25519_BasePoint(priv)` | X25519 public key of priv |
| `XChaCha20Poly1305_Encrypt(key, nonce, pt, aad)` | AEAD encryption, output `ct ‖ tag` |
| `XChaCha20Poly1305_Decrypt(key, nonce, ct, aad)` | AEAD decryption |
| `HKDF(IKM, salt, info, len)` | HKDF-SHA256 extract-and-expand |
| `HKDF_Extract(salt, IKM)` | HKDF extract |
| `HKDF_Expand(PRK, info, len)` | HKDF expand |
| `Argon2id(pwd, salt, m, t, p, len)` | Argon2id v1.3, memory m KiB, t iterations, parallelism p |
| `a ‖ b`, `a || b` | Concatenation |
| `zeros(n)` | n zero bytes |
| `x[i:j]` | Bytes i (inclusive) to j (exclusive) |

## 10. Rust Crate Dependencies

Version requirements from the workspace `Cargo.toml`. The pinned versions and
supply-chain policy are in [Dependencies](../security/dependencies.md) and
[Supply Chain](../security/supply-chain.md).

| Crate | Version | Purpose |
|-------|---------|---------|
| `ed25519-dalek` | 2.1 | Ed25519 |
| `x25519-dalek` | 2.0 (`static_secrets`) | X25519 |
| `curve25519-dalek` | 4.1 | Ed25519 → X25519 point conversion, small-order check |
| `chacha20poly1305` | 0.10 | XChaCha20-Poly1305 |
| `hkdf` | 0.12 | HKDF-SHA256 |
| `sha2` | 0.10 | SHA-256, SHA-512 |
| `hmac` | 0.12 | HMAC-SHA256 |
| `argon2` | 0.5 (`zeroize`) | Argon2id |
| `rand` / `rand_core` | 0.8 / 0.6 | `OsRng` |
| `getrandom` | 0.2 | OS entropy |
| `subtle` | 2.5 | Constant-time comparison |
| `zeroize` | 1.8 (`derive`) | Zeroization |
| `bip39` | 2.2 | Recovery words ([S02 §13](02-identity-key-protection.md)) |
| `rusqlite` | 0.38 (`bundled-sqlcipher-vendored-openssl`) | SQLCipher ([S03](03-encrypted-storage.md)) |

## Security Considerations

- The suite is classical. An adversary who records traffic today and later
  gains a large quantum computer can break X25519 and Ed25519.
- Unlock security rests on the passphrase and the device factor together
  ([S02 §3](02-identity-key-protection.md)). Argon2id raises the cost of
  guessing; it does not make a weak passphrase strong.
- The database key is derived from the identity seed. Anyone who learns the
  seed can open the database; the seed's protection covers both.
- Memory locking (§6.2) and dump exclusion (§6.4) reduce, but do not remove,
  the chance that secrets reach swap or crash dumps. Only the identity seed and
  the database key are locked, and only when the OS grants the lock; session
  state can reach swap, and every secret can reach the hibernation file while
  unlocked.
- On Windows, crash-dump suppression (§6.3) does not stop a debugger or dump
  tool (Task Manager, ProcDump) run by the same user.
- Pseudonyms are bound to the identity keys present at contact establishment
  and do not change for the life of the contact (§8.2).

## 11. Conformance Checklist

- [ ] The algorithm suite of §2 is fixed; no negotiation.
- [ ] Ed25519 seeds, not expanded keys, are stored.
- [ ] X25519 DH rejects non-contributory results as an error (§3.2).
- [ ] Ed25519 → X25519 public conversion rejects invalid and small-order points; private conversion matches the converted public key (§3.3).
- [ ] AEAD nonces are random 24-byte values or derived from single-use keys (§3.4); short blobs are rejected.
- [ ] HKDF PRKs and outputs are zeroized; every label matches the registry byte for byte.
- [ ] Argon2id parameters are validated against the §3.8 bounds before allocation; working memory is allocated fallibly and zeroized on every path.
- [ ] Calibration starts at 512 MiB, halves on allocation failure down to 64 MiB, and raises iterations until one run takes at least 1000 ms or reaches 100.
- [ ] Key material, nonces, salts, capabilities, tokens and identifiers come from the OS CSPRNG (§5.1); `scripts/check-os-rng.sh` passes.
- [ ] `najwa_crypto::initialize()` disables core dumps (Linux, macOS) or sets the error mode (Windows) and verifies the CSPRNG before any secret state is loaded; on Windows the local service then calls `exclude_from_error_reporting()`; startup fails closed.
- [ ] While unlocked, the identity seed and the database key are each held once, in their own page-aligned `GuardedMemory` region, locked against paging; a refused lock leaves the secret pageable and counted by `unlocked_region_count()`, without failing (§6.2).
- [ ] `ensure_lock_quota()` runs once per process, from `initialize()` and before every SQLCipher open: on Windows a soft 64 MiB minimum working set, on Linux and macOS the soft `RLIMIT_MEMLOCK` raised to the hard limit; a failure is only logged (§6.2).
- [ ] Secret types zeroize on drop and redact `Debug` output.
- [ ] MAC, tag and unlock public-key comparisons use `constant_time_eq`.
- [ ] Pairwise pseudonyms use the §8.2 derivation, Ed25519 memcmp ordering, 37-byte `info` and 64-byte salt.
- [ ] Received payloads are rejected on pseudonym mismatch before state is committed.
- [ ] S18 vectors for §2–§3 and §8.2 pass.
