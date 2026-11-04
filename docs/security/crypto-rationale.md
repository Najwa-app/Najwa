# Cryptographic Rationale

This page explains why the release uses each primitive and parameter it uses,
and what was considered instead. The normative definitions are in
[S01](../specs/01-crypto-primitives.md); the keys built from them are listed in
the [key inventory](../reference/keys.md).

The operating principle is one suite, no negotiation. Cipher agility invites
downgrade attacks and multiplies the code that must be reviewed. Changing a
primitive requires a new protocol version.

## 1. Signatures: Ed25519

Chosen because:

- **Deterministic signing.** No randomness is needed at signing time, so a
  faulty RNG cannot leak the private key through related signature nonces.
- **Small and fast.** 32-byte public keys and 64-byte signatures; verification
  is fast and the standard implementations are constant-time.
- **Same curve as X25519.** The identity key signs and, after a standard
  conversion, takes part in Diffie-Hellman. One curve family to review.
- **Interoperable.** RFC 8032 test vectors; `ed25519-dalek`, libsodium,
  BoringSSL and OpenSSL agree bit for bit.

Rejected:

- **ECDSA (P-256).** Randomized nonces with a history of reuse and bias bugs.
- **RSA-PSS.** Keys and signatures eight times larger, slower, and no benefit
  here.
- **Schnorr over secp256k1.** Sound, but it would not share a curve with the key
  agreement.

## 2. Key agreement: X25519

Chosen because:

- **Pairs with Ed25519.** Identity keys convert to X25519 for X3DH and for
  pairwise pseudonyms.
- **Constant-time by construction.** The Montgomery ladder has no
  secret-dependent branches.
- **Established.** RFC 7748, and the same function the X3DH and Double Ratchet
  literature is written against.

The release rejects low-order peer keys: an all-zero shared secret is an error,
and small-order Ed25519 keys are refused before conversion. A hostile contact
key cannot produce a predictable secret or abort the receive task.

Rejected:

- **ECDH over P-256.** Same objections as ECDSA, and point validation is easier
  to get wrong.
- **Finite-field Diffie-Hellman.** Larger keys, slower, no benefit.

## 3. Authenticated encryption: XChaCha20-Poly1305

Chosen because:

- **Random nonces are safe.** The 192-bit nonce makes collisions negligible, so
  every stored or transmitted blob that needs a fresh nonce simply draws 24
  random bytes. There is no counter state to persist or get wrong.
- **No hardware dependency.** ChaCha20 is fast and constant-time in software.
  AES without hardware support is slow and prone to cache-timing leaks.
- **One AEAD everywhere.** The identity record, recovery record, deposit
  envelope, ratchet messages, field encryption and disappearing-message content
  all use the same primitive.

Ratchet messages do not use random nonces. Each message key is used for exactly
one message, so the ratchet derives a 16-byte IV from the key and pads it to
24 bytes. Uniqueness then follows from the key schedule.

Rejected:

- **AES-GCM.** A sound primitive, but its 96-bit nonce rules out random nonces
  at volume, and nonce reuse is catastrophic.
- **ChaCha20-Poly1305 (96-bit nonce).** Same nonce limit; XChaCha20 extends it.
- **AES-OCB.** Less widely implemented and reviewed.

## 4. Key derivation: HKDF-SHA256

Chosen because:

- **Standard construction.** RFC 5869 with a clean extract/expand split.
- **Domain separation.** Every derivation has its own label, listed in one
  [registry](../reference/hkdf-strings.md), so keys for different purposes never
  collide.
- **Flexible output.** One construction yields 16-byte message ids, 32-byte
  keys, the 64-byte root/chain split and the 80-byte message-key expansion.

Salt choices follow the published designs: X3DH uses a zero salt over the
concatenated DH outputs, and the root-key step uses the current root key as
salt with the new DH output as input keying material.

Rejected:

- **Bare SHA-256 over concatenations.** No extract step and easy to misuse.
- **A second hash family.** SHA-512-based KDFs would add a primitive without
  raising the security level that X25519 sets.

## 5. Passphrase hashing: Argon2id v1.3

Chosen because:

- **Memory-hard.** Each guess costs memory as well as time, which blunts GPU and
  ASIC attacks.
- **Hybrid variant.** Argon2id resists both time-memory trade-offs and
  side-channel attacks better than Argon2i or Argon2d alone.
- **Standardized.** Password Hashing Competition winner; RFC 9106.

Rejected:

- **PBKDF2.** Not memory-hard; GPUs accelerate it linearly.
- **scrypt.** Memory-hard, but its parameters are coupled and RFC 9106 is the
  current standard.
- **bcrypt.** Fixed small memory; fast on modern attack hardware.

### 5.1 Parameters

- **Calibrated per device.** When an identity record is created, the release
  picks the highest cost that takes about one second: 512 MiB of memory, as many
  lanes as the machine has cores (up to 16), and enough iterations (at least 3)
  to reach one second. A legitimate user pays this once per unlock; an attacker
  pays it per guess.
- **512 MiB target.** Desktops have the memory. Memory per guess is what limits
  an attacker's parallelism.
- **64 MiB floor.** If 512 MiB cannot be allocated, calibration halves the
  memory until it succeeds, but never below 64 MiB, the memory of RFC 9106's
  recommended option for constrained systems. A device that cannot reach the
  floor cannot create an identity.
- **Slower is accepted, faster is not.** Calibration never lowers the cost below
  one second to save time.
- **Stored with the record.** Unlock uses the stored parameters, so a record
  stays readable after hardware changes.

## 6. Hashing: SHA-256

Chosen because it is ubiquitous, fast, constant-time in common libraries,
sufficient at the 128-bit security level, and already required by HKDF-SHA256
and HMAC-SHA256.

SHA-256 is used for the identity-record checksum, the 8-byte `cap_hint`, the
content hash in message ids, the logical message id, the prekey manifest
commitment, file integrity, mailbox proof-of-work, and the binding hashes that
tie a wrapped device factor to its storage slot.

Rejected: SHA-3 and BLAKE2/BLAKE3. No technical objection; one hash family keeps
the suite small.

## 7. MAC: HMAC-SHA256

The Double Ratchet chain step uses `HMAC(CK, 0x01)` for the message key and
`HMAC(CK, 0x02)` for the next chain key, as the Double Ratchet specification
recommends. HMAC also authenticates the unlock attempt counter and the stored
Argon2 timing reference, keyed with the device factor, so deleting or editing
those files cannot reset the lockout.

## 8. Randomness

- **OS CSPRNG only.** `getrandom(2)` on Linux, `BCryptGenRandom` on Windows,
  `getentropy` on macOS, through one wrapper. The OS is the entropy source.
- **Checked at startup.** The desktop service and the mailbox server read 32
  bytes through the fallible API before loading any secret and refuse to start
  on an error or an all-zero result.

## 9. Two-factor key protection

The identity seed is encrypted under a key derived from both the passphrase and
a random 32-byte device factor. Either factor alone is useless.

- **Why a device factor.** A copied identity record cannot be attacked offline
  without the device, however weak the passphrase.
- **Why hardware wrapping.** The release keeps the device factor wrapped by a
  key that never leaves the platform's secure hardware: an RSA-2048 key inside
  the TPM 2.0 on Windows (Microsoft Platform Crypto Provider, OAEP-SHA256), a
  TPM 2.0 sealed object on Linux, and a Secure Enclave P-256 key on macOS
  (ECIES). Each uses the platform's standard, reviewed interface; none needs
  custom key handling.
- **Why a binding hash.** Each wrapped value includes a hash of its storage slot,
  so a wrapped factor cannot be moved to another slot or identity.
- **Why software storage needs consent.** Without hardware, the device factor
  can only be protected by the OS account. The release makes that weaker mode an
  explicit, per-identity choice and never falls back to it silently.

## 10. Recovery

- **Separate recovery seed.** The recovery kit holds a 256-bit random seed that
  is independent of the identity seed. It decrypts a recovery record holding the
  identity seed. The identity key never has to be written down, and a kit can be
  replaced without changing the identity.
- **24 BIP-39 words.** A standard, checksummed word encoding of 256 bits.
- **Bound to the identity.** The recovery key is derived with `IK_pub` as salt
  and the record is authenticated with `IK_pub` in its AAD. Recovery checks that
  the decrypted seed yields that public key, so a kit can never restore a
  different identity.

## 11. Storage

- **SQLCipher for the database.** Whole-database encryption with page
  authentication, maintained and widely deployed. The raw key is derived from the
  identity seed, so unlocking the identity, which already pays the Argon2 cost,
  is the only password step.
- **Field encryption on top.** Ratchet secrets and prekey private keys carry a
  second XChaCha20-Poly1305 layer under per-row keys, so a bug that exposes a row
  outside SQLCipher does not expose the key material in it.
- **Volatile keys for disappearing messages.** Each disappearing message has its
  own random key. Destroying the key destroys the message, even when flash
  storage keeps an old copy of the ciphertext.

## 12. Protocol constructions

- **X3DH and the Double Ratchet.** Asynchronous session start against a stored
  prekey bundle, forward secrecy per message and recovery of secrecy after a
  compromise. Both are published and widely analysed.
- **Per-mailbox signing keys.** Prekeys are signed by a key derived from the
  identity seed and the mailbox address, so two mailbox operators cannot link
  their users by comparing public keys.
- **Envelope secrets.** The mailbox routes by the deposit capability but never
  receives the envelope secret that keys the outer encryption, so it cannot open
  what it stores.
- **Pairwise pseudonyms.** Payloads name the sender by a per-contact value
  instead of the identity key.

## 13. What is not in Najwa

- **No TLS.** Transport runs over Tor onion services, which authenticate the
  endpoint by its address and encrypt the connection. Content is end-to-end
  encrypted. Certificates would add management surface and no protection.
- **No Noise framework.** X3DH and the Double Ratchet give the asynchronous
  start the product needs; they are used directly.
- **No post-quantum primitives.** The suite is classical.
- **No custom primitives.** Every algorithm is a published construction with
  reference implementations in the RustCrypto and dalek libraries.
