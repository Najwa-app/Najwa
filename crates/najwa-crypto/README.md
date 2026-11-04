# najwa-crypto

Fixed-suite cryptographic primitives for every other Najwa crate: Ed25519,
X25519 and Ed25519-to-X25519 conversion, XChaCha20-Poly1305, HKDF-SHA256 with
the domain-separation label registry, Argon2id, SHA-256 and HMAC-SHA256,
constant-time comparison, a checked CSPRNG and secret-memory helpers. No other
crate implements a primitive.

Implements [S01](../../docs/specs/01-crypto-primitives.md); [S18](../../docs/specs/18-test-vectors.md) vectors are in
`tests/vectors.rs`.

Entry points: `initialize()` (disables core dumps and checks the CSPRNG; callers
refuse to start if it fails), `keys::{Ed25519KeyPair, X25519KeyPair}`,
`aead::{encrypt, decrypt}`, `kdf::{hkdf_sha256, argon2id}`,
`hash::{sha256, hmac_sha256, constant_time_eq}`, `random::random_bytes`.

License: GPL-3.0-or-later.
