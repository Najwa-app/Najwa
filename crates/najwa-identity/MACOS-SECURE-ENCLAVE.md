# macOS Secure Enclave device factor

On macOS, Najwa wraps the identity's device factor (`DKM`,
[S02 §17](../../docs/specs/02-identity-key-protection.md)) with a P-256 key
generated inside the Secure Enclave and keeps the ciphertext in the
data-protection Keychain. The Secure Enclave protects only the 32-byte device
factor. The passphrase, the identity record, the attempt limiter and the
recovery kit are the same on every platform (S02 §4, §7, §10, §13).

The backend is the `macos-secure-enclave` feature of `najwa-identity` (also
exposed as `najwa-ffi/macos-secure-enclave`), part of `hardware-keystore`. The app
always builds with it and with the approval-gated OS storage fallback
(S02 §17.2). A macOS package is not yet released; see
[Release readiness](../../RELEASE-READINESS.md).

## Required OS facilities

- A Mac with a Secure Enclave and macOS 10.15 or later.
- A signed process with access to the data-protection Keychain (the application
  identifier and keychain-access entitlements of the signing identity). A process
  without these entitlements cannot use the data-protection Keychain.
- The user logged in and the Mac unlocked: the key and the credential are
  accessible only when the device is unlocked.

## Names and formats

`<gen>` is the lowercase hex of the identity record's `saltP` (S02 §17.1). The
credential name is `Najwa/DKM/record/<gen>`.

| Item | Value |
|------|-------|
| Keychain | Data-protection Keychain (`kSecUseDataProtectionKeychain`), not synchronizable |
| Credential | Generic password, service `com.najwa.identity`, account = credential name, accessible `WhenUnlockedThisDeviceOnly` |
| Secure Enclave key | EC P-256 (`kSecAttrKeyTypeECSECPrimeRandom`, 256 bits), token `kSecAttrTokenIDSecureEnclave`, permanent, label `Najwa device factor` |
| Key access control | `AccessibleWhenUnlockedThisDeviceOnly` with `PrivateKeyUsage`; no user-presence or biometric requirement |
| Key application tag | `com.najwa.identity.enclave.v2.` \|\| SHA-256(credential name) — 62 bytes |
| Binding | `SHA-256("Najwa/v2/Secure-Enclave/DKM\0" \|\| credential name)` |
| Plaintext | binding (32 bytes) \|\| `DKM` (32 bytes) |
| Algorithm | `kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM` |
| Envelope | `NJWMSE01` \|\| ciphertext; ciphertext 1 to 4096 bytes |

Every query sets `kSecUseAuthenticationUI` to fail, so a background operation
never shows a dialog.

## Sealing a new generation

1. If a credential or a key with this tag already exists, fail. A generation is
   never replaced.
2. Generate the Secure Enclave key (`SecKeyCreateRandomKey`) with the attributes
   above. A failure after the OS created a key reference removes that key.
3. Validate the key: token is the Secure Enclave, type EC P-256, class private,
   256 bits, and ECIES decryption supported.
4. Search by tag. Exactly one key must match, and its application label must
   equal the generated key's. This catches duplicate tags created by the OS.
5. Encrypt `binding || DKM` with the public key. Build the envelope.
6. Decrypt the envelope with the persisted key and compare the result with `DKM`
   in constant time.
7. Add the credential with `SecItemAdd`. An existing credential is never updated.
8. On a failure after step 2, remove only the newly generated key, by its exact
   key reference.

## Unsealing

1. Read the credential from the data-protection Keychain.
2. Check the envelope: magic `NJWMSE01` and a ciphertext of 1 to 4096 bytes. A
   raw 32-byte value or any other blob is rejected.
3. Load the key by tag. Exactly one key must match, and it must pass the
   validation of sealing step 3.
4. Decrypt. The plaintext must be exactly 64 bytes and its first 32 bytes must
   equal the binding for this name. Return the last 32 bytes as `DKM`.

There is no Touch ID, password prompt or other user gesture.

## Failure behavior

- **No Secure Enclave, missing entitlements, no Keychain access, unsupported
  algorithm:** storing fails. The app then offers OS key storage, which the user
  may decline (S02 §17.4). No software key is created without that approval.
- **Mac locked or user logged out:** the key and the credential are unavailable;
  storing and retrieving fail.
- **Missing key or credential, tampered envelope, wrong binding, another Mac:**
  retrieval fails. The identity cannot be unlocked; the recovery kit restores it
  (S02 §19). Approving OS storage does not make the lost generation readable.
- **No other source:** the backend never reads a raw Keychain secret, a file key
  or an unscoped credential. `NAJWA_DKM_FILE` is ignored, and the app refuses to
  start when it is set.
- All failures are reported as device-factor errors (`keystore_unavailable` in
  the app).

## Deletion

Deleting a generation removes every key with its tag, then the credential. A
missing key or credential counts as deleted. A key-deletion error is reported
and the credential is kept.

## Approved OS storage on macOS

With the user's approval (S02 §17.4), a generation that the Secure Enclave could
not store is written as a generic password with service `com.najwa.identity` and
account `Najwa/DKM/record/approved-software/<gen>`, through the Security
framework's generic-password API in the user's default keychain. The secret is
the 72-byte approved-storage blob of S02 §17.4. No Secure Enclave key is
involved.

## Security boundary

- The Secure Enclave private key cannot be exported. Najwa never receives it.
- Code running as the same user with access to this Keychain item and key can
  ask the Secure Enclave to decrypt the envelope. It still needs the passphrase,
  but it can then guess offline at Argon2id cost (S02 §20).
- Security.framework returns the decrypted plaintext in a `CFData` buffer that
  Najwa cannot zeroize. Najwa's own copies are zeroized.
- Items marked `ThisDeviceOnly` do not migrate to another Mac. Hardware loss
  makes the device factor unavailable; the recovery kit restores the identity.
- An unlocked, compromised process can read the decrypted identity key and
  messages.

## Testing

Run on a Mac with a Secure Enclave, from the repository root, with a signed test
process that has the application's Keychain entitlements.

```sh
cargo test --manifest-path Cargo.toml --locked -p najwa-identity --features macos-secure-enclave
cargo test --manifest-path Cargo.toml --locked -p najwa-identity --features macos-secure-enclave --lib hardware_enclave_ -- --ignored --test-threads=1
cargo test --manifest-path Cargo.toml --locked -p najwa-identity --features macos-secure-enclave --test macos_enclave hardware_identity -- --ignored --test-threads=1
cargo test --manifest-path Cargo.toml --locked -p najwa-identity --features macos-secure-enclave --test vectors -- --ignored --test-threads=1
cargo clippy --manifest-path Cargo.toml --locked -p najwa-identity --features macos-secure-enclave --all-targets -- -D warnings
cargo check --manifest-path Cargo.toml --locked -p najwa-ffi --features hardware-keystore
```

If Cargo's ad-hoc-signed test binaries lack Keychain access, build them with
`cargo test --no-run`, sign the produced binaries with the development identity
and entitlements, and run them with the same filters. Do not relax the
data-protection policy to make an unsigned binary pass.

The normal tests reject malformed and oversized envelopes and a software
(non-enclave) P-256 key. The ignored hardware tests use uniquely named synthetic
generations and delete what they create. They cover export refusal, tampering,
a wrong binding, overwrite refusal, removal of the new key after a failed
credential write, deletion, and a full identity create, reopen, wrong
passphrase, passphrase change and key loss. Also check process restart, a locked
screen, a denied entitlement and an unavailable Secure Enclave on the Mac.

Validation status per platform: [Release readiness](../../RELEASE-READINESS.md).

References: [Protecting keys with the Secure Enclave](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave),
[TN3137: On Mac keychain APIs and implementations](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains),
[kSecUseDataProtectionKeychain](https://developer.apple.com/documentation/security/ksecusedataprotectionkeychain),
[SecKeyCreateEncryptedData](https://developer.apple.com/documentation/security/seckeycreateencrypteddata(_:_:_:_:)).
