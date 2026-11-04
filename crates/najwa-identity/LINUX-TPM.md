# Linux TPM device factor

On Linux, Najwa seals the identity's device factor (`DKM`,
[S02 §17](../../docs/specs/02-identity-key-protection.md)) in a TPM 2.0 sealed
object and keeps the sealed object in the Secret Service. The TPM protects only
the 32-byte device factor. The passphrase, the identity record, the attempt
limiter and the recovery kit are the same on every platform (S02 §4, §7, §10,
§13).

The backend is the `linux-tpm` feature of `najwa-identity` (TPM2 Software Stack
through `tss-esapi`), part of `hardware-keystore`. The app always builds with it
and with the approval-gated OS storage fallback (S02 §17.2).

## Required OS facilities

- A TPM 2.0 exposed through the kernel resource manager at `/dev/tpmrm0`, and
  read/write access to it for the user running Najwa (distributions usually grant
  this through a group such as `tss` or a udev rule).
- An owner hierarchy with an empty authorization value. Najwa never takes
  ownership, sets an authorization value, resets the TPM or allocates persistent
  handles.
- An unlocked Secret Service session (GNOME Keyring, KWallet or another
  implementation of the freedesktop Secret Service API).
- TPM2-TSS runtime libraries. On Debian and Ubuntu: `libtss2-esys-3.0.2-0`,
  `libtss2-mu0`, `libtss2-tctildr0`, `libtss2-tcti-device0`. Building needs
  `libtss2-dev` and `pkg-config`.

The transport is fixed to `device:/dev/tpmrm0`. `TSS2_TCTI`, `TPM2TOOLS_TCTI` and
other environment selections are ignored; release builds have no simulator or
network transport. Only unit-test builds can select a simulator.

## Names and formats

`<gen>` is the lowercase hex of the identity record's `saltP` (S02 §17.1).

| Item | Value |
|------|-------|
| Secret Service item | service `com.najwa.identity`, user `Najwa/DKM/record/<gen>` |
| Storage primary | Owner hierarchy; RSA-2048 restricted decryption key, AES-256-CFB symmetric, default exponent, empty authorization; recreated deterministically for each operation |
| Sealed object | Keyed-hash, scheme NULL, name algorithm SHA-256, empty authorization policy, empty authorization value; attributes `fixedTPM`, `fixedParent`, `userWithAuth`, `noDA`, and `sensitiveDataOrigin` clear |
| Binding | `SHA-256("Najwa/v2/Linux-TPM/DKM\0" \|\| credential name)` |
| Sealed data | binding (32 bytes) \|\| `DKM` (32 bytes) |
| Envelope | `NJWLTP01` \|\| `public_len` (u16 BE) \|\| `private_len` (u16 BE) \|\| marshalled public area \|\| TPM private blob; 12 to 4096 bytes |
| Stored form | Lowercase hex of the envelope (at most 8192 characters) |

`fixedTPM` and `fixedParent` keep the object bound to this TPM and this parent.
The private blob is encrypted by the TPM under the storage primary; it never
contains the device factor in plaintext.

## Sealing a new generation

1. If a Secret Service item already exists for the name, fail. A generation is
   never replaced.
2. Open the TPM context on `/dev/tpmrm0` and create the storage primary.
3. Start an HMAC session salted with the storage primary, using AES-256-CFB
   parameter encryption and SHA-256.
4. With command and response encryption enabled, `TPM2_Create` a sealed object
   holding `binding || DKM` under the primary. The device factor crosses the TPM
   bus only encrypted.
5. Load the new object and unseal it (step 3 of unsealing below). The result
   must equal `DKM` in constant time. Only then is the object published.
6. Encode the envelope and store its hex form in the Secret Service.

## Unsealing

1. Read the Secret Service item and hex-decode it. Reject an odd length, more
   than 8192 hex characters or a non-hex character.
2. Parse the envelope. Reject a wrong magic, a zero length, lengths that do not
   add up to the envelope size, a public area that does not re-marshal to the
   same bytes, or a public area whose attributes, scheme, name algorithm or
   policy differ from the sealed-object template. A raw 32-byte value or any
   other blob is rejected before the TPM is used.
3. Create the storage primary, load the object, start the salted session with
   response encryption, and `TPM2_Unseal`. The child object is flushed after the
   unseal, whether or not it succeeded.
4. The unsealed data must be exactly 64 bytes and its first 32 bytes must equal
   the binding for this name. Return the last 32 bytes as `DKM`.

There is no TPM PIN, policy session or user-presence gesture. `noDA` exempts the
object from the TPM's dictionary-attack lockout; with an empty authorization
value there is nothing to guess at the TPM.

## Failure behavior

- **No `/dev/tpmrm0`, no access, an owner hierarchy with an authorization value,
  unsupported algorithms:** storing fails. The app then offers OS key storage,
  which the user may decline (S02 §17.4). No software key is created without that
  approval.
- **Locked or absent Secret Service:** storing and retrieving fail.
- **Missing item, tampered envelope, wrong binding, another TPM, a cleared owner
  hierarchy:** retrieval fails. The identity cannot be unlocked; the recovery kit
  restores it (S02 §19). Approving OS storage does not make the lost generation
  readable.
- **No other source:** the backend never reads a raw secret, a file key or an
  unscoped credential. `NAJWA_DKM_FILE` is ignored, and the app refuses to start
  when it is set.
- All failures are reported as device-factor errors (`keystore_unavailable` in
  the app).

## Deletion

Deleting a generation removes its Secret Service item. A missing item counts as
deleted. There is no persistent TPM object to delete, so deletion works without
a TPM.

Deletion does not revoke the sealed object itself. A copy of the envelope taken
earlier can still be unsealed on the same TPM, because the storage primary is
recreated from the same owner seed. Clearing the TPM (which changes the owner
seed) or moving to another TPM makes every copy unusable.

## Approved OS storage on Linux

With the user's approval (S02 §17.4), a generation that the TPM could not store
is written to the Secret Service instead: service `com.najwa.identity`, user
`Najwa/DKM/record/approved-software/<gen>`, secret = the 72-byte
approved-storage blob of S02 §17.4. The keyring's own protection applies; no TPM
is involved.

## Security boundary

- `/dev/tpmrm0` may be a virtual TPM. The backend does not attest that it is
  physical hardware; inside a virtual machine, the protection depends on the
  hypervisor.
- Any process running as the same user with access to the Secret Service and the
  TPM device can unseal the device factor. It still needs the passphrase, but it
  can then guess offline at Argon2id cost (S02 §20).
- An unlocked, compromised process can read the decrypted identity key and
  messages.

## Testing

**Containerized tests (software TPMs).** `scripts/testing/linux-tpm.Dockerfile`
starts two disposable `swtpm` instances on loopback ports 2321 and 2323 and an
isolated GNOME Keyring with a synthetic password. No host TPM or keyring is
mounted.

```sh
docker build -f scripts/testing/linux-tpm.Dockerfile -t najwa-linux-tpm-test .
docker run --rm -v "$PWD:/work" -v najwa-cargo-registry:/usr/local/cargo/registry najwa-linux-tpm-test
```

The script runs the `simulator_` tests (seal, reopen, wrong name, tampering,
another TPM, Secret Service storage, raw-secret rejection, overwrite refusal,
identity create, reopen, wrong passphrase, passphrase change and device loss),
the normal feature tests, Clippy, and the default-feature tests. Software TPMs
do not prove behavior on physical hardware.

**Physical TPM.** On a Linux desktop with a TPM 2.0 at `/dev/tpmrm0`, an unlocked
Secret Service and the TPM2-TSS development packages:

```sh
cargo test --locked -p najwa-identity --features linux-tpm
cargo test --locked -p najwa-identity --features linux-tpm --lib hardware_roundtrip -- --ignored --test-threads=1
cargo test --locked -p najwa-identity --features linux-tpm --test linux_tpm hardware_identity -- --ignored --test-threads=1
cargo test --locked -p najwa-identity --features linux-tpm --test vectors -- --ignored --test-threads=1
```

The hardware tests use only synthetic transient objects and uniquely named items
and delete what they create.

**App-level behavior.** In `apps/local-web/tests/persistent_profile.rs`:

- `hardware_key_loss_refuses_unlock_after_restart` needs a working TPM.
- `missing_tpm_refuses_identity_without_creating_software_keys` runs on a
  computer without `/dev/tpmrm0` and checks that creation fails without a
  software key.
- `missing_tpm_software_fallback_requires_profile_consent_and_survives_restart`
  runs without a TPM and with an unlocked Secret Service, and checks the approval
  flow, restart, passphrase change and recovery.

```sh
cargo test --locked -p najwa-web --test persistent_profile hardware_key_loss
cargo test --locked -p najwa-web --test persistent_profile missing_tpm -- --ignored --test-threads=1
```

Validation status per platform: [Release readiness](../../RELEASE-READINESS.md).

References: [TPM2 Software Stack](https://github.com/tpm2-software/tpm2-tss),
[Rust TSS ESAPI](https://github.com/parallaxsecond/rust-tss-esapi).
