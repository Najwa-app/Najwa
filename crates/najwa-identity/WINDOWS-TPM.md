# Windows TPM device factor

On Windows, Najwa protects the identity's device factor (`DKM`,
[S02 §17](../../docs/specs/02-identity-key-protection.md)) with an RSA key held
by the TPM 2.0 through the Microsoft Platform Crypto Provider. The TPM wraps
only the 32-byte device factor. The passphrase, the identity record, the attempt
limiter and the recovery kit are the same on every platform (S02 §4, §7, §10,
§13).

The backend is the `windows-tpm` feature of `najwa-identity`, part of
`hardware-keystore`. The app always builds with it and with the approval-gated
OS storage fallback (S02 §17.2).

## Required OS facilities

- A TPM 2.0, enabled in firmware. TPM Base Services must report TPM version 2.0
  and an interface type of hardware (`TPM_IFTYPE_HW`), SPB or TrustZone. TPM 1.2,
  emulator and unknown interface types are refused.
- The Microsoft Platform Crypto Provider (`MS_PLATFORM_CRYPTO_PROVIDER`). Its
  implementation type must include the hardware flag and must not include the
  software flag.
- Credential Manager for the signed-in user.

No administrator rights, TPM ownership change or TPM reset is needed.

## Names and formats

`<gen>` is the lowercase hex of the identity record's `saltP` (S02 §17.1).

| Item | Value |
|------|-------|
| Credential target | `Najwa/DKM/record/<gen>` |
| Credential type and persistence | `CRED_TYPE_GENERIC`, `CRED_PERSIST_LOCAL_MACHINE`, user name `najwa-dkm` |
| TPM key name | `Najwa.DKM.v2.` followed by the lowercase hex SHA-256 of the credential target (UTF-8) |
| TPM key | RSA-2048, current-user scope, key usage decrypt only, export policy 0 |
| Binding | `SHA-256("Najwa/v2/TPM/DKM\0" \|\| credential target)` |
| Plaintext | binding (32 bytes) \|\| `DKM` (32 bytes) |
| Padding | RSA-OAEP with SHA-256 and an empty label |
| Envelope | `NJWTPM01` \|\| 256-byte ciphertext — exactly 264 bytes |

The OAEP label is empty to avoid provider-specific label restrictions. The
credential target is bound inside the encrypted plaintext instead.

## Sealing a new generation

1. Check the TPM device information and the provider (above).
2. `NCryptCreatePersistedKey` with the RSA algorithm, the TPM key name, current
   user scope and no overwrite flag. An existing key with that name makes the
   call fail, so a generation is never replaced.
3. Set the key length to 2048 and the key usage to decrypt only.
   `NCryptFinalizeKey` with `NCRYPT_SILENT_FLAG`.
4. Verify the finalized key: export policy 0, length 2048, and the provider's
   PCP export permission false.
5. Encrypt `binding || DKM` with RSA-OAEP. The result must be 256 bytes.
6. Build the envelope `NJWTPM01 || ciphertext`.
7. Decrypt the envelope with the new key and compare the result with `DKM` in
   constant time. Public-key encryption alone does not prove the TPM can decrypt.
8. Write the envelope to Credential Manager (`CredWriteW`).
9. Mark the key committed. If any step after key creation fails, the new key is
   deleted. A crash between steps 2 and 8 can leave an unused orphan key.

## Unsealing

1. `CredReadW` the credential target. The blob must be exactly 264 bytes. Najwa
   copies it and zeroizes the OS-allocated blob before freeing it.
2. Check the magic `NJWTPM01`. A raw 32-byte credential or any other blob is
   rejected before the TPM is used.
3. Check the TPM device information and the provider. Open the key by name with
   `NCRYPT_SILENT_FLAG` and repeat the policy checks of sealing step 4.
4. Decrypt with RSA-OAEP. The plaintext must be exactly 64 bytes and its first 32
   bytes must equal the binding for this credential target.
5. Return the last 32 bytes as `DKM`. The decryption buffer is zeroized.

Every TPM call uses `NCRYPT_SILENT_FLAG`. There is no TPM PIN, Windows Hello
prompt or other user gesture.

## Failure behavior

- **No usable TPM** (no TPM, TPM 1.2, an emulator, a provider without the hardware
  flag): storing fails. The app then offers OS key storage, which the user may
  decline (S02 §17.4). No software key is created without that approval.
- **Missing key, tampered envelope, raw credential or wrong binding:** retrieval
  fails. The identity cannot be unlocked; the recovery kit restores it (S02 §19).
  Approving OS storage does not make the lost generation readable.
- **TPM cleared or replaced, profile copied to another computer:** the key is
  gone or different; as above.
- **No other source:** the backend never reads a raw credential, a file key or an
  unscoped credential. `NAJWA_DKM_FILE` is ignored, and the app refuses to start
  when it is set.
- All failures are reported as device-factor errors (`keystore_unavailable` in
  the app). Wrong-passphrase failures stay generic (S02 §9.2).

## Deletion

Deleting a generation opens the provider, deletes the TPM key, and then deletes
the Credential Manager entry. A missing credential counts as deleted. A TPM key
counts as deleted when opening or deleting it returns a status that proves it no
longer exists (S02 §17.6):

| Status | Meaning |
|--------|---------|
| `NTE_BAD_KEYSET` (`0x80090016`), `NTE_NOT_FOUND` (`0x80090011`) | no such key |
| `TPM_E_PCP_WRONG_PARENT` (`0x8029040E`), `TPM_20_E_INTEGRITY` (`0x8028009F`) | the key was made under a storage parent this TPM no longer has: the TPM was cleared |

A cleared TPM's key file may stay in the provider's store; this TPM can no
longer load it. Any other TPM or Credential Manager error is reported, and the
credential is kept. That includes a TPM that is absent or disabled in firmware
(`TBS_E_TPM_NOT_FOUND`), not ready or not provisioned: such a TPM can come back
with the key intact. Deletion, and so profile erasure (S13 §10.4), then stays
incomplete until the TPM works. Other generations are not affected.

## Approved OS storage on Windows

With the user's approval (S02 §17.4), a generation that the TPM could not store
is written to Credential Manager instead, under
`Najwa/DKM/record/approved-software/<gen>`, with the same type, persistence and
user name. The blob is the 72-byte approved-storage format of S02 §17.4. Windows
protects it for the user account; no TPM is involved.

## Security boundary

- The RSA private key is generated in the TPM and never exported or imported.
  Najwa never receives it. RSA-2048 is the algorithm the Platform Crypto Provider
  supports for this purpose; it protects one additional device factor, not the
  passphrase.
- Any process running as the same Windows user can ask the TPM to decrypt the
  envelope. It still needs the passphrase, but it can then guess offline at
  Argon2id cost (S02 §20).
- The provider stores the TPM-wrapped key blob in the user profile, and Credential
  Manager stores the envelope. Copies of both made before deletion can still
  decrypt on the same TPM.
- An unlocked, compromised process can read the decrypted identity key and
  messages.

## Testing

Run from the repository root in PowerShell. `scripts/native-cargo.ps1` loads the
MSVC compiler and Windows SDK and passes its arguments to Cargo.

Tests that need no TPM (envelope bounds, device-information checks, refusal of
the file override):

```powershell
.\scripts\native-cargo.ps1 test -p najwa-identity --features windows-tpm --locked
```

Tests on a physical TPM. They create only uniquely named synthetic keys and
credentials, remove what they create, and never call all-account deletion. They
fail when no TPM is available; a skip or a software fallback is not a pass.

```powershell
.\scripts\native-cargo.ps1 test -p najwa-identity --features windows-tpm --lib hardware_ --locked -- --ignored --test-threads=1
.\scripts\native-cargo.ps1 test -p najwa-identity --features windows-tpm --test windows_tpm hardware_identity --locked -- --ignored
.\scripts\native-cargo.ps1 clippy -p najwa-identity --features windows-tpm --all-targets --locked -- -D warnings
```

They cover wrapping and unwrapping, tampering, a different key, refusal of
private-key export, refusal to overwrite a generation, rollback of a key after a
failed credential write, deletion, raw-credential rejection, and a full identity
create, reopen, wrong passphrase, passphrase change and key loss.

The app-level test `hardware_key_loss_refuses_unlock_after_restart` in
`apps/local-web/tests/persistent_profile.rs` also needs a working TPM. It deletes
the device factor of a synthetic profile and checks that unlock fails after a
restart, even after OS storage is approved:

```powershell
.\scripts\native-cargo.ps1 test -p najwa-web --test persistent_profile hardware_key_loss --locked
```

Validation status per platform: [Release readiness](../../RELEASE-READINESS.md).

References: [Platform Crypto Provider](https://learn.microsoft.com/en-us/windows/security/hardware-security/tpm/how-windows-uses-the-tpm),
[CNG key storage properties](https://learn.microsoft.com/en-us/windows/win32/seccng/key-storage-property-identifiers),
[NCryptDecrypt](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptdecrypt).
