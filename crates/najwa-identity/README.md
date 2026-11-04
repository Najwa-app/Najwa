# najwa-identity

Identity creation and local key protection. The identity record unlocks with a
passphrase (Argon2id) plus a device key: a TPM 2.0 key on Windows and Linux, the
Secure Enclave on macOS, or the OS key store when the user explicitly approves it
for that identity. Also provides the durable unlock rate limiter, the recovery kit
(a 12- or 24-word phrase, 24 in the app, and a recovery record) and atomic file writes.

Implements [S02](../../docs/specs/02-identity-key-protection.md); [S18](../../docs/specs/18-test-vectors.md)
vectors are in `tests/vectors.rs`. Hardware notes: [Windows TPM](WINDOWS-TPM.md),
[Linux TPM](LINUX-TPM.md), [macOS Secure Enclave](MACOS-SECURE-ENCLAVE.md).

Entry points: `IdentityManager`, `IdentityRecordStandard`, `UnlockRateLimiter`, `backup`
(recovery kit), `platform` (device-key backends, chosen by the `windows-tpm`, `linux-tpm`,
`macos-secure-enclave` and `approved-software-fallback` features).

License: GPL-3.0-or-later.
