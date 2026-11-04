# Dependencies and advisories

Assessment as of 2026-10-28, for the `Cargo.lock` and
`apps/desktop/package-lock.json` in this source tree. It covers the packaged app
(`najwa-web`) and the mailbox server (`najwa-mailbox`). This is not a clean
audit: two upstream advisories and several maintenance warnings remain open.
Re-run the checks in section 5 before every distribution and update this page.

## 1. Security-relevant dependencies

Versions are exact entries in `Cargo.lock`.

| Area | Crates | Used by |
| --- | --- | --- |
| Signatures, key agreement | `ed25519-dalek` 2.2.0, `x25519-dalek` 2.0.1, `curve25519-dalek` 4.1.3 | `najwa-crypto` |
| AEAD, hashing, KDF | `chacha20poly1305` 0.10.1, `sha2` 0.10.9, `hmac` 0.12.1, `hkdf` 0.12.4, `argon2` 0.5.3, `subtle` 2.6.1 | `najwa-crypto` |
| Randomness, secret memory | `rand` 0.8.8, `getrandom` 0.2.17, `zeroize` 1.9.0, `secrecy` 0.10.3 | `najwa-crypto` and all crates |
| Recovery phrase | `bip39` 2.2.2 | `najwa-identity` |
| Passphrase and phrase strength | `zxcvbn` 3.1.1 (exact pin) | `najwa-identity` (new passphrases, S02 §11.1), `najwa-protocol` (rendezvous phrases) |
| Encrypted database | `rusqlite` 0.38.0, `libsqlite3-sys` 0.36.0 (SQLCipher 4.10.0), `openssl-src` 300.6.1+3.6.3 (OpenSSL 3.6.3) | `najwa-storage`, `najwa-mailbox` |
| Tor | `arti-client` and `tor-*` 0.40.0, `rustls` 0.23.46, `rustls-webpki` 0.103.16, `ring` 0.17.14 | `najwa-transport` |
| Device keys | `windows-sys` 0.59.0 (Windows TPM and Credential Manager), `tss-esapi` 7.7.0 (Linux TPM, exact pin), `keyring` 3.6.3 and `dbus-secret-service` 4.1.0 (Linux Secret Service, vendored libdbus), `security-framework` 2.11.1 and `security-framework-sys` 2.17.0 (macOS, exact pin) | `najwa-identity` |
| OS lock listener | `windows-sys` 0.59.0 (session and suspend notifications), `dbus` 0.9.12 (logind and screen-saver signals, the vendored libdbus above), `core-foundation` 0.9.4 (macOS run loop; IOKit and CoreGraphics are called directly) | `najwa-web` |
| File parsers | `image` 0.25.10, `lopdf` 0.42.0, `quick-xml` 0.41.0, `flate2` 1.1.10 | `najwa-sanitize` |
| Serialization | `serde_json` 1.0.151, `bincode` 1.3.3 (ratchet-state persistence), `base64` 0.22.1 | protocol, storage, app |
| HTTP | `tokio` 1.54.1, `axum` 0.8.9, `hyper` 1.11.1, `tower-http` 0.6.11 | `najwa-web` (loopback), `najwa-mailbox` |

`najwa-sanitize` requires at least `lopdf` 0.42 and `quick-xml` 0.41, the
releases that bound nesting and allocation on crafted PDF and XML input. A
regression test feeds the sanitizer and the verifier a PDF whose objects nest
10,380 levels deep and requires a refusal without a crash.

Interface packages (exact versions in `package.json`): `svelte` 5.57.1,
`jsqr` 1.4.0 (decodes QR images, so it parses untrusted input),
and `phosphor-svelte` 3.1.0. Build-only: `vite` 8.3.5,
`@sveltejs/vite-plugin-svelte` 7.3.1, `svelte-check` 4.7.6, `typescript` 6.0.3,
`@playwright/test` 1.63.0.

## 2. Open Rust advisories

Reachability was checked with
`cargo tree --locked -e normal,build -p najwa-web --target <triple> -i <crate>`
for `x86_64-pc-windows-msvc`, `x86_64-unknown-linux-gnu` and
`aarch64-apple-darwin`, and with `--workspace --all-features --target all`.

### RUSTSEC-2023-0071: `rsa` 0.9.10

Timing side channel (Marvin attack) in RSA private-key operations. No fixed
release exists.

- **Reachable:** yes, on all three targets, through Arti (`tor-llcrypto`,
  `tor-key-forge`, `ssh-key`). Not in the mailbox server.
- **Assessment:** Najwa's code never calls RSA. As a Tor client, Arti uses RSA
  public keys to verify relay and directory signatures. The RSA private-key
  helpers in Arti serve relay, authority and key-generation roles that Najwa
  does not enable; RSA certificate signing in `tor-cert` sits behind its
  `encode` feature, which is off. The Windows TPM device key also uses RSA, but
  through the OS CNG provider, and Linux TPM operations go through TPM2-TSS;
  neither uses the Rust `rsa` crate.
- **Status:** accepted for the client role. Reassess on any Arti upgrade, before
  enabling any relay, onion-service or key-management feature, and if an
  upstream fix appears. [Advisory](https://rustsec.org/advisories/RUSTSEC-2023-0071.html).

### RUSTSEC-2026-0387: `crypto-bigint` 0.5.5

- **Reachable:** no. It is in `Cargo.lock` through optional ECDSA support of
  `ssh-key` (under Arti), but no workspace package compiles it on any target,
  even with all features enabled.
- **Status:** not shipped. Recheck whenever features or Arti change.
  [Advisory](https://rustsec.org/advisories/RUSTSEC-2026-0387.html).

## 3. Maintenance warnings

The audit also reports these crates as unmaintained:

| Crate | Version | Reaches the app | Notes |
| --- | --- | --- | --- |
| `bincode` | 1.3.3 | Yes | Used by `najwa-protocol` to serialize ratchet state, which it reads back only from its own encrypted database. |
| `bincode` | 2.0.1 | No | Lockfile only (optional Arti dependency). |
| `paste` | 1.0.15 | Compile time only | Procedural macro used by Arti crates; emits no runtime code of its own. |
| `ttf-parser` | 0.25.1 | Yes | Pulled in by `lopdf` in the sanitizer. |
| `zbus_names`, `zvariant`, `zvariant_derive` | 3.0.0, 4.2.0, 4.2.0 | No | Lockfile only (an unused optional `keyring` backend). The app uses `dbus-secret-service`. |

## 4. Interface advisory

`npm audit` reports one low-severity advisory,
[GHSA-gcqx-w48m-w2h4](https://github.com/advisories/GHSA-gcqx-w48m-w2h4)
(prototype pollution in `deepmerge` 4.3.1). It appears twice: for `deepmerge`
and for its consumer `@sveltejs/vite-plugin-svelte` 7.3.1. Both are marked
`dev` in the lockfile: they run inside the Vite build and are not part of the
shipped interface. No fixed version is available for the locked chain. No
moderate, high or critical entries are reported.

## 5. Re-running the assessment

```sh
cargo audit                                   # unfiltered, against Cargo.lock
cd apps/desktop && npm audit                  # against package-lock.json
cargo tree --locked -e normal,build -p najwa-web --target x86_64-pc-windows-msvc -i <crate>
cargo tree --locked -e normal,build -p najwa-web --target x86_64-unknown-linux-gnu -i <crate>
cargo tree --locked -e normal,build -p najwa-mailbox -i <crate>
```

Do not apply an ignore list to the audit. For each finding, record the version
in the lockfile, whether each shipped target compiles it, what Najwa does with
it, and the decision. After any dependency update, re-run the full test suite,
including the [S18](../specs/18-test-vectors.md) vectors and the sanitizer's
parser tests, and rebuild the packages ([Testing](../development/testing.md)).
`tor-transports.json` pins a binary outside both lockfiles; review it as
described in [Supply chain](supply-chain.md).
