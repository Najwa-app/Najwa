# Supply chain and distribution

A messenger is only as trustworthy as the binary a user runs. This page
describes how Najwa release packages are built, what is pinned or compiled from
source, what the packages contain from third parties, the current signing
status, and how a user checks a download. Build commands are in
[Building](../development/building.md); the dated dependency and advisory
assessment is in [Dependencies](dependencies.md).

## 1. Source and locked dependencies

The source is licensed GPL-3.0-or-later (`LICENSE`). Every package includes the
license text and lyrebird's license notices.

| Input | How it is fixed |
| --- | --- |
| Rust crates | `Cargo.lock`: 693 packages. The 681 from crates.io carry SHA-256 checksums that Cargo verifies on download; the rest are the workspace's own crates. There are no Git dependencies. Every documented build uses `--locked`. |
| Interface packages | `apps/desktop/package.json` names exact versions; `package-lock.json` (lockfile version 3) records an integrity hash for each package. Builds use `npm ci`. |
| Rust toolchain | Not pinned by a toolchain file. The minimum is 1.90 (`rust-version`). CI installs the current stable release; the Docker Linux builder uses the `rust:1.90-bookworm` image. |
| Container base images | Referenced by tag (`ubuntu:22.04`, `rust:1.90-bookworm`, `debian:bookworm-slim`), not by digest. |
| CI actions | Each GitHub Action is pinned to a full commit SHA. |

## 2. Components compiled from source

| Component | Version in `Cargo.lock` | Notes |
| --- | --- | --- |
| SQLCipher | 4.10.0 (SQLite 3.50.4), bundled in `libsqlite3-sys` 0.36.0 | Enabled by the `rusqlite` feature `bundled-sqlcipher-vendored-openssl`. Compiled into the executable. Arti's directory cache uses the same single SQLite build. |
| OpenSSL | 3.6.3, from `openssl-src` 300.6.1+3.6.3 | Compiled from source and statically linked as SQLCipher's crypto provider. No system OpenSSL is used. Building it needs Perl, and NASM on Windows. |
| Arti (Tor client) | `arti-client` and the `tor-*` crates 0.40.0 | Embedded; no separate Tor process. Default features off; enabled: `tokio`, `onion-service-client`, `rustls`, `bridge-client`, `pt-client`. TLS inside Arti uses `rustls` 0.23.46 with `ring` 0.17.14. |

Najwa's own cryptography uses the RustCrypto and dalek crates listed in
[Dependencies](dependencies.md). The workspace keeps them on fixed
semver-compatible lines, and the [S18](../specs/18-test-vectors.md) vectors check
their outputs byte for byte; re-run the vectors after any update.

## 3. Third-party binaries in the package

### lyrebird

lyrebird is the Tor Project's pluggable-transport helper. Najwa runs it only
when the user configures an obfs4 or snowflake bridge. It is the only
third-party executable in the package. `tor-transports.json` pins it:

| Field | Value |
| --- | --- |
| Source | `https://dist.torproject.org/torbrowser/15.0.26/` (Tor Browser 15.0.26 expert bundles) |
| Signing key | `EF6E286DDA85EA2A4BA7DE684E2C6E8793298290` (Tor Browser Developers) |
| Per platform | archive name and SHA-256; path and SHA-256 of `lyrebird` and of its license notice inside the archive |

Platforms pinned: Windows x86-64, Linux x86-64, macOS arm64 and x86-64.

The archive SHA-256 values were copied from the Tor Browser 15.0.26 checksum
file, whose OpenPGP signature by the key above was checked when the pins were
written. At packaging time `scripts/fetch-tor-transports.py`:

1. downloads the archive over HTTPS, or reuses the copy in
   `target/tor-upstream-verification`;
2. refuses it unless its SHA-256 equals the pinned value;
3. extracts only the two named members, each of which must be a regular file of
   at most 32 MiB, and never runs anything from the archive;
4. refuses each extracted file unless its SHA-256 equals the pinned value.

The script does not verify an OpenPGP signature itself; the trust root is the
pinned hashes in the reviewed source. To move to a new Tor Browser release,
download its checksum file and signature, verify the signature against the key
above, and update every hash in `tor-transports.json`.

At run time, before starting a bridge, the app hashes its
`transports/lyrebird` file and compares it with the `binarySha256` for its
platform, which is compiled into the executable from the same manifest. If the
file is missing or differs, bridges are refused (`bridge_helper_unavailable`)
and nothing is executed. Connecting without bridges does not use lyrebird.

### Windows C runtime

The Windows package contains `vcruntime140.dll`, copied from the Visual Studio
redistributable files on the build machine (the packager never takes it from
`PATH` or `System32`). Its version follows the build machine's Visual Studio
installation.

## 4. How release packages are built

Candidate packages come from the manual GitHub workflow
(`.github/workflows/native-preview.yml`) or an equivalent local or Docker
build. Each build:

1. installs the interface dependencies with `npm ci` and builds the interface;
2. builds `najwa-web` with `--locked --features bundled-ui --release`, embedding
   the interface in the executable;
3. runs the packager's checks: the executable is newer than the app sources,
   reports an embedded interface, matches the host OS and architecture, carries
   the hardware-preferred key policy with explicit approval for OS storage, and
   embeds exactly the interface that was just built (SHA-256 digest);
4. fetches and verifies lyrebird (section 3);
5. writes the archive and a `.sha256` file holding its SHA-256;
6. in CI, runs the profile-guard tests against the packaged executable.

Each package contains `build-info.json`, the output of `Najwa --build-info`:
product, version, OS, architecture, embedded-interface digest and key-protection
policy. It describes the build; it does not authenticate it.

The workflow keeps its artifacts for 14 days and publishes nothing.

## 5. Signing and reproducibility

Packages are not signed by a publisher:

| Platform | Status |
| --- | --- |
| Windows | No Authenticode signature. Windows SmartScreen warns on first run. |
| Linux | No signature. |
| macOS | Ad-hoc signature only (`codesign --sign -`), so the bundle runs locally. No Developer ID signature and no notarization; Gatekeeper blocks it by default. |

There is no release signing key, no signed tag and no detached signature for
archives. The `.sha256` file is produced in the same build and served from the
same place as the archive. Publisher signing is a release gate; see
[release readiness](../../RELEASE-READINESS.md).

Builds are not reproducible. Package names include the build time, archive
entries carry file timestamps, and the toolchain and base images are not pinned
to exact digests. No build provenance or attestation is produced.

## 6. Verifying a download

1. Obtain the archive and its `.sha256` file from the project's release page.
   If the expected checksum is also published elsewhere (for example in a
   release announcement), compare against that copy too.
2. Check the archive:

   ```sh
   # Linux
   sha256sum -c najwa-linux-x64-release-<stamp>.tar.gz.sha256
   # macOS
   shasum -a 256 -c najwa-macos-arm64-release-<stamp>.zip.sha256
   ```

   ```powershell
   # Windows: compare with the first field of the .sha256 file
   (Get-FileHash .\najwa-windows-x64-release-<stamp>.zip -Algorithm SHA256).Hash.ToLower()
   ```

3. Keep the extracted folder together. The executable checks the bundled
   lyrebird against its compiled-in hash before using it. To check it yourself,
   hash `transports/lyrebird` (or `lyrebird.exe`) and compare it with
   `binarySha256` for your platform in `tor-transports.json` at the matching
   source revision.
4. Read `build-info.json` for the version and policy the package was built with.

A matching checksum shows the file is the one the checksum came from. It does
not show who built it: anyone who can replace the archive on the download page
can replace the `.sha256` file too. Until packages are signed, users who need
stronger assurance should build from a reviewed source revision themselves
([Building](../development/building.md)).

## 7. Mailbox server

No signed mailbox binary is published. Operators build `najwa-mailbox` from
source or with `scripts/deployment/Dockerfile`, using the same `Cargo.lock`.
Its dependency graph is smaller than the client's (no Arti) but includes the
same SQLCipher and OpenSSL build. See [Server deployment](../server/deployment.md).

## 8. Dependency advisories

Before any distribution, run an unfiltered `cargo audit` against `Cargo.lock`
and `npm audit` against `apps/desktop/package-lock.json`, check which findings
reach the shipped targets, and update [Dependencies](dependencies.md).

## 9. Reporting a compromise

If a source, build or distribution compromise is suspected, stop distributing
the affected packages, identify the affected revisions and builds, and publish
replacement packages and an advisory through the project's channels. Report
security issues as described in [SECURITY.md](../../SECURITY.md).
