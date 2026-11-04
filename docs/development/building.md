# Building and packaging

This page covers building the browser interface, the native app (`najwa-web`)
and its release packages, plus the mailbox server, the development CLI and the
C library. Run commands from the repository root unless a step says otherwise.
Every Cargo command uses `--locked`, so the committed `Cargo.lock` is used
exactly; `npm ci` does the same for `apps/desktop/package-lock.json`.

## Prerequisites

| Tool | Version | Used for |
| --- | --- | --- |
| Rust | 1.90 or newer (`rust-version` in `Cargo.toml`); CI uses current stable | All Rust crates |
| Node.js and npm | 24 (CI). The UI toolchain needs at least 20.19 or 22.12. | Browser interface |
| Python | 3 | Packaging, transport-helper download, harnesses |
| C/C++ compiler | Platform default | Bundled SQLCipher and OpenSSL, native crates |
| Perl | Any current | OpenSSL's build configuration |

Platform additions:

- **Windows x64**: Visual Studio with the C++ desktop build tools (x64 MSVC
  compiler and the VC++ redistributable files), a Windows 10/11 SDK with x64
  libraries, the `stable-x86_64-pc-windows-msvc` Rust toolchain, Strawberry Perl
  and NASM.
- **Linux**: on Ubuntu or Debian, `build-essential pkg-config perl python3
  libdbus-1-dev libtss2-dev`. The workspace build enables Linux TPM support, so
  `libtss2-dev` is needed for any build that includes `najwa-web`.
- **macOS**: Xcode Command Line Tools (compiler and `codesign`).

OpenSSL is compiled from source for SQLCipher, so no system OpenSSL development
package is needed. The first build downloads crates and npm packages. Packaging
downloads the pinned pluggable-transport archive from the Tor Project.

## 1. Build the interface

```sh
cd apps/desktop
npm ci
npm run web:build
cd ../..
```

`web:build` type-checks the interface and writes it to `target/local-web-ui`.
Rebuild it whenever the interface changes: the native `bundled-ui` build embeds
this directory, and the packager refuses an executable whose embedded copy
differs from it.

## 2. Build the native app

Linux and macOS:

```sh
cargo build --locked -p najwa-web --features bundled-ui --release
```

Windows (PowerShell):

```powershell
./scripts/native-cargo.ps1 -CargoArguments @('build','--locked','-p','najwa-web','--features','bundled-ui','--release')
```

`scripts/native-cargo.ps1` sets up the MSVC environment without a developer
shell. It finds the newest Visual Studio installation (through `vswhere`), the
newest x64 MSVC compiler and the newest Windows SDK with x64 libraries, sets
`INCLUDE`, `LIB` and `PATH`, adds `C:\Strawberry\perl\bin` and a WinGet-installed
NASM when NASM is not already on `PATH`, and runs
`cargo +stable-x86_64-pc-windows-msvc` with the given arguments. Use it for every
Cargo command on Windows.

The output is `target/release/najwa-web` (`najwa-web.exe` on Windows). The build
fails if `target/local-web-ui/index.html` is missing. `najwa-web` refuses to
compile without its default `hardware-keystore` and
`approved-software-fallback` features, and only for Windows, Linux or macOS.

The release profile uses link-time optimization, one codegen unit, stripped
symbols and `panic = "unwind"`, so that zeroize-on-drop still runs during a
panic. The `release-debug` profile keeps symbols.

## 3. Package

Windows, all steps (after `npm ci`):

```powershell
./scripts/package-local-web.ps1            # interface, native build, package
./scripts/package-local-web.ps1 -SkipBuild # package an existing build
./scripts/package-local-web.ps1 -DebugBuild
```

Any platform, after steps 1 and 2:

```sh
python scripts/package-local-web.py --skip-build [--configuration release|debug]
```

On Linux and macOS, omitting `--skip-build` makes the packager run
`npm run web:build` and the Cargo build itself. On Windows the packager refuses
to build and you use `package-local-web.ps1` instead.

Before writing anything, the packager checks that:

- the executable is not older than any file it was built from: every input in
  Cargo's dep-info file next to it (`target/<configuration>/najwa-web.d`), the
  `Cargo.toml` of each crate those inputs belong to, the workspace `Cargo.toml`
  and `Cargo.lock`. A listed input that no longer exists also refuses. Crates
  `najwa-web` does not link, such as `najwa-mailbox`, do not count. Without a
  dep-info file, every Rust source, build script and manifest of every workspace
  member counts;
- `najwa-web --build-info` reports an embedded interface, the build host's OS and
  architecture, and the key-protection policy (hardware preferred: TPM 2.0 on
  Windows and Linux, Secure Enclave on macOS; OS storage only with explicit
  approval);
- the embedded interface digest equals the digest of `target/local-web-ui`.

It then downloads the pinned lyrebird archive (cached in
`target/tor-upstream-verification`), checks the archive and extracted-file
SHA-256 values against `tor-transports.json`, assembles the package and prints
a JSON line with the archive path, directory, SHA-256 and size.

Outputs, in `target/packages/`:

| Item | Name |
| --- | --- |
| Package directory | `najwa-<os>-<arch>-<configuration>-<UTC yyyymmdd-HHMMSS>/` |
| Archive | the directory as `.zip` (Windows, macOS) or `.tar.gz` (Linux) |
| Checksum | `<archive>.sha256`, one line `<hex>  <archive name>` |

Package contents:

| OS | Contents |
| --- | --- |
| Windows x64 | `Najwa.exe`, `vcruntime140.dll` (copied from the Visual Studio redistributable), `transports/lyrebird.exe`, `transports/LYREBIRD-LICENSES.txt`, `README.txt`, `LICENSE.txt`, `build-info.json` |
| Linux x64 | `Najwa`, `transports/lyrebird`, `transports/LYREBIRD-LICENSES.txt`, `README.txt`, `LICENSE.txt`, `build-info.json` |
| macOS | `Najwa.app` (bundle id `org.najwa.web`, minimum macOS 13.0, runs without a Dock icon) with lyrebird in `Contents/Resources/transports`, ad-hoc signed with `codesign --sign -`; plus `README.txt`, `LICENSE.txt`, `build-info.json` |

`tor-transports.json` pins helpers for Windows x64, Linux x64 and macOS on Apple
silicon and Intel; packaging fails for any other target. Windows and Linux x64
are the release targets. macOS packages can be built but are not yet a release
target.

The packaged Linux app needs at run time a Secret Service keyring in the desktop
session, `xdg-open`, the TPM2-TSS libraries (on Ubuntu or Debian
`libtss2-esys-3.0.2-0 libtss2-mu0 libtss2-tctildr0 libtss2-tcti-device0`) and,
for hardware protection, access to `/dev/tpmrm0`. The Windows package needs
nothing beyond the OS. Every package needs a web browser.

## 4. Linux package from a Windows host

Build the interface (step 1), then:

```sh
docker buildx build --file scripts/deployment/Dockerfile.native-preview --build-context web-ui=./target/local-web-ui --output type=local,dest=target/linux-native-preview .
```

The build stage uses Ubuntu 22.04 with the Rust 1.90 toolchain, builds and
packages `najwa-web`, and compiles the test binaries. A separate Ubuntu 22.04
stage with only the runtime libraries and a disposable keyring then runs the
sanitizer and identity unit tests, the Linux TPM integration tests, the
approved-OS-storage test, the missing-TPM tests, the `najwa-web` unit tests, one persistent-profile
test, the profile guards and `lyrebird -version` against the extracted package.
The output directory receives the package directory, the archive, its
`.sha256` and `validation.log`. No TPM is present in the container, so
hardware-backed persistence is compiled but not run there. Docker is only a
build tool; the package runs without it.

## 5. Development run

Windows:

```powershell
./scripts/local-web.ps1 [-Profile DIRECTORY] [-Port 1421] [-SkipBuild]
```

This builds the interface and a debug `najwa-web` without `bundled-ui`, then runs
it with `--assets target/local-web-ui`. On Linux and macOS:

```sh
cargo run --locked -p najwa-web -- --assets target/local-web-ui --profile /tmp/najwa-dev-profile
```

Use a separate `--profile` for development identities. See the
[app README](../../apps/local-web/README.md) for the command-line options.

## 6. Mailbox server

```sh
cargo build --locked --release -p najwa-mailbox
docker build -t najwa-mailbox -f scripts/deployment/Dockerfile .
```

The binary takes the path of its TOML configuration as its only argument.
Deployment is covered in [Server deployment](../server/deployment.md); the
Tor-backed development mailbox is in
[Onion development](../../scripts/deployment/ONION-DEVELOPMENT.md).

## 7. Development CLI and C library

```sh
cargo build --locked -p najwa-cli
cargo build --locked -p najwa-ffi
```

`najwa-ffi` builds both an `rlib` and a C dynamic library (`libnajwa_ffi.so`,
`najwa_ffi.dll` or `libnajwa_ffi.dylib`). Its header,
`crates/najwa-ffi/include/najwa.h`, is committed, maintained by hand and is the
ABI reference. After changing an exported signature, regenerate the declarations
with the `cbindgen` command at the top of `cbindgen.toml` and restore the
hand-written macros and comments. The test workflow (section 8) compiles the
header as C and C++ and runs the C smoke test against the library.

## 8. Continuous integration

`.github/workflows/test.yml` runs on every push to `main` and every pull request,
with read-only repository permissions. One Ubuntu 22.04 job installs the same
system packages as the native workflow and runs, in order:

- `scripts/check-no-clearnet-dns.sh`, `scripts/check-os-rng.sh` and
  `scripts/test_package_local_web.py`;
- `gcc -fsyntax-only` on `najwa.h` as C99 and as C++, with warnings as errors;
- `cargo test --workspace --locked --exclude najwa-web`, then the `najwa-web`
  profile guards (the no-TPM split in [Testing](testing.md#crate-tests));
- `scripts/testing/c-abi-smoke.sh`;
- in a private D-Bus session with a synthetic GNOME Keyring: the ignored
  `platform_keychain` tests (`scripts/testing/keychain-tests.sh`) and the
  `persistent_profile` test that falls back to approved OS storage;
- `npm ci`, `npm run web:build`, Edge for Playwright and `npm run web:test` in
  `apps/desktop`.

Tests that need a TPM, live Tor or a live mailbox stay ignored. It caches only
the Cargo registry and runs no Windows or macOS job.

`.github/workflows/native-preview.yml` builds candidate packages. It runs only
when started manually and has read-only repository permissions. Each job (Windows
Server 2025, Ubuntu 22.04, macOS 15 on Apple silicon and Intel) installs Node.js
24 and stable Rust, builds the interface and the native app, runs
`scripts/test_package_local_web.py`, packages, runs the profile guards against the
packaged executable (on Linux also the missing-TPM refusal tests), and uploads
the archive and its `.sha256` as a workflow artifact kept for 14 days. Hosted
runners have no TPM or Secure Enclave. The workflow does not sign or publish
anything.

## Build hygiene

`target/`, generated profiles, recovery kits, downloaded helpers and test output
are ignored by Git. Do not commit them.
