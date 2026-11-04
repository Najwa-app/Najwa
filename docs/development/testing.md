# Testing

Najwa's tests run at several levels. Each level proves something the others
cannot, and several need hardware, a network or a mailbox. This page lists how
to run each level, what it proves and what it needs. Commands run from the
repository root unless stated. On Windows, run Cargo through
`./scripts/native-cargo.ps1 -CargoArguments @(...)` with the same arguments (see
[Building](building.md)). Use only synthetic identities and keep generated
profiles and reports out of the source tree.

The [test workflow](building.md#8-continuous-integration) runs on every push to
`main` and every pull request, on Linux only: the source checks, the packaging
unit tests, the crate tests without a TPM, the C header compile check and the
C ABI smoke test, the Secret Service tests in a private D-Bus session, and the
interface build and tests. The manual native workflow adds the packaging checks
and the profile guards on Windows, Linux and macOS. Run the other levels
locally.

## Summary

| Level | Command | Needs |
| --- | --- | --- |
| Crate tests | `cargo test --locked --workspace` | Some `najwa-web` tests need a TPM or an unlocked keyring (below) |
| Lints | `cargo clippy --locked --workspace --all-targets --no-deps` | Nothing extra |
| Interface | `npm run web:test` in `apps/desktop` | Microsoft Edge |
| Packaging | `python scripts/test_package_local_web.py`, profile guards against a package | A built package for the guards |
| Live Tor | `cargo test --locked -p najwa-transport --test live_tor -- --ignored` | Internet access to Tor |
| Live mailbox | `live_mailbox` tests in `najwa-core` | Docker test mailbox; onion and Tor for one test |
| Two-peer desktop | `scripts/test-desktop-messaging.py` | Development onion mailbox, Tor |
| Browser end to end | `live_messaging` and `large_file_resume` in `najwa-web` | Packaged app, onion mailbox, Tor, Edge, Node.js |
| TPM simulator, keyring | `scripts/testing/*.Dockerfile` | Docker |
| Physical hardware | Per-platform guides | A real TPM or Secure Enclave |
| C ABI smoke | `sh scripts/testing/c-abi-smoke.sh` | Linux or macOS, a C compiler |
| Source checks | `bash scripts/check-no-clearnet-dns.sh`, `bash scripts/check-os-rng.sh` | Bash, grep |

## Crate tests

```sh
cargo test --locked --workspace
cargo clippy --locked --workspace --all-targets --no-deps
```

This runs every crate's unit tests and the integration tests in each
`crates/*/tests` directory. Highlights:

- Conformance vectors from [S18](../specs/18-test-vectors.md): `najwa-crypto/tests/vectors.rs`,
  `najwa-identity/tests/vectors.rs` and `najwa-protocol/tests/{vectors,signal_vectors,s18_s06,s18_s07}.rs`
  check byte-exact outputs from fixed inputs. Expected values must come from the
  specification, not from the implementation under test.
- `najwa-protocol` end-to-end tests: Initial message processing, QR contact flow,
  prekey wire contract, low-order key refusal and deposit isolation.
- `najwa-storage`, `najwa-core`, `najwa-privacy` and `najwa-cli` regression suites:
  transaction atomicity, file reopen, deduplication, timers, erasure and CLI behavior.
- `najwa-sanitize/tests/real_file_fixtures.rs` and the parser unit tests, including
  refusal, without aborting, of a PDF whose objects nest 10,380 levels deep.
- `najwa-mailbox` endpoint and stress tests, which drive the real router and
  database in process.
- `najwa-ffi/tests/ffi_contract.rs` and `startup_security.rs`: the C ABI's null,
  invalid-UTF-8, string-ownership, lifecycle and callback-registration contracts,
  and that initialization disables process dumps before accepting work.
- `apps/local-web/tests/profile_guards.rs` and `persistent_profile.rs`: they start
  the real `najwa-web` binary and check the profile lease, the erasure marker,
  the HTTP boundary, identity creation and recovery, restart and idle lock.

Building `najwa-web` enables its hardware features for the whole workspace, so
the workspace run uses the real platform key store:

- `persistent_profile` creates synthetic identities in the platform key store
  and deletes them afterwards. Most of its tests need a working hardware key
  store (a TPM on Windows and Linux). On Linux,
  `saved_preferences_bridge_failure_idle_lock_and_offline_erasure` falls back to
  approved OS storage and needs an unlocked Secret Service. The two ignored
  `missing_tpm_` tests need Linux with no TPM.
- The service locks when the operating system locks the session or sleeps, and
  that includes every test instance. Keep the screen awake and unlocked while
  `persistent_profile` runs, or its tests fail with `stale_operation` or a
  `locked` phase.
- On a machine without them, run `cargo test --locked --workspace --exclude najwa-web`
  and `cargo test --locked -p najwa-web --test profile_guards`.
- `najwa-identity/tests/platform_file.rs` compiles only without hardware
  features: run it with `cargo test --locked -p najwa-identity`.

Set `NAJWA_WEB_TEST_EXE` to a packaged executable to run the `najwa-web`
integration tests against it instead of the freshly built binary. Set
`NAJWA_WEB_TEST_UI` to the absolute path of `target/local-web-ui` to make
`persistent_identity_recovery_and_http_boundary` also run a real-browser smoke
test (`apps/desktop/local-web/smoke.mjs`, Edge through Playwright).

Tests marked `#[ignore]` need hardware, a network or a mailbox and are covered
below. A default green run does not include them.

`bash scripts/check-no-clearnet-dns.sh` greps every crate and app (`crates/` and
`apps/`, skipping `target/` and `node_modules/`) for system-resolver calls and
fails if it finds one outside an explicitly allowed line.

`bash scripts/check-os-rng.sh` greps the crates and the local service for
`thread_rng` and other userspace generators in production code (S01 §5.1) and
fails if it finds one outside the files reviewed as non-security.

Benchmarks (`cargo bench -p najwa-crypto`, `-p najwa-protocol`, `-p najwa-sanitize`)
measure local CPU cost only.

## Interface tests

```sh
cd apps/desktop
npm ci
npm run web:build
npm run web:test
```

Playwright serves the built `target/local-web-ui` and drives it in Microsoft
Edge (`npx playwright install msedge` if Edge is missing; add `--with-deps` on
Linux). Every `/api/*` call is mocked. The suites cover the account and
recovery flow, storage consent, first-run mailbox setup and mailbox settings,
contact setup and invitation retry, the contact directory and contact controls,
the chat pane and history, the composer, message timers and locking,
preferences, reconnection and file transfers, including behavior while the
network is offline. They prove interface behavior only: no native code, key storage or
Tor is involved.

## Packaging tests

```sh
python scripts/test_package_local_web.py
```

This checks that the packager's interface digest uses the same byte order as the
embedded copy, that its stale-build check refuses after a change to an input
listed in Cargo's dep-info file (or, without one, to any workspace source) but
not after a change to a crate the executable does not link, and that packages
without the hardware-preferred,
explicit-approval policy, or with the wrong backend for the OS, are refused. The
packager also checks every build it packages (see [Building](building.md#3-package)).

Against a finished package, run the profile guards with the packaged executable,
as CI does:

```sh
NAJWA_WEB_TEST_EXE=/path/to/package/Najwa cargo test --locked -p najwa-web --features bundled-ui --release --test profile_guards
```

On Linux without a TPM, inside an unlocked Secret Service session, also run the
same command with `--test persistent_profile missing_tpm_ -- --ignored --test-threads=1`
in place of `--test profile_guards`. These tests prove that the packaged binary refuses to create an identity without either a
TPM or the user's approval, and that an approved profile survives restart. The
[Docker Linux build](building.md#4-linux-package-from-a-windows-host) runs these
and further checks against its own package.

## Live Tor

```sh
cargo test --locked -p najwa-transport --test live_tor -- --ignored --nocapture
```

Bootstraps embedded Arti on the public Tor network (30 to 60 seconds) and
fetches over HTTP from the Tor Project's onion mirror. Proves bootstrap,
onion-only HTTP, single-use circuit handles and the DNS-leak self-test. Needs
outbound access to Tor and depends on the mirror being up.

## Live mailbox

`crates/najwa-core/tests/live_mailbox.rs` runs two clients with real SQLCipher
stores against a real mailbox server. Start the test mailbox (no Tor, no
proof-of-work, no batching) and run the tests on its Docker network:

```sh
cd scripts/deployment
docker compose -f docker-compose.test.yml up -d --build
cd ../..
docker run --rm --network deployment_default -v "$PWD:/work" -w /work -e CARGO_TARGET_DIR=target-linux -e TEST_MAILBOX_ADDR=mailbox rust:bookworm cargo test --locked -p najwa-core --test live_mailbox -- --ignored --skip tor_sqlite --nocapture
docker compose -f scripts/deployment/docker-compose.test.yml down
```

Proves deposit and fetch, prekey bundles and their replenishment, single-use
invitation capabilities, rate limiting, cover and slot-paced deposits, and
messaging across a client restart against the real server. The separate
`tor_sqlite_messaging_end_to_end_across_restart` test does the same through two
embedded Arti clients; set `TEST_MAILBOX_ONION` to an onion service that
forwards port 80 to a disposable test mailbox.

## Two-peer desktop boundary

Start the [development onion mailbox](../../scripts/deployment/ONION-DEVELOPMENT.md),
then build the peer and run the harness (Windows shown):

```powershell
./scripts/native-cargo.ps1 -CargoArguments @('build','--locked','-p','najwa-ffi','--example','desktop_peer')
$onion = (docker compose -f scripts/deployment/docker-compose.onion-dev.yml exec -T tor cat /var/lib/najwa-onion/hostname).Trim()
python scripts/test-desktop-messaging.py target/debug/examples/desktop_peer.exe $onion target/desktop-messaging-e2e
```

Two processes with in-memory identities use the same `DesktopClient` boundary
as the app and their own embedded Arti clients. The harness registers both
mailboxes, accepts a signed invitation, waits for both contacts to become ready
with matching safety numbers, sends text both ways, then locks Alice, checks
that her cover traffic keeps running, sends to her while locked and checks the
message arrives after she unlocks. The output directory must be new.

## Browser end to end

These tests drive the packaged app through a real browser, public Tor and an
onion mailbox. Build a package, start the development onion mailbox, install
Node.js and the interface dependencies (`npm ci` in `apps/desktop`), then:

```sh
NAJWA_WEB_TEST_EXE=/path/to/package/Najwa NAJWA_MAILBOX_ONION=<56-character>.onion \
  cargo test --locked -p najwa-web --features bundled-ui --release --test live_messaging -- --ignored --nocapture
```

The test runs `apps/desktop/local-web/live-messaging.mjs` with two fresh
profiles: both identities are created through the recovery-kit flow, both
mailboxes are registered over Tor, Bob accepts Alice's invitation, the safety
numbers must match, text and encrypted receipts go both ways, then Bob is
stopped, Alice sends, the message must reach the mailbox, and Bob restarts with
the same identity, history and contacts and receives it. The report is written
to `target/live-release-check/result.json` or `NAJWA_LIVE_REPORT`.

Optional stages, set as environment variables:

| Variable | Adds |
| --- | --- |
| `NAJWA_ASYNC_CONTACT_SETUP=1` | Contact setup without overlapping online sessions |
| `NAJWA_CONTACT_FEATURES=1` | QR invitation, contact controls and an offline file transfer |
| `NAJWA_READ_RECEIPTS=1` | Read receipts sent while the original sender is offline |
| `NAJWA_SECOND_MAILBOX=<onion>` | A second mailbox and primary-mailbox selection |
| `NAJWA_LARGE_FILES=1` | Maximum-size (256 MiB) transfers with upload and restart recovery |
| `NAJWA_BROWSER_CHANNEL` | Playwright browser channel (default `msedge`) |

`large_file_resume` (`NAJWA_LARGE_FRESH=1` for a first run) keeps its synthetic
profiles in `target/large-files-stable-profiles` so an interrupted 256 MiB
transfer can be continued without uploading again.
`node local-web/reconnect-live.mjs <packaged executable>` (from `apps/desktop`)
checks in Chrome and Edge that a browser pairs through the launch token, that an
open page recovers after the app restarts, that an unpaired browser is refused
and that nothing is left in browser storage.

The [two-browser harness](../../apps/desktop/local-demo/README.md) is a manual
alternative with in-memory identities.

## TPM simulator and keyring containers

```sh
docker build -f scripts/testing/linux-tpm.Dockerfile -t najwa-linux-tpm-test .
docker run --rm -v "$PWD:/work" -v najwa-cargo-registry:/usr/local/cargo/registry najwa-linux-tpm-test

docker build -f scripts/testing/keychain.Dockerfile -t najwa-keychain-test .
docker run --rm -v "$PWD:/work" -v najwa-cargo-registry:/usr/local/cargo/registry najwa-keychain-test
```

The TPM container starts two `swtpm` simulators on loopback and a disposable
Secret Service, then runs the identity crate's simulator tests, its tests with
and without the `linux-tpm` feature, and Clippy with warnings denied. The
keychain container runs the ignored `platform_keychain` tests against a
disposable Secret Service. Neither mounts a host TPM or keyring. They prove the
Linux TPM2 and Secret Service code paths, not behavior on real hardware.

## Physical hardware

Real TPM and Secure Enclave tests create and delete uniquely named keys on the
device. Follow [Windows TPM](../../crates/najwa-identity/WINDOWS-TPM.md),
[Linux TPM](../../crates/najwa-identity/LINUX-TPM.md) and
[macOS Secure Enclave](../../crates/najwa-identity/MACOS-SECURE-ENCLAVE.md).
Simulator, container and missing-TPM results do not substitute for these.

## C ABI smoke test

```sh
sh scripts/testing/c-abi-smoke.sh
```

Builds the `najwa-ffi` dynamic library, compiles `crates/najwa-ffi/tests/c_abi_smoke.c`
against the committed header with `-Wall -Wextra -Werror`, links it and runs it.
It calls all 20 functions before initialization: the version string,
null-pointer and not-initialized results, empty lists, string freeing, callback
registration and clearing, cancel and lock. It proves that the header compiles
and every symbol links and behaves as declared before initialization. Linking does not check argument types, so it does not prove that
every declared signature matches the Rust definition. The script builds with
`--offline`; fetch dependencies first. It needs a Unix-like system with `cc`.

CI also compiles the header on its own, as C and as C++:

```sh
gcc -std=c99 -Wall -Wextra -Werror -pedantic -fsyntax-only -x c crates/najwa-ffi/include/najwa.h
g++ -Wall -Wextra -Werror -pedantic -fsyntax-only -x c++ crates/najwa-ffi/include/najwa.h
```

On Windows, build the library with `scripts/native-cargo.ps1` and link the smoke
test directly against `target/debug/najwa_ffi.dll` with MinGW `gcc`; copy the
DLL next to the executable to run it.

## Release validation

For a package intended for distribution, record the source revision, the
archive SHA-256, the OS and architecture, whether hardware or approved OS
storage was used, the mailbox and its delivery settings, and the result of each
level above run against that package. A passing default test run does not cover
the ignored tests, real hardware or real Tor. Dependency review is in
[Dependencies](../security/dependencies.md).
