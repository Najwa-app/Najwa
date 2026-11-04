# Development mailbox on Tor

This Docker Compose stack runs a Najwa mailbox and its Tor service on your
machine and publishes the mailbox API as a v3 onion service on the **public
Tor network**. Anyone who learns the address can reach the API; reading or
writing a queue still needs its capabilities. Use disposable identities. This
is a development server, not a production deployment; for that, see
[Deployment](../../docs/server/deployment.md).

The app, its embedded Tor client and its UI run outside Docker. Docker hosts
only the mailbox and the mailbox's Tor service.

## What runs

| Service | Image | Role |
| --- | --- | --- |
| `tor` | `najwa-onion-dev-tor` (`onion-dev/Dockerfile.tor`) | Debian `tor` as `debian-tor`; hosts the onion service and copies its public hostname to a shared volume |
| `initialize` | `najwa-onion-dev-mailbox` | one-shot job without network access; checks the hostname, creates the operator seed if missing, writes the mailbox configuration |
| `mailbox` | `najwa-onion-dev-mailbox` (`scripts/deployment/Dockerfile`) | the mailbox server as user `najwa`, reading `/var/lib/najwa-mailbox/mailbox.toml` |

- The mailbox sits on the internal network `mailbox-private`, which has no
  Internet route. Only the Tor container also joins `tor-internet`.
- No host ports are published. Tor forwards onion port 80 to the mailbox's API
  on port 8080 inside the private network.
- The health listener binds `127.0.0.1:9090` inside the mailbox container. It is
  not reachable from other containers or through the onion.
- Tor runs with `SocksPort 0`, `ControlPort 0` and `SafeLogging 1`.
- Every service has a read-only root filesystem, drops all Linux capabilities,
  sets `no-new-privileges` and disables core dumps. Tor and the mailbox have
  process and 512 MiB memory limits and rotate their logs at 10 MB.
- There is no restart policy. The mailbox is offline whenever the computer,
  Docker or these containers stop.

## Start

From the repository root, with Docker running Linux containers:

```powershell
docker compose -f scripts/deployment/docker-compose.onion-dev.yml up -d --build
docker compose -f scripts/deployment/docker-compose.onion-dev.yml ps
docker compose -f scripts/deployment/docker-compose.onion-dev.yml logs --tail 30 tor
docker compose -f scripts/deployment/docker-compose.onion-dev.yml exec -T tor cat /var/lib/najwa-onion/hostname
```

The last command prints the onion address. Wait until the Tor log shows
`Bootstrapped 100%` before using it. The Tor container reports healthy as soon
as its hostname file exists, which is before bootstrap finishes. The mailbox
reports healthy when its local API process answers, which says nothing about
onion reachability.

The private network defaults to `172.31.253.0/24`, with the mailbox at `.2` and
Tor at `.3`. If Docker reports a subnet conflict, choose an unused subnet and
set all three variables in every shell that runs Compose commands for this
stack:

```powershell
$env:NAJWA_DEV_SUBNET = "172.31.252.0/24"
$env:NAJWA_DEV_MAILBOX_IP = "172.31.252.2"
$env:NAJWA_DEV_TOR_IP = "172.31.252.3"
```

## State

| Volume | Mounted by | Contents |
| --- | --- | --- |
| `tor-state` | `tor` | Tor state and the onion private keys |
| `onion-address` | `tor` (write), `initialize` (read-only) | the public hostname only |
| `mailbox-state` | `initialize`, `mailbox` | database, generated `mailbox.toml`, `operator-seed` |

`initialize` creates `operator-seed` once, from 32 bytes of `/dev/urandom`
written as 64 hex characters with mode `0600`. The seed never appears in the
repository, an image layer, the Compose environment or command output. Later
runs keep the existing seed and database.

## Development settings

The template is `scripts/deployment/onion-dev/mailbox.toml`. `initialize`
substitutes the onion hostname into it.

| Setting | This stack | Production template (`config/mailbox.toml`) |
| --- | --- | --- |
| Registration proof-of-work | 20–24 bits | 20–24 bits |
| Proof-of-work floor on invitation-queue deposits | 16 bits | 16 bits |
| Deposits per minute before proof-of-work | 4,096 | 10 |
| Deposit ceiling per queue | 4,096 per minute | 60 per minute |
| Fetch ceiling per queue | 120 per minute | 120 per minute |
| Prekey fetches | 10 per minute, proof-of-work above 5 | same |
| Long-term queue quota | 4,096 blobs, 512 MiB | same |
| `default_retention_days` | 1 | 14 |
| Hold / maximum hold / jitter | 0 / 0 / 0 s | 0 / 0 / 0 s |
| Operator key | generated `operator-seed` in the volume | configured by the operator |
| Attestation | provider `local-development`, no jurisdiction | operator's claims |
| Batching attestation in `/v1/status` | on | on, when a key is configured |
| Log level | `warn` | `info` |

The raised deposit limits let a 256 MiB file (about 1,100 blobs) go through
without proof-of-work on every part. They do not change the production template.

`default_retention_days` applies only to registrations that do not state a
retention period. The app registers every queue with 14 days; the probe below
registers 1 day.

With zero hold and jitter, a blob is fetchable as soon as it is stored. Client
polling, proof-of-work and Tor still add delay. The timing-privacy profile is
`min_hold_secs = 30`, `max_hold_secs = 300`, `jitter_secs = 60`.

## Change settings

The mailbox reads its configuration at startup from `mailbox-state`. After
editing `scripts/deployment/onion-dev/mailbox.toml`, regenerate the
configuration and restart only the mailbox:

```powershell
docker compose -f scripts/deployment/docker-compose.onion-dev.yml run --rm --no-deps initialize
docker compose -f scripts/deployment/docker-compose.onion-dev.yml restart mailbox
docker compose -f scripts/deployment/docker-compose.onion-dev.yml ps
```

`initialize` keeps the operator seed and database, and Tor keeps the onion
address. New hold and jitter values apply to blobs deposited after the restart;
stored blobs keep their release times.

`POST /v1/status` shows the configured timing to the owner of an active queue.
It needs a Base64 `fetch_capability`. With an operator key and batching
attestation enabled, the response includes:

```json
{
  "batching_attestation": {
    "signature": "<base64, 64 bytes>",
    "min_hold_secs": 0,
    "max_hold_secs": 0,
    "jitter_secs": 0,
    "signed_at": 1767225600
  }
}
```

The values are the configured bounds, not the delay of any single blob. The
signature is made on the first status request after startup and reused for up
to 24 hours ([S16 §3.8](../../docs/specs/16-mailbox-server.md)).
`GET /v1/attestation` returns the operator's public key and claims, not timing.

## Health and logs

```powershell
docker compose -f scripts/deployment/docker-compose.onion-dev.yml exec -T mailbox curl -s http://127.0.0.1:9090/v1/health
docker compose -f scripts/deployment/docker-compose.onion-dev.yml logs --tail 50 mailbox
```

## Probe through Tor

The `onion_mailbox_probe` example uses Najwa's embedded Arti client. It needs no
external SOCKS proxy and uses no user identity or message content. It:

1. bootstraps Arti in the state directory you name;
2. fetches `/v1/attestation` and verifies the signature, the hostname and that
   the timestamp is within 300 seconds of local time;
3. checks that `/v1/health` returns `404` through the onion;
4. registers fresh random capabilities with proof-of-work;
5. deposits a random 1,024-byte blob, fetches until the same bytes return,
   acknowledges them and checks they are gone;
6. deactivates the capability, and reports if that cleanup fails.

```powershell
$onion = (docker compose -f scripts/deployment/docker-compose.onion-dev.yml exec -T tor cat /var/lib/najwa-onion/hostname).Trim()
cargo run --manifest-path Cargo.toml --locked -p najwa-protocol --example onion_mailbox_probe -- $onion target/onion-probe-tor
```

It prints `PASS` on success. The probe tests the mailbox protocol and onion
transport only. It is not a conversation test and does not run the app's cover
schedule.

On Windows, build with a native MSVC Rust toolchain from a Visual Studio C++
developer shell, with Perl and NASM installed for the vendored SQLite and
OpenSSL build. A GNU-host cross-build can pick incompatible OpenSSL paths. See
[Building](../../docs/development/building.md).

## Use it from the app

Start the local service with a disposable profile (see the
[local web service README](../../apps/local-web/README.md)) and add the onion
address as a mailbox in Settings
([Getting started](../../docs/getting-started.md)). Run a second profile with
its own `--profile` directory and `--port` to exchange messages between two
identities.

For a scripted two-peer conversation test against this stack, use the harness
in [the desktop boundary guide](../../crates/najwa-ffi/DESKTOP.md). If the first
registrations fail with onion reachability errors, restart only the Tor service
(`docker compose -f scripts/deployment/docker-compose.onion-dev.yml restart tor`)
without removing volumes and retry.

## Stop

```powershell
docker compose -f scripts/deployment/docker-compose.onion-dev.yml down
```

This keeps the volumes: the onion address, operator seed and stored blobs
survive. `down --volumes` deletes all of them; the next start creates a new
address and a new operator identity. Do not copy Tor key files or the operator
seed into the workspace.

## Test mailbox without Tor

`scripts/deployment/docker-compose.test.yml` runs a plain HTTP mailbox for the
live integration tests in `crates/najwa-core/tests/live_mailbox.rs`. Its
configuration (`config/mailbox-test.toml`) turns proof-of-work off, uses zero
hold and jitter, raises rate limits to 1,000 per minute and logs plain text. It
publishes no host ports; tests run in a container on the Compose network
`deployment_default` and reach the server as `mailbox`.

```powershell
docker compose -f scripts/deployment/docker-compose.test.yml up -d --build
docker run --rm --network deployment_default -v "${PWD}:/work" -w /work -e CARGO_TARGET_DIR=target-linux -e TEST_MAILBOX_ADDR=mailbox rust:bookworm cargo test -p najwa-core --test live_mailbox -- --ignored --skip tor_sqlite --nocapture
docker compose -f scripts/deployment/docker-compose.test.yml down
```

The `tor_sqlite` test needs `TEST_MAILBOX_ONION` and live Tor, so it is skipped
here. The test mailbox's health listener is loopback-only inside its container
and cannot be reached as `mailbox:9090`. See
[Testing](../../docs/development/testing.md).
