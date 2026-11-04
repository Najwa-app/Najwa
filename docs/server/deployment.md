# Deploying a mailbox

This guide sets up a Najwa mailbox on a Linux host with systemd and the
distribution's `tor` package, using the files in `scripts/deployment/`. A
container route is in §11. On Ubuntu 26.04, `scripts/deployment/install-mailbox.sh`
runs §2–§10 in one command with the template defaults; see the
[quick start](quick-start.md). The protocol, every endpoint and every configuration
key are defined in [S16](../specs/16-mailbox-server.md). Running the mailbox
afterwards is covered in [Operations](operations.md).

For local protocol testing, use the
[development onion stack](../../scripts/deployment/ONION-DEVELOPMENT.md)
instead.

## 1. Before you start

You need:

- A Linux host with systemd and root access.
- The `tor` package (Debian/Ubuntu: `apt install tor`).
- `sqlite3` for backups and inspection.
- Working time synchronization. Tor, challenge expiry and proof-of-work
  timestamps ([S16 §7.1](../specs/16-mailbox-server.md)) depend on the clock.
- To build natively: Rust 1.90 or newer, a C compiler, `make`, `perl` and
  `pkg-config` (the workspace builds a vendored SQLite with OpenSSL). Ubuntu
  26.04 packages a new enough Rust:
  `apt install build-essential pkg-config perl rustc cargo`. On older releases use
  the toolchain from [Building](../development/building.md). Or Docker.

Storage is bounded by quotas. With the supplied template, one long-term queue
holds up to 4,096 blobs and 512 MiB, and each user registers several queues
(primary, cover, one per contact). Measure disk, I/O and CPU for the number of
users you plan to serve; there is no validated sizing table.

## 2. Harden the host (optional)

`scripts/deployment/harden-server.sh` prepares a fresh Ubuntu 22.04+, Debian 12+
or RHEL/Fedora host. It has been run on Ubuntu 26.04. Read it before running it.
Audit first, then apply:

```sh
sudo bash scripts/deployment/harden-server.sh --check
sudo bash scripts/deployment/harden-server.sh
```

`--yes` skips the confirmation prompts. Over SSH, run the apply step as a
systemd unit so that a dropped connection cannot stop it halfway through an
upgrade or a firewall reset; its output goes to the journal:

```sh
sudo systemd-run --unit=najwa-harden --wait --collect -E DEBIAN_FRONTEND=noninteractive \
  bash "$PWD/scripts/deployment/harden-server.sh" --yes
sudo journalctl -u najwa-harden -o cat
```

The script:

1. Installs updates, including new kernels, and `unattended-upgrades`. Reboot
   afterwards if `/var/run/reboot-required` exists.
2. Replaces the firewall rules with UFW, or iptables if UFW is absent:
   inbound only SSH (22); outbound TCP to any port, NTP (UDP 123) and DNS (53);
   loopback unrestricted. Tor connects to relays on whatever port each relay
   advertises, so outbound TCP is not limited to 443 and 9001. NTP keeps the
   clock right for Tor and proof-of-work; DNS serves package updates and NTP
   server names. Other outbound UDP is blocked. With firewalld, the script sets
   the `drop` zone with only SSH allowed in; firewalld does not filter outbound
   traffic. With UFW it also turns martian-packet logging on in
   `/etc/ufw/sysctl.conf`, which UFW applies after `/etc/sysctl.d` at every start.
3. Creates the `najwa-mailbox` system user and `/var/lib/najwa-mailbox` (0700),
   `/var/log/najwa-mailbox` (0750) and `/etc/najwa-mailbox` (0750, `root:najwa-mailbox`).
4. Writes kernel `sysctl` hardening and disables core dumps.
5. Stops and masks avahi, cups, bluetooth, ModemManager, snapd and apport if
   present, with their activation sockets. Apport is Ubuntu's crash reporter; it
   would otherwise turn core dumps back on at boot.
6. Installs fail2ban for SSH and enables AppArmor (or sets SELinux to
   enforcing) where available.
7. Restricts cron file permissions and adds a `noexec,nosuid,nodev` mount for
   `/dev/shm`.
8. Last, ensures a non-root sudo user exists. If none does, it creates
   `najwa-deploy`. With root's SSH keys, the new user gets those keys and
   passwordless sudo, because it has no password; without keys, it gets root's
   password. It then turns off root login, and password login if any user has SSH
   keys, sets 5 authentication tries, and drops connections whose client stops
   answering for 10 minutes. These go in
   `/etc/ssh/sshd_config.d/00-najwa-hardening.conf`, which sshd reads before
   cloud-image defaults such as `50-cloud-init.conf` (sshd keeps the first value
   it reads). The script compares each value with `sshd -T`, the settings sshd
   actually uses.

To make sudo ask for a password afterwards, run `sudo passwd najwa-deploy`, then
`sudo rm /etc/sudoers.d/najwa-deploy`. Keep your current SSH session open until
you have confirmed a new login works.
Then continue with §3.

From Windows, `scripts/deployment/harden-server.ps1 -Target user@host` uploads
the script over SSH and runs it with `sudo`; `-Check` and `-Yes` map to
`--check` and `--yes` (`-Host` is accepted as an alias of `-Target`). Without
`-Target` it audits a local container whose name contains `najwa-mailbox`:
user, capabilities, health, and whether every network it is attached to is
Docker-internal.

## 3. Build the server

From the repository root:

```sh
cargo build --locked --release -p najwa-mailbox
```

The binary is `target/release/najwa-mailbox`. It takes one argument, the path of
its configuration file, and has no other options. On 2 vCPUs the first build
takes about 10 minutes and peaks at about 1.5 GB of memory.

To build the container image instead (also from the repository root):

```sh
docker build -t najwa-mailbox -f scripts/deployment/Dockerfile .
```

## 4. Create the service account and directories

Skip any step the hardening script already did; check ownership with
`ls -ld` rather than recreating.

```sh
sudo useradd --system --no-create-home --shell /usr/sbin/nologin najwa-mailbox
sudo install -d -m 0700 -o najwa-mailbox -g najwa-mailbox /var/lib/najwa-mailbox
sudo install -d -m 0750 -o najwa-mailbox -g najwa-mailbox /var/log/najwa-mailbox
sudo install -d -m 0750 -o root -g najwa-mailbox /etc/najwa-mailbox
sudo install -m 0755 -o root -g root target/release/najwa-mailbox /usr/local/bin/najwa-mailbox
```

The server writes logs to standard output, not to `/var/log/najwa-mailbox`, but
the supplied systemd unit lists that directory as writable and fails to start if
it does not exist.

## 5. Generate the operator signing key

The operator key is an Ed25519 seed stored as 64 hexadecimal characters. Write
it straight to a file without printing it:

```sh
sudo sh -c 'umask 077; openssl rand -hex 32 > /etc/najwa-mailbox/operator-seed'
sudo chown root:najwa-mailbox /etc/najwa-mailbox/operator-seed
sudo chmod 0440 /etc/najwa-mailbox/operator-seed
```

The server derives its `operator_id` (the public key) from this seed and signs
`/v1/attestation` and the optional batching attestation with it. If the
configured file is unreadable or malformed, the server refuses to start.

Back the seed up separately from the database. Never commit it, paste it into a
ticket, or put it in the configuration file; use `operator_key_path` (§7).

## 6. Configure Tor

Append the service definition from `scripts/deployment/config/torrc` to
`/etc/tor/torrc`:

```text
HiddenServiceDir /var/lib/tor/najwa-mailbox/
HiddenServicePort 80 127.0.0.1:8080
HiddenServiceVersion 3
SocksPort 0
ControlPort 0
Log notice file /var/log/tor/notices.log
```

`SocksPort 0` turns off Tor's local client port for this Tor instance; remove it
only if something else on the host needs Tor as a client. The port after
`127.0.0.1:` must match `listen_port` in §7.

```sh
sudo systemctl restart tor
sudo cat /var/lib/tor/najwa-mailbox/hostname
```

The hostname is your public address: 56 characters followed by `.onion`. The
same directory holds the onion private key (`hs_ed25519_secret_key`). Losing that
key changes the address and strands every user of this mailbox. Back it up as
described in [Operations](operations.md#2-backup-and-restore).

## 7. Configure the server

Install the production template and edit it:

```sh
sudo install -m 0640 -o root -g najwa-mailbox scripts/deployment/config/mailbox.toml /etc/najwa-mailbox/mailbox.toml
sudoedit /etc/najwa-mailbox/mailbox.toml
```

Change these values:

| Key | Set to | Reason |
| --- | --- | --- |
| `[server] listen_addr` | `"127.0.0.1"` | the template binds all interfaces for container use |
| `[server] onion_address` | the hostname without `.onion` | reported in `/v1/attestation` |
| `[attestation] operator_key_path` | `"/etc/najwa-mailbox/operator-seed"` | add this line; leave `operator_key_seed_hex` empty |
| `[attestation] jurisdiction`, `infrastructure_provider` | your claims | shown to anyone who asks; self-asserted |

`sudo sed 's/\.onion$//' /var/lib/tor/najwa-mailbox/hostname` prints the
address in the form `onion_address` expects.

Review the rest against your policy ([S16 §5](../specs/16-mailbox-server.md)
lists every key):

- Keep `max_blob_size_bytes` at 262144 or more. Release clients register queues
  with `max_message_size = 262144`; a smaller server limit rejects every
  registration with `400`.
- Keep `refuse_last_opk = true`. The server refuses to start otherwise.
- Keep the proof-of-work section. `registration_always_requires_pow = false`
  removes the only cost of registering queues.
- Quotas: the template allows 4,096 blobs and 512 MiB per long-term queue and
  100 blobs and 8 MiB per invitation queue. One 256 MiB file travels as about
  1,100 blobs of 256 KiB, roughly 275 MiB of queue storage.
- Retention: release clients register every queue with `retention_days = 14`;
  `default_retention_days` applies only to registrations that omit it.
  Unacknowledged blobs never last longer than 90 days, and a queue with no
  deposit or fetch for 30 days is deleted with its blobs.
- Release timing: the template makes each message fetchable as soon as it is
  stored. Read §7.1 before you change it.
- `register_per_min` caps registration attempts per queue per minute; fresh
  queues are priced by proof-of-work.
- Unknown or misspelled keys stop the server at startup with an error naming
  the key. A configuration written for an earlier server must drop
  `[batching] enabled`, `[logging] directory` and `rotate_days`.

### 7.1 Release timing: hold and jitter

The `[batching]` section decides how long the server keeps each new message
before anyone can fetch it. For every stored blob the server draws two random
numbers: a hold between `min_hold_secs` and `max_hold_secs`, and an extra delay
between 0 and `jitter_secs`. It hands the blob out only after the sum has passed
([S16 §6](../specs/16-mailbox-server.md#6-release-timing)).

| Profile | `min_hold_secs` / `max_hold_secs` / `jitter_secs` | A message becomes fetchable |
| --- | --- | --- |
| Responsive (template) | 0 / 0 / 0 | as soon as it is stored |
| Timing privacy | 30 / 300 / 60 | 30 to 360 seconds after it arrives |

**What a hold protects against.** Someone who can watch your server's network
traffic but not inside the server, such as your hosting provider, sees when
encrypted traffic arrives and when it leaves. Without a hold, a deposit followed
shortly by a fetch suggests that the two belong together. A random hold weakens
that link, and because each blob is held independently, messages also leave in
a different order from the one they arrived in.

**What it does not protect against.** You. The server computes every release
time and sees every deposit and fetch, so a hold hides nothing from the operator
or from anyone who gets into the server.

**What it costs.** Everything waits: messages, receipts, acknowledgements and
each step of setting up a new contact, which takes several round trips. A file
travels as parts of up to 256 KiB, each held separately, so it arrives when its
slowest part does.

**It is separate from the app's delivery modes.** Each user picks *Responsive*
or *Timing privacy* in the app
([FAQ](../understanding/faq.md#what-is-the-difference-between-responsive-and-timing-privacy)).
That choice paces when their app sends and works with any mailbox, whatever its
release timing. Your hold applies to everyone who uses your mailbox, and its
delay adds to the app's.

**Publishing your choice.** With `publish_batching_attestation = true`, the
server includes the three values, signed with your operator key, in
`/v1/status`, which only users registered with you can read. The signature shows
what you configured, not that the server applies it. If you list the mailbox
publicly, state the same values in its
[list entry](../../MAILBOXES.md#adding-a-mailbox).

**Changing it.** Edit the values and restart the server. New values apply to
messages deposited after the restart; stored messages keep their release time.
Update your list entry at the same time.

Keep the template's 0 / 0 / 0 unless the people you serve would rather wait
minutes per message than let someone watching your server's network match
arrivals to pickups by timing.

## 8. Install and start the service

```sh
sudo install -m 0644 scripts/deployment/config/najwa-mailbox.service /etc/systemd/system/najwa-mailbox.service
sudo systemctl daemon-reload
sudo systemctl enable --now najwa-mailbox
sudo systemctl status najwa-mailbox
sudo journalctl -u najwa-mailbox -n 50
```

The unit runs `/usr/local/bin/najwa-mailbox /etc/najwa-mailbox/mailbox.toml` as
`najwa-mailbox`, starts after `tor.service` and restarts on exit. It sets
`UMask=0077`, so the database, WAL and SHM files are created readable only by
the service account. It also applies `NoNewPrivileges`, an empty capability
bounding set, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`,
`PrivateDevices`, the kernel, clock and hostname protections,
`RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`, `MemoryDenyWriteExecute`
and `SystemCallFilter=@system-service`. `systemd-analyze security
najwa-mailbox` lists the full set. If the
configuration path is wrong, the server exits with `cannot read config file`
and systemd keeps restarting it; the journal names the path it tried.
`systemctl stop` sends SIGTERM, and the server finishes in-flight requests
before it exits.

A good start logs `starting najwa-mailbox server`, `health endpoint listening
(local only)` and `API server listening`.

## 9. Network exposure

The mailbox needs no inbound firewall opening. Tor carries all client traffic.
Confirm both listeners are on loopback:

```sh
sudo ss -ltnp | grep najwa-mailbox
```

Expect `127.0.0.1:8080` (API) and `127.0.0.1:9090` (health). Do not publish
either port, put a reverse proxy in front of them, or add any client
authentication layer ([S16 §14.1](../specs/16-mailbox-server.md)).

## 10. Validate

1. Health on the host:

   ```sh
   curl -s http://127.0.0.1:9090/v1/health
   ```

   Expect `"status":"healthy"` and `"server_status":"Active"`.

2. Attestation on the host:

   ```sh
   curl -s http://127.0.0.1:8080/v1/attestation
   ```

   Expect your `onion_address` and non-empty `operator_id` and `signature`.
   Record `operator_id`; it identifies your operator key.

3. Over Tor, from another machine with a repository checkout, run the protocol
   probe. It bootstraps its own embedded Tor client, verifies the attestation
   signature, hostname and freshness, confirms `/v1/health` is not reachable
   through the onion, registers a fresh capability with proof-of-work, deposits
   a random blob, fetches the same bytes, acknowledges, and deactivates:

   ```sh
   cargo run --locked -p najwa-protocol --example onion_mailbox_probe -- <hostname>.onion target/onion-probe-tor
   ```

   The second argument is a directory for the probe's Tor state. The probe
   prints the operator ID, jurisdiction and provider it verified. It is not an
   end-to-end messaging test.

4. In the app, add the address in Settings on two test profiles, exchange an
   invitation, and send messages while the recipient is closed.
5. Restart the server (`sudo systemctl restart najwa-mailbox`) and confirm the
   queued messages still arrive.

A healthy `/v1/health` alone does not prove the onion is reachable or that
messages are delivered.

## 11. Container deployment

The image built in §3:

- runs as the unprivileged user `najwa`;
- contains `/usr/local/bin/najwa-mailbox` and the production template at
  `/etc/najwa-mailbox/mailbox.toml` (all-interface bind, no operator key);
- takes the configuration path as its command (default
  `/etc/najwa-mailbox/mailbox.toml`);
- checks health with `curl` against `127.0.0.1:9090` inside the container.

Use `scripts/deployment/docker-compose.onion-dev.yml` as the reference layout:
a separate Tor container, the mailbox on an internal network with no published
ports, a one-shot initializer that generates the operator seed inside the data
volume and writes the configuration, read-only root filesystems, all Linux
capabilities dropped and `no-new-privileges`. For production, change at least:

- the configuration source: start from `config/mailbox.toml` rather than the
  development template, which raises deposit limits to 4,096 per minute and
  defaults retention to one day;
- the restart policy (`restart: unless-stopped` instead of `"no"`);
- backups for the Tor state and mailbox state volumes (the hostname volume is
  derived from Tor state and needs none).

## 12. Publish and upgrade

There is no directory service in the app. To offer your mailbox to anyone, add
it to the [public mailbox list](../../MAILBOXES.md) by pull request. Otherwise
give users, through a channel they trust:

- the onion address;
- your `operator_id`;
- your policy: retention, quotas and release timing.

To upgrade:

1. Back up the database, seed and Tor state
   ([Operations](operations.md#2-backup-and-restore)).
2. `sudo systemctl stop najwa-mailbox`, replace the binary (or image), and start
   it again.
3. Check the journal. The server refuses a database whose schema version differs
   from its own and has no in-place migration; if it refuses, reinstall the
   previous binary and restore the backup.

Keep the database, operator seed and Tor state across upgrades. Never start a
second server on a copy of the database.
