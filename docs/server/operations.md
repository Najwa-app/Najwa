# Operating a mailbox

This guide covers a running mailbox: what to keep, backup and restore,
monitoring, key handling, policy changes, retirement and incident response.
Setup is in [Deployment](deployment.md). Server behavior is defined in
[S16](../specs/16-mailbox-server.md). Paths below are those of the native
deployment.

## 1. What to keep

A mailbox has four persistent assets. Losing any of the first three changes
what users see.

| Asset | Native path | If lost |
| --- | --- | --- |
| Database | `/var/lib/najwa-mailbox/mailbox.db` with `-wal` and `-shm` | every queue, stored blob and prekey bundle is gone; users must register again |
| Onion service keys | `/var/lib/tor/najwa-mailbox/` | the address changes; every user must add the new address |
| Operator seed | `/etc/najwa-mailbox/operator-seed` | `operator_id` changes; users who recorded it see a different key |
| Configuration | `/etc/najwa-mailbox/mailbox.toml` | policy must be rebuilt |

The database is ordinary unencrypted SQLite. It holds encrypted blobs and
plaintext metadata (§8.4). Protect it and every copy of it like the onion key.

Exactly one server process may use a database and an onion address. Never run a
copy of the database as a second live server, and never run two servers behind
one address.

## 2. Backup and restore

### 2.1 Database backup

SQLite's backup command produces a consistent copy while the server runs. Run it
as the service account so no file in the data directory changes owner:

```sh
sudo install -d -m 0700 -o najwa-mailbox -g najwa-mailbox /var/lib/najwa-mailbox/backup
sudo -u najwa-mailbox sqlite3 /var/lib/najwa-mailbox/mailbox.db \
  ".backup '/var/lib/najwa-mailbox/backup/mailbox-$(date +%F).db'"
```

Then encrypt the copy, move it off the host and delete the local file. Do not
open the live database as root: SQLite may create `-wal` or `-shm` files owned by
root that the server then cannot open.

To copy files instead, stop the service first and copy `mailbox.db`,
`mailbox.db-wal` and `mailbox.db-shm` together. The WAL file can hold committed
data.

Backups keep blobs and metadata past the live server's deletion times,
including acknowledged and expired data. Keep them only as long as you need
them for recovery, and never longer than 90 days.

### 2.2 Key backup

Back up the onion keys and the operator seed separately from the database and
from each other:

```sh
sudo tar -C /var/lib/tor -czf /root/najwa-onion-keys.tgz najwa-mailbox
sudo cp /etc/najwa-mailbox/operator-seed /root/najwa-operator-seed
```

Encrypt both, store them offline, and delete the local copies. They change
only when you rotate them (§5).

For the container layout, stop the mailbox (`docker compose ... stop mailbox`)
and archive the `mailbox-state` volume, which holds the database, the generated
configuration and the operator seed. Archive the `tor-state` volume for the
onion keys.

### 2.3 Restore

```sh
sudo systemctl stop najwa-mailbox
sudo mkdir -p /root/mailbox-replaced
sudo mv /var/lib/najwa-mailbox/mailbox.db* /root/mailbox-replaced/
sudo install -m 0600 -o najwa-mailbox -g najwa-mailbox mailbox-backup.db /var/lib/najwa-mailbox/mailbox.db
sudo systemctl start najwa-mailbox
sudo journalctl -u najwa-mailbox -n 50
```

The server refuses a database with a different schema version. Restore with the
same server version that made the backup.

To restore onion keys, stop Tor, extract the archive into `/var/lib/tor`, give
the directory back to Tor's account (`debian-tor` on Debian and Ubuntu) with mode
`0700`, and start Tor.

A restored database is the state at backup time. Expect:

- **Lost deposits.** Blobs accepted after the backup are gone. Their senders
  received `accepted: true` and will not resend them.
- **Unknown queues.** Queues registered after the backup do not exist. Their
  owners get `404` on fetch; deposits to them are silently discarded.
- **Replayed blobs.** Blobs acknowledged after the backup are delivered again.
  Clients discard duplicates within their deduplication window
  ([S07 §7.3](../specs/07-message-format.md)).
- **Reissued prekeys.** One-time prekeys served after the backup become
  available again and can be served a second time. Sessions started with a
  prekey the owner already used fail to decrypt.
- **Immediate release.** Every stored blob whose `release_at` has passed is
  fetchable at once.

Tell users the time window of possible loss.

## 3. Monitoring

### 3.1 Health

```sh
curl -s http://127.0.0.1:9090/v1/health
```

The health listener exists only on the host's loopback interface (inside the
container for the container layout, where the image's health check calls it).
It reports `status`, `server_status`, `uptime_secs`, `capabilities_active`,
`messages_stored`, `disk_usage_mb`, `version` and, while retiring, `retire_at`
([S16 §3.11](../specs/16-mailbox-server.md)).

Alert when:

- the request fails or returns anything but `200`;
- `uptime_secs` keeps resetting (a restart loop);
- `disk_usage_mb` or `messages_stored` grows without a matching rise in users.

`disk_usage_mb` counts only the main database file. Watch the WAL file and free
disk space separately (`sudo ls -l /var/lib/najwa-mailbox/`, `df`).

A healthy answer does not show that Tor publishes the service or that clients
can reach it.

### 3.2 Logs

The server writes one line per event to standard output: JSON when
`[logging] format = "json"`, plain text otherwise. Read it with
`journalctl -u najwa-mailbox` or `docker compose ... logs mailbox`. The
`RUST_LOG` environment variable overrides `[logging] level`.

| Message | Level | Meaning |
| --- | --- | --- |
| `starting najwa-mailbox server` | info | startup, with listen address, health address and database path |
| `server is Retiring; new registrations get 503 (S16 §13)` | info | `[server] retire_at` is set (§7) |
| `health endpoint listening (local only)` | info | health listener bound |
| `API server listening` | info | API listener bound |
| `retention cleanup completed` | info | a cleanup run deleted something; carries counts |
| `retention cleanup failed` | warn | a cleanup run failed; it retries next interval |
| `database error` | error | a request failed with `500` |
| `deposit: unknown/deactivated capability — silent drop (S16 §3.3)` | warn | deposits to inactive or unknown queues were discarded; `dropped` counts them since the previous such line |
| `shutdown signal received, draining requests...` | info | SIGINT or SIGTERM received |
| `server shut down gracefully` | info | in-flight requests finished; the process exits 0 |

The server never logs capability values, blob contents or message IDs. Logs
still record when activity happened; restrict access and keep them briefly.

Anyone can cause silent drops by depositing to random capabilities; such
deposits need no proof-of-work. The warning is therefore written at most once a
minute, with the count, so a flood shows as a large `dropped` value rather than
as log volume.

A configuration error stops the server before it opens the database: a missing
file (`cannot read config file ...`), or an unknown or misspelled key
(`invalid config file ...` followed by `unknown field` and the key's name).

### 3.3 Tor

- Watch Tor's log for `Bootstrapped 100%` after every restart. If it stalls,
  check that the host firewall allows outbound TCP to any port: relays listen
  on many ports besides 443 and 9001
  ([Deployment §2](deployment.md#2-harden-the-host-optional)).
- Probe the onion from outside the host on a schedule. The
  `onion_mailbox_probe` example ([Deployment §10](deployment.md#10-validate))
  checks reachability, the attestation signature and a full deposit/fetch cycle;
  a plain `GET /v1/attestation` over Tor checks reachability alone.
- Keep the clock synchronized; the host firewall must allow NTP (UDP 123) out.
  Tor fails with a wrong clock, and clients' proof
  of work is rejected when its timestamp is more than 60 seconds ahead of the
  server or older than the challenge lifetime.

### 3.4 Database inspection

Use read-only, aggregate queries as the service account. Never export capability
values.

```sh
DB=/var/lib/najwa-mailbox/mailbox.db
sudo -u najwa-mailbox sqlite3 -readonly "$DB" "SELECT capability_type, deactivated, COUNT(*) FROM capabilities GROUP BY 1, 2;"
sudo -u najwa-mailbox sqlite3 -readonly "$DB" "SELECT COUNT(*), COALESCE(SUM(size), 0) FROM messages;"
```

Proof-of-work challenges are held in memory, not in the database
([S16 §3.2](../specs/16-mailbox-server.md)).

## 4. Capacity, proof-of-work and abuse

### 4.1 Difficulty follows the number of queues

Proof-of-work difficulty rises with the number of capabilities that are not
deactivated ([S16 §7.2](../specs/16-mailbox-server.md)). With the supplied
configuration:

| Active capabilities | Registration and `/v1/challenge` | Challenge in a type-1 deposit `429` | Challenge in a type-2 deposit `429` |
| --- | --- | --- | --- |
| under 5,000 | 20 bits | 16 bits | 8 bits |
| 5,000–7,999 | 20 bits | 16 bits | 16 bits |
| 8,000–9,499 | 20 bits | 20 bits | 20 bits |
| 9,500 and more | 24 bits | 24 bits | 24 bits |

Release clients take every challenge from `/v1/challenge`, so they always solve
at least `min_difficulty` (20 bits). Each user holds several capabilities
(primary, cover, one per contact, one per open invitation). Responses slower
than 100 ms also raise difficulty for 60 seconds: every slow response adds 10
points of load.

### 4.2 Abuse patterns

| Pattern | What you see | What helps |
| --- | --- | --- |
| Registration flood | `capabilities_active` jumps; difficulty rises for everyone | proof-of-work prices it; unused queues expire after 30 days; `register_per_min` stops one pair being retried in a loop |
| Challenge flood | request volume; clients occasionally retry a voided challenge | the in-memory store holds at most 65,536 challenges and drops the oldest; nothing is written to disk |
| Unknown-capability deposits | a large `dropped` count on the silent-drop warning; with a fresh capability per deposit, memory grows (each one holds a rate-window entry for up to 360 seconds) | watch process memory |
| One queue at quota | repeated `507` for that queue | per-queue quotas contain it; the owner can replace the queue |

Do not add authentication, IP filtering or per-client limits: they add an
identification layer the protocol forbids
([S16 §14.1](../specs/16-mailbox-server.md)). The server cannot see Tor circuits.

### 4.3 Retention and cleanup

Cleanup runs every `interval_secs` (600 s). It deletes fetched but
unacknowledged blobs after the queue's retention period (14 days for release
clients), every blob after 90 days, queues 24 hours after deactivation, queues
past their expiry, and queues with no deposit or fetch for 30 days
([S16 §10](../specs/16-mailbox-server.md)). When free pages reach
`vacuum_threshold_percent`, it runs VACUUM, which blocks requests while it runs.
On a large database, raise the threshold so VACUUM runs rarely.

## 5. Keys

### 5.1 Operator seed

The seed is the private half of `operator_id`. The server reads it once at
startup.

To rotate it:

```sh
sudo sh -c 'umask 077; openssl rand -hex 32 > /etc/najwa-mailbox/operator-seed.new'
sudo chown root:najwa-mailbox /etc/najwa-mailbox/operator-seed.new
sudo chmod 0440 /etc/najwa-mailbox/operator-seed.new
sudo mv /etc/najwa-mailbox/operator-seed.new /etc/najwa-mailbox/operator-seed
sudo systemctl restart najwa-mailbox
curl -s http://127.0.0.1:8080/v1/attestation
```

Publish the new `operator_id` through the channel you used before. Back up the
new seed (§2.2). The release client does not check attestations, so rotation
does not interrupt messaging.

### 5.2 Onion keys

The onion address is derived from the key in `/var/lib/tor/najwa-mailbox/`.
Changing the key creates a new address. Clients store the address with each
queue, so treat a key change as retiring this mailbox and opening a new one
(§7).

### 5.3 Capability values

Capabilities in the database and in backups are bearer secrets. Anyone holding a
fetch capability can read and delete that queue. Never copy them into logs,
tickets or reports.

## 6. Changing policy

Edit `/etc/najwa-mailbox/mailbox.toml` and restart the service. The server
rejects unknown keys, so a typo stops it at startup; read the journal after
every restart. A restart lets in-flight requests finish, then resets rate-limit
windows and drops outstanding proof-of-work challenges; clients retry.

- Quotas and blob limits apply from the next deposit. Each queue's
  `retention_days` and `max_message_size` are fixed when it is registered.
- Hold and jitter values apply to blobs deposited after the restart; stored
  blobs keep their release times.
- The batching attestation is signed again on the first status request after
  the restart.

## 7. Retirement

Retiring a mailbox stops new registrations while existing queues keep working
([S16 §13](../specs/16-mailbox-server.md)):

1. Pick a shutdown date and announce it through the channel your users trust.
   Ask them to add another mailbox in the app, make it primary, and give
   contacts time to receive the new routes before they remove this mailbox.
   Allow at least 30 days so users who are offline can return. If the mailbox
   is in the [public mailbox list](../../MAILBOXES.md), remove its entry by pull
   request when you set the date in step 2, so new users stop choosing it.
2. Set the date in `/etc/najwa-mailbox/mailbox.toml` as a Unix time, under
   `[server]`, and restart:

   ```sh
   date -u -d 2027-01-31T00:00:00Z +%s     # prints 1801353600
   sudoedit /etc/najwa-mailbox/mailbox.toml # [server] retire_at = 1801353600
   sudo systemctl restart najwa-mailbox
   curl -s http://127.0.0.1:9090/v1/health  # "server_status":"Retiring","retire_at":...
   ```

   The journal shows `server is Retiring; new registrations get 503`. New
   registrations now get `503`; deposits, fetches and prekeys work as before.
   `/v1/status` reports `server_status` and `retire_at` to queue owners, but
   the release client does not act on them yet, so the announcement is still
   what moves users. To cancel, remove the line and restart.
3. Keep the server running and monitored until that date. It does not stop by
   itself at `retire_at`.
4. Stop the mailbox and Tor: `sudo systemctl stop najwa-mailbox tor`.
5. Destroy the database files, every backup, the operator seed and the onion
   service directory. `shred -u` helps only on filesystems that overwrite in
   place; on SSDs and copy-on-write filesystems, rely on full-disk encryption
   and destroy its key.

Nothing in the protocol can prove remote deletion to users, and copies you do
not control are out of reach.

## 8. Incident response

### 8.1 Host compromise

Take the server offline. Assume the attacker has the database, logs, operator
seed and onion keys. With the onion keys they can run a server at your
address. Do not bring the address back: deploy a new host with a new onion key
and a new seed, announce the change, and tell users to move their queues
(§7 step 1). Blob contents stay encrypted; the metadata in §8.4 does not.

### 8.2 Operator seed exposed

The attacker can sign attestations as you. Rotate the seed (§5.1) and announce
the new `operator_id`. Messaging is unaffected.

### 8.3 Onion keys exposed

The attacker can publish a competing service at your address and receive
deposits from clients that reach it. Retire the address (§7) and move users to
a new one.

### 8.4 Database loss or compelled disclosure

For loss or corruption, restore per §2.3 and tell users the time window of
possible loss.

If you must disclose data, know what the database holds:

- every fetch and deposit capability and their pairing, type, expiry and
  registration settings;
- encrypted blobs with deposit, release and first-fetch times, sizes and the
  depositing capability;
- prekey bundles: public keys, signatures and manifests, and every one-time
  prekey ID ever uploaded per queue;
- last-activity and deactivation times.

It holds no key that decrypts a blob, no user names and no client network
addresses. The 90-day cap limits how far back the live database reaches;
backups may reach further.

## 9. Things not to do

- Expose the API or health port outside the host.
- Replace volumes, the database or Tor state to get a failing server to start.
- Start a second server on a copy of the database.
- Publish logs, seeds, capabilities or database files in tickets.
- Set `refuse_last_opk = false` or remove registration proof-of-work.
- Treat a health check or a signed attestation as proof of delivery or of honest
  operation.
