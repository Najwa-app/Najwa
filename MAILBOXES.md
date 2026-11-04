# Public mailboxes

Najwa needs at least one mailbox to hold your messages while you are away. This
is a hand-maintained list of mailboxes whose operators offer them to anyone.
The app does not read this list. Copy an address from here into **Settings**
([Getting started §4](docs/getting-started.md#4-add-your-mailbox)).

## Before you pick one

- **Being listed is not an endorsement.** Reviewers check only that the mailbox
  works over Tor and that its attestation is signed by the operator ID shown.
  Nobody checks who runs it, where it runs, or what it logs.
- **An operator cannot read your messages,** but sees when and how much your
  queues are used, and can delete or withhold what it holds. See the
  [threat model](docs/understanding/threat-model.md).
- **One operator can run several addresses.** Each entry names the other listed
  mailboxes its operator runs, but nobody can verify that. Adding two
  mailboxes from operators you trust keeps you reachable if one fails.
- **You and your contacts do not need the same mailbox.** Your contacts deposit
  to yours, and you deposit to theirs.
- **Release timing** is how long a mailbox holds each message before it can be
  fetched. A hold (for example 30 / 300 / 60 seconds) makes it harder for
  someone watching the server's network to match a message's arrival with its
  pickup, and delays every message by up to that long. It hides nothing from
  the operator. See [Deployment §7.1](docs/server/deployment.md#71-release-timing-hold-and-jitter).

## Listed mailboxes

<table>
  <thead>
    <tr><th align="left">Mailboxes</th></tr>
  </thead>
  <tbody>
    <tr>
      <td>
        <strong>Najwa beta</strong><br>
        <code>arf6xaulabjywcqrkbdiswlwtr5o24p3533lx2jrxpscdtztulymbuad.onion</code><br>
        Release: 0 / 0 / 0 s <sub>(hold min / max / jitter)</sub> · <a href="https://github.com/Najwa-app/Najwa/issues">issues</a> · Listed: 2026-10-29<br>
        Jurisdiction: not stated · Provider: not stated
        <details>
          <summary>Operator ID and limits</summary>
          Operator ID: <code>VNSqMhH59s8zWj8gKGvpSCgVsq+r4nUWM3ngRYLUqb8=</code><br>
          Per queue: 4,096 messages, 512 MiB · Proof of work: difficulty 20–24<br>
          Same operator as: none
        </details>
      </td>
    </tr>
  </tbody>
</table>

## Adding a mailbox

1. Set the mailbox up with the [quick start](docs/server/quick-start.md) or the
   full [deployment guide](docs/server/deployment.md). It must run
   `najwa-mailbox` from this repository, keep `max_blob_size_bytes` at 262144
   or more (release clients need it), and keep
   `registration_always_requires_pow = true`.
2. Collect its values. The installer prints the address and operator ID, and
   `cat /var/lib/najwa-install/summary.txt` shows them again. On a manual
   install, `curl -s http://127.0.0.1:8080/v1/attestation` on the server shows
   both, with the jurisdiction and provider it publishes. The rest is in
   `/etc/najwa-mailbox/mailbox.toml`:

   | Entry | Configuration |
   | --- | --- |
   | Release | `[batching]` `min_hold_secs` / `max_hold_secs` / `jitter_secs` |
   | Jurisdiction, Provider | `[attestation]` `jurisdiction`, `infrastructure_provider`; "not stated" when empty |
   | Per queue | `[quotas]` `max_messages_per_capability`, `max_storage_per_capability_mb` |
   | Proof of work | `[pow]` `min_difficulty`–`max_difficulty` |

3. Open a pull request that adds this row to the table, just before
   `</tbody>`, with the capitalized parts replaced:

   ```html
       <tr>
         <td>
           <strong>SHORT NAME</strong><br>
           <code>ADDRESS.onion</code><br>
           Release: MIN / MAX / JITTER s <sub>(hold min / max / jitter)</sub> · <a href="LINK OR mailto:EMAIL">contact</a> · Listed: YYYY-MM-DD<br>
           Jurisdiction: JURISDICTION · Provider: PROVIDER
           <br><strong>Notes:</strong> ANYTHING ELSE USERS SHOULD KNOW; DELETE THIS LINE OTHERWISE
           <details>
             <summary>Operator ID and limits</summary>
             Operator ID: <code>OPERATOR ID</code><br>
             Per queue: MESSAGES messages, MIB MiB · Proof of work: difficulty MIN–MAX<br>
             Same operator as: NAMES OF YOUR OTHER LISTED MAILBOXES, OR none
           </details>
         </td>
       </tr>
   ```

   Use a short name that is not already listed.

By listing a mailbox, you agree to:

- back up the operator seed and onion keys
  ([Operations §2](docs/server/operations.md#2-backup-and-restore));
- answer problem reports at the contact you gave;
- update your entry by pull request when its release timing or limits change;
- when you retire it, follow [Operations §7](docs/server/operations.md#7-retirement):
  pick a shutdown date at least 30 days away, set it as `retire_at`, remove your
  entry by pull request that day, and keep the mailbox running until the date.

### Review

A reviewer runs the protocol probe from a repository checkout:

```sh
cargo run --locked -p najwa-protocol --example onion_mailbox_probe -- <address>.onion target/onion-probe-tor
```

It must end with `PASS`, and the operator ID, jurisdiction and provider it
prints must match the entry (empty for "not stated"). The probe registers a
throwaway queue, deposits, fetches and acknowledges one blob, then deactivates
the queue.

## Removal

An entry is removed when:

- its operator asks, by pull request or issue;
- the probe fails on two checks at least 7 days apart;
- its operator ID changes without a pull request explaining why;
- a problem report gets no answer at the listed contact within 30 days.

Removal from this list changes nothing for people already registered there;
the mailbox keeps working until its operator stops it.
