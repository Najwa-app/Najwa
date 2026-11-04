# Local two-browser test harness

A development harness that connects the messenger interface to two separate
Rust peer processes (the `browser_peer` example in `najwa-ffi`) over real Tor.
Each peer generates a fresh in-memory identity and runs its own SQLCipher store,
embedded Arti client and cover schedule. The mailbox runs locally in Docker and
is reached through its onion address. The harness exercises real encrypted
messaging from a browser. It does not exercise credential dialogs, TPM or OS key
storage, recovery, the lock lifecycle or packaging; use the
[persistent app](../../local-web/README.md) and [Testing](../../../docs/development/testing.md)
for those.

Use only disposable identities and messages. Peer identities are never saved,
so a stopped run cannot be reopened. Do not host or deploy the runner.

## Boundary

The runner (`scripts/local-browser-demo.py`) binds only `127.0.0.1`. Every POST
must carry the exact `Host`, the matching `Origin`, a same-origin fetch context,
`Content-Type: application/json` and a random per-run token held only in memory
(`X-Najwa-Demo`). Requests carry the peer's session and generation; stale ones
are refused. Only an allowlist of messaging operations reaches the peer: no
passphrase, recovery, hardware or key-export operation exists. Static files are
confined to the asset directory. Responses are `no-store` and carry a CSP whose
`connect-src 'self'` applies only to this harness. Displayed messages are
plaintext in the browser, including over loopback HTTP.

The demo build (`local-demo/vite.config.ts`) replaces only the IPC adapter and
writes to `target/browser-demo-ui`. The normal builds do not include it.

## Start

1. Start the [Docker development mailbox](../../../scripts/deployment/ONION-DEVELOPMENT.md).
2. From `apps/desktop`, check and build the demo interface:

   ```powershell
   npx svelte-check --tsconfig local-demo/tsconfig.json
   npx vite build --config local-demo/vite.config.ts
   ```

3. From the repository root, build the peer and start two users:

   ```powershell
   ./scripts/native-cargo.ps1 -CargoArguments @('build','--locked','-p','najwa-ffi','--example','browser_peer')
   $demoOnion = (docker compose -f scripts/deployment/docker-compose.onion-dev.yml exec -T tor cat /var/lib/najwa-onion/hostname).Trim()
   python -u scripts/local-browser-demo.py --peer target/debug/examples/browser_peer.exe --assets target/browser-demo-ui --onion $demoOnion --output target/browser-demo-fresh
   ```

The output directory must not exist yet. Open Alice at `http://127.0.0.1:4181/`
and Bob at `http://127.0.0.1:4182/`, ideally in two different browsers. The
runner waits for both Tor clients, registers both users on the mailbox,
publishes their prekeys, exchanges a signed invitation and checks that both
sides compute the same safety number. Contacts still show as unverified until
the users verify them. The runner sends no chat messages.

Send a message from either window. It is queued locally at once and delivered
by the background outbox. Each peer checks its mailbox every two seconds after
the previous check finishes, and the development mailbox adds no hold or
jitter, so delivery time is mostly Tor and proof-of-work. Messages travel
through the Rust outbox, the Double Ratchet, the deposit envelope, Tor and the
Docker mailbox, and are decrypted by the other process.

To add a third, independent user, use a new output directory and a free port:

```powershell
python -u scripts/local-browser-demo.py --peer target/debug/examples/browser_peer.exe --assets target/browser-demo-ui --onion $demoOnion --output target/browser-demo-charlie --user "Charlie" --port 4183
```

With `--user` the runner does no mailbox registration or contact setup. Open
`http://127.0.0.1:4183/`, add the mailbox in Settings and exchange invitations
in the interface. `--onion` does not configure that user's mailbox.

Stop the runner with Ctrl+C. The output directory and Docker volumes remain.

## Automated Chrome and Firefox round trip

With the runner above still running, install the driver dependency in an
isolated environment and run the visible round trip from the repository root:

```powershell
python -m venv target/browser-demo-webdriver
target/browser-demo-webdriver/Scripts/python.exe -m pip install -r scripts/browser-demo-requirements.txt
target/browser-demo-webdriver/Scripts/python.exe -u scripts/show-local-browser-demo.py --output target/browser-demo-visible-fresh --keep-open
```

The driver opens Chrome (Alice) and Firefox (Bob) side by side with fresh
browser profiles, waits for contact setup, sends a message through Alice's
interface and waits for that exact text to arrive as an incoming message in
Bob's, then sends Bob's reply back the same way. Each text carries a fresh run
marker, so earlier messages cannot satisfy the test, and the sender's local echo
never counts as delivery. If a send is refused because its mailbox is paused,
the driver clicks the retry action in Settings once and resends the preserved
draft; it never retries after a timeout or an uncertain result.

`status.json` records progress. `proof.json` is written only after both
directions pass and records the browser names and versions. Screenshots and
page text record the displayed messages; they contain the plaintext test
messages. Selenium may download browser drivers into the output directory.
Without `--keep-open` the windows close after the test.

## Boundary checks

```powershell
python scripts/test-local-browser-demo.py
./scripts/native-cargo.ps1 -CargoArguments @('clippy','--locked','-p','najwa-ffi','--example','browser_peer','--no-deps','--','-D','warnings')
```

The Python tests check refusal of a wrong `Host`, `Origin`, token, fetch context
or content type, stale sessions and generations, operations outside the
allowlist, oversized requests and path traversal, and the CSP and `no-store`
headers.
