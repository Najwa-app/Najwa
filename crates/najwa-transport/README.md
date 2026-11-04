# najwa-transport

The only network path. Runs an embedded Arti Tor client, sends HTTP/1.1 to
`.onion` addresses only (no clearnet fallback and no system DNS), isolates
circuits per mailbox, contact, cover and one-shot operation, takes clock
offsets from the Tor consensus, and configures bridges and pluggable
transports through Arti. The app accepts plain, obfs4 and snowflake bridge
lines and runs the bundled lyrebird helper for obfs4 and snowflake.

Implements [S04](../../docs/specs/04-transport.md).

Entry points: `tor::TorTransport` (`new`, `bootstrap`), `config::TorConfig`,
`http` (onion-only requests and URL validation), `circuit::CircuitIsolation`,
`dns_leak` (self-test).

License: GPL-3.0-or-later.
