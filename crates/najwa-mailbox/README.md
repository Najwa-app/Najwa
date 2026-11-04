# najwa-mailbox

The store-and-forward mailbox server, run by an operator behind a Tor onion
service. It holds encrypted blobs it cannot read, keyed by unlinkable deposit
and fetch capabilities. It registers and deactivates capabilities, issues and
checks proof-of-work challenges, accepts deposits within quotas, releases
blobs for fetch and deletes them on acknowledge, serves prekey bundles, and
applies retention, request-size and response-timing limits.

Implements [S16](../../docs/specs/16-mailbox-server.md). Deployment and operation: [deployment](../../docs/server/deployment.md),
[operations](../../docs/server/operations.md).

Entry points: the `najwa-mailbox` binary (`najwa-mailbox [mailbox.toml]`);
the library's `api::router`, `config::Config`, `db::Database` and
`state::AppState`, shared with the integration tests.

License: GPL-3.0-or-later.
