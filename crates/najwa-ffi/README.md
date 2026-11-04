# najwa-ffi

The native boundary between the messaging crates and an application. It owns
one process-wide client state: the SQLCipher store, the embedded Tor client,
the messaging service, the cover runtime and the operation gate that lets lock
reject new work, drain in-flight work and then drop keys. It exposes that state
two ways: a 20-symbol C ABI (`include/najwa.h`) and the typed Rust
`desktop::DesktopClient` that `apps/local-web` calls.

Implements [S17](../../docs/specs/17-ffi-bindings.md). The typed desktop boundary is described in
[DESKTOP.md](DESKTOP.md).

Entry points: `desktop::DesktopClient` (`init`, `attach_identity`, `lock`,
`send_reply`, `sync`, `messages`, `displayed`, contact, mailbox, transfer and
preference operations); the `najwa_*` C functions with `najwa_free_string`;
the `desktop_peer` and `browser_peer` examples used by the live test harnesses.

License: GPL-3.0-or-later.
