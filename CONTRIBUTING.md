# Contributing to Najwa

Start with the [architecture](docs/development/architecture.md), the
[build instructions](docs/development/building.md) and the
[release status](RELEASE-READINESS.md). Fixes to usability, delivery reliability
and documentation are welcome. Open an issue to discuss protocol changes or new
platforms before starting a large implementation.

## Issues and pull requests

Open an issue that describes the problem and how to reproduce it. In a pull
request, explain the resulting behavior, any limitations, and the checks you ran.
Add a focused regression test when the behavior warrants one. Screenshots help
with interface changes; use disposable identities and redact private data.

Keep `Cargo.lock` and `apps/desktop/package-lock.json` committed. Avoid unrelated
dependency updates and formatting changes. Run the
[relevant checks](docs/development/testing.md), and keep the documentation in
line with what the code does.

To list a public mailbox, follow [Adding a mailbox](MAILBOXES.md#adding-a-mailbox).

## Protocol and format changes

Changes to key derivation labels, wire formats, key identifiers, schema versions,
recovery or locking break compatibility with existing profiles and peers. They
need an explicit compatibility review. Update the specification, the registries
in `docs/reference/` and the test vectors in the same change. Versioned
cryptographic strings are compatibility data: never change one for cosmetic reasons.

Code comments cite specification sections such as `S07 §2.3`. Spec and section
numbers are stable identifiers: do not renumber them. A removed top-level section
keeps its number with the title "Reserved"; new sections take the next free number.

## What not to commit

Never commit identities, recovery words or files, database files, browser tokens,
operator seeds, Tor state, build output or local test evidence. The ignore rules
reduce accidental inclusion; review the actual diff before you share it.
Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## License

Contributions are distributed under the repository's GPL-3.0-or-later license.
