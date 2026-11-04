# najwa-cli

A development command-line tool that drives the identity and storage crates
directly. It creates, unlocks and checks an identity record and opens and
integrity-checks the encrypted database in a data directory. It has no network
commands and is not part of the packaged app.

Implements no specification of its own; it exercises
[S02](../../docs/specs/02-identity-key-protection.md) and
[S03](../../docs/specs/03-encrypted-storage.md) code paths.

Entry points: `najwa-cli identity create|unlock <data-dir> [--password-stdin]`,
`najwa-cli identity exists <data-dir>` and
`najwa-cli db open <data-dir> [--password-stdin]`.

`identity create` refuses a passphrase that fails the S02 §11.1 rule: fewer
than 12 characters, more than 1024 bytes, or too easy to guess (zxcvbn estimate
below 2^40, also with spaces removed). The error names the rule that failed and
adds zxcvbn's warning when it has one. Unlock accepts any existing passphrase.

License: GPL-3.0-or-later.
