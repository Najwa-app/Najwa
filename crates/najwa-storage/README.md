# najwa-storage

The encrypted client database. Opens SQLCipher with a 32-byte key, applies the
hardening pragmas and the schema, and stores contacts, ratchet state, prekeys,
mailboxes and capabilities, messages and the deduplication cache, the outbox
and ACK intents, read receipts, file-transfer progress and settings. Sensitive
columns get an additional per-field encryption layer. Multi-row changes that
must not diverge (ratchet state, message row and retry blob) commit in one
transaction.

Implements [S03](../../docs/specs/03-encrypted-storage.md).

Entry points: `database::SqliteStorage` (`open`, `open_in_memory`, `rekey`),
`encrypted_field`, `hardening`. The caller supplies the database key; the app
derives it from the unlocked identity in `najwa-ffi`.

License: GPL-3.0-or-later.
