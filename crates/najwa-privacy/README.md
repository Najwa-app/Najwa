# najwa-privacy

Local profile erasure for the app. `lifecycle::emergency::begin` copies the
encrypted identity record into a durable `wipe.pending` marker before anything
is removed. `erase` then deletes that identity's device key from the platform
key store and overwrites and deletes every profile file except the lease and
the marker, removing the marker last. While the marker exists the profile stays
in the erasing state and cannot be unlocked; erasure can be retried. The caller
drains operations and closes every key owner first. Erasure needs no network.

Implements the local erasure part of [S13](../../docs/specs/13-privacy-hardening.md).

Entry points: `lifecycle::emergency::{begin, erase, PENDING_FILE}`, called by
`apps/local-web`.

License: GPL-3.0-or-later.
