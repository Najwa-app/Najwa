# najwa-protocol

Protocol logic for one-to-one conversations: signed invitations and contact setup,
safety numbers, X3DH with signed prekey manifests, the Double Ratchet and its
persisted state, the wire format (padding buckets, deposit envelopes, ACKs, read
receipts, control and file-transfer frames), pairwise pseudonyms, and the mailbox
client (registration, prekeys, deposit, fetch, acknowledge, proof-of-work).

Implements [S05](../../docs/specs/05-contact-establishment.md), [S06](../../docs/specs/06-key-agreement-ratchet.md),
[S07](../../docs/specs/07-message-format.md) and the client side of [S16](../../docs/specs/16-mailbox-server.md);
[S18](../../docs/specs/18-test-vectors.md) vectors are in `tests/`.

Entry points: `contact::accept::accept_contact`, `contact::fingerprint::safety_number`,
`x3dh::{x3dh_initiate, x3dh_respond}`, `ratchet::{ratchet_encrypt, ratchet_decrypt}`,
`message::types::WireMessage`, `message::envelope`, `prekey::manager::PrekeyManager`,
`mailbox::http::HttpMailboxClient` (implements `mailbox::client::MailboxClient`).

License: GPL-3.0-or-later.
