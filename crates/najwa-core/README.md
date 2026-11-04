# najwa-core

The messaging service. Commits each outgoing message to a durable outbox in one
transaction with the advanced ratchet state and delivers queued frames through
mailboxes. Runs the receive path: fetch, envelope decryption, ratchet processing,
deduplication, atomic commit, mailbox acknowledgement, delivery ACKs, read
receipts and session repair. Also schedules cover traffic, runs disappearing-message
timers and chunks, sanitizes and reassembles file transfers.

Implements [S08](../../docs/specs/08-messaging-service.md), [S10](../../docs/specs/10-cover-traffic.md),
[S12](../../docs/specs/12-disappearing-messages.md) and the transfer part of [S11](../../docs/specs/11-file-transfer-sanitization.md).

Entry points: `service::MessagingService` (`enqueue_message_with_flags`, `drive_outgoing`,
`poll_messages`), `storage::CoreStorage`, `cover::CoverTrafficScheduler`,
`disappearing::VolatileKeyCache`, `filetransfer::FileTransferManager`.

License: GPL-3.0-or-later.
