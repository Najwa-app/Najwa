# Release status

Najwa 0.1.0, public beta. Last reviewed 2026-10-29.

Najwa is a desktop messenger: a native service on your computer holds your
identity, keys, Tor client and encrypted database, and serves the interface to
your browser on `127.0.0.1`. It supports one identity per profile, one-to-one
conversations and independent store-and-forward mailboxes. You need a mailbox
address from a mailbox operator; none is bundled. The
[public mailbox list](MAILBOXES.md) has addresses operators offer to anyone.

## Platforms

| Platform | Package | Device-key protection | Status |
| --- | --- | --- | --- |
| Windows x64 | `.zip` with `Najwa.exe` | TPM 2.0; Windows key storage after approval | Preview. Tested with a physical TPM. |
| Linux x64 | `.tar.gz` with `Najwa` | TPM 2.0 through `/dev/tpmrm0`; Secret Service keyring after approval | Preview. Tested on Ubuntu with Secret Service. Not yet tested with a physical TPM. |
| macOS (Apple Silicon, Intel) | `.zip` with `Najwa.app` | Secure Enclave; Keychain after approval | Untested preview. Built and checked by CI on GitHub's Mac runners, but not yet tested on Mac hardware or with a Secure Enclave. Ad-hoc signed only and not notarized, so macOS blocks it until you allow it. |
| Android, iOS | — | — | Not available. |

On every platform, hardware protection is the default. If the hardware is
missing or unusable, Najwa offers the operating system's key storage only after
you tick an approval box. The approval applies to that identity only, is shown in
the app, and is remembered. It never unlocks an identity whose hardware key is
lost; that needs the recovery kit. See
[S02 §17](docs/specs/02-identity-key-protection.md).

## What has been tested

- **By hand, on development machines:** creating contacts while the other person
  was offline, sending messages and replies, persistence across restarts,
  automatic retry, identity protection with a physical Windows TPM, and a
  256 MiB file transfer over the public Tor network.
- **Mailbox, 2026-10-29:** a mailbox installed on Ubuntu 26.04, by hand and with
  the one-command installer, checked over Tor; two test peers exchanging
  messages through it, including one queued while the recipient was locked.
- **Automated, 2026-10-29:** the Rust workspace tests, the interface build, 85
  browser checks against a mocked native service, and the packaging-policy and
  checksum tests.
- **CI:** every push to `main` runs the Linux test suite. Every version tag
  builds the Windows, Linux and both macOS packages, runs the profile-guard
  tests on each, and drafts the GitHub release. The Linux job also tests the
  missing-TPM approval path. CI runners have no TPM or Secure Enclave.

Najwa has not had an independent security audit. Before distributing a package,
run the [release validation](docs/development/testing.md#release-validation)
checks on that exact package.

## Distribution

Packages are on the [releases page](https://github.com/Najwa-app/Najwa/releases).
They are **unsigned**. Each package comes with a `.sha256` file from the same
build; [verify the download](docs/security/supply-chain.md#6-verifying-a-download)
before running it. A general public binary release waits for:

- code signing (Windows publisher signing; macOS Developer ID and notarization);
- a refreshed [dependency review](docs/security/dependencies.md).

## Not in this release

- Group conversations and channels.
- Linked devices (one identity used on several devices at once).
- Android and iOS apps.
- Mailbox discovery inside the app. The [public mailbox list](MAILBOXES.md) is
  maintained by hand in this repository.
- A hosted web version.
- Message-history backup or export.

The `local-demo` harness is a developer tool, not a supported app.

## Known limitations

- **Delivery is slow compared with ordinary messengers.** Everything travels over
  Tor. Files up to 256 MB are allowed; 10 MB or less is recommended.
- **Each person must open and unlock Najwa for their part.** The sender can close
  the app once a message shows as deposited; the recipient gets it the next time
  they unlock, as long as the mailbox still holds it (at most 90 days).
- **Mailbox operators see traffic patterns.** They cannot read messages, but they
  see when and how much each capability is used. Responsive mode, the default,
  reveals more about send timing than Timing privacy. Najwa does not protect
  against an observer who can watch the whole network. See the
  [threat model](docs/understanding/threat-model.md).
- **Recovery restores the identity only.** The recovery kit does not contain
  contacts or messages.
- **Long gaps can break one direction of a chat.** If your app misses an entire
  run of a contact's messages (for example, the mailbox deleted them after
  90 days), later messages from that contact cannot be read and are dropped.
  Re-adding the contact restores the conversation. See
  [S08](docs/specs/08-messaging-service.md).
- **Files and timers.** Sending a file requires the conversation's
  disappearing-message timer to be off. File types Najwa cannot sanitize are
  refused.
- **Deleting removes the chat on both sides.** When you delete a contact, Najwa
  also removes the conversation from their Najwa once their app receives the
  notice. The same applies the other way round: a contact who deletes you
  removes your copy, unless you blocked them first. Neither side can remove
  copies the other made outside Najwa.
- **Erasing is local.** Erasing a profile cannot remove copies held by contacts,
  by mailboxes, or in backups you made yourself.
