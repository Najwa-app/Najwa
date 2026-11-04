<p align="center"><img src="logo.png" alt="Najwa" width="160" /></p>

# Najwa (نجوى)

**Private messaging that protects who you talk to, not only what you say.**

Najwa is a one-to-one messenger for your computer. There is no phone number, no
email and no account. Messages travel over Tor through independent mailboxes, so
you and your contact never need to be online at the same time, and your contact
list and message history stay on your computer.

**[Download](https://github.com/Najwa-app/Najwa/releases)** ·
[Getting started](docs/getting-started.md) ·
[Find a mailbox](MAILBOXES.md) ·
[Run a mailbox](docs/server/quick-start.md) ·
[FAQ](docs/understanding/faq.md)

> **Public beta.** Najwa has not had an independent security audit, and its
> packages are unsigned. Read the [release status](RELEASE-READINESS.md) and the
> [threat model](docs/understanding/threat-model.md) before relying on it for
> anything sensitive.

## Why Najwa

Most encrypted messengers protect *what* you say. Around each message they still
leave a trail: a phone number or account that ties you to your name, and a
central server that sees who writes to whom, when and how often. That metadata
can reveal as much as the messages. Najwa is built to leave as little of it as
possible.

- **No phone number, email or account.** Your identity is a key pair generated
  on your computer. Nothing links it to who you are unless you tell someone.
- **No central server.** Messages wait in mailboxes run by independent
  operators, and anyone can run one. A mailbox holds sealed, padded parcels: it
  cannot read them, see names or learn your identity key. Each mailbox sees a
  different key for you, so mailboxes cannot match you up by key.
- **Tor for everything.** Every connection goes to a Tor onion service, with no
  fallback to the ordinary internet. Neither mailboxes nor contacts learn your
  IP address.
- **Your data stays with you.** Contacts and history exist only on your
  computer, encrypted, and open only with your passphrase together with the
  computer's security chip (TPM 2.0 or Secure Enclave). The disk alone opens
  nothing.
- **It can hide when you write.** Cover traffic runs all the time. In *Timing
  privacy* mode your real messages take the place of dummy ones, so someone
  watching your connection cannot tell when you send.
- **Files without hidden details.** Pictures are re-encoded, and location,
  author and other hidden details are removed from every file before it
  leaves. Najwa refuses files it cannot clean.
- **One fixed cipher suite.** No algorithm negotiation, so nothing to downgrade.

In short: most encrypted messengers protect what you say. Najwa also protects
who you are and whom you talk to, and in Timing privacy mode, when you talk.

## Start in three steps

1. **Download Najwa** for Windows, Linux or macOS from the
   [releases page](https://github.com/Najwa-app/Najwa/releases),
   [check the download](docs/security/supply-chain.md#6-verifying-a-download)
   against its `.sha256` file, extract it and open it. Tor is included; there is
   nothing else to install. macOS packages are an untested preview.
2. **Create your identity and add a mailbox.** Choose a passphrase, save your
   recovery kit, and paste a mailbox address from the
   [public mailbox list](MAILBOXES.md).
3. **Invite someone.** Send them your invitation link or QR code through a
   channel you trust. Once they accept, compare safety numbers and start
   writing.

The [getting started guide](docs/getting-started.md) walks through each step.

## What you get

- **Recovery kit.** 24 recovery words and an encrypted recovery file restore
  your identity on a new computer.
- **Signed invitations and safety numbers.** Comparing safety numbers over
  another channel proves you reached the right person.
- **Conversations.** Search, quoted replies, delivery and read receipts, and
  disappearing-message timers per conversation.
- **Files up to 256 MB,** cleaned before sending and transferred in resumable
  parts. Files of 10 MB or less work best over Tor.
- **Reliable delivery.** Up to eight mailboxes, automatic retries, and a clear
  "deposited in mailbox" mark that tells you when you can close the app.
- **Delete on both sides.** Deleting a contact also removes the conversation
  from their Najwa.
- **Bridges** (obfs4 and Snowflake) where Tor is blocked.
- **Your choice of speed or timing privacy.** *Responsive* (the default) sends
  at once; *Timing privacy* paces sends with cover traffic.

## Security at a glance

| What is protected | From whom | How |
| --- | --- | --- |
| What you say | everyone except you and your contact | X3DH and the Double Ratchet: a new key for every message, deleted after use, inside a second encryption layer for the mailbox |
| Who you are | mailboxes | no account; random capabilities instead of addresses; a different signing key for each mailbox |
| Where you are | mailboxes, contacts, the network | Tor onion services only |
| How long a message is | mailboxes, the network | padding to one of eleven sizes |
| When you send | someone watching your connection | Timing privacy mode and cover traffic |
| Past messages, if your keys leak later | anyone | forward secrecy |
| Your data on disk | someone who takes your computer | passphrase (Argon2id) plus the security chip |

**Najwa does not protect against** a compromised computer while Najwa is
unlocked, or anyone who learns your passphrase and recovery kit. It makes no
claim against an adversary who can watch traffic across much of the internet
and match timings over time. Mailbox operators can see when your app is online,
how many contact routes you have on their mailbox, and when each one is used.
The details are in the [threat model](docs/understanding/threat-model.md) and
the [security properties](docs/security/properties.md).

## Known limitations

- **Slower than ordinary messengers.** Everything travels over Tor, and Timing
  privacy holds each message for the next cover slot, about 30 seconds apart.
- **One-to-one only.** No groups, no voice or video calls, no linked devices,
  and no phone apps yet.
- **Contacts are added by invitation.** You exchange an invitation link or QR
  code privately; there is no lookup by phone number or name.
- **Read receipts are always on.**
- **No cloud copy.** History lives only on your computer. The recovery kit
  restores your identity, not your contacts or messages, and mailboxes keep
  undelivered messages for at most 90 days.
- **Classical cryptography.** Najwa does not protect against future quantum
  computers.

More are listed in the [release status](RELEASE-READINESS.md#known-limitations).

## Run a mailbox

Mailboxes hold people's encrypted messages while their app is closed. Every
independent mailbox gives people one more operator to choose from, and anyone
can run one. On a fresh Ubuntu 26.04 server:

```sh
curl -fsSL https://raw.githubusercontent.com/Najwa-app/Najwa/main/scripts/deployment/install-mailbox.sh -o install-mailbox.sh
sudo bash install-mailbox.sh
```

About 15 minutes later it prints your mailbox's address. Read the
[quick start](docs/server/quick-start.md) first; it also covers backing up the
keys. Then [list your mailbox](MAILBOXES.md#adding-a-mailbox) so others can use
it. The full [deployment](docs/server/deployment.md) and
[operations](docs/server/operations.md) guides cover other systems and
day-to-day running.

## Learn more and contribute

- **How it works:** [the design in plain language](docs/understanding/how-it-works.md),
  then the [protocol specifications](docs/SPECS-VERSION.md).
- **Security:** [threat model](docs/understanding/threat-model.md),
  [security properties](docs/security/properties.md),
  [cryptographic rationale](docs/security/crypto-rationale.md), and
  [reporting a vulnerability](SECURITY.md).
- **Build and contribute:** [building from source](docs/development/building.md)
  and [contributing](CONTRIBUTING.md).

The full documentation index is in [docs/README.md](docs/README.md).

## Repository layout

| Path | Contents |
| --- | --- |
| `apps/local-web` | The native service: profiles, local HTTP API, embedded browser UI |
| `apps/desktop` | Svelte browser interface served by the native service |
| `crates/` | Rust libraries (crypto, identity, storage, transport, protocol, core, sanitizer, privacy, FFI, CLI) and the `najwa-mailbox` server |
| `scripts/` | Build, packaging, deployment and test tooling |
| `docs/` | User, operator, developer and protocol documentation |

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
