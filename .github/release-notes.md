**Najwa {VERSION}, public beta.** A private one-to-one messenger for your
computer: no phone number or account, everything over Tor, and messages that
wait in independent mailboxes while you are offline. Najwa has not had an
independent security audit. Read the
[release status](https://github.com/Najwa-app/Najwa/blob/{TAG}/RELEASE-READINESS.md)
and the [threat model](https://github.com/Najwa-app/Najwa/blob/{TAG}/docs/understanding/threat-model.md)
before relying on it for anything sensitive.

### Download

| Your computer | File |
| --- | --- |
| Windows, 64-bit x86 | `najwa-windows-x64-….zip` |
| Linux, 64-bit x86 | `najwa-linux-x64-….tar.gz` |
| Mac with Apple silicon, macOS 13 or later (untested preview) | `najwa-macos-arm64-….zip` |
| Mac with Intel, macOS 13 or later (untested preview) | `najwa-macos-x64-….zip` |

Each file has a `.sha256` file next to it.
[Check your download](https://github.com/Najwa-app/Najwa/blob/{TAG}/docs/security/supply-chain.md#6-verifying-a-download)
before opening it.

### First start

1. Extract the whole package and open Najwa. The packages are not signed: on
   Windows select **More info**, then **Run anyway**; on a Mac open **System
   Settings → Privacy & Security** and select **Open Anyway**.
2. Create your identity with a passphrase and save your recovery kit.
3. Add a mailbox from the
   [public mailbox list](https://github.com/Najwa-app/Najwa/blob/{TAG}/MAILBOXES.md),
   then invite someone.

The [getting started guide](https://github.com/Najwa-app/Najwa/blob/{TAG}/docs/getting-started.md)
walks through each step. What is in this version: the
[changelog](https://github.com/Najwa-app/Najwa/blob/{TAG}/CHANGELOG.md).
