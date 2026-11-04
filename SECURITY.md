# Security policy

Najwa is beta software and has not had an independent security audit. Before
relying on it, read the [threat model](docs/understanding/threat-model.md), the
[security properties](docs/security/properties.md) and the
[dependency assessment](docs/security/dependencies.md).

## Supported scope

Reports are in scope for:

- the native service and browser interface (`apps/local-web`, `apps/desktop`);
- the Rust crates in this repository, including the `najwa-mailbox` server;
- the protocol as specified in [docs/specs](docs/SPECS-VERSION.md);
- the packaging scripts and the published preview packages.

The `local-demo` harness is a developer tool. Report issues in it, but it is not
supported for real identities.

## Reporting a vulnerability

Use **Security → Report a vulnerability** on the repository to send a private
report. If that option is unavailable, open a public issue asking for a private
contact channel. Do not include exploit details, logs or identifying data in the
public issue. There is no dedicated security email address and no committed
response time yet.

Include:

- the affected commit or package checksum, and the platform;
- prerequisites and reproduction steps;
- the impact, and a proposed fix if you have one.

Use synthetic identities. Never send a real recovery kit, passphrase, private key
or live profile.

## Handling

Maintainers acknowledge the report, reproduce it, assess the affected platforms,
coordinate a fix and publish an advisory when appropriate. Preview packages are
unsigned; see [release status](RELEASE-READINESS.md) for how to verify a download.
