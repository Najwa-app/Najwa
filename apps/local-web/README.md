# Najwa local service (`najwa-web`)

The native application. One process owns one profile: the identity and its
device key, the SQLCipher store, the embedded Tor client and the messaging
service. It serves the browser interface on `127.0.0.1` and exposes the
operations that interface uses. Release packages embed the interface in the
executable (`bundled-ui` feature), so the packaged app needs no Node, Rust,
Docker or launcher script.

## Running

```text
najwa-web [--profile DIRECTORY] [--assets DIRECTORY] [--port 1421] [--no-browser]
najwa-web --build-info
```

| Option | Effect |
| --- | --- |
| `--profile` | Profile directory. Default: the OS local application-data directory (below). |
| `--assets` | Serve the interface from a directory instead of the embedded copy. |
| `--port` | Loopback port. Default `1421`; `0` is refused. |
| `--no-browser` | Do not open the browser. |
| `--build-info` | Print a JSON description of the build (version, OS, architecture, embedded-UI digest, key-protection policy) and exit. The packager checks it. |

Default profile directories:

| OS | Path |
| --- | --- |
| Windows | `%LOCALAPPDATA%\Najwa\Najwa Web\data\profile` |
| Linux | `$XDG_DATA_HOME/najwaweb/profile` (normally `~/.local/share/najwaweb/profile`) |
| macOS | `~/Library/Application Support/org.Najwa.Najwa-Web/profile` |

From a source checkout on Windows, `scripts/local-web.ps1 [-Profile DIRECTORY] [-Port 1421] [-SkipBuild]`
builds the interface and a debug executable and runs it with external assets.
See [Building](../../docs/development/building.md).

## Behavior

- The process takes an exclusive lease on `owner.lock` in the profile. A second
  launch for the same profile opens the browser on the running instance and
  exits; with `--no-browser` it exits with an error.
- It binds the port only after it owns the profile, starts locked, and opens the
  browser with its random launch token in the URL fragment, which the browser
  does not send to the server. On Linux and macOS the token reaches the browser
  through `web-launch.html`, an owner-only redirect page in the profile, so it
  never appears in a process's arguments. A browser that has launched this
  profile before may also reach it through a strict, `HttpOnly` cookie scoped
  to `/api/bootstrap`.
- Every request must carry the exact `Host`, a matching `Origin` when present, and
  a same-origin fetch context (except the launch page's navigation to `/`). API calls also need the session token, and POST
  bodies need the expected content type. Responses carry `no-store`, a strict
  Content-Security-Policy and anti-framing headers.
- Each request carries the identity session and generation it was issued for.
  Lock, every identity operation (such as unlock) and erasure advance the
  generation, so requests issued earlier are rejected as stale.
- The profile locks after the configured idle time (default 300 seconds) and on
  Quit or Ctrl+C. Locking cancels and drains in-flight work before keys are dropped.
- Browser tabs on the same service share one identity. A different browser does
  not make a different identity; a different `--profile` does.

The HTTP surface is for this computer only. Do not expose it on another interface
or put it behind a reverse proxy. The operations are listed in the
[API reference](../../docs/reference/api-reference.md); the internals are in
[Architecture](../../docs/development/architecture.md).

## Features

`hardware-keystore` and `approved-software-fallback` are default features and the
build refuses to compile without both: hardware key protection is preferred and
OS key storage requires the user's explicit approval. `bundled-ui` embeds
`target/local-web-ui`, which `npm run web:build` produces.

## Tests

`tests/` holds the profile-guard, persistent-profile and live-messaging
integration tests. See [Testing](../../docs/development/testing.md) for what each
needs and proves.

License: GPL-3.0-or-later.
