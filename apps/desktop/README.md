# Najwa interface

The Svelte browser interface served by the native service in
[`apps/local-web`](../local-web/README.md). The built assets are static files;
identity, keys, Tor and storage live in the native service, so the bundle alone
cannot send or read messages and is not a hosted website.

## Layout

| Path | Contents |
| --- | --- |
| `src/` | Messenger components shared by both entry points. Each entry point's Vite config maps their `najwa:bridge` import to its own `bridge.ts`. |
| `local-web/` | The supported entry point (`LocalWeb.svelte`), the HTTP bridge to the native service, its Playwright tests (`local-web/tests/`) and the live Tor harnesses (`*.mjs`). |
| `local-demo/` | A disposable two-browser development harness; see its [README](local-demo/README.md). |

## Commands

Run from this directory with Node.js 24 after `npm ci`.

| Command | Result |
| --- | --- |
| `npm run web:build` | Type-checks `local-web/` and writes the interface to `../../target/local-web-ui`. The native `bundled-ui` build embeds that directory. |
| `npm run web:check` | Type check only. |
| `npm run web:test` | Playwright tests of the built interface in Microsoft Edge, with the native API mocked. Run `web:build` first. |

Full instructions: [Building](../../docs/development/building.md) and
[Testing](../../docs/development/testing.md).

License: GPL-3.0-or-later.
