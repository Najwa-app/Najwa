#!/usr/bin/env bash
# S04 §6.1 — no crate may resolve a hostname through the system resolver.
#
# Najwa is Tor-only: every hostname must be handed to embedded Arti, which
# resolves it inside the Tor network. A single `lookup_host`/`to_socket_addrs`
# anywhere in the workspace hands the name to the OS resolver instead, telling
# the local network/ISP what this host is doing — the exact disclosure the
# whole transport design exists to prevent.
#
# This scans every crate under crates/ and every app under apps/ on purpose
# (S04 §6.3): a per-crate test catches only its own crate. Build output
# (target/) and node_modules/ are skipped.
#
# Usage:  scripts/check-no-clearnet-dns.sh        (run from anywhere)
# Exit:   0 = clean, 1 = a forbidden resolver call was found.
#
# A line may opt out with a trailing `dns-audit-allow` comment — use it only
# where the name appears as data (docs, this script's own patterns, a test that
# scans for the string), never to permit a real call.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# System-resolver entry points. `TcpStream::connect("host:port")` also resolves,
# but is not greppable without false positives on SocketAddr args — the Tor-only
# transport boundary (S04 §2) is what rules that out, and any new direct socket
# code should be reviewed against it.
PATTERNS='lookup_host|to_socket_addrs|ToSocketAddrs|getaddrinfo|trust_dns|hickory_resolver'

hits="$(grep -rnE "$PATTERNS" "$ROOT/crates" "$ROOT/apps" --include='*.rs' \
    --exclude-dir=target --exclude-dir=node_modules | grep -v 'dns-audit-allow' || true)"

if [ -n "$hits" ]; then
    echo "S04 §6.1 VIOLATION — system-resolver call(s) found:" >&2
    echo "$hits" >&2
    echo >&2
    echo "Hand the hostname to the Tor transport instead. If the match is data" >&2
    echo "rather than a call, append a 'dns-audit-allow' comment on that line." >&2
    exit 1
fi

echo "S04 §6.1 OK — no system-resolver calls in $ROOT/crates or $ROOT/apps"
