#!/usr/bin/env bash
# S01 §5.1 — key material, nonces, salts, capabilities, tokens and identifiers
# come from the OS CSPRNG (`najwa_crypto::random` or `rand::rngs::OsRng`).
#
# `rand::thread_rng` is a userspace generator, only reseeded from the OS. S01
# §5.3 allows it for non-security randomness (scheduling jitter, shuffling), so
# this fails on any use in production code outside the files listed in
# ALLOWED. Their uses were reviewed as non-security: jitter, shuffles, random
# selection, and cover filler that is encrypted under the envelope. A new key
# or token in an allowed file is not caught: review those by hand.
#
# Scans crates/ and apps/local-web/. Test code is skipped: tests/ and benches/
# directories, *tests.rs files, and items under `#[cfg(test)]`.
#
# Usage:  scripts/check-os-rng.sh        (run from anywhere)
# Exit:   0 = clean, 1 = a userspace RNG was found in production code.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

PATTERNS='thread_rng|ThreadRng|rand::random|SmallRng|StdRng'

ALLOWED='crates/najwa-core/src/cover/scheduler.rs
crates/najwa-core/src/fetch_plan.rs
crates/najwa-core/src/pipeline.rs
crates/najwa-core/src/receive.rs
crates/najwa-core/src/send.rs
crates/najwa-mailbox/src/db/mod.rs
crates/najwa-protocol/src/mailbox/http.rs'

hits="$(
    cd "$ROOT"
    find crates apps/local-web -name '*.rs' \
        -not -path '*/target/*' -not -path '*/tests/*' -not -path '*/benches/*' \
        -not -name '*tests.rs' \
        | sort | grep -vxF "$ALLOWED" \
        | xargs awk -v pat="$PATTERNS" '
            FNR == 1 { pending = 0; skip = 0 }
            # The item after #[cfg(test)]: one line if it ends in ";", else
            # up to its matching close brace.
            pending && /^[[:space:]]*#\[/ { next }
            pending {
                pending = 0
                if ($0 ~ /;[[:space:]]*$/ && $0 !~ /\{/) next
                skip = 1; depth = 0; opened = 0
            }
            skip {
                o = gsub(/\{/, "{"); c = gsub(/\}/, "}")
                depth += o - c; if (o) opened = 1
                if (opened && depth <= 0) skip = 0
                next
            }
            /^[[:space:]]*#\[cfg\(test\)\]/ { pending = 1; next }
            $0 ~ pat { print FILENAME ":" FNR ":" $0 }
        '
)"

if [ -n "$hits" ]; then
    echo "S01 §5.1 VIOLATION — userspace RNG in production code:" >&2
    echo "$hits" >&2
    echo >&2
    echo "Use najwa_crypto::random or rand::rngs::OsRng. If the value is only" >&2
    echo "scheduling jitter or a shuffle (S01 §5.3), add the file to ALLOWED." >&2
    exit 1
fi

echo "S01 §5.1 OK — no userspace RNG in production code outside the reviewed files"
