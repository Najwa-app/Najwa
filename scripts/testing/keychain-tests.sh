#!/bin/sh
# Run through keychain.Dockerfile in its private D-Bus session, with synthetic keys.
set -eu
export HOME=/tmp/najwa-keychain-home
export XDG_RUNTIME_DIR=/tmp/najwa-keychain-runtime
mkdir -p "$HOME" "$XDG_RUNTIME_DIR"
chmod 700 "$HOME" "$XDG_RUNTIME_DIR"
eval "$(printf '%s' 'synthetic-test-password' | gnome-keyring-daemon --unlock --components=secrets)"
export NAJWA_REQUIRE_KEYCHAIN=1
export NAJWA_KEYCHAIN_TEST_SANDBOX=1
unset NAJWA_DKM_FILE
cargo test --locked -p najwa-identity --test platform_keychain -- --ignored --test-threads=1 --nocapture
