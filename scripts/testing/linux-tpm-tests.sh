#!/bin/sh
# Isolated software TPMs and a disposable Secret Service. No host device/keyring.
set -eu
test_root=$(mktemp -d)
export HOME="$test_root/home"
export XDG_RUNTIME_DIR="$test_root/runtime"
mkdir -p "$HOME" "$XDG_RUNTIME_DIR" "$test_root/tpm1" "$test_root/tpm2"
chmod 700 "$HOME" "$XDG_RUNTIME_DIR"
cleanup() {
    for pid_file in "$test_root/tpm1.pid" "$test_root/tpm2.pid"; do
        if [ -f "$pid_file" ]; then kill "$(cat "$pid_file")" 2>/dev/null || true; fi
    done
    rm -rf "$test_root"
}
trap cleanup EXIT HUP INT TERM
swtpm socket --tpm2 --tpmstate dir="$test_root/tpm1" \
    --server type=tcp,port=2321,bindaddr=127.0.0.1 \
    --ctrl type=tcp,port=2322,bindaddr=127.0.0.1 \
    --flags not-need-init,startup-clear --pid file="$test_root/tpm1.pid" --daemon
swtpm socket --tpm2 --tpmstate dir="$test_root/tpm2" \
    --server type=tcp,port=2323,bindaddr=127.0.0.1 \
    --ctrl type=tcp,port=2324,bindaddr=127.0.0.1 \
    --flags not-need-init,startup-clear --pid file="$test_root/tpm2.pid" --daemon
# Disposable, synthetic keyring password; the container cannot access host keys.
keyring_env=$(printf '%s' 'najwa-synthetic-test-only' | gnome-keyring-daemon --unlock --components=secrets)
eval "$keyring_env"
export GNOME_KEYRING_CONTROL
cargo test --locked -p najwa-identity --features linux-tpm --lib simulator_ -- --ignored --test-threads=1
cargo test --locked -p najwa-identity --features linux-tpm
cargo clippy --locked -p najwa-identity --features linux-tpm --all-targets -- -D warnings
cargo test --locked -p najwa-identity
