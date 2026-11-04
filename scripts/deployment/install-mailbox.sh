#!/usr/bin/env bash
# Najwa mailbox — one-command install on a fresh Ubuntu 26.04 server.
#
#   curl -fsSL https://raw.githubusercontent.com/Najwa-app/Najwa/main/scripts/deployment/install-mailbox.sh -o install-mailbox.sh
#   sudo bash install-mailbox.sh
#
# Runs harden-server.sh, installs Tor and the build tools, builds najwa-mailbox
# from source, creates the onion service and operator key, writes the template
# configuration and starts the service: docs/server/deployment.md §2–§10 with
# the template defaults. Safe to run again: it never replaces an existing key or
# configuration; a rerun rebuilds and restarts the server from current source.
# Quick start: docs/server/quick-start.md
set -euo pipefail

REPO="${NAJWA_REPO:-https://github.com/Najwa-app/Najwa.git}"
REF="${NAJWA_REF:-main}"
STATE=/var/lib/najwa-install
BUILD_HOME=/var/lib/najwa-build
ONION_DIR=/var/lib/tor/najwa-mailbox
CONF=/etc/najwa-mailbox/mailbox.toml
SEED=/etc/najwa-mailbox/operator-seed
BIN=/usr/local/bin/najwa-mailbox

say()  { echo; echo "==> $*"; }
fail() { echo "ERROR: $*" >&2; echo failed > "$STATE/status"; exit 1; }

[[ $(id -u) -eq 0 ]] || { echo "Run as root: sudo bash $0"; exit 1; }
[[ -f "$0" ]] || { echo "Save the script to a file first, then run: sudo bash install-mailbox.sh"; exit 1; }
. /etc/os-release
if [[ "$ID" != ubuntu || "${VERSION_ID%%.*}" -lt 26 ]]; then
    echo "This installer needs Ubuntu 26.04 or newer (found $PRETTY_NAME)."
    echo "On other systems follow docs/server/deployment.md."
    exit 1
fi
mkdir -p "$STATE"

# Run detached from the SSH session, so a dropped connection cannot stop it
# halfway through an upgrade or a firewall reset. Under systemd (cloud-init, or
# the unit started here) INVOCATION_ID is set and the install runs inline.
if [[ -z "${INVOCATION_ID:-}" ]]; then
    if systemctl is-active --quiet najwa-install; then
        echo "An install is already running. Follow it with: journalctl -fu najwa-install -o cat"
        exit 1
    fi
    rm -f "$STATE/status"
    : > "$STATE/install.log"
    systemd-run --quiet --unit=najwa-install --collect \
        -E NAJWA_REPO="$REPO" -E NAJWA_REF="$REF" bash "$(realpath "$0")"
    echo "Installing in the background; this takes about 15 minutes. If your connection"
    echo "drops, log in again and run: tail -f $STATE/install.log"
    # Follow a file, not the journal, and wait for the status file: the upgrade
    # restarts systemd and journald, and systemctl briefly cannot answer.
    tail -n +1 -f "$STATE/install.log" & follower=$!
    while [[ ! -s "$STATE/status" ]]; do
        state=$(systemctl show -p ActiveState --value najwa-install 2>/dev/null) || state=unknown
        [[ "$state" == inactive || "$state" == failed ]] && break
        sleep 2
    done
    sleep 2; kill "$follower" 2>/dev/null || true
    [[ "$(cat "$STATE/status" 2>/dev/null)" == ok ]]
    exit
fi

exec > >(tee -a "$STATE/install.log") 2>&1
export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a
trap 'echo failed > "$STATE/status"' ERR

say "1/7 Getting the source"
HERE=$(dirname "$(realpath "$0")")
if [[ -f "$HERE/../../Cargo.toml" && -d "$HERE/../../crates/najwa-mailbox" ]]; then
    SRC=$(cd "$HERE/../.." && pwd)
else
    apt-get update -qq
    apt-get install -y -qq git >/dev/null
    SRC=$STATE/src
    if [[ -d "$SRC/.git" ]]; then
        git -C "$SRC" fetch -q --depth 1 origin "$REF"
        git -C "$SRC" reset -q --hard FETCH_HEAD
    else
        rm -rf "$SRC"
        git clone -q --depth 1 --branch "$REF" "$REPO" "$SRC"
    fi
fi
echo "Source: $SRC"

say "2/7 Updating and hardening the server (deployment.md §2)"
bash "$SRC/scripts/deployment/harden-server.sh" --yes

say "3/7 Installing Tor and the build tools"
apt-get install -y -qq tor sqlite3 build-essential pkg-config perl rustc cargo >/dev/null

say "4/7 Building najwa-mailbox (about 10 minutes)"
# Build as an unprivileged account; dependency build scripts never run as root.
id najwa-build >/dev/null 2>&1 || useradd -r -M -d "$BUILD_HOME" -s /usr/sbin/nologin najwa-build
install -d -m 0700 -o najwa-build -g najwa-build "$BUILD_HOME"
rm -rf "$BUILD_HOME/src"
install -d -o najwa-build -g najwa-build "$BUILD_HOME/src"
tar -C "$SRC" --exclude=./target --exclude=./.git -cf - . | runuser -u najwa-build -- tar -C "$BUILD_HOME/src" -xf -
runuser -u najwa-build -- env HOME="$BUILD_HOME" CARGO_HOME="$BUILD_HOME/cargo" CARGO_TARGET_DIR="$BUILD_HOME/target" \
    cargo build --locked --release -p najwa-mailbox --manifest-path "$BUILD_HOME/src/Cargo.toml"

say "5/7 Setting up the onion service (deployment.md §6)"
if ! grep -q "^HiddenServiceDir $ONION_DIR/" /etc/tor/torrc; then
    grep -v '^#' "$SRC/scripts/deployment/config/torrc" | grep . >> /etc/tor/torrc
fi
# Check the way the tor service does: its defaults file switches to debian-tor,
# which owns the onion directory once it exists (plain root fails on a rerun).
tor_check=$(tor --defaults-torrc /usr/share/tor/tor-service-defaults-torrc -f /etc/tor/torrc --verify-config) \
    || { echo "$tor_check"; fail "Tor rejects /etc/tor/torrc"; }
systemctl restart tor
# tor@default stays "activating" for a while after a restart.
for _ in $(seq 90); do
    [[ -s "$ONION_DIR/hostname" ]] && systemctl is-active --quiet tor@default && break
    sleep 1
done
[[ -s "$ONION_DIR/hostname" ]] || fail "Tor did not create $ONION_DIR/hostname"
systemctl is-active --quiet tor@default || fail "Tor is not running; see: journalctl -u tor@default"
ONION=$(sed 's/\.onion$//' "$ONION_DIR/hostname")

say "6/7 Operator key and configuration (deployment.md §5, §7)"
[[ -e "$SEED" ]] || (umask 077; openssl rand -hex 32 > "$SEED")
chown root:najwa-mailbox "$SEED"
chmod 0440 "$SEED"
if [[ -e "$CONF" ]]; then
    echo "Keeping the existing $CONF"
else
    install -m 0640 -o root -g najwa-mailbox "$SRC/scripts/deployment/config/mailbox.toml" "$CONF"
    sed -i -e 's/^listen_addr = "0.0.0.0"/listen_addr = "127.0.0.1"/' \
        -e "s/^onion_address = \"\"/onion_address = \"$ONION\"/" \
        -e "/^operator_key_seed_hex = \"\"/a operator_key_path = \"$SEED\"" "$CONF"
fi

say "7/7 Installing and starting the service (deployment.md §8, §10)"
[[ -e "$BIN" ]] && cp -p "$BIN" "$BIN.prev"
install -m 0755 -o root -g root "$BUILD_HOME/target/release/najwa-mailbox" "$BIN"
install -m 0644 "$SRC/scripts/deployment/config/najwa-mailbox.service" /etc/systemd/system/najwa-mailbox.service
systemctl daemon-reload
systemctl enable --quiet najwa-mailbox
systemctl restart najwa-mailbox
healthy() {
    for _ in $(seq 30); do
        curl -sf http://127.0.0.1:9090/v1/health | grep -q '"status":"healthy"' && return 0
        sleep 1
    done
    return 1
}
if ! healthy; then
    journalctl -u najwa-mailbox -n 20 --no-pager -o cat
    if [[ -e "$BIN.prev" ]]; then
        echo "The new build does not start; restoring the previous one."
        install -m 0755 "$BIN.prev" "$BIN"
        systemctl restart najwa-mailbox
    fi
    fail "najwa-mailbox is not healthy; see the log above and deployment.md §8"
fi
ATTEST=$(curl -sf http://127.0.0.1:8080/v1/attestation)
grep -q "\"onion_address\":\"$ONION\"" <<<"$ATTEST" || fail "the attestation does not report $ONION"
OPERATOR_ID=$(sed -n 's/.*"operator_id":"\([^"]*\)".*/\1/p' <<<"$ATTEST")

# The summary holds no secrets: it is printed, kept in the journal and shown at login.
ADMIN=$(getent group sudo | cut -d: -f4 | tr ',' '\n' | grep -v -e '^root$' -e '^$' | head -n1 || true)
IP=$(hostname -I | awk '{print $1}')
{
    echo "Najwa mailbox is running."
    echo
    echo "  Address:      $ONION.onion"
    echo "  Operator ID:  $OPERATOR_ID"
    echo
    echo "Back up these two keys now, for example in a password manager. Without the"
    echo "onion key this address is lost for good. Show them with:"
    echo "  sudo base64 -w0 $ONION_DIR/hs_ed25519_secret_key; echo"
    echo "  sudo cat $SEED"
    echo "Restore steps: docs/server/operations.md §2."
    echo
    if [[ -n "$ADMIN" ]]; then
        echo "Root can no longer log in over SSH. Log in from now on with the same key or"
        echo "password as:  ssh $ADMIN@$IP"
    fi
    [[ -f /var/run/reboot-required ]] && echo "An update needs a restart: sudo reboot. The mailbox starts again by itself."
    echo "To offer the mailbox to others, see MAILBOXES.md. Show this again:"
    echo "  cat $STATE/summary.txt"
} > "$STATE/summary.txt"
chmod 0644 "$STATE/summary.txt"
printf 'Najwa mailbox %s.onion\nDetails: cat %s/summary.txt\n' "$ONION" "$STATE" > /etc/motd
say "Done"
cat "$STATE/summary.txt"
echo ok > "$STATE/status"
