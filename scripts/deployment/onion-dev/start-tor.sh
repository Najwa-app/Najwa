#!/bin/sh
set -eu
umask 077
# Only the public hostname is shared with initialization. Onion private keys
# stay in tor-state, which the mailbox and initializer never mount.
rm -f /var/lib/najwa-onion/hostname
# Tor needs a numeric backend address before mailbox startup. A private,
# explicitly assigned Compose address avoids a DNS/startup dependency cycle.
case "${NAJWA_MAILBOX_IP:-}" in
    ''|*[!0-9.]*) echo 'Invalid mailbox IPv4 address' >&2; exit 1 ;;
esac
sed "s/MAILBOX_IP/$NAJWA_MAILBOX_IP/" /etc/tor/torrc > /var/lib/tor/runtime-torrc
tor -f /var/lib/tor/runtime-torrc &
tor_pid=$!
trap 'kill -TERM "$tor_pid" 2>/dev/null || true; wait "$tor_pid" || true; exit' INT TERM
attempt=0
while [ ! -s /var/lib/tor/najwa/hostname ]; do
    if ! kill -0 "$tor_pid" 2>/dev/null; then
        wait "$tor_pid"
        exit 1
    fi
    attempt=$((attempt + 1))
    if [ "$attempt" -gt 60 ]; then
        kill -TERM "$tor_pid"
        wait "$tor_pid" || true
        exit 1
    fi
    sleep 1
done
cp /var/lib/tor/najwa/hostname /var/lib/najwa-onion/hostname.new
chmod 644 /var/lib/najwa-onion/hostname.new
mv /var/lib/najwa-onion/hostname.new /var/lib/najwa-onion/hostname
wait "$tor_pid"
