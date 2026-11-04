#!/bin/sh
set -eu
umask 077
state=/var/lib/najwa-mailbox
onion=$(cat /var/lib/najwa-onion/hostname)
host=${onion%.onion}
case "$host" in
    ''|*[!a-z2-7]*) echo 'Invalid onion hostname' >&2; exit 1 ;;
esac
if [ "${#host}" -ne 56 ] || [ "$onion" != "$host.onion" ]; then
    echo 'Expected a v3 onion hostname' >&2
    exit 1
fi
if [ ! -e "$state/operator-seed" ]; then
    # Generate inside the private volume. Never print or place the seed in
    # environment variables, compose output, image layers, or the repository.
    od -An -v -N32 -tx1 /dev/urandom | tr -d ' \n' > "$state/operator-seed.new"
    test "$(wc -c < "$state/operator-seed.new")" -eq 64
    mv "$state/operator-seed.new" "$state/operator-seed"
fi
test "$(wc -c < "$state/operator-seed")" -eq 64
chmod 600 "$state/operator-seed"
sed "s/ONION_HOSTNAME/$host/" /opt/najwa/mailbox.toml > "$state/mailbox.toml.new"
mv "$state/mailbox.toml.new" "$state/mailbox.toml"
echo 'Development mailbox initialized; operator key retained in its private volume.'
