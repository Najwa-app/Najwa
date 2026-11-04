"""Two synthetic desktop-boundary peers over embedded Arti and a real onion.

Build najwa-ffi's desktop_peer example first. Takes executable, onion hostname,
and a fresh output directory. No credential/private-key export or clearnet API.
"""
import concurrent.futures
import json
import pathlib
import queue
import subprocess
import sys
import threading
import time


class Peer:
    def __init__(self, executable, directory):
        directory.mkdir(parents=True, exist_ok=False)
        self.log = (directory / 'stderr.log').open('w', encoding='utf-8')
        self.process = subprocess.Popen([executable, str(directory)], stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=self.log, text=True, encoding='utf-8',
                                        creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0)
        self.results = queue.Queue()
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self):
        try:
            for line in self.process.stdout:
                self.results.put(json.loads(line))
        except (UnicodeError, ValueError, OSError):
            self.results.put({'error': 'peer_protocol_failed'})
        else:
            self.results.put({'error': 'peer_exited'})

    def call(self, kind, **values):
        deadline = time.monotonic() + 1800
        retries = 0
        while time.monotonic() < deadline:
            self.process.stdin.write(json.dumps({'kind': kind, **values}) + '\n')
            self.process.stdin.flush()
            result = self.results.get(timeout=min(660, max(1, deadline - time.monotonic())))
            if result.get('error') == 'busy' and kind != 'send':
                time.sleep(2)
                continue
            # Registration persists its exact pair before network work. Retrying
            # this operation is safe; sending a message must never be retried
            # here because the first call may already have committed its outbox.
            if kind == 'mailbox' and result.get('error') in {
                    'sync_failed', 'registration_failed', 'timeout', 'not_connected'} and retries < 3:
                retries += 1
                print(f'Mailbox setup retry {retries}: {result["error"]}', flush=True)
                time.sleep(5)
                continue
            if 'error' in result:
                raise RuntimeError(f'{kind}: {result["error"]}')
            return result['ok']
        raise RuntimeError(f'{kind}: operation deadline exceeded')

    def close(self):
        try:
            self.process.stdin.write('{"kind":"quit"}\n')
            self.process.stdin.flush()
            self.process.wait(timeout=15)
        except Exception:
            pass
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=10)
        for stream in (self.process.stdin, self.process.stdout):
            try:
                stream.close()
            except OSError:
                pass
        self.log.close()


def main():
    executable, onion, output = sys.argv[1:]
    # Windows CreateProcess does not find a relative path with forward slashes,
    # which is how the documented command passes it.
    executable = str(pathlib.Path(executable).resolve())
    output = pathlib.Path(output).resolve()
    peers = []
    try:
        alice = Peer(executable, output / 'alice'); peers.append(alice)
        bob = Peer(executable, output / 'bob'); peers.append(bob)
        deadline = time.monotonic() + 600
        while not all(peer.call('status')['connection'] == 'connected' for peer in peers):
            if time.monotonic() > deadline:
                raise RuntimeError('Tor bootstrap deadline')
            time.sleep(5)
        print('Both embedded Arti clients connected.', flush=True)
        with concurrent.futures.ThreadPoolExecutor(2) as pool:
            futures = [pool.submit(peer.call, 'mailbox', onion=onion) for peer in peers]
            for future in futures:
                future.result()
        print('Mailboxes registered and scoped prekeys published.', flush=True)
        invitation = bob.call('invite', name='Synthetic Bob')
        alice_id = alice.call('accept', invitation=invitation, name='Synthetic Alice')
        print('Signed invitation accepted; reciprocal Initial queued.', flush=True)
        deadline = time.monotonic() + 1200
        progress_at = 0
        while True:
            a = alice.call('contacts'); b = bob.call('contacts')
            if a and b and a[0]['ready'] and b[0]['ready']:
                break
            if time.monotonic() > deadline:
                raise RuntimeError('contact setup deadline')
            if time.monotonic() >= progress_at:
                print(f'Contact setup: Alice ready={[c["ready"] for c in a]}, Bob ready={[c["ready"] for c in b]}', flush=True)
                progress_at = time.monotonic() + 60
            time.sleep(10)
        bob_id = b[0]['id']
        assert a[0]['safetyNumber'] == b[0]['safetyNumber']
        assert not a[0]['verified'] and not b[0]['verified']
        print('Both long-term contact queues ready; safety numbers match.', flush=True)
        alice.call('send', contact=alice_id, text='Synthetic desktop Alice → Bob')
        print('Alice text queued locally; waiting for batched Tor delivery.', flush=True)
        await_message(bob, bob_id, 'Synthetic desktop Alice → Bob')
        bob.call('send', contact=bob_id, text='Synthetic desktop Bob → Alice')
        print('Bob reply queued locally; waiting for batched Tor delivery.', flush=True)
        await_message(alice, alice_id, 'Synthetic desktop Bob → Alice')
        print('Encrypted text delivered in both directions.', flush=True)
        alice.call('lock')
        state = alice.call('status')
        assert not state['unlocked'] and state['coverRunning']
        bob.call('send', contact=bob_id, text='Synthetic message while Alice locked')
        print('Text queued while Alice is locked and her cover continues.', flush=True)
        alice.call('unlock')
        await_message(alice, alice_id, 'Synthetic message while Alice locked')
        print('PASS: lock retains cover; re-unlock receives queued ciphertext.', flush=True)
    finally:
        for peer in peers:
            peer.close()


def await_message(peer, contact, content):
    started = time.monotonic()
    deadline = started + 1200
    progress_at = started + 60
    while True:
        messages = peer.call('messages', contact=contact)
        found = [m for m in messages if m['text'] == content and not m['outgoing']]
        if found:
            peer.call('displayed', contact=contact, ids=[found[0]['id']])
            return
        if time.monotonic() > deadline:
            raise RuntimeError('message delivery deadline')
        if time.monotonic() >= progress_at:
            print(f'Delivery pending after {int(time.monotonic() - started)}s; '
                  f'{len(messages)} text rows visible at recipient.', flush=True)
            progress_at = time.monotonic() + 60
        time.sleep(10)


if __name__ == '__main__':
    main()
