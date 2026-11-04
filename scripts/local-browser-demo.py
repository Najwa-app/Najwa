"""Opt-in local browser test: disposable Rust peers and a Docker onion mailbox.

Never a release server. Loopback only, distinct origins, RAM-only authorization,
bounded authenticated commands. No passphrase, TPM, or identity-record API.
"""
import argparse
import concurrent.futures
import hmac
import http.server
import json
import mimetypes
import pathlib
import queue
import re
import secrets
import subprocess
import threading
import time
import urllib.parse

CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; "
       "font-src 'self'; connect-src 'self'; object-src 'none'; frame-src 'none'; "
       "worker-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")


class Peer:
    def __init__(self, executable, profile, username):
        self.username = username
        self.session = secrets.token_hex(16)
        self.token = secrets.token_hex(32)
        self.lock = threading.Lock()
        self.responses = queue.Queue()
        self.log = profile.with_suffix('.log').open('w', encoding='utf-8')
        self.process = subprocess.Popen(
            [str(executable), str(profile)], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=self.log, text=True, encoding='utf-8',
            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0)
        threading.Thread(target=self.read, daemon=True).start()
        welcome = self.responses.get(timeout=60)
        self.fingerprint = welcome['ok']['fingerprint']
        self.cached_status = {'enabled': True, 'unlocked': True, 'connection': 'connecting',
                              'coverRunning': False, 'mailboxes': [], 'pausedMailboxes': []}

    def read(self):
        try:
            for line in self.process.stdout:
                self.responses.put(json.loads(line))
        except (OSError, ValueError, UnicodeError):
            self.responses.put({'error': 'peer_protocol_failed'})
        finally:
            self.responses.put({'error': 'peer_exited'})

    def call(self, operation, wait=False):
        acquired = self.lock.acquire(timeout=660) if wait else self.lock.acquire(blocking=False)
        if not acquired:
            return {'error': 'busy'}
        try:
            self.process.stdin.write(json.dumps(operation, ensure_ascii=False) + '\n')
            self.process.stdin.flush()
            result = self.responses.get(timeout=660)
            if operation['kind'] == 'status' and 'ok' in result:
                self.cached_status = {'enabled': True, **result['ok']}
                result = {'ok': self.cached_status}
            return result
        except (OSError, queue.Empty):
            # A timed-out stdin protocol cannot safely associate later results.
            self.process.terminate()
            return {'error': 'peer_exited'}
        finally:
            self.lock.release()

    def status(self):
        result = self.call({'kind': 'status'})
        return {'ok': self.cached_status} if result.get('error') == 'busy' else result

    def close(self):
        try:
            self.process.stdin.close()
            self.process.wait(timeout=15)
        except (OSError, subprocess.TimeoutExpired):
            self.process.terminate()
            self.process.wait(timeout=10)
        self.process.stdout.close()
        self.log.close()


class Demo:
    def __init__(self, peers, onion, output):
        self.peers = peers
        self.onion = onion
        self.output = output
        self.phase = 'Starting independent Rust peers'

    def progress(self, phase):
        self.phase = phase
        print(phase, flush=True)
        (self.output / 'status.json').write_text(json.dumps({'phase': phase}), encoding='utf-8')

    def require(self, peer, operation):
        deadline = time.monotonic() + 1800
        retries = 0
        while time.monotonic() < deadline:
            result = peer.call(operation, wait=True)
            code = result.get('error')
            if code == 'busy':
                time.sleep(2)
                continue
            # These native operations persist and reuse their exact setup state.
            # Chat sends are deliberately never retried here.
            if operation['kind'] in {'add_mailbox', 'invitation', 'accept_invitation'} and code in {
                    'sync_failed', 'registration_failed', 'registration_transport', 'registration_pow',
                    'registration_limited', 'registration_server', 'timeout', 'not_connected'} and retries < 3:
                retries += 1
                print(f"{peer.username}: {operation['kind']} retry {retries} ({code})", flush=True)
                time.sleep(5)
                continue
            if code:
                raise RuntimeError(f"{operation['kind']}: {code}")
            return result['ok']
        raise RuntimeError('setup deadline exceeded')

    def setup(self):
        try:
            self.progress('Connecting both embedded Tor clients')
            deadline = time.monotonic() + 600
            while not all(self.require(p, {'kind': 'status'})['connection'] == 'connected' for p in self.peers):
                if time.monotonic() > deadline:
                    raise RuntimeError('Tor bootstrap deadline')
                time.sleep(3)
            self.progress('Registering mailbox queues and publishing scoped prekeys')
            with concurrent.futures.ThreadPoolExecutor(2) as pool:
                futures = [pool.submit(self.require, p, {'kind': 'add_mailbox', 'onion': self.onion}) for p in self.peers]
                for future in futures:
                    future.result()
            alice, bob = self.peers
            invitation = self.require(bob, {'kind': 'invitation', 'name': bob.username})
            self.require(alice, {'kind': 'accept_invitation', 'name': alice.username, 'invitation': invitation})
            self.progress('Completing signed invitation and reciprocal contact setup through Tor')
            deadline = time.monotonic() + 1200
            while True:
                contacts = [self.require(p, {'kind': 'contacts'}) for p in self.peers]
                if all(c and c[0]['ready'] for c in contacts):
                    if contacts[0][0]['safetyNumber'] != contacts[1][0]['safetyNumber']:
                        raise RuntimeError('safety numbers differ')
                    self.progress('Ready — both contact queues established; safety numbers match')
                    return
                if time.monotonic() > deadline:
                    raise RuntimeError('contact setup deadline')
                time.sleep(5)
        except Exception as error:
            self.progress(f'Setup failed: {type(error).__name__}')
            print(str(error), flush=True)


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, port, peer, demo, assets):
        self.origin = f'http://127.0.0.1:{port}'
        self.authority = f'127.0.0.1:{port}'
        self.peer, self.demo, self.assets = peer, demo, assets.resolve()
        self.slots = threading.BoundedSemaphore(8)
        super().__init__(('127.0.0.1', port), Handler)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


class Handler(http.server.BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(15)

    def log_message(self, *_):
        pass

    def respond(self, status, payload, content_type='application/json'):
        body = json.dumps(payload).encode('utf-8') if content_type == 'application/json' else payload
        self.send_response(status)
        for key, value in {
                'Content-Type': content_type, 'Content-Length': str(len(body)),
                'Content-Security-Policy': CSP, 'Cache-Control': 'no-store',
                'Referrer-Policy': 'no-referrer', 'X-Content-Type-Options': 'nosniff',
                'Cross-Origin-Resource-Policy': 'same-origin',
                'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()'}.items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def valid_host(self):
        return self.headers.get('Host') == self.server.authority

    def do_GET(self):
        if not self.valid_host() or self.headers.get('Sec-Fetch-Site') in {'cross-site', 'same-site'}:
            self.respond(403, {'error': 'forbidden'})
            return
        path = urllib.parse.unquote(urllib.parse.urlsplit(self.path).path)
        if path == '/api/bootstrap':
            peer = self.server.peer
            self.respond(200, {'token': peer.token, 'session': peer.session,
                               'username': peer.username, 'fingerprint': peer.fingerprint})
            return
        asset = (self.server.assets / ('index.html' if path == '/' else path.lstrip('/'))).resolve()
        if not asset.is_relative_to(self.server.assets) or asset.suffix not in {'.html', '.js', '.css', '.png', '.svg', '.ico'} or not asset.is_file():
            self.respond(404, {'error': 'not_found'})
            return
        content_type = {'.js': 'application/javascript', '.css': 'text/css', '.html': 'text/html'}.get(asset.suffix)
        self.respond(200, asset.read_bytes(), content_type or mimetypes.guess_type(asset.name)[0] or 'application/octet-stream')

    def do_POST(self):
        if (not self.valid_host() or self.path != '/api/invoke'
                or self.headers.get('Origin') != self.server.origin
                or self.headers.get('Sec-Fetch-Site') not in {None, 'same-origin'}
                or self.headers.get('Content-Type') != 'application/json'
                or not hmac.compare_digest(self.headers.get('X-Najwa-Demo', '').encode('utf-8'), self.server.peer.token.encode('utf-8'))):
            self.respond(403, {'error': 'forbidden'})
            return
        try:
            length = int(self.headers.get('Content-Length', '-1'))
            if not 1 <= length <= 32768 or self.headers.get('Transfer-Encoding'):
                raise ValueError('invalid length')
            body = self.rfile.read(length)
            if len(body) != length:
                raise ValueError('incomplete body')
            value = json.loads(body)
            if not isinstance(value, dict) or set(value) != {'command', 'args'} or not isinstance(value['args'], dict):
                raise ValueError('invalid envelope')
            result = self.invoke(value['command'], value['args'])
        except (ValueError, TypeError, KeyError, TimeoutError, RecursionError):
            self.respond(400, {'error': 'invalid_request'})
            return
        self.respond(200, result)

    def invoke(self, command, args):
        peer = self.server.peer
        if command == 'demo_status' and not args:
            return {'ok': self.server.demo.phase}
        if command == 'messaging_status' and not args:
            return peer.status()
        if command != 'messaging_request' or set(args) != {'request'}:
            return {'error': 'unavailable'}
        request = args['request']
        if (not isinstance(request, dict) or set(request) != {'session', 'generation', 'operation'}
                or request['session'] != peer.session or type(request['generation']) is not int
                or request['generation'] != 1):
            return {'error': 'stale_operation'}
        operation = request['operation']
        if not isinstance(operation, dict) or not isinstance(operation.get('kind'), str):
            return {'error': 'invalid_request'}
        # Manual setup uses the same authenticated, typed Rust boundary as chat.
        if operation['kind'] not in {'contacts', 'messages', 'displayed', 'send', 'set_timer', 'verify', 'sync', 'reconnect', 'retry_mailbox', 'add_mailbox', 'select_mailbox', 'forget_mailbox', 'set_delivery_mode', 'invitation', 'accept_invitation'}:
            return {'error': 'unavailable'}
        return peer.call(operation)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--peer', type=pathlib.Path, required=True)
    parser.add_argument('--assets', type=pathlib.Path, required=True)
    parser.add_argument('--onion', required=True)
    parser.add_argument('--output', type=pathlib.Path, required=True)
    parser.add_argument('--user', help='Start one user with manual mailbox/contact setup')
    parser.add_argument('--port', type=int, default=4183, help='Loopback port for --user (default: 4183)')
    args = parser.parse_args()
    if args.user is not None and not args.user.strip():
        parser.error('--user must contain a display name')
    if not 1 <= args.port <= 65535:
        parser.error('--port must be between 1 and 65535')
    if not re.fullmatch('[a-z2-7]{56}\\.onion', args.onion):
        parser.error('complete v3 onion required')
    if not (args.assets / 'index.html').is_file() or not args.peer.is_file():
        parser.error('build the peer and isolated demo assets first')
    args.output.mkdir(parents=True, exist_ok=False)
    peers, servers = [], []
    try:
        names = (args.user,) if args.user is not None else ('Alice · Chrome', 'Bob · Firefox')
        for name in names:
            profile = 'user' if args.user is not None else name.split()[0].lower()
            peers.append(Peer(args.peer.resolve(), args.output / profile, name))
        demo = Demo(peers, args.onion, args.output)
        ports = (args.port,) if args.user is not None else (4181, 4182)
        for port, peer in zip(ports, peers):
            server = Server(port, peer, demo, args.assets)
            servers.append(server)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            print(f'{peer.username}: {server.origin}/', flush=True)
        if args.user is None:
            threading.Thread(target=demo.setup, daemon=True).start()
        else:
            demo.progress('Manual setup — add your mailbox in Settings, then exchange invitations')
        threading.Event().wait()
    except KeyboardInterrupt:
        pass
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()
        for peer in peers:
            peer.close()


if __name__ == '__main__':
    main()
