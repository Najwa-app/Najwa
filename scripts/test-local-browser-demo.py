"""Security boundary tests for the opt-in local harness, using no real identity."""
import http.client
import importlib.util
import json
import pathlib
import tempfile
import threading
import types
import unittest

spec = importlib.util.spec_from_file_location('local_demo', pathlib.Path(__file__).with_name('local-browser-demo.py'))
demo = importlib.util.module_from_spec(spec)
spec.loader.exec_module(demo)


class Boundary(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.directory.name)
        (self.root / 'assets').mkdir()
        (self.root / 'assets/index.html').write_text('test page', encoding='utf-8')
        (self.root / 'outside.js').write_text('private outside file', encoding='utf-8')
        self.calls = []
        self.peer = types.SimpleNamespace(
            token='a' * 64, session='b' * 32, username='Test Alice', fingerprint='c' * 64,
            status=lambda: {'ok': {'connection': 'connected'}},
            call=lambda operation: self.calls.append(operation) or {'ok': None})
        self.server = demo.Server(0, self.peer, types.SimpleNamespace(phase='ready'), self.root / 'assets')
        self.port = self.server.server_address[1]
        self.server.authority = f'127.0.0.1:{self.port}'
        self.server.origin = f'http://{self.server.authority}'
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.directory.cleanup()

    def request(self, method, path, value=None, headers=None):
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=5)
        body = json.dumps(value) if value is not None else None
        connection.request(method, path, body, headers or {})
        response = connection.getresponse()
        result = response.status, dict(response.getheaders()), response.read()
        connection.close()
        return result

    def post(self, value, **changes):
        headers = {'Origin': self.server.origin, 'Content-Type': 'application/json',
                   'X-Najwa-Demo': self.peer.token, 'Sec-Fetch-Site': 'same-origin', **changes}
        return self.request('POST', '/api/invoke', value, headers)

    def envelope(self, operation):
        return {'command': 'messaging_request', 'args': {'request': {
            'session': self.peer.session, 'generation': 1, 'operation': operation}}}

    def test_isolated_origin_authentication_and_csp(self):
        value = self.envelope({'kind': 'send', 'contact': '1', 'text': 'synthetic test'})
        for changes in ({'Origin': 'https://example.org'}, {'X-Najwa-Demo': ''},
                        {'X-Najwa-Demo': '\u00e9'}, {'Host': 'example.org'},
                        {'Sec-Fetch-Site': 'same-site'}, {'Content-Type': 'text/plain'}):
            self.assertEqual(self.post(value, **changes)[0], 403)
        self.assertEqual(self.calls, [])
        status, headers, _ = self.post(value)
        self.assertEqual(status, 200)
        self.assertEqual(self.calls, [value['args']['request']['operation']])
        self.assertIn("connect-src 'self'", headers['Content-Security-Policy'])
        self.assertNotIn('Access-Control-Allow-Origin', headers)
        self.assertEqual(headers['Cache-Control'], 'no-store')

    def test_session_commands_bounds_and_static_file_boundary(self):
        value = self.envelope({'kind': 'contacts'})
        value['args']['request']['generation'] = True
        self.assertEqual(json.loads(self.post(value)[2])['error'], 'stale_operation')
        value = self.envelope({'kind': 'export_identity'})
        self.assertEqual(json.loads(self.post(value)[2])['error'], 'unavailable')
        value = {'command': 'identity_action', 'args': {}}
        self.assertEqual(json.loads(self.post(value)[2])['error'], 'unavailable')
        self.assertEqual(self.calls, [])
        self.assertEqual(self.post({'command': 'demo_status', 'args': {}, 'extra': True})[0], 400)
        oversized = self.envelope({'kind': 'send', 'contact': '1', 'text': 'a' * 32768})
        self.assertEqual(self.post(oversized)[0], 400)
        self.assertEqual(self.request('GET', '/%2e%2e/outside.js')[0], 404)
        self.assertEqual(self.request('GET', '/api/bootstrap', headers={'Sec-Fetch-Site': 'same-site'})[0], 403)
        self.assertEqual(self.request('GET', '/')[0], 200)

    def test_manual_setup_requires_authenticated_current_session(self):
        operations = [
            {'kind': 'add_mailbox', 'onion': 'a' * 56 + '.onion'},
            {'kind': 'invitation', 'name': 'Test Alice'},
            {'kind': 'accept_invitation', 'name': 'Test Alice', 'invitation': 'synthetic'},
        ]
        for operation in operations:
            value = self.envelope(operation)
            self.assertEqual(self.post(value, Origin='https://example.org')[0], 403)
            self.assertEqual(self.post(value, **{'X-Najwa-Demo': ''})[0], 403)
            value['args']['request']['session'] = 'wrong-session'
            self.assertEqual(json.loads(self.post(value)[2])['error'], 'stale_operation')
        self.assertEqual(self.calls, [])
        for operation in operations:
            self.assertEqual(json.loads(self.post(self.envelope(operation))[2]), {'ok': None})
        self.assertEqual(self.calls, operations)


if __name__ == '__main__':
    unittest.main()
