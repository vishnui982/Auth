"""Loopback-only protected mock REST API; credentials determine the caller."""
import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import urllib.error
import urllib.request

from agent_guard.canonical import MAX_BYTES, canonical, loads
from agent_guard.client import NoRedirect
from agent_guard.errors import GuardError
from agent_guard.server import Authenticator
from agent_guard.v2.audit import require
from .adapters import HTTPAdapter


class HTTPTransport:
    def __init__(self, token):
        self.token = token

    def send(self, adapter, actor, request, authorization):
        adapter.normalize(actor, request)
        req = urllib.request.Request(request['url'], data=canonical(request['body']), method=request['method'],
            headers={'Content-Type': 'application/json', 'Authorization': 'Bearer ' + self.token,
                     'X-Agent-Guard-Evidence': base64.b64encode(canonical(authorization)).decode()})
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        with opener.open(req, timeout=60) as response:
            return loads(response.read(MAX_BYTES + 1))


def make_http_service(resource, identities):
    auth = Authenticator(identities)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def setup(self):
            super().setup()
            self.connection.settimeout(60)

        def do_POST(self):
            try:
                require(not self.headers.get('Origin') and not self.headers.get('Transfer-Encoding'), 'unsupported_request')
                for key in ('Host', 'Authorization', 'Content-Length', 'Content-Type'):
                    require(len(self.headers.get_all(key, [])) == 1, 'invalid_headers')
                require(self.headers['Host'] == f'127.0.0.1:{self.server.server_port}', 'destination_mismatch')
                actor = auth.authenticate(self.headers.get('Authorization'))
                require(self.path in ('/payments', '/documents'), 'unregistered_destination')
                require(self.headers['Content-Type'] == 'application/json', 'unsupported_media_type')
                length = self.headers['Content-Length']
                require(length.isascii() and length.isdigit() and 0 < int(length) <= MAX_BYTES, 'invalid_body_size')
                raw = self.rfile.read(int(length))
                require(len(raw) == int(length), 'incomplete_body')
                require(len(self.headers.get_all('X-Agent-Guard-Evidence', [])) == 1, 'authorization_evidence_required')
                certificate = loads(base64.b64decode(self.headers['X-Agent-Guard-Evidence'], validate=True))
                origin = f'http://127.0.0.1:{self.server.server_port}'
                actual = {'method': 'POST', 'url': origin + self.path, 'body': loads(raw)}
                result = resource.invoke(HTTPAdapter(origin), actor, actual, certificate)
                status = 200
            except (GuardError, ValueError) as exc:
                status, result = 403, {'error': exc.code if isinstance(exc, GuardError) else 'invalid_request'}
            except Exception:
                status, result = 503, {'error': 'resource_unavailable'}
            data = canonical(result)
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(data)))
            self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(data)
            self.close_connection = True

    return ThreadingHTTPServer(('127.0.0.1', 0), Handler)
