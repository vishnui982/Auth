"""Bounded local-development HTTP transport. Identity comes from credentials."""

import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import logging

from .action import Action, IDENTIFIER
from .canonical import MAX_BYTES, canonical, fields, loads
from .errors import GuardError


class Authenticator:
    def __init__(self, identities):
        if type(identities) is not dict or not identities:
            raise GuardError("invalid_identity_configuration", 400)
        for token_hash, actor in identities.items():
            if (type(token_hash) is not str or len(token_hash) != 64 or
                any(c not in "0123456789abcdef" for c in token_hash) or
                type(actor) is not str or not IDENTIFIER.fullmatch(actor)):
                raise GuardError("invalid_identity_configuration", 400)
        self.identities = dict(identities)

    def authenticate(self, header):
        if not header or not header.startswith("Bearer ") or len(header) > 256:
            raise GuardError("unauthenticated", 401)
        candidate = hashlib.sha256(header[7:].encode()).hexdigest()
        for token_hash, actor in self.identities.items():
            if hmac.compare_digest(candidate, token_hash):
                return actor
        raise GuardError("unauthenticated", 401)


def make_server(gateway, identities, host="127.0.0.1", port=8765, *,
                action_type=Action, api_version="v1", receipt_key="authorization"):
    auth = Authenticator(identities)
    routes = {name: f"/{api_version}/{name}" for name in ("act", "authorize", "execute")}

    class Handler(BaseHTTPRequestHandler):
        server_version = "AgentGuard/0.1"
        sys_version = ""

        def setup(self):
            super().setup()
            self.connection.settimeout(5)

        def log_message(self, *_):
            pass  # Do not put credentials, resources, or content into access logs.

        def respond(self, status, value):
            data = canonical(value)
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(data)
            self.close_connection = True

        def do_GET(self):
            self.respond(200 if self.path == "/health" else 404,
                         {"status": "ok"} if self.path == "/health" else {"error": "not_found"})

        def do_POST(self):
            try:
                if self.path not in routes.values():
                    raise GuardError("not_found", 404)
                if self.headers.get("Origin") or self.headers.get("Transfer-Encoding"):
                    raise GuardError("unsupported_request", 400)
                for name in ("Authorization", "Content-Length", "Content-Type"):
                    if len(self.headers.get_all(name, [])) != 1:
                        raise GuardError("invalid_headers", 400)
                actor = auth.authenticate(self.headers.get("Authorization"))
                if self.headers.get("Content-Type") != "application/json":
                    raise GuardError("unsupported_media_type", 415)
                length = self.headers["Content-Length"]
                if not length.isascii() or not length.isdigit():
                    raise GuardError("invalid_content_length", 400)
                size = int(length)
                if not 0 < size <= MAX_BYTES:
                    raise GuardError("invalid_body_size", 413)
                raw = self.rfile.read(size)
                if len(raw) != size:
                    raise GuardError("incomplete_body", 400)
                body = loads(raw)
                required = {"action", "authorization"} if self.path == routes["execute"] else {"action"}
                fields(body, required)
                action = action_type.from_dict(body["action"])
                if self.path == routes["authorize"]:
                    certificate = gateway.authorize(action, actor)
                    value = certificate if receipt_key == "receipt" else {"action": action.to_dict(), "authorization": certificate}
                elif self.path == routes["execute"]:
                    value = gateway.execute(action, actor, body["authorization"])
                else:
                    value = gateway.act(action, actor)
                status = 403 if value[receipt_key]["payload"]["decision"] == "deny" else 200
                self.respond(status, value)
            except GuardError as exc:
                self.respond(exc.status, {"error": exc.code})
            except (TimeoutError, ConnectionError):
                self.close_connection = True
            except Exception:
                logging.exception("Gateway request failed")
                self.respond(503, {"error": "gateway_unavailable"})

    return ThreadingHTTPServer((host, port), Handler)
