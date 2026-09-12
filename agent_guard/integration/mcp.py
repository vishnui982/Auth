"""Minimal MCP 2025-11-25 stdio example; no MCP dependency in the core."""
import argparse
import hashlib
import sys
from pathlib import Path

from agent_guard.canonical import MAX_BYTES, canonical, fields, loads
from agent_guard.errors import GuardError
from agent_guard.server import Authenticator
from agent_guard.v2.audit import require
from agent_guard.v2.cli import load
from agent_guard.v2.engines import Engines
from .adapters import MCPAdapter
from .resource import ResourceVerifier


class MCPServer:
    def __init__(self, resource, actor):
        self.resource, self.actor = resource, actor
        self.initialized, self.ready = False, False

    def handle(self, message):
        ident = message.get('id')
        try:
            require(message.get('jsonrpc') == '2.0', 'invalid_jsonrpc')
            method = message.get('method')
            if method == 'notifications/initialized':
                require(self.initialized, 'initialize_first')
                self.ready = True
                return None
            if ident is None:
                return None  # Notifications never execute tools.
            if method == 'initialize':
                require(not self.initialized, 'already_initialized')
                self.initialized = True
                result = {'protocolVersion': '2025-11-25', 'capabilities': {'tools': {}},
                          'serverInfo': {'name': 'agent-guard-demo', 'version': '1.0'}}
            elif method == 'ping':
                result = {}
            else:
                require(self.ready, 'initialize_first')
                if method == 'tools/list':
                    result = {'tools': [{'name': 'documents.create', 'description': 'Record a protected mock document',
                        'inputSchema': {'type': 'object', 'properties': {'body': {'type': 'object'}},
                                        'required': ['body'], 'additionalProperties': False}}]}
                elif method == 'tools/call':
                    params = message.get('params', {})
                    fields(params, {'name', 'arguments', '_meta'})
                    fields(params['_meta'], {'org.agentguard/authorization'})
                    actual = {'name': params['name'], 'arguments': params['arguments']}
                    observation = self.resource.invoke(MCPAdapter(), self.actor, actual,
                                                       params['_meta']['org.agentguard/authorization'])
                    result = {'content': [{'type': 'text', 'text': 'Confirmed by the local mock document service.'}],
                              'structuredContent': observation, 'isError': False}
                else:
                    raise GuardError('method_not_found')
            return {'jsonrpc': '2.0', 'id': ident, 'result': result}
        except GuardError as exc:
            if ident is None:
                return None
            return {'jsonrpc': '2.0', 'id': ident, 'error': {'code': -32000, 'message': exc.code}}


class MCPTransport:
    def __init__(self, server):
        self.server = server
        server.handle({'jsonrpc': '2.0', 'id': 1, 'method': 'initialize',
                       'params': {'protocolVersion': '2025-11-25', 'capabilities': {},
                                  'clientInfo': {'name': 'guard-demo', 'version': '1'}}})
        server.handle({'jsonrpc': '2.0', 'method': 'notifications/initialized'})

    def send(self, adapter, actor, request, authorization):
        response = self.server.handle({'jsonrpc': '2.0', 'id': 2, 'method': 'tools/call',
            'params': {**request, '_meta': {'org.agentguard/authorization': authorization}}})
        if 'error' in response:
            raise GuardError(response['error']['message'])
        return response['result']['structuredContent']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state', required=True)
    parser.add_argument('--token-file', required=True)
    args = parser.parse_args()
    gateway = load(args.state, Engines('tools/bin/opa', 'proof/.lake/build/bin/guard-kernel'))
    identities = loads((Path(args.state)/'identities.json').read_bytes())
    actor = Authenticator(identities).authenticate('Bearer ' + Path(args.token_file).read_text().strip())
    server = MCPServer(ResourceVerifier(gateway), actor)
    while raw := sys.stdin.buffer.readline(MAX_BYTES + 2):
        try:
            require(len(raw) <= MAX_BYTES and raw.endswith(b'\n'), 'invalid_frame')
            response = server.handle(loads(raw))
        except (GuardError, AttributeError, TypeError):
            response = {'jsonrpc': '2.0', 'id': None, 'error': {'code': -32700, 'message': 'invalid_request'}}
        if response is not None:
            sys.stdout.buffer.write(canonical(response) + b'\n')
            sys.stdout.buffer.flush()


if __name__ == '__main__':
    main()
