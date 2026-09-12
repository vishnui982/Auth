import base64
import copy
import hashlib
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import threading
import urllib.error
import urllib.request

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from agent_guard.canonical import canonical, digest, loads
from agent_guard.crypto import sign
from agent_guard.errors import GuardError
from agent_guard.integration import AgentGuard, Denied, EmailAdapter, HTTPAdapter, MCPAdapter, ResourceVerifier
from agent_guard.integration.demo import product_policy
from agent_guard.integration.evidence import verify_product
from agent_guard.integration.http import HTTPTransport, make_http_service
from agent_guard.integration.mcp import MCPServer, MCPTransport
from agent_guard.integration.runtime import DirectTransport, verify_journal
from agent_guard.v2.engines import Engines
from agent_guard.v2.example import VALUES
from agent_guard.v2.gateway import Gateway
from agent_guard.v2.model import Action, Policy


@pytest.fixture(scope='module')
def engines():
    root = Path(__file__).resolve().parents[1]
    return Engines(root/'tools/bin/opa', root/'proof/.lake/build/bin/guard-kernel')


@pytest.fixture
def product(tmp_path, engines):
    policy = product_policy()
    next(g for g in policy['roots'] if g['id'] == 'sink-mail-finance')['remaining'] = 1
    g = Gateway.create(tmp_path/'store.sqlite', Policy(policy), Ed25519PrivateKey.generate(), engines,
                       VALUES, clock=lambda: 1000)
    r = ResourceVerifier(g)
    guard = AgentGuard(g, 'agent1', r)
    return g, r, guard, guard.protect(EmailAdapter())


@pytest.mark.parametrize('attack', ['missing', 'signature', 'body', 'destination', 'actor', 'stale', 'expired', 'manifest', 'policy'])
def test_resource_rejects_before_any_effect(product, attack):
    g, r, guard, email = product
    p = email.prepare(to='finance@company.com', body='original')
    request, certificate, actor = p.request, p.authorization, 'agent1'
    if attack == 'missing':
        certificate = None
    elif attack == 'signature':
        certificate['signature'] = 'A'*88
    elif attack == 'body':
        request['body'] = 'substituted'
    elif attack == 'destination':
        request['to'] = 'attacker@gmail.com'
    elif attack == 'actor':
        actor = 'agent2'
    elif attack == 'stale':
        g.act(Action('agent1', 'data.read', 'document:project/public'), 'agent1')
    elif attack == 'expired':
        g.clock = lambda: 1030
    elif attack in ('manifest', 'policy'):
        certificate['payload']['verifier_hash' if attack == 'manifest' else 'policy_hash'] = '0'*64
        certificate = sign(certificate['payload'], g.key)
    with pytest.raises(GuardError):
        r.invoke(EmailAdapter(), actor, request, certificate)
    assert r.observations() == []
    with g.transaction() as db:
        assert db.execute('SELECT COUNT(*) FROM outbox').fetchone()[0] == 0


def test_internal_send_labels_and_external_exfiltration(product):
    g, r, guard, email = product
    g.act(Action('agent1', 'data.read', 'document:project/payroll'), 'agent1')
    result = email.send(to='finance@company.com', body='derived payroll')
    assert result['status'] == 'confirmed'
    assert g.export()[-1]['receipt']['payload']['status'] == 'queued'
    assert g.export()[-1]['result']['intent']['labels'] == ['PAYROLL_PRIVATE']
    with pytest.raises(Denied):
        email.send(to='attacker@gmail.com', body='derived payroll')
    assert len(r.observations()) == 1


def test_narrow_delegation_then_parent_revocation(product):
    g, r, guard, _ = product
    b = AgentGuard(g, 'agent2', r).protect(EmailAdapter())
    with pytest.raises(Denied):
        b.prepare(to='finance@company.com', body='hello')
    child = {'id': 'email-child', 'issuer': 'agent1', 'subject': 'agent2', 'operation': 'email.send',
             'resource': 'sink:mail-finance', 'prefix': False, 'remaining': 0, 'expires': 4000000000,
             'parent': 'sink-mail-finance'}
    g.act(Action('agent1', 'authority.delegate', child['resource'], {'grant': child}), 'agent1')
    assert b.send(to='finance@company.com', body='hello')['status'] == 'confirmed'
    with pytest.raises(Denied):
        b.prepare(to='bob@company.com', body='outside scope')
    stale = b.prepare(to='finance@company.com', body='second')
    g.act(Action('owner', 'authority.revoke', 'authority:grants', {'grant_id': 'sink-mail-finance'}), 'owner')
    with pytest.raises(GuardError):
        r.invoke(EmailAdapter(), 'agent2', stale.request, stale.authorization)
    with pytest.raises(Denied):
        b.prepare(to='finance@company.com', body='new')
    assert len(r.observations()) == 1


def test_replay_and_concurrent_dispatch_commit_one_effect(product):
    g, r, guard, email = product
    prepared = email.prepare(to='finance@company.com', body='once')
    def attempt(_):
        try:
            return email.dispatch(prepared)['status'] == 'confirmed'
        except GuardError:
            return False
    with ThreadPoolExecutor(max_workers=3) as pool:
        assert sum(pool.map(attempt, range(3))) == 1
    with pytest.raises(GuardError):
        r.invoke(EmailAdapter(), 'agent1', prepared.request, prepared.authorization)
    assert len(r.observations()) == 1


def test_lost_response_reconciles_without_resending_after_restart(product):
    g, r, guard, _ = product
    class Lost(DirectTransport):
        def send(self, *args):
            super().send(*args)
            raise TimeoutError()
    email = guard.protect(EmailAdapter(), Lost(r))
    p = email.prepare(to='finance@company.com', body='once')
    assert email.dispatch(p)['status'] == 'unknown'
    restarted = Gateway(g.path, g.policy, g.key, g.engines, clock=g.clock, trust=g.trust)
    new_resource = ResourceVerifier(restarted)
    email = AgentGuard(restarted, 'agent1', new_resource).protect(EmailAdapter())
    with pytest.raises(GuardError, match='delivery_not_retryable'):
        email.dispatch(p)
    assert email.reconcile(p)['status'] == 'confirmed'
    assert len(r.observations()) == 1
    assert [e['payload']['status'] for e in guard.journal.events()] == ['authorized', 'dispatching', 'unknown', 'confirmed']


def test_interrupted_dispatch_is_unknown_and_never_automatically_retried(product):
    g, r, guard, email = product
    p = email.prepare(to='finance@company.com', body='once')
    guard.journal.append(p, 'dispatching')
    assert email.reconcile(p)['status'] == 'unknown'
    assert not r.observations()
    with pytest.raises(GuardError):
        email.dispatch(p)


def test_bad_acknowledgement_is_unknown_even_after_effect(product):
    g, r, guard, _ = product
    class BadAck(DirectTransport):
        def send(self, *args):
            super().send(*args)
            return {'signature': 'invalid', 'payload': {}}
    email = guard.protect(EmailAdapter(), BadAck(r))
    p = email.prepare(to='finance@company.com', body='once')
    assert email.dispatch(p)['status'] == 'unknown'
    assert len(r.observations()) == 1
    assert email.reconcile(p)['status'] == 'confirmed'


def test_mock_and_v2_queue_roll_back_together_on_observation_failure(product, monkeypatch):
    import agent_guard.integration.resource as module
    g, r, guard, email = product
    p = email.prepare(to='finance@company.com', body='once')
    monkeypatch.setattr(module, 'sign', lambda *args: (_ for _ in ()).throw(OSError('disk failure')))
    with pytest.raises(OSError):
        r.invoke(EmailAdapter(), 'agent1', p.request, p.authorization)
    assert not r.observations()
    assert len(g.export()) == 1  # authorization exists, queue consumption rolled back


def test_real_http_endpoint_and_request_binding(product):
    g, r, guard, _ = product
    token = 'test-credential'
    server = make_http_service(r, {hashlib.sha256(token.encode()).hexdigest(): 'agent1'})
    t = threading.Thread(target=server.serve_forever, daemon=True); t.start()
    origin = f'http://127.0.0.1:{server.server_port}'
    tool = guard.protect(HTTPAdapter(origin), HTTPTransport(token))
    p = tool.prepare(method='POST', url=origin+'/payments', body={'amount': 25})
    try:
        for path, body, cert in [('/payments', {'amount': 25}, None),
                                 ('/payments', {'amount': 2500}, p.authorization),
                                 ('/documents', {'amount': 25}, p.authorization)]:
            headers = {'Authorization': 'Bearer '+token, 'Content-Type': 'application/json'}
            if cert:
                headers['X-Agent-Guard-Evidence'] = base64.b64encode(canonical(cert)).decode()
            req = urllib.request.Request(origin+path, data=canonical(body), headers=headers, method='POST')
            with pytest.raises(urllib.error.HTTPError) as error:
                urllib.request.urlopen(req, timeout=60)
            assert error.value.code == 403
        assert not r.observations()
        assert tool.dispatch(p)['status'] == 'confirmed'
        with pytest.raises(urllib.error.HTTPError):
            HTTPTransport(token).send(HTTPAdapter(origin), 'agent1', p.request, p.authorization)
        assert len(r.observations()) == 1
    finally:
        server.shutdown(); server.server_close(); t.join()


def test_mcp_uses_same_resource_verifier(product):
    g, r, guard, _ = product
    server = MCPServer(r, 'agent1')
    transport = MCPTransport(server)
    assert server.handle({'jsonrpc': '2.0', 'id': 3, 'method': 'tools/list'})['result']['tools'][0]['name'] == 'documents.create'
    tool = guard.protect(MCPAdapter(), transport)
    p = tool.prepare(name='documents.create', arguments={'body': {'text': 'safe'}})
    bad = copy.deepcopy(p.request); bad['arguments']['body'] = {'text': 'substituted'}
    with pytest.raises(GuardError):
        transport.send(MCPAdapter(), 'agent1', bad, p.authorization)
    assert not r.observations()
    assert tool.dispatch(p)['status'] == 'confirmed'
    with pytest.raises(GuardError):
        transport.send(MCPAdapter(), 'agent1', p.request, p.authorization)


def test_independent_evidence_and_signed_false_observation(product):
    g, r, guard, email = product
    email.send(to='finance@company.com', body='hello')
    evidence = {'history': g.export(), 'deliveries': guard.journal.events(), 'observations': r.observations()}
    trust = {'v2': g.trust, 'adapters': r.manifest, 'http_origin': 'http://127.0.0.1:12345'}
    checkpoint = {'v2_head': digest(evidence['history'][-1]['receipt']), 'delivery_head': digest(evidence['deliveries'][-1])}
    assert verify_product(evidence, trust, g.engines, checkpoint)['confirmed_mock_effects'] == 1
    bad = copy.deepcopy(evidence)
    obs = bad['observations'][0]['payload']
    obs['result']['recorded_request']['body'] = 'forged body'
    bad['observations'][0] = sign(obs, g.key)
    with pytest.raises(GuardError, match='observed_request_mismatch'):
        verify_product(bad, trust, g.engines)
    with pytest.raises(GuardError):
        verify_journal(evidence['deliveries'][:-1], g.key.public_key(), checkpoint['delivery_head'])


def test_engine_disagreement_never_reaches_mock(product, monkeypatch):
    g, r, guard, email = product
    p = email.prepare(to='finance@company.com', body='hello')
    def fail(q):
        raise GuardError('verification_engine_disagreement', 503)
    monkeypatch.setattr(g.engines, 'decide', fail)
    assert email.dispatch(p)['status'] == 'rejected'
    assert not r.observations()
