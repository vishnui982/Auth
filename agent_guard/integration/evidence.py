"""Offline product evidence verification layered on full V2 history replay."""
from agent_guard.canonical import canonical, digest, fields
from agent_guard.crypto import verify
from agent_guard.v2.audit import require, verify_history
from agent_guard.v2.cli import verification_args
from agent_guard.v2.model import Action, AuthorizationState
from .adapters import EmailAdapter, HTTPAdapter, MCPAdapter
from .resource import adapter_manifest
from .runtime import verify_journal


def verify_product(evidence, trust, engines, checkpoint=None):
    fields(evidence, {'history', 'deliveries', 'observations'})
    fields(trust, {'v2', 'adapters', 'http_origin'})
    require(trust['adapters'] == adapter_manifest(), 'adapter_trust_mismatch')
    kwargs = verification_args(trust['v2'], engines)
    result = verify_history(evidence['history'], genesis=AuthorizationState(trust['v2']['genesis']),
                            expected_head=checkpoint['v2_head'] if checkpoint else None, **kwargs)
    key = kwargs['key']
    receipts = {digest(b['receipt']): b for b in evidence['history']}
    certificates = {digest(b['receipt']): b for b in evidence['history']
                    if b['receipt']['payload']['kind'] == 'authorization'}
    adapters = {'email.send': EmailAdapter(), 'http.post': HTTPAdapter(trust['http_origin']), 'tool.invoke': MCPAdapter()}
    observed, nonces = set(), set()
    for observation in evidence['observations']:
        p = verify(observation, key)
        fields(p, {'version', 'kind', 'status', 'actor', 'action_hash', 'nonce', 'queue_event_hash', 'adapter_hash', 'result'})
        require(type(p['version']) is int and p['version'] == 1 and p['kind'] == 'mock_tool_observation' and
                p['status'] == 'confirmed' and p['adapter_hash'] == digest(trust['adapters']), 'invalid_observation')
        bundle = receipts.get(p['queue_event_hash'])
        require(bundle is not None and bundle['receipt']['payload']['status'] == 'queued', 'missing_queue_event')
        action = Action.from_dict(bundle['action'])
        require(p['action_hash'] == action.hash and p['actor'] == bundle['action']['actor'] and
                p['nonce'] == bundle['receipt']['payload']['nonce'] and p['nonce'] not in nonces, 'observation_binding_mismatch')
        actual = p['result']['recorded_request']
        adapter = adapters.get(bundle['action']['operation'])
        require(adapter is not None and adapter.normalize(p['actor'], actual).hash == action.hash, 'observed_request_mismatch')
        expected = {'record_id': p['nonce'], 'service': bundle['action']['resource'],
                    'recorded_request': actual, 'outcome': 'recorded_by_local_mock'}
        require(canonical(p['result']) == canonical(expected), 'invalid_mock_result')
        observed.add(digest(observation)); nonces.add(p['nonce'])
    states = verify_journal(evidence['deliveries'], key, checkpoint['delivery_head'] if checkpoint else None)
    for envelope in evidence['deliveries']:
        p = envelope['payload']
        auth = certificates.get(p['authorization_hash'])
        require(auth is not None and auth['receipt']['payload']['decision'] == 'allow' and
                p['attempt'] == auth['receipt']['payload']['nonce'] and
                p['action_hash'] == auth['receipt']['payload']['action_hash'], 'delivery_authorization_mismatch')
        if p['status'] == 'confirmed':
            require(digest(p['observation']) in observed and
                    p['observation']['payload']['nonce'] == p['attempt'] and
                    p['observation']['payload']['action_hash'] == p['action_hash'], 'unconfirmed_delivery')
    return {**result, 'delivery_events': len(evidence['deliveries']), 'confirmed_mock_effects': len(observed),
            'attempts': len(states)}
