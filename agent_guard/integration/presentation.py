"""Dependency-free presentation renderer. Never fabricates signed evidence."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def render_site(output, story, policy=None, verified=False):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    paths = {'rego': 'agent_guard/v2/agent.rego', 'lean': 'proof/AgentGuard.lean',
             'checks': 'proof/Check.lean', 'proofs': 'docs/PROOFS.md', 'readme': 'README.md'}
    sources = {key: (ROOT / path).read_text() for key, path in paths.items()
               if (ROOT / path).is_file()}
    data = {'verified': verified, 'story': story, 'policy': policy, 'sources': sources}
    template = Path(__file__).with_name('ui.html').read_text()
    encoded = json.dumps(data).replace('<', '\\u003c').replace('>', '\\u003e').replace('&', '\\u0026')
    (output / 'index.html').write_text(template.replace('__DATA__', encoded))
    (output / 'technical.html').write_text(Path(__file__).with_name('technical.html').read_text())
    return output


def illustrative_story():
    """Presentation-only scenarios corresponding to the real product demo."""
    rows = [
        ('Agent A reads public information', 'A rooted read grant permits this public document. No private labels are active.', 'executed', 'data.read', 'document:project/public'),
        ('Agent A reads payroll', 'The read is allowed. PAYROLL_PRIVATE now becomes active in the shared protection domain.', 'executed', 'data.read', 'document:project/payroll'),
        ('Create a derived summary', 'The summary inherits PAYROLL_PRIVATE. Rephrasing protected information does not erase its label.', 'executed', 'data.write', 'document:project/summary'),
        ('Send to finance@company.com', 'The finance destination accepts the private label. The local mailbox would record a confirmed mock effect.', 'confirmed', 'email.send', 'sink:mail-finance'),
        ('External exfiltration blocked', 'The external destination does not accept PAYROLL_PRIVATE. The send is denied before dispatch.', 'denied', 'email.send', 'sink:mail-external'),
        ('Destination substitution rejected', 'Replacing finance with an external recipient changes the exact action commitment.', 'rejected', None, None),
        ('Consumed authorization replay rejected', 'Reusing a consumed certificate cannot create a second effect.', 'rejected', None, None),
        ('Direct HTTP bypass rejected', 'POST /payments requires valid authorization evidence at the receiving endpoint.', 'rejected', None, None),
        ('HTTP body substitution rejected', 'Replacing the authorized payment body breaks the request binding.', 'rejected', None, None),
        ('HTTP path substitution rejected', 'Moving the request to another registered endpoint breaks the path binding.', 'rejected', None, None),
        ('Protected HTTP payment confirmed', 'The exact authorized request would record one synthetic payment in the local service.', 'confirmed', 'http.post', 'sink:http-payments'),
        ('Agent B lacks authority', 'Agent B has no rooted read authority for the summary, so access is denied.', 'denied', 'data.read', 'document:project/summary'),
        ('Delegate one exact resource', 'Agent A grants Agent B read access to only the summary, with no further delegation.', 'executed', 'authority.delegate', 'document:project/summary'),
        ('Agent B reads the summary', 'The owner → Agent A → Agent B witness permits this exact read.', 'executed', 'data.read', 'document:project/summary'),
        ('Revoke the parent authority', 'The owner revokes read-project. All authority chains depending on that root become invalid.', 'executed', 'authority.revoke', 'authority:grants'),
        ('Agent B is denied after revocation', 'The delegated grant still exists, but its revoked ancestor makes it unusable.', 'denied', 'data.read', 'document:project/summary'),
        ('MCP interoperability', 'A registered documents.create call uses the same action, certificate, and recipient gate.', 'confirmed', 'tool.invoke', 'sink:mcp-documents'),
        ('Lost acknowledgement', 'A response is lost after dispatch. Delivery is unknown; automatically resending could duplicate an effect.', 'unknown', 'email.send', 'sink:mail-bob'),
        ('Reconcile without resending', 'Look up the signed recipient observation to confirm the original effect without a second send.', 'confirmed', 'email.send', 'sink:mail-bob'),
    ]
    story = []
    for i, (title, detail, status, operation, resource) in enumerate(rows):
        actor = 'agent2' if i in (11, 13, 15) else 'owner' if i == 14 else 'agent1'
        story.append({'title': title, 'detail': detail, 'status': status, 'actor': actor, 'event': None,
                      'action': {'version': 2, 'actor': actor, 'operation': operation, 'resource': resource,
                                 'parameters': {}} if operation else None,
                      'state': {'active_labels': ['PAYROLL_PRIVATE'] if i >= 1 else [],
                                'objects': {'document:project/summary': {'labels': ['PAYROLL_PRIVATE'] if i >= 2 else []}},
                                'revoked': ['read-project'] if i >= 14 else []}})
    return story
