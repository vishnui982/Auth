"""Synthetic policy demonstrating two resource namespaces and explicit authority."""
def example_policy(expires=4102444800):
    roots = []
    for gid, subject, op, resource, prefix, remaining in [
        ("read-project", "agent1", "data.read", "document:project", True, 2),
        ("write-project", "agent1", "data.write", "document:project", True, 1),
        ("write-settings", "agent1", "data.write", "kv:settings", True, 0),
        ("send-external", "agent1", "message.send", "sink:external", False, 1),
        ("send-internal", "agent1", "message.send", "sink:internal", False, 1),
        ("child-send", "agent2", "message.send", "sink:external", False, 0),
    ]:
        roots.append(dict(id=gid, issuer="owner", subject=subject, operation=op,
                          resource=resource, prefix=prefix, remaining=remaining, expires=expires, parent=None))
    return {"version": 2, "principals": ["owner", "agent1", "agent2"], "administrators": ["owner"],
        "labels": ["PII", "CONFIDENTIAL"], "roots": roots, "denies": [],
        "operations": {"data.read": "read", "data.write": "write", "message.send": "send",
                       "authority.delegate": "delegate", "authority.revoke": "revoke"},
        "resources": {
            "document:project/public": {"kind": "object", "labels": [], "accepts": []},
            "document:project/payroll": {"kind": "object", "labels": ["PII"], "accepts": []},
            "document:project/summary": {"kind": "object", "labels": [], "accepts": []},
            "kv:settings/theme": {"kind": "object", "labels": [], "accepts": []},
            "sink:external": {"kind": "sink", "labels": [], "accepts": []},
            "sink:internal": {"kind": "sink", "labels": [], "accepts": ["PII", "CONFIDENTIAL"]},
            "authority:grants": {"kind": "authority", "labels": [], "accepts": []}},
        "budgets": {"agent1": {"data.write": 3}}}


VALUES = {"document:project/public": "Public example", "document:project/payroll": {"synthetic_payroll": 100},
          "document:project/summary": "", "kv:settings/theme": {"theme": "light"}}
