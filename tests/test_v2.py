import copy
from concurrent.futures import ThreadPoolExecutor
import hashlib
from pathlib import Path
import random
import subprocess
import threading

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from agent_guard.canonical import canonical, digest
from agent_guard.crypto import sign
from agent_guard.errors import GuardError
from agent_guard.v2.audit import verify_event, verify_history
from agent_guard.v2.engines import Engines
from agent_guard.v2.example import VALUES, example_policy
from agent_guard.v2.gateway import Gateway
from agent_guard.v2.model import Action, AuthorizationState, Policy, initial_state
from agent_guard.v2.semantics import evaluate, query, transition

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def engines():
    # Required integration dependency: absence is a failure, never a silently skipped proof test.
    return Engines(ROOT / "tools/bin/opa", ROOT / "proof/.lake/build/bin/guard-kernel")


@pytest.fixture
def gate(tmp_path, engines):
    return Gateway.create(tmp_path / "store.sqlite", Policy(example_policy()), Ed25519PrivateKey.generate(),
                          engines, VALUES, clock=lambda: 1000)


def act(op="data.read", rid="document:project/public", params=None, actor="agent1"):
    return Action(actor, op, rid, params)


def snap(g):
    with g.transaction() as db:
        return g.state(db)


def allowed(g, action, actor=None):
    event = g.act(action, actor or action.to_dict()["actor"])
    assert event["receipt"]["payload"]["decision"] == "allow"
    return event


def denied(g, action, actor=None):
    before = snap(g).hash
    event = g.act(action, actor or action.to_dict()["actor"])
    assert event["receipt"]["payload"]["decision"] == "deny"
    assert snap(g).hash == before
    verify_event(event, **g.verification_args())
    return event


def child(**changes):
    return {**dict(id="child-read", issuer="agent1", subject="agent2", operation="data.read",
                    resource="document:project/public", prefix=False, expires=4000000000,
                    remaining=0, parent="read-project"), **changes}


def delegate(grant, actor="agent1"):
    return act("authority.delegate", grant["resource"], {"grant": grant}, actor)


def test_actual_lean_proofs_are_checked():
    result = subprocess.run([str(ROOT / "tools/bin/lake"), "env", "lean", "Check.lean"],
                             cwd=ROOT / "proof", capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "sorryAx" not in result.stdout
    for forbidden in ("sorry", "admit", "axiom"):
        assert not __import__("re").search(r"\b" + forbidden + r"\b", (ROOT / "proof/AgentGuard.lean").read_text())


def test_deep_immutable_state_action_policy(engines):
    p = example_policy()
    policy = Policy(p)
    state = initial_state(policy, "domain", VALUES)
    h = state.hash
    state.to_dict()["grants"][0]["remaining"] = 100
    p["roots"].clear()
    assert state.hash == h and policy.to_dict()["roots"]
    value = {"value": {"x": [1, 2]}}
    action = act("data.write", params=value)
    old = action.hash
    value["value"]["x"].append(3)
    assert action.hash == old


def test_three_evaluators_differential_adversarial_inputs(engines):
    policy = Policy(example_policy())
    state = initial_state(policy, "domain", VALUES)
    base = query(policy, state, act(), "agent1", 1000)
    rng = random.Random(1729)
    # Real independent OPA and compiled Lean execution on every generated case.
    for _ in range(64):
        q = copy.deepcopy(base)
        q["effect"] = rng.choice(["read", "write", "send", "delegate", "revoke"])
        q["actor"] = rng.choice(["agent1", "agent2", "unknown"])
        q["identity"] = rng.choice(["agent1", "agent2"])
        q["supported"] = rng.choice([True, False])
        q["labels"] = rng.choice([[], ["PII"], ["PII", "CONFIDENTIAL"]])
        q["accepts"] = rng.choice([[], ["PII"], ["PII", "CONFIDENTIAL"]])
        q["budget"], q["count"] = rng.choice([None, 0, 1, 5]), rng.randrange(5)
        q["revoked"] = rng.choice([[], ["read-project"]])
        q["now"] = rng.choice([1000, 4102444800])
        assert engines.decide(q) == evaluate(q)
    # Positive witnesses and mutations exercise delegation, not just early denials.
    valid = query(policy, state, delegate(child()), "agent1", 1000)
    assert engines.decide(valid)["allow"]
    for field, value in [("issuer", "agent2"), ("remaining", 3), ("expires", 4200000000),
                         ("resource", "document:project-other/public"), ("operation", "data.write"),
                         ("parent", "missing"), ("id", "read-project"), ("subject", "unknown")]:
        q = copy.deepcopy(valid)
        q["child"][field] = value
        assert not engines.decide(q)["allow"]


def test_protected_read_derivation_and_cross_agent_flow(gate):
    g = gate
    allowed(g, act("message.send", "sink:external", {"payload": "public"}))
    allowed(g, act(rid="document:project/payroll"))
    allowed(g, act("data.write", "document:project/summary", {"value": {"summary": "private"}}))
    s = snap(g).to_dict()
    assert s["active_labels"] == ["PII"]
    assert s["objects"]["document:project/summary"]["labels"] == ["PII"]
    denied(g, act("message.send", "sink:external", {"payload": "private"}))
    denied(g, act("message.send", "sink:external", {"payload": "private"}, "agent2"))
    internal = allowed(g, act("message.send", "sink:internal", {"payload": "private"}))
    assert internal["receipt"]["payload"]["status"] == "queued"
    assert internal["result"]["intent"]["labels"] == ["PII"]
    verify_history(g.export(), genesis=g.genesis, **g.verification_args())


def test_delegation_rooted_and_revocation_cascades(gate):
    g = gate
    denied(g, act(actor="agent2"))
    allowed(g, delegate(child()))
    allowed(g, act(actor="agent2"))
    stale = g.authorize(act(actor="agent2"), "agent2")
    allowed(g, act("authority.revoke", "authority:grants", {"grant_id": "read-project"}, "owner"))
    with pytest.raises(GuardError, match="stale_state"):
        g.execute(act(actor="agent2"), "agent2", stale["receipt"])
    denied(g, act(actor="agent2"))
    verify_history(g.export(), genesis=g.genesis, **g.verification_args())


@pytest.mark.parametrize("changes", [
    {"remaining": 2}, {"expires": 4200000000}, {"issuer": "agent2"}, {"subject": "unknown"},
    {"operation": "data.write"}, {"parent": "unknown"}, {"id": "read-project"},
    {"resource": "document:project-other/public"},
])
def test_cannot_amplify_delegation(gate, changes):
    denied(gate, delegate(child(**changes)))


def test_child_cannot_redelegate_non_delegable_permission(gate):
    allowed(gate, delegate(child()))
    grandchild = child(id="grandchild", parent="child-read", issuer="agent2", subject="agent1")
    denied(gate, delegate(grandchild, "agent2"))


def test_unrelated_principal_cannot_revoke(gate):
    denied(gate, act("authority.revoke", "authority:grants", {"grant_id": "read-project"}, "agent2"))


def test_explicit_deny_overrides_delegated_or_direct_authority(engines):
    p = example_policy()
    p["denies"] = [{"actor": "agent1", "operation": "data.read", "resource": "document:project", "prefix": True}]
    policy = Policy(p)
    state = initial_state(policy, "domain", VALUES)
    assert not engines.decide(query(policy, state, act(), "agent1", 1000))["allow"]
    assert not engines.decide(query(policy, state, delegate(child()), "agent1", 1000))["allow"]


def test_all_label_combinations_and_unknown_operation(engines):
    policy = Policy(example_policy())
    state = initial_state(policy, "domain", VALUES)
    base = query(policy, state, act("message.send", "sink:external", {"payload": "x"}), "agent1", 1000)
    for labels in [[], ["PII"], ["CONFIDENTIAL"], ["PII", "CONFIDENTIAL"]]:
        for accepts in [[], ["PII"], ["CONFIDENTIAL"], ["PII", "CONFIDENTIAL"]]:
            q = {**base, "labels": labels, "accepts": accepts}
            assert engines.decide(q)["allow"] == (set(labels) <= set(accepts))
    q = query(policy, state, act("shell.execute", params={"command": "ignored"}), "agent1", 1000)
    assert not engines.decide(q)["allow"]


def test_stored_genesis_cannot_replace_external_trust_anchor(gate):
    fake = copy.deepcopy(gate.trust)
    fake["genesis"]["active_labels"] = ["PII"]
    with gate.transaction() as db:
        db.execute("UPDATE meta SET value=? WHERE key='trust'", (canonical(fake).decode(),))
    with pytest.raises(GuardError, match="stored_trust_mismatch"):
        Gateway(gate.path, gate.policy, gate.key, gate.engines, clock=gate.clock, trust=gate.trust)


def test_root_expiry_between_authorize_and_execute(gate):
    gate.clock = lambda: 4102444799
    c = gate.authorize(act(), "agent1")
    gate.clock = lambda: 4102444800
    with pytest.raises(GuardError, match="authorization_no_longer_valid"):
        gate.execute(act(), "agent1", c["receipt"])


def test_prefix_matching_is_segment_bounded(gate):
    # Unknown resources and near-prefix aliases never gain authority.
    denied(gate, act(rid="document:project-evil/public"))
    for rid in ["document:project/../payroll", "document:project%2fpayroll", "document:project//payroll"]:
        with pytest.raises(GuardError):
            act(rid=rid)


def test_budget_cannot_be_raced(gate):
    action = act("data.write", "kv:settings/theme", {"value": {"theme": "dark"}})
    with ThreadPoolExecutor(max_workers=5) as pool:
        events = list(pool.map(lambda _: gate.act(action, "agent1"), range(5)))
    assert sum(b["receipt"]["payload"]["decision"] == "allow" for b in events) == 3
    assert snap(gate).to_dict()["counts"]["agent1"]["data.write"] == 3


def test_one_certificate_commits_once(gate):
    c = gate.authorize(act(), "agent1")["receipt"]
    def attempt(_):
        try:
            gate.execute(act(), "agent1", c)
            return True
        except GuardError:
            return False
    with ThreadPoolExecutor(max_workers=4) as pool:
        assert sum(pool.map(attempt, range(4))) == 1


def test_restart_checks_history_and_persistent_replay(gate):
    event = allowed(gate, act())
    restarted = Gateway(gate.path, gate.policy, gate.key, gate.engines, clock=gate.clock, trust=gate.trust)
    with pytest.raises(GuardError):
        restarted.execute(act(), "agent1", event["authorization"])
    with gate.transaction() as db:
        db.execute("UPDATE issued SET consumed=0")
    with pytest.raises(GuardError, match="nonce_state_mismatch"):
        Gateway(gate.path, gate.policy, gate.key, gate.engines, clock=gate.clock, trust=gate.trust)


def test_audit_failure_rolls_back_write_authority_state_and_nonce(gate, monkeypatch):
    a = act("data.write", "document:project/summary", {"value": "new"})
    c = gate.authorize(a, "agent1")["receipt"]
    before = snap(gate).hash
    record = gate._record
    def fail(*args, **kwargs):
        raise OSError("simulated disk full")
    monkeypatch.setattr(gate, "_record", fail)
    with pytest.raises(OSError):
        gate.execute(a, "agent1", c)
    assert snap(gate).hash == before
    monkeypatch.setattr(gate, "_record", record)
    gate.execute(a, "agent1", c)


def test_opa_lean_disagreement_fails_closed(gate, monkeypatch):
    run = gate.engines._run
    def disagree(command, data):
        result = run(command, data)
        if command[0] == str(gate.engines.lean):
            result["allow"] = not result["allow"]
        return result
    monkeypatch.setattr(gate.engines, "_run", disagree)
    with pytest.raises(GuardError, match="verification_engine_disagreement"):
        gate.act(act(), "agent1")
    assert gate.export() == []


@pytest.mark.parametrize("invalid", [{}, {"allow": 1, "nextLabels": []}, {"allow": True, "nextLabels": [4]}])
def test_malformed_engine_result_fails_closed(gate, monkeypatch, invalid):
    run = gate.engines._run
    monkeypatch.setattr(gate.engines, "_run", lambda command, data:
                        invalid if command[0] == str(gate.engines.lean) else run(command, data))
    with pytest.raises(GuardError, match="invalid_engine_result"):
        gate.act(act(), "agent1")


def test_engine_missing_or_timeout_does_not_fallback(gate, monkeypatch):
    def fail(*args, **kwargs):
        raise subprocess.TimeoutExpired("lean", 15)
    monkeypatch.setattr(subprocess, "run", fail)
    with pytest.raises(GuardError, match="verification_engine_unavailable"):
        gate.act(act(), "agent1")


@pytest.mark.parametrize("part", ["action", "before", "after", "result", "receipt", "authorization"])
def test_tampering_all_evidence_components(gate, part):
    bundle = allowed(gate, act())
    if part == "action":
        bundle[part]["resource"] = "document:project/payroll"
    elif part in {"before", "after"}:
        bundle[part]["active_labels"] = ["PII"]
    elif part == "result":
        bundle[part]["value"] = "changed"
    else:
        bundle[part]["payload"]["actor"] = "agent2"
    with pytest.raises(GuardError):
        verify_event(bundle, **gate.verification_args())


def test_even_signed_false_transition_is_rejected(gate):
    event = allowed(gate, act(rid="document:project/payroll"))
    event["after"]["active_labels"] = []
    event["receipt"]["payload"]["after_hash"] = digest(event["after"])
    event["receipt"] = sign(event["receipt"]["payload"], gate.key)
    with pytest.raises(GuardError, match="invalid_state_transition"):
        verify_event(event, **gate.verification_args())


def test_trace_genesis_missing_authorization_and_truncation(gate):
    allowed(gate, act())
    denied(gate, act(actor="agent2"))
    history = gate.export()
    verified = verify_history(history, genesis=gate.genesis, **gate.verification_args())
    for bad in [history[1:], history[::-1], history + [history[0]]]:
        with pytest.raises(GuardError):
            verify_history(bad, genesis=gate.genesis, **gate.verification_args())
    with pytest.raises(GuardError, match="checkpoint_mismatch"):
        verify_history(history[:-1], genesis=gate.genesis, expected_head=verified["head"], **gate.verification_args())


def test_http_v2_identity_and_resource_certificate_boundary(gate):
    from agent_guard.server import make_server
    from agent_guard.client import request
    token = "synthetic-test-token"
    server = make_server(gate, {hashlib.sha256(token.encode()).hexdigest(): "agent1"}, port=0,
                         action_type=Action, api_version="v2", receipt_key="receipt")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_port}"
    try:
        body = {"action": act().to_dict()}
        status, auth = request(url, token, body, "authorize", api_version="v2")
        assert status == 200
        status, event = request(url, token, {**body, "authorization": auth["receipt"]}, "execute", api_version="v2")
        assert status == 200
        verify_event(event, **gate.verification_args())
        assert request(url, token, {**body, "authorization": {}}, "execute", api_version="v2")[0] == 400
        assert request(url, "wrong", body, api_version="v2")[0] == 401
        body["action"]["actor"] = "owner"
        assert request(url, token, body, api_version="v2")[0] == 403
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
