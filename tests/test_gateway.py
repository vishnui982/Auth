import copy
from concurrent.futures import ThreadPoolExecutor
import threading

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from agent_guard import Action, Policy
from agent_guard.canonical import digest
from agent_guard.cli import load_gateway
from agent_guard.crypto import sign
from agent_guard.errors import GuardError
from agent_guard.gateway import Gateway
from agent_guard.receipt import verify_bundle, verify_chain


def read():
    return Action("agent1", "read", "document:public/welcome")


def write(content="new"):
    return Action("agent1", "write", "document:drafts/note", {"content": content})


def state(g):
    with g.store.transaction() as db:
        return g.store.state(db)


def test_end_to_end_read_write_receipts(setup):
    g, _, trust = setup
    first = g.act(read(), "agent1")
    assert first["result"] == {"content": "Welcome to Agent Guard."}
    verify_bundle(first, **trust)
    g.act(write(), "agent1")
    last = g.act(Action("agent1", "read", "document:drafts/note"), "agent1")
    assert last["result"] == {"content": "new"}
    history = g.store.export()
    assert verify_chain(history, **trust) == digest(last["receipt"])


@pytest.mark.parametrize("action,actor,reason", [
    (Action("agent1", "read", "document:secret/payroll"), "agent1", "explicit_deny"),
    (Action("agent1", "write", "document:public/welcome", {"content": "bad"}), "agent1", "default_deny"),
    (Action("agent1", "delete", "document:public/welcome"), "agent1", "unsupported_operation"),
    (Action("agent1", "execute", "document:public/welcome"), "agent1", "unsupported_operation"),
    (Action("agent1", "read", "document:public/welcome", {"extra": True}), "agent1", "invalid_fields"),
    (read(), "agent2", "actor_mismatch"),
])
def test_denial_has_no_effect(setup, action, actor, reason):
    g, _, _ = setup
    before = state(g)
    response = g.act(action, actor)
    assert response["authorization"]["payload"]["decision"] == "deny"
    assert response["authorization"]["payload"]["reason"] == reason
    assert "result" not in response
    assert state(g) == before
    assert g.store.export() == []


def test_no_certificate_no_execution(setup):
    g, _, _ = setup
    with pytest.raises(GuardError):
        g.execute(write(), "agent1", {})
    assert state(g)["revision"] == 0


@pytest.mark.parametrize("altered", [write("changed"), Action("agent1", "write", "document:public/welcome", {"content": "new"}),
                                    Action("agent1", "read", "document:drafts/note"),
                                    Action("agent2", "write", "document:drafts/note", {"content": "new"})])
def test_action_substitution(setup, altered):
    g, _, _ = setup
    certificate = g.authorize(write(), "agent1")
    with pytest.raises(GuardError):
        g.execute(altered, "agent1", certificate)
    assert state(g)["revision"] == 0


@pytest.mark.parametrize("field,value,reason", [
    ("policy_hash", "wrong", "policy_mismatch"), ("verifier_hash", "wrong", "verifier_mismatch"),
    ("audience", "wrong", "audience_mismatch"), ("state_hash", "wrong", "stale_state"),
    ("actor", "agent2", "actor_mismatch"), ("decision", "deny", "policy_decision_mismatch"),
    ("rule_ids", [], "policy_decision_mismatch"), ("nonce", "x", "invalid_nonce"),
    ("kind", "execution", "invalid_certificate_type"),
])
def test_resource_checks_all_bindings_even_if_signed(setup, field, value, reason):
    g, _, _ = setup
    p = g.authorize(write(), "agent1")["payload"]
    p[field] = value
    with pytest.raises(GuardError, match=reason):
        g.execute(write(), "agent1", sign(p, g.key))
    assert state(g)["revision"] == 0


def test_bad_signature_and_wrong_signer(setup):
    g, _, _ = setup
    cert = g.authorize(write(), "agent1")
    for forged in [{**cert, "signature": "!"}, sign(cert["payload"], Ed25519PrivateKey.generate())]:
        with pytest.raises(GuardError, match="invalid_signature"):
            g.execute(write(), "agent1", forged)


def test_expiry_future_and_max_lifetime(setup):
    old, _, _ = setup
    clock = [1000]
    g = Gateway(old.store, old.policy, old.key, clock=lambda: clock[0])
    cert = g.authorize(write(), "agent1")
    for now in [999, 1030, 9999]:
        clock[0] = now
        with pytest.raises(GuardError, match="invalid_certificate_time"):
            g.execute(write(), "agent1", cert)
    clock[0] = 1001
    p = copy.deepcopy(cert["payload"])
    p["expires_at"] = 2000
    with pytest.raises(GuardError, match="invalid_certificate_time"):
        g.execute(write(), "agent1", sign(p, g.key))
    g.execute(write(), "agent1", cert)


def test_replay_survives_restart(setup):
    g, _, _ = setup
    certificate = g.authorize(write(), "agent1")
    g.execute(write(), "agent1", certificate)
    restarted = load_gateway(g.store.path.parent)
    with pytest.raises(GuardError):
        restarted.execute(write(), "agent1", certificate)
    assert state(restarted)["revision"] == 1
    assert len(restarted.store.export()) == 1


def test_stale_authorization_after_different_action(setup):
    g, _, _ = setup
    cert = g.authorize(write(), "agent1")
    g.act(read(), "agent1")
    with pytest.raises(GuardError, match="stale_state"):
        g.execute(write(), "agent1", cert)


def test_concurrent_certificate_executes_once(setup):
    g, _, _ = setup
    cert = g.authorize(write(), "agent1")
    barrier = threading.Barrier(8)
    def attempt(_):
        barrier.wait()
        try:
            g.execute(write(), "agent1", cert)
            return True
        except GuardError:
            return False
    with ThreadPoolExecutor(max_workers=8) as pool:
        assert sum(pool.map(attempt, range(8))) == 1
    assert state(g)["revision"] == 1


def test_concurrent_act_produces_valid_chain(setup):
    g, _, trust = setup
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(lambda _: g.act(read(), "agent1"), range(16)))
    history = g.store.export()
    assert len(history) == 16
    verify_chain(history, **trust)


def test_audit_failure_rolls_back_effect_and_nonce(setup, monkeypatch):
    g, _, _ = setup
    cert = g.authorize(write(), "agent1")
    before = state(g)
    original = g.store.record
    def fail(*_):
        raise OSError("simulated disk full")
    monkeypatch.setattr(g.store, "record", fail)
    with pytest.raises(OSError):
        g.execute(write(), "agent1", cert)
    assert state(g) == before
    assert g.store.export() == []
    monkeypatch.setattr(g.store, "record", original)
    g.execute(write(), "agent1", cert)


def test_missing_resource_does_not_record_success(setup):
    g, _, _ = setup
    with g.store.transaction() as db:
        db.execute("DELETE FROM documents WHERE resource = 'document:drafts/note'")
    with pytest.raises(GuardError, match="resource_not_found"):
        g.act(write(), "agent1")
    assert state(g)["revision"] == 0
    assert g.store.export() == []


def test_configuration_pins_block_silent_policy_or_key_changes(setup):
    g, _, _ = setup
    with pytest.raises(GuardError, match="store_configuration_mismatch"):
        Gateway(g.store, Policy({"version": 1, "rules": []}), g.key)
    with pytest.raises(GuardError, match="store_configuration_mismatch"):
        Gateway(g.store, g.policy, Ed25519PrivateKey.generate())


@pytest.mark.parametrize("part", ["action", "authorization", "receipt", "result", "state_before", "state_after"])
def test_offline_bundle_tampering(setup, part):
    g, _, trust = setup
    bundle = g.act(read(), "agent1")
    if part == "action":
        bundle[part]["resource"] = "document:drafts/note"
    elif part in {"authorization", "receipt"}:
        bundle[part]["payload"]["action_hash"] = "changed"
    elif part == "result":
        bundle[part]["content"] = "changed"
    else:
        bundle[part]["revision"] += 1
    with pytest.raises(GuardError):
        verify_bundle(bundle, **trust)


def test_offline_wrong_trust_anchor(setup):
    g, _, trust = setup
    bundle = g.act(read(), "agent1")
    for changes in [{"key": Ed25519PrivateKey.generate().public_key()}, {"audience": "wrong"},
                    {"expected_verifier": "wrong"}, {"policy": Policy({"version": 1, "rules": []})}]:
        with pytest.raises(GuardError):
            verify_bundle(bundle, **{**trust, **changes})


def test_chain_reordering_removal_and_checkpoint(setup):
    g, _, trust = setup
    for _ in range(3):
        g.act(read(), "agent1")
    history = g.store.export()
    head = verify_chain(history, **trust)
    for bad in [history[::-1], history[1:], [history[0], history[2]], history + [history[0]]]:
        with pytest.raises(GuardError):
            verify_chain(bad, **trust)
    # A valid prefix is indistinguishable from a complete history without a checkpoint.
    verify_chain(history[:2], **trust)
    with pytest.raises(GuardError, match="head_mismatch"):
        verify_chain(history[:2], expected_head=head, **trust)
