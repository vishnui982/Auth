"""Verify signatures, replay policy AND state transitions, and anchor a full trace."""
from agent_guard.canonical import digest, fields
from agent_guard.crypto import verify
from agent_guard.errors import GuardError
from .model import Action, AuthorizationState, Policy, check, natural
from .semantics import query, transition

PAYLOAD = {"version", "kind", "sequence", "previous", "policy_hash", "verifier_hash", "domain",
           "actor", "action_hash", "before_hash", "after_hash", "decision", "query_hash", "time",
           "expires", "nonce", "authorization_hash", "status", "result_hash"}


def require(condition, code):
    if not condition:
        raise GuardError(code)


def verify_event(bundle, *, key, policy, verifier_hash, domain, engines):
    fields(bundle, {"action", "before", "after", "result", "receipt", "authorization"})
    action = Action.from_dict(bundle["action"])
    before, after = AuthorizationState(bundle["before"]), AuthorizationState(bundle["after"])
    p = verify(bundle["receipt"], key)
    fields(p, PAYLOAD)
    require(type(p["version"]) is int and p["version"] == 2, "invalid_version")
    for name in ("sequence", "time", "expires"):
        natural(p[name])
    require(p["sequence"] > 0 and p["domain"] == domain == bundle["before"]["domain"] == bundle["after"]["domain"], "domain_mismatch")
    require(p["policy_hash"] == policy.hash and p["verifier_hash"] == verifier_hash, "trust_mismatch")
    require(p["action_hash"] == action.hash and p["before_hash"] == before.hash and
            p["after_hash"] == after.hash and p["result_hash"] == digest(bundle["result"]), "binding_mismatch")
    require(type(p["nonce"]) is str and len(p["nonce"]) == 64 and
            all(c in "0123456789abcdef" for c in p["nonce"]), "invalid_nonce")
    q = query(policy, before, action, p["actor"], p["time"])
    d = engines.decide(q)
    require(p["query_hash"] == digest(q) and p["decision"] == ("allow" if d["allow"] else "deny"), "decision_mismatch")
    if p["kind"] == "authorization":
        require(bundle["authorization"] is None and p["authorization_hash"] is None and
                before.hash == after.hash and bundle["result"] is None and
                p["expires"] == p["time"] + 30 and
                p["status"] == ("authorized" if d["allow"] else "denied"), "invalid_authorization")
    elif p["kind"] == "execution":
        require(d["allow"], "unauthorized_execution")
        auth = verify(bundle["authorization"], key)
        fields(auth, PAYLOAD)
        require(auth["kind"] == "authorization" and auth["version"] == 2 and auth["decision"] == "allow" and
                auth["status"] == "authorized" and auth["authorization_hash"] is None and
                auth["result_hash"] == digest(None), "invalid_authorization")
        for name in ("actor", "domain", "action_hash", "before_hash", "policy_hash", "verifier_hash", "nonce", "expires"):
            require(auth[name] == p[name], "authorization_binding_mismatch")
        require(auth["after_hash"] == p["before_hash"] and
                type(auth["time"]) is int and auth["time"] <= p["time"] < auth["expires"] == auth["time"] + 30 and
                type(auth["sequence"]) is int and auth["sequence"] < p["sequence"], "invalid_authorization_time")
        aq = query(policy, before, action, auth["actor"], auth["time"])
        require(auth["query_hash"] == digest(aq) and engines.decide(aq)["allow"], "invalid_authorization_decision")
        require(p["authorization_hash"] == digest(bundle["authorization"]), "authorization_hash_mismatch")
        require(transition(policy, before, action, p["actor"], p["time"], bundle["result"]).hash == after.hash,
                "invalid_state_transition")
        require(p["status"] == ("queued" if q["effect"] == "send" else "executed"), "invalid_execution_status")
    else:
        raise GuardError("invalid_receipt_kind")
    return p


def verify_history(events, *, genesis, expected_head=None, **trust):
    state_hash, previous = genesis.hash, None
    issued, consumed = {}, set()
    for i, event in enumerate(events, 1):
        p = verify_event(event, **trust)
        require(p["sequence"] == i and p["previous"] == previous and p["before_hash"] == state_hash,
                "broken_history")
        if p["kind"] == "authorization":
            require(p["nonce"] not in issued, "duplicate_nonce")
            issued[p["nonce"]] = digest(event["receipt"])
        else:
            require(issued.get(p["nonce"]) == p["authorization_hash"] and p["nonce"] not in consumed,
                    "missing_or_replayed_authorization")
            consumed.add(p["nonce"])
        previous, state_hash = digest(event["receipt"]), p["after_hash"]
    if expected_head is not None:
        require(previous == expected_head, "checkpoint_mismatch")
    return {"head": previous, "state_hash": state_hash, "events": len(events)}
