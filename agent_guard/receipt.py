"""Public-key verification and independent replay of the finite policy relation."""

from .action import Action
from .canonical import digest, fields
from .crypto import verify
from .errors import GuardError

AUTH_FIELDS = {"kind", "version", "actor", "action_hash", "policy_hash", "state_hash",
               "verifier_hash", "audience", "decision", "reason", "rule_ids", "nonce",
               "issued_at", "expires_at"}
EXEC_FIELDS = {"kind", "version", "authorization_hash", "action_hash", "policy_hash",
               "verifier_hash", "state_before_hash", "state_after_hash", "result_hash",
               "previous_receipt", "sequence", "executed_at", "status"}


def require(condition, code):
    if not condition:
        raise GuardError(code)


def verify_authorization(envelope, *, key, action, policy, actor, audience,
                         expected_verifier, state_hash, now):
    p = verify(envelope, key)
    fields(p, AUTH_FIELDS)
    require(p["kind"] == "authorization" and type(p["version"]) is int and p["version"] == 1,
            "invalid_certificate_type")
    require(p["actor"] == actor == action.actor, "actor_mismatch")
    require(p["action_hash"] == action.hash, "action_mismatch")
    require(p["policy_hash"] == policy.hash, "policy_mismatch")
    require(p["verifier_hash"] == expected_verifier, "verifier_mismatch")
    require(p["audience"] == audience, "audience_mismatch")
    require(p["state_hash"] == state_hash, "stale_state")
    require(type(p["issued_at"]) is int and type(p["expires_at"]) is int and
            p["issued_at"] <= now < p["expires_at"] <= p["issued_at"] + 30,
            "invalid_certificate_time")
    require(type(p["nonce"]) is str and len(p["nonce"]) == 64 and
            all(c in "0123456789abcdef" for c in p["nonce"]), "invalid_nonce")
    d = policy.evaluate(action, actor)
    require(p["decision"] == ("allow" if d.allowed else "deny") and
            p["reason"] == d.reason and p["rule_ids"] == list(d.rule_ids),
            "policy_decision_mismatch")
    require(d.allowed, "authorization_denied")
    return p


def verify_bundle(bundle, *, key, policy, expected_verifier, audience):
    """Historical evidence check. Expiry is checked at the signed execution time."""
    fields(bundle, {"action", "authorization", "receipt", "result", "state_before", "state_after"})
    action = Action.from_dict(bundle["action"])
    p = verify(bundle["receipt"], key)
    fields(p, EXEC_FIELDS)
    require(p["kind"] == "execution" and type(p["version"]) is int and p["version"] == 1
            and p["status"] == "executed", "invalid_receipt_type")
    require(type(p["executed_at"]) is int, "invalid_execution_time")
    before, after = bundle["state_before"], bundle["state_after"]
    for state in (before, after):
        fields(state, {"version", "store_id", "revision", "documents_hash"})
        require(type(state["version"]) is int and state["version"] == 1 and
                type(state["revision"]) is int and state["revision"] >= 0,
                "invalid_state")
    require(before["store_id"] == after["store_id"] == audience and
            after["revision"] == before["revision"] + 1, "invalid_transition")
    require(type(p["sequence"]) is int and p["sequence"] == after["revision"], "invalid_sequence")
    require(p["authorization_hash"] == digest(bundle["authorization"]), "authorization_mismatch")
    require(p["action_hash"] == action.hash and p["policy_hash"] == policy.hash and
            p["verifier_hash"] == expected_verifier, "receipt_binding_mismatch")
    require(p["state_before_hash"] == digest(before) and
            p["state_after_hash"] == digest(after), "state_mismatch")
    require(p["result_hash"] == digest(bundle["result"]), "result_mismatch")
    verify_authorization(bundle["authorization"], key=key, action=action, policy=policy,
                         actor=action.actor, audience=audience, expected_verifier=expected_verifier,
                         state_hash=digest(before), now=p["executed_at"])
    return p


def verify_chain(bundles, *, expected_head=None, **trust):
    previous = None
    last_state = None
    for sequence, bundle in enumerate(bundles, start=1):
        p = verify_bundle(bundle, **trust)
        require(p["sequence"] == sequence and p["previous_receipt"] == previous,
                "broken_receipt_chain")
        if last_state is not None:
            require(p["state_before_hash"] == last_state, "broken_state_chain")
        previous = digest(bundle["receipt"])
        last_state = p["state_after_hash"]
    if expected_head is not None:
        require(previous == expected_head, "head_mismatch")
    return previous
