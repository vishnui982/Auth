from dataclasses import FrozenInstanceError
import itertools

import pytest

from agent_guard import Action, Policy
from agent_guard.canonical import canonical, digest, loads
from agent_guard.errors import GuardError


def test_deep_immutability_and_stable_hash():
    params = {"z": [1, {"nested": "value"}], "a": True}
    action = Action("agent1", "custom", "document:public/welcome", params)
    old = action.hash
    params["z"][1]["nested"] = "changed"
    action.parameters["z"].append(2)
    assert action.hash == old
    assert action.hash == Action("agent1", "custom", "document:public/welcome",
                                 {"a": True, "z": [1, {"nested": "value"}]}).hash
    with pytest.raises(FrozenInstanceError):
        action.resource = "document:secret/payroll"


@pytest.mark.parametrize("raw", [
    '{"a":1,"a":2}', '{"a":{"b":1,"b":2}}', '{"a":NaN}', '{"a":Infinity}',
    '{"a":1.0}', '{"a":9007199254740992}', '{"a":"\\ud800"}',
    '{"a":"e\\u0301"}', '[[[[[[[[[[[[[[[[[[0]]]]]]]]]]]]]]]]]]',
])
def test_reject_ambiguous_json(raw):
    with pytest.raises(GuardError):
        loads(raw)


def test_canonical_golden_vector():
    value = {"z": 1, "a": "é", "nested": {"b": False, "a": None}}
    assert canonical(value) == '{"a":"é","nested":{"a":null,"b":false},"z":1}'.encode()
    assert digest({"a": 1}) == "015abd7f5cc57a2dd94b7590f04ad8084273905ee33ec5cebeae62276a97f862"


@pytest.mark.parametrize("resource", ["file:/etc/passwd", "document:../secret", "document:a//b",
                                      "document:a/", "document:a%2fb", "document:a\\b", "document:/root"])
def test_resource_ids_have_no_path_aliases(resource):
    with pytest.raises(GuardError):
        Action("agent1", "read", resource)


@pytest.mark.parametrize("field,value", [("version", 2), ("version", True), ("actor", 3),
                                         ("parameters", []), ("parameters", None), ("operation", "")])
def test_strict_action_schema(field, value):
    action = Action("agent1", "read", "document:a").to_dict()
    action[field] = value
    with pytest.raises(GuardError):
        Action.from_dict(action)


def test_unknown_fields_and_payload_binding():
    action = Action("agent1", "write", "document:a", {"content": "one"})
    assert action.hash != Action("agent1", "write", "document:a", {"content": "two"}).hash
    with pytest.raises(GuardError):
        Action.from_dict({**action.to_dict(), "legal": True})


def rule(effect, id="rule", actor="agent1", operation="read", resource="document:a"):
    return dict(id=id, effect=effect, actor=actor, operation=operation, resource=resource)


def test_exhaustive_finite_policy_semantics():
    # Independent set-based specification over every subset of these six rules
    # and a finite Cartesian product of actors, operations, resources, identities.
    candidates = [rule("allow", "a"), rule("deny", "d"), rule("allow", "other", actor="agent2"),
                  rule("allow", "write", operation="write"), rule("deny", "b", resource="document:b"),
                  rule("allow", "execute", operation="execute")]
    for mask in range(2 ** len(candidates)):
        rules = [r for i, r in enumerate(candidates) if mask & (1 << i)]
        policy = Policy({"version": 1, "rules": rules})
        for actor, op, resource, identity in itertools.product(
                ["agent1", "agent2"], ["read", "write", "execute"], ["document:a", "document:b"],
                ["agent1", "agent2"]):
            action = Action(actor, op, resource, {"content": "x"} if op == "write" else {})
            match = lambda r: (r["actor"], r["operation"], r["resource"]) == (actor, op, resource)
            expected = (actor == identity and op in {"read", "write"} and
                        any(match(r) and r["effect"] == "allow" for r in rules) and
                        not any(match(r) and r["effect"] == "deny" for r in rules))
            assert policy.evaluate(action, identity).allowed == expected


def test_policy_order_and_immutability():
    rules = [rule("allow", "a"), rule("deny", "d")]
    policy = Policy({"version": 1, "rules": rules})
    assert policy.hash == Policy({"version": 1, "rules": list(reversed(rules))}).hash
    old = policy.hash
    rules[0]["resource"] = "document:other"
    policy.to_dict()["rules"].clear()
    assert policy.hash == old
    assert policy.evaluate(Action("agent1", "read", "document:a"), "agent1").reason == "explicit_deny"


@pytest.mark.parametrize("rules", [[rule("maybe")], [rule("allow"), rule("deny")],
                                  [{**rule("allow"), "condition": "legal"}], [rule("allow", actor="*")]])
def test_invalid_policy_rejected(rules):
    with pytest.raises(GuardError):
        Policy({"version": 1, "rules": rules})
