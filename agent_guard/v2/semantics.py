"""Executable state semantics and a small witness interface shared with Lean/OPA."""
from agent_guard.canonical import canonical, digest, fields
from agent_guard.errors import GuardError
from .model import AuthorizationState, check, validate_grant


def covers(scope, prefix, resource):
    return resource == scope or (prefix and resource.startswith(scope + "/"))


def attenuates(parent, child):
    return (child["parent"] == parent["id"] and child["issuer"] == parent["subject"] and
            child["operation"] == parent["operation"] and
            covers(parent["resource"], parent["prefix"], child["resource"]) and
            (parent["prefix"] or not child["prefix"]) and child["expires"] <= parent["expires"] and
            child["remaining"] < parent["remaining"])


def chain_for(grant, grants):
    by_id = {g["id"]: g for g in grants}
    chain, seen = [], set()
    while grant is not None:
        if grant["id"] in seen or len(chain) > 16:
            return []
        seen.add(grant["id"])
        chain.append(grant)
        if grant["parent"] is None:
            return list(reversed(chain))
        grant = by_id.get(grant["parent"])
    return []


def query(policy, state, action, identity, now):
    p, s, a = policy.to_dict(), state.to_dict(), action.to_dict()
    effect = p["operations"].get(a["operation"], "unknown")
    spec = p["resources"].get(a["resource"])
    supported = spec is not None
    child, target = None, None
    try:
        if effect == "read":
            fields(a["parameters"], set())
            supported &= spec is not None and spec["kind"] == "object"
        elif effect == "write":
            fields(a["parameters"], {"value"})
            check(len(canonical(a["parameters"]["value"])) <= 16384, "value_too_large")
            supported &= spec is not None and spec["kind"] == "object"
        elif effect == "send":
            fields(a["parameters"], {"payload"})
            check(len(canonical(a["parameters"]["payload"])) <= 16384, "payload_too_large")
            supported &= spec is not None and spec["kind"] == "sink"
        elif effect == "delegate":
            fields(a["parameters"], {"grant"})
            validate_grant(a["parameters"]["grant"])
            child = a["parameters"]["grant"]
            supported = (child["resource"] == a["resource"] and child["parent"] is not None and
                         len(s["grants"]) < 256)
        elif effect == "revoke":
            fields(a["parameters"], {"grant_id"})
            target = next((g for g in s["grants"] if g["id"] == a["parameters"]["grant_id"]), None)
            supported &= spec is not None and spec["kind"] == "authority"
        else:
            supported = False
    except GuardError:
        supported, child, target = False, None, None
    operation = child["operation"] if child else a["operation"]
    return {"actor": a["actor"], "identity": identity, "actionOp": a["operation"],
        "operation": operation, "resource": a["resource"], "effect": effect, "supported": bool(supported),
        "principals": p["principals"], "administrators": p["administrators"],
        "roots": p["roots"], "chains": [chain_for(g, s["grants"]) for g in s["grants"]],
        "grantIds": [g["id"] for g in s["grants"]], "revoked": s["revoked"], "now": now,
        "denies": p["denies"], "labels": s["active_labels"],
        "objectLabels": s["objects"].get(a["resource"], {}).get("labels", []),
        "accepts": spec["accepts"] if spec else [],
        "count": s["counts"].get(a["actor"], {}).get(a["operation"], 0),
        "budget": p["budgets"].get(a["actor"], {}).get(a["operation"]),
        "child": child, "target": target}


def valid_chain(q, chain):
    return (bool(chain) and chain[0] in q["roots"] and
            all(g["id"] not in q["revoked"] and q["now"] < g["expires"] for g in chain) and
            all(attenuates(parent, child) for parent, child in zip(chain, chain[1:])))


def permitted_chain(q, chain):
    if not valid_chain(q, chain):
        return False
    leaf = chain[-1]
    return (leaf["subject"] == q["actor"] and leaf["operation"] == q["operation"] and
            covers(leaf["resource"], leaf["prefix"], q["resource"]) and
            (q["effect"] != "delegate" or
             (q["child"] is not None and attenuates(leaf, q["child"]))))


def evaluate(q):
    common = (q["supported"] and q["actor"] == q["identity"] and q["actor"] in q["principals"] and
              (q["budget"] is None or q["count"] < q["budget"]) and not any(
                  d["actor"] == q["actor"] and d["operation"] in {q["operation"], q["actionOp"]} and
                  covers(d["resource"], d["prefix"], q["resource"]) for d in q["denies"]))
    authority = any(permitted_chain(q, chain) for chain in q["chains"])
    if q["effect"] == "delegate":
        c = q["child"]
        authority = (authority and c is not None and c["issuer"] == q["actor"] and
                     c["subject"] in q["principals"] and c["id"] not in q["grantIds"] and
                     q["now"] < c["expires"])
    elif q["effect"] == "revoke":
        t = q["target"]
        authority = (t is not None and t["id"] not in q["revoked"] and
                     (q["actor"] in q["administrators"] or q["actor"] in {t["issuer"], t["subject"]}))
    flow = q["effect"] != "send" or set(q["labels"]) <= set(q["accepts"])
    allowed = bool(common and authority and flow)
    labels = sorted(set(q["labels"]) | (set(q["objectLabels"]) if allowed and q["effect"] == "read" else set()))
    return {"allow": allowed, "nextLabels": labels}


def transition(policy, state, action, identity, now, result):
    q = query(policy, state, action, identity, now)
    decision = evaluate(q)
    check(decision["allow"], "transition_not_authorized")
    s, a = state.to_dict(), action.to_dict()
    s["step"] += 1
    s["active_labels"] = decision["nextLabels"]
    counts = s["counts"].setdefault(a["actor"], {})
    counts[a["operation"]] = counts.get(a["operation"], 0) + 1
    effect = q["effect"]
    if effect == "read":
        fields(result, {"value"})
        check(digest(result["value"]) == s["objects"][a["resource"]]["value_hash"], "read_value_mismatch")
    elif effect == "write":
        check(result == {"written": True}, "write_result_mismatch")
        obj = s["objects"][a["resource"]]
        obj["value_hash"] = digest(a["parameters"]["value"])
        obj["labels"] = sorted(set(obj["labels"]) | set(s["active_labels"]))
    elif effect == "send":
        # This is durable enqueue, not a claim of network delivery.
        item = {"id": digest({"domain": s["domain"], "step": s["step"], "action": a}),
                "actor": a["actor"], "resource": a["resource"], "payload": a["parameters"]["payload"],
                "labels": s["active_labels"]}
        check(result == {"status": "queued", "intent": item}, "queue_result_mismatch")
        s["outbox_hash"] = digest({"previous": s["outbox_hash"], "intent": item})
    elif effect == "delegate":
        check(result == {"delegated": q["child"]["id"]}, "delegation_result_mismatch")
        s["grants"].append(q["child"])
    elif effect == "revoke":
        check(result == {"revoked": q["target"]["id"]}, "revocation_result_mismatch")
        s["revoked"] = sorted(s["revoked"] + [q["target"]["id"]])
    return AuthorizationState(s)
