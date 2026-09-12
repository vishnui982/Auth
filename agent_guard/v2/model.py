"""Strict, immutable wire objects. Resource names never resolve to host paths."""
from dataclasses import dataclass
import re

from agent_guard.canonical import canonical, digest, fields, loads
from agent_guard.errors import GuardError

ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
OP = re.compile(r"[a-z][a-z0-9_.-]{0,63}\Z")
RESOURCE = re.compile(r"[a-z][a-z0-9-]{0,31}:[A-Za-z0-9][A-Za-z0-9_/-]{0,191}\Z")
GRANT = {"id", "issuer", "subject", "operation", "resource", "prefix", "expires", "remaining", "parent"}
EFFECTS = {"read", "write", "send", "delegate", "revoke"}


def check(ok, code="invalid_model"):
    if not ok:
        raise GuardError(code, 400)


def ident(value):
    check(type(value) is str and ID.fullmatch(value), "invalid_identifier")


def resource(value):
    check(type(value) is str and RESOURCE.fullmatch(value) and "//" not in value and
          not value.endswith("/"), "invalid_resource")


def natural(value, bound=2**53 - 1):
    check(type(value) is int and 0 <= value <= bound, "invalid_integer")


def names(value, limit=128):
    check(type(value) is list and len(value) <= limit and all(type(x) is str for x in value))
    check(len(set(value)) == len(value), "duplicate_identifier")
    for x in value:
        ident(x)


def validate_grant(g):
    fields(g, GRANT)
    for f in ("id", "issuer", "subject"):
        ident(g[f])
    check(type(g["operation"]) is str and OP.fullmatch(g["operation"]))
    resource(g["resource"])
    check(type(g["prefix"]) is bool)
    natural(g["expires"])
    natural(g["remaining"], 16)
    if g["parent"] is not None:
        ident(g["parent"])


@dataclass(frozen=True, init=False)
class Snapshot:
    _bytes: bytes

    def __init__(self, value):
        object.__setattr__(self, "_bytes", canonical(value))

    def to_dict(self):
        return loads(self._bytes)

    @property
    def hash(self):
        return digest(self.to_dict())


class Action(Snapshot):
    def __init__(self, actor, operation, resource_id, parameters=None):
        ident(actor)
        check(type(operation) is str and OP.fullmatch(operation), "invalid_operation")
        resource(resource_id)
        parameters = {} if parameters is None else parameters
        check(type(parameters) is dict, "invalid_parameters")
        super().__init__({"version": 2, "actor": actor, "operation": operation,
                          "resource": resource_id, "parameters": parameters})

    @classmethod
    def from_dict(cls, value):
        fields(value, {"version", "actor", "operation", "resource", "parameters"})
        check(type(value["version"]) is int and value["version"] == 2)
        check(type(value["parameters"]) is dict)
        return cls(value["actor"], value["operation"], value["resource"], value["parameters"])


class Policy(Snapshot):
    def __init__(self, value):
        fields(value, {"version", "principals", "administrators", "labels", "roots", "denies",
                       "operations", "resources", "budgets"})
        check(type(value["version"]) is int and value["version"] == 2)
        for key in ("principals", "administrators", "labels"):
            names(value[key], 64)
        check(set(value["administrators"]) <= set(value["principals"]))
        check(type(value["operations"]) is dict and 0 < len(value["operations"]) <= 64)
        for op, effect in value["operations"].items():
            check(OP.fullmatch(op) and type(effect) is str and effect in EFFECTS)
        check(type(value["resources"]) is dict and len(value["resources"]) <= 64)
        for rid, spec in value["resources"].items():
            resource(rid)
            fields(spec, {"kind", "labels", "accepts"})
            check(spec["kind"] in ("object", "sink", "authority"))
            names(spec["labels"])
            names(spec["accepts"])
            check(set(spec["labels"] + spec["accepts"]) <= set(value["labels"]))
        check(type(value["roots"]) is list and len(value["roots"]) <= 64)
        seen = set()
        for g in value["roots"]:
            validate_grant(g)
            check(g["parent"] is None and g["issuer"] in value["administrators"] and
                  g["subject"] in value["principals"] and g["id"] not in seen and
                  g["operation"] in value["operations"], "invalid_authority_root")
            seen.add(g["id"])
        check(type(value["denies"]) is list and len(value["denies"]) <= 128)
        for d in value["denies"]:
            fields(d, {"actor", "operation", "resource", "prefix"})
            check(d["actor"] in value["principals"] and d["operation"] in value["operations"])
            resource(d["resource"])
            check(type(d["prefix"]) is bool)
        check(type(value["budgets"]) is dict)
        for actor, limits in value["budgets"].items():
            check(actor in value["principals"] and type(limits) is dict)
            for op, limit in limits.items():
                check(op in value["operations"])
                natural(limit)
        super().__init__(value)


class AuthorizationState(Snapshot):
    def __init__(self, value):
        fields(value, {"version", "domain", "step", "grants", "revoked", "active_labels",
                       "objects", "counts", "facts", "outbox_hash"})
        check(type(value["version"]) is int and value["version"] == 2)
        ident(value["domain"])
        natural(value["step"])
        check(type(value["grants"]) is list and len(value["grants"]) <= 256)
        ids = set()
        for g in value["grants"]:
            validate_grant(g)
            check(g["id"] not in ids, "duplicate_grant")
            ids.add(g["id"])
        names(value["revoked"], 256)
        names(value["active_labels"])
        names(value["facts"])
        check(type(value["objects"]) is dict and len(value["objects"]) <= 64)
        for rid, obj in value["objects"].items():
            resource(rid)
            fields(obj, {"labels", "value_hash"})
            names(obj["labels"])
            check(type(obj["value_hash"]) is str and re.fullmatch("[0-9a-f]{64}", obj["value_hash"]))
        check(type(value["counts"]) is dict)
        for actor, counts in value["counts"].items():
            ident(actor)
            check(type(counts) is dict)
            for op, count in counts.items():
                check(OP.fullmatch(op))
                natural(count)
        check(type(value["outbox_hash"]) is str and re.fullmatch("[0-9a-f]{64}", value["outbox_hash"]))
        super().__init__(value)


def initial_state(policy, domain, values):
    p = policy.to_dict()
    expected = {r for r, spec in p["resources"].items() if spec["kind"] == "object"}
    check(set(values) == expected, "initial_resources_mismatch")
    return AuthorizationState({"version": 2, "domain": domain, "step": 0,
        "grants": p["roots"], "revoked": [], "active_labels": [], "facts": [], "counts": {},
        "objects": {r: {"labels": sorted(p["resources"][r]["labels"]), "value_hash": digest(v)}
                    for r, v in values.items()}, "outbox_hash": digest([])})
