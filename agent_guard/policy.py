"""Pure finite authorization relation: exact grants, deny overrides, default deny."""

from dataclasses import dataclass

from .action import Action, validate_tool
from .canonical import canonical, digest, fields, loads
from .errors import GuardError


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    rule_ids: tuple[str, ...] = ()


@dataclass(frozen=True, init=False)
class Policy:
    _data: bytes

    def __init__(self, value):
        fields(value, {"version", "rules"})
        if type(value["version"]) is not int or value["version"] != 1:
            raise GuardError("unsupported_policy_version", 400)
        if type(value["rules"]) is not list or len(value["rules"]) > 256:
            raise GuardError("invalid_rules", 400)
        ids = set()
        for rule in value["rules"]:
            fields(rule, {"id", "effect", "actor", "operation", "resource"})
            if type(rule["id"]) is not str or not rule["id"] or rule["id"] in ids:
                raise GuardError("invalid_rule_id", 400)
            ids.add(rule["id"])
            if rule["effect"] not in ("allow", "deny"):
                raise GuardError("invalid_effect", 400)
            Action(rule["actor"], rule["operation"], rule["resource"])
        # Rule order has no meaning; commit to the normalized rule set.
        normalized = {"version": 1, "rules": sorted(value["rules"], key=lambda r: r["id"])}
        object.__setattr__(self, "_data", canonical(normalized))

    def to_dict(self):
        return loads(self._data)

    @property
    def hash(self):
        return digest(self.to_dict())

    def evaluate(self, action: Action, authenticated_actor: str) -> Decision:
        if authenticated_actor != action.actor:
            return Decision(False, "actor_mismatch")
        try:
            validate_tool(action)
        except GuardError as exc:
            return Decision(False, exc.code)
        matching = [r for r in self.to_dict()["rules"] if
                    (r["actor"], r["operation"], r["resource"]) ==
                    (action.actor, action.operation, action.resource)]
        denies = tuple(r["id"] for r in matching if r["effect"] == "deny")
        allows = tuple(r["id"] for r in matching if r["effect"] == "allow")
        if denies:
            return Decision(False, "explicit_deny", denies)
        if allows:
            return Decision(True, "explicit_allow", allows)
        return Decision(False, "default_deny")
