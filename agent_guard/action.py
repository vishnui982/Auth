from dataclasses import dataclass
import re

from .canonical import canonical, digest, fields, loads
from .errors import GuardError

IDENTIFIER = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}\Z")
RESOURCE = re.compile(r"document:[a-zA-Z0-9][a-zA-Z0-9_/-]{0,127}\Z")


@dataclass(frozen=True, init=False)
class Action:
    actor: str
    operation: str
    resource: str
    _parameters: bytes

    def __init__(self, actor, operation, resource, parameters=None):
        if type(actor) is not str or not IDENTIFIER.fullmatch(actor):
            raise GuardError("invalid_actor", 400)
        if type(operation) is not str or not IDENTIFIER.fullmatch(operation):
            raise GuardError("invalid_operation", 400)
        if type(resource) is not str or not RESOURCE.fullmatch(resource):
            raise GuardError("invalid_resource", 400)
        if "//" in resource or resource.endswith("/"):
            raise GuardError("invalid_resource", 400)
        parameters = {} if parameters is None else parameters
        if type(parameters) is not dict:
            raise GuardError("invalid_parameters", 400)
        object.__setattr__(self, "actor", actor)
        object.__setattr__(self, "operation", operation)
        object.__setattr__(self, "resource", resource)
        object.__setattr__(self, "_parameters", canonical(parameters))
        canonical(self.to_dict())

    @property
    def parameters(self):
        # No mutable references survive construction or escape this object.
        return loads(self._parameters)

    def to_dict(self):
        return {"version": 1, "actor": self.actor, "operation": self.operation,
                "resource": self.resource, "parameters": self.parameters}

    @classmethod
    def from_dict(cls, value):
        fields(value, {"version", "actor", "operation", "resource", "parameters"})
        if type(value["version"]) is not int or value["version"] != 1:
            raise GuardError("unsupported_action_version", 400)
        if type(value["parameters"]) is not dict:
            raise GuardError("invalid_parameters", 400)
        return cls(value["actor"], value["operation"], value["resource"], value["parameters"])

    @property
    def hash(self):
        return digest(self.to_dict())


def validate_tool(action: Action):
    """Closed operation registry: extending Action never silently grants a tool."""
    if action.operation == "read":
        fields(action.parameters, set())
    elif action.operation == "write":
        fields(action.parameters, {"content"})
        content = action.parameters["content"]
        if type(content) is not str or len(content.encode("utf-8")) > 16384:
            raise GuardError("invalid_content", 400)
    else:
        raise GuardError("unsupported_operation")
