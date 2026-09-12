"""Transport-neutral normalization. Registrations are administrator-owned, exact destinations."""
from abc import ABC, abstractmethod
from dataclasses import dataclass
from urllib.parse import urlsplit

from agent_guard.canonical import fields
from agent_guard.v2.model import Action, check


class ProtectedToolAdapter(ABC):
    @abstractmethod
    def normalize(self, actor, request) -> Action:
        """Bind every effect-bearing request field; reject unknown destinations/fields."""


@dataclass(frozen=True)
class EmailAdapter(ProtectedToolAdapter):
    def normalize(self, actor, request):
        fields(request, {"to", "body"})
        check(type(request["body"]) is str, "invalid_email_body")
        # Deliberately no suffix matching or caller-controlled classification.
        destinations = {"finance@company.com": "sink:mail-finance",
                        "bob@company.com": "sink:mail-bob", "attacker@gmail.com": "sink:mail-external"}
        check(type(request["to"]) is str and request["to"] in destinations, "unregistered_destination")
        return Action(actor, "email.send", destinations[request["to"]],
                      {"payload": {"service": "mock-mailbox", "method": "send", **request}})


@dataclass(frozen=True)
class HTTPAdapter(ProtectedToolAdapter):
    origin: str

    def __post_init__(self):
        u = urlsplit(self.origin)
        check(u.scheme == "http" and u.hostname == "127.0.0.1" and u.port is not None and
              self.origin == f"http://127.0.0.1:{u.port}", "invalid_mock_origin")

    def normalize(self, actor, request):
        fields(request, {"method", "url", "body"})
        check(type(request["body"]) is dict, "invalid_http_body")
        routes = {self.origin + "/payments": "sink:http-payments",
                  self.origin + "/documents": "sink:http-documents"}
        check(request["method"] == "POST", "unregistered_method")
        check(type(request["url"]) is str and request["url"] in routes, "unregistered_destination")
        return Action(actor, "http.post", routes[request["url"]], {"payload": request})


@dataclass(frozen=True)
class MCPAdapter(ProtectedToolAdapter):
    def normalize(self, actor, request):
        fields(request, {"name", "arguments"})
        check(request["name"] == "documents.create", "unregistered_tool")
        fields(request["arguments"], {"body"})
        check(type(request["arguments"]["body"]) is dict, "invalid_tool_body")
        return Action(actor, "tool.invoke", "sink:mcp-documents",
                      {"payload": {"server": "guard-demo", "method": "tools/call", **request}})
