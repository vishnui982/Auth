"""Optional integration layer. V2 has no dependency on adapters or MCP."""
from .adapters import EmailAdapter, HTTPAdapter, MCPAdapter, ProtectedToolAdapter
from .resource import ResourceVerifier
from .runtime import AgentGuard, Denied

__all__ = ["AgentGuard", "Denied", "ResourceVerifier", "ProtectedToolAdapter", "EmailAdapter", "HTTPAdapter", "MCPAdapter"]
