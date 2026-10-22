"""mcp-firewall: a policy gateway for MCP servers over stdio."""

__version__ = "0.1.0"

from .policy import Decision, Enforcer, Policy, PolicyError  # noqa: F401

__all__ = ["Decision", "Enforcer", "Policy", "PolicyError", "__version__"]
