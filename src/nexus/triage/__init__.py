"""Triage: offline Windows baseline validation — file, process, service, registry checks.

13 tools matching the original windows-triage MCP server.
"""

from .server import register_tools

__all__ = ["register_tools"]
