"""Velociraptor MCP server — gRPC/HTTP VQL execution backend.

Run standalone:
    python -m nexus.integration.velociraptor_mcp_server

Or register as a gateway HTTP backend when deployed.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from nexus.integration.vql_runner import (
    MonitorConfig,
    VQLQuerySpec,
    VQLRunner,
    create_velociraptor_client,
)

log = logging.getLogger(__name__)


def _get_runner() -> VQLRunner:
    endpoint = os.environ.get("VELOCIRAPTOR_ENDPOINT", "https://127.0.0.1:8000/")
    api_key = os.environ.get("VELOCIRAPTOR_API_KEY", "")
    config = MonitorConfig(endpoint=endpoint, api_key=api_key)
    return VQLRunner(config=config, queries=[], client=create_velociraptor_client(config))


def create_velociraptor_server() -> Server:
    """Create MCP server exposing Velociraptor VQL tools."""
    server = Server("dfir-nexus-velociraptor")
    runner = _get_runner()

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        return [
            Tool(
                name="vql_query",
                description="Execute a VQL query against Velociraptor",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "vql": {"type": "string"},
                        "timeout_seconds": {"type": "integer", "default": 60},
                    },
                    "required": ["vql"],
                },
            ),
            Tool(
                name="vql_collect_artifact",
                description="Collect a named Velociraptor artifact",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "artifact_name": {"type": "string"},
                        "parameters": {"type": "object"},
                    },
                    "required": ["artifact_name"],
                },
            ),
            Tool(
                name="vrun_health",
                description="Check Velociraptor endpoint connectivity",
                inputSchema={"type": "object", "properties": {}},
            ),
        ]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
        try:
            if name == "vql_query":
                vql = arguments["vql"]
                timeout = int(arguments.get("timeout_seconds", 60))
                spec = VQLQuerySpec(name="ad-hoc", vql=vql, timeout_seconds=timeout)
                runner.queries = [spec]
                results = runner.run_once()
                payload = [r.to_dict() for r in results.values()]
                return [TextContent(type="text", text=json.dumps({"results": payload}))]

            if name == "vql_collect_artifact":
                import re
                artifact = arguments["artifact_name"]
                params = arguments.get("parameters") or {}
                # Sanitize keys/values to prevent injection
                for k, v in params.items():
                    if not re.match(r"^[a-zA-Z0-9_]+\Z", str(k)):
                        raise ValueError(f"Invalid parameter name: {k}")
                    if '"' in str(v):
                        raise ValueError("Double quotes are not allowed in parameter values")
                param_vql = ", ".join(f'{k}="{v}"' for k, v in params.items())
                vql = f"SELECT * FROM Artifact.{artifact}({param_vql})" if param_vql else f"SELECT * FROM Artifact.{artifact}()"
                spec = VQLQuerySpec(name=artifact, vql=vql, artifact_name=artifact)
                runner.queries = [spec]
                results = runner.run_once()
                return [TextContent(type="text", text=json.dumps({"results": [r.to_dict() for r in results.values()]}))]

            if name == "vrun_health":
                ok = bool(runner.config.endpoint)
                return [TextContent(type="text", text=json.dumps({
                    "endpoint": runner.config.endpoint,
                    "configured": ok,
                    "api_key_set": bool(runner.config.api_key),
                }))]

            return [TextContent(type="text", text=json.dumps({"error": f"unknown tool: {name}"}))]
        except Exception as e:
            log.exception("velociraptor tool %s failed", name)
            return [TextContent(type="text", text=json.dumps({"error": str(e)}))]

    return server


async def run_stdio() -> None:
    server = create_velociraptor_server()
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


def main() -> None:
    asyncio.run(run_stdio())


if __name__ == "__main__":
    main()
