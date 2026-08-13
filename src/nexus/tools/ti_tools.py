"""MCP threat-intel tools — wrap TIRouter (offline mock default)."""

from __future__ import annotations

import asyncio

from mcp.server.fastmcp import FastMCP

from nexus.audit import AuditWriter


def register_tools(server: FastMCP, audit: AuditWriter) -> None:
    @server.tool()
    def ti_list_providers() -> dict:
        """List TI providers and whether they are mock / live / unconfigured."""
        from nexus.ti import create_default_router

        router = create_default_router()
        providers = [p.to_dict() if hasattr(p, "to_dict") else p.__dict__ for p in router.list_providers()]
        audit.log(tool="ti_list_providers", params={}, result_summary={"n": len(providers)})
        return {"providers": providers, "mock": router.use_mock}

    @server.tool()
    def ti_lookup(value: str, ioc_type: str = "", providers: str = "") -> dict:
        """Look up one IOC. Default = core providers (abuse.ch + MISP). Optional CSV providers=."""
        from nexus.ti import create_default_router

        router = create_default_router()
        plist = [p.strip() for p in providers.split(",") if p.strip()] or None
        result = asyncio.run(router.lookup(value, ioc_type=ioc_type or None, providers=plist))
        audit.log(tool="ti_lookup", params={"ioc_type": ioc_type or "auto"}, result_summary={"malicious": result.get("malicious_count")})
        return result

    @server.tool()
    def ti_fanout(value: str, ioc_type: str = "") -> dict:
        """Fan out an IOC across the default abuse.ch set."""
        from nexus.ti import create_default_router

        router = create_default_router()
        result = asyncio.run(router.fanout(value, ioc_type=ioc_type or None))
        audit.log(tool="ti_fanout", params={"ioc_type": ioc_type or "auto"}, result_summary={"malicious": result.get("malicious_count")})
        return result
