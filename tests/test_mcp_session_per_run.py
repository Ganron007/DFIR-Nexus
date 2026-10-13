"""D71: a pipeline run holds one MCP session per server for the whole run.

Without it, every tool call opened its own session; over stdio each call started a new
DFIR-Nexus server. Measured 2026-10-13 on the real stdio server (128 tools): three get_health
calls took 14.8 s each without held sessions and ~0 s with them. This pins the contract on the
loader: with ``sessions``, each server is entered once and its tools are bound to that session.
"""
from __future__ import annotations

import asyncio
import contextlib


def test_each_server_is_entered_once_and_its_tools_bound_to_that_session(monkeypatch):
    import langchain_mcp_adapters.client as adapter_client
    import langchain_mcp_adapters.tools as adapter_tools

    from nexus.langgraph import llm_pipeline

    entered: list[str] = []
    closed: list[str] = []

    class _Tool:
        def __init__(self, name, session):
            self.name, self.session = name, session

    class _FakeClient:
        def __init__(self, servers):
            self._server = next(iter(servers))

        @contextlib.asynccontextmanager
        async def session(self, server_name):
            entered.append(server_name)
            try:
                yield f"session:{server_name}"
            finally:
                closed.append(server_name)

        async def get_tools(self):
            raise AssertionError("a held-session load must not take per-call tools")

    async def _load(session, *, server_name=None, **_kw):
        return [_Tool("get_health", session), _Tool("record_finding", session)]

    monkeypatch.setattr(adapter_client, "MultiServerMCPClient", _FakeClient)
    monkeypatch.setattr(adapter_tools, "load_mcp_tools", _load)
    config = {"nexus-windows": {"transport": "stdio", "command": "nexus", "args": ["serve"]}}

    async def _run():
        async with contextlib.AsyncExitStack() as sessions:
            tools = await llm_pipeline._load_mcp_tools(config, sessions=sessions)
            assert entered == ["nexus-windows"] and closed == []
            assert {t.session for t in tools.values()} == {"session:nexus-windows"}
        assert closed == ["nexus-windows"]

    asyncio.run(_run())
