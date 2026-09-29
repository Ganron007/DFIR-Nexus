"""WO-1 (D46): MCP tools run off the serving loop; case writers serialize.

The MCP SDK invokes sync tool functions inline on the serving event loop, so
one slow tool froze the portal (measured >900 s) and parallel calls silently
serialized. `apply_tool_offload` wraps registration so every sync tool runs in
a worker thread; the case-file writers keep one shared lock because the old
loop-blocking had accidentally serialized their read-modify-write cycles.
"""
from __future__ import annotations

import asyncio
import inspect
import time

from mcp.server.fastmcp import FastMCP

from nexus.app import _CASE_WRITER_TOOLS, apply_tool_offload, create_server


def _schema(tool) -> object:
    return getattr(tool, "parameters", None) or getattr(tool, "inputSchema", None)


def test_all_registered_tools_are_coroutine_functions(monkeypatch):
    monkeypatch.setenv("NEXUS_RAG_PRELOAD", "0")
    server = create_server()
    tools = server._tool_manager._tools
    assert tools, "server registered no tools"
    sync_tools = [
        name
        for name, tool in tools.items()
        if not inspect.iscoroutinefunction(getattr(tool, "fn", None))
    ]
    assert sync_tools == [], f"tools still registered sync: {sync_tools[:8]}"


def test_schemas_identical_with_and_without_offload(monkeypatch):
    monkeypatch.setenv("NEXUS_RAG_PRELOAD", "0")

    monkeypatch.setenv("NEXUS_MCP_TOOL_OFFLOAD", "0")
    base = create_server()
    base_tools = base._tool_manager._tools

    monkeypatch.delenv("NEXUS_MCP_TOOL_OFFLOAD")
    wrapped = create_server()
    wrapped_tools = wrapped._tool_manager._tools

    assert set(base_tools) == set(wrapped_tools)
    diffs = [
        name
        for name in base_tools
        if _schema(base_tools[name]) != _schema(wrapped_tools[name])
    ]
    assert diffs == [], f"offload changed tool schemas: {diffs[:8]}"
    # and the wrapped ones really are async now
    assert inspect.iscoroutinefunction(wrapped_tools[next(iter(wrapped_tools))].fn)


def test_case_writer_set_covers_the_critical_writers():
    for name in (
        "record_finding",
        "record_timeline_event",
        "evidence_register",
        "set_case_metadata",
        "generate_report",
    ):
        assert name in _CASE_WRITER_TOOLS


async def test_sync_tool_runs_off_the_loop():
    server = FastMCP("offload-test")
    apply_tool_offload(server)

    @server.tool()
    def slow_tool(seconds: float) -> str:
        time.sleep(seconds)
        return "done"

    fn = server._tool_manager._tools["slow_tool"].fn
    assert inspect.iscoroutinefunction(fn)

    ticks: list[float] = []
    t0 = time.time()

    async def ticker() -> None:
        while True:
            ticks.append(time.time() - t0)
            await asyncio.sleep(0.05)

    task = asyncio.create_task(ticker())
    t1 = time.time()
    result = await fn(1.2)
    elapsed = time.time() - t1
    task.cancel()

    assert result == "done"
    assert elapsed >= 1.2
    # The loop kept ticking while the tool slept: it ran in a worker thread.
    assert len(ticks) >= 10, f"loop blocked during the tool call ({len(ticks)} ticks)"


async def test_case_writer_tools_serialize_but_readers_overlap():
    server = FastMCP("lock-test")
    apply_tool_offload(server)
    events: list[str] = []

    @server.tool()
    def record_finding(note: str) -> str:
        events.append(f"enter-{note}")
        time.sleep(0.15)
        events.append(f"exit-{note}")
        return note

    @server.tool()
    def read_only(note: str) -> str:
        events.append(f"enter-{note}")
        time.sleep(0.15)
        events.append(f"exit-{note}")
        return note

    writer = server._tool_manager._tools["record_finding"].fn
    await asyncio.gather(writer("a"), writer("b"))

    assert events in (
        ["enter-a", "exit-a", "enter-b", "exit-b"],
        ["enter-b", "exit-b", "enter-a", "exit-a"],
    ), f"case writers interleaved: {events}"

    events.clear()
    reader = server._tool_manager._tools["read_only"].fn
    await asyncio.gather(reader("a"), reader("b"))

    # readers are not locked: the two calls overlap
    assert events[0].startswith("enter-") and events[1].startswith("enter-"), events
