"""Client-side MCP tool-call timeout (langgraph/tool_call.py).

The defect these pin: an MCP tool call had **no** client-side timeout. The
``timeout`` field passed to the tool bounds the tool's own subprocess. When the
transport itself died — stdio child exited, streamable-HTTP session dropped —
``ainvoke`` never returned and the pipeline hung with no error.

These are the cheap guarantees: the budget maths, a call inside the budget, and
a call past it failing with a reason that names what it was waiting on.
"""

from __future__ import annotations

import asyncio

import pytest

from nexus.langgraph import tool_call
from nexus.langgraph.tool_call import ToolCallTimeout, call_timeout, call_tool


class _FakeTool:
    def __init__(self, name: str, delay: float = 0.0, result=None):
        self.name = name
        self._delay = delay
        self._result = result if result is not None else {"ok": True}

    async def ainvoke(self, payload):  # noqa: ANN001, ANN201
        if self._delay:
            await asyncio.sleep(self._delay)
        return self._result


# ---------------------------------------------------------------------------
# Budget maths
# ---------------------------------------------------------------------------

def test_default_budget_when_call_declares_none(monkeypatch):
    monkeypatch.delenv("NEXUS_MCP_CALL_TIMEOUT", raising=False)
    assert call_timeout(None) == tool_call.DEFAULT_CALL_TIMEOUT_S


def test_tool_budget_plus_margin(monkeypatch):
    monkeypatch.delenv("NEXUS_MCP_CALL_MARGIN", raising=False)
    assert call_timeout(600) == 600 + tool_call.DEFAULT_MARGIN_S


def test_margin_override_is_honoured(monkeypatch):
    monkeypatch.setenv("NEXUS_MCP_CALL_MARGIN", "15")
    assert call_timeout(100) == 115


def test_floor_protects_a_tiny_declared_budget(monkeypatch):
    monkeypatch.setenv("NEXUS_MCP_CALL_MARGIN", "0")
    assert call_timeout(1) == tool_call.MIN_CALL_TIMEOUT_S


def test_bad_env_value_falls_back_to_default(monkeypatch):
    monkeypatch.setenv("NEXUS_MCP_CALL_TIMEOUT", "not-a-number")
    assert call_timeout(None) == tool_call.DEFAULT_CALL_TIMEOUT_S


def test_margin_is_always_greater_than_the_tool_budget():
    # A transport budget below the tool's own kill time could fail a healthy
    # long parse. This is the property that keeps a false timeout out.
    for declared in (30, 600, 3600, 7200):
        assert call_timeout(declared) > declared


# ---------------------------------------------------------------------------
# Invocation
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_call_within_budget_returns_the_tool_result():
    tool = _FakeTool("run_windows_command", delay=0.01, result={"stdout": "hi"})
    out = await call_tool(tool, {"command": ["x"]})
    assert out == {"stdout": "hi"}


@pytest.mark.asyncio
async def test_dead_transport_raises_instead_of_hanging(monkeypatch):
    monkeypatch.setattr(tool_call, "MIN_CALL_TIMEOUT_S", 0.05)
    monkeypatch.setenv("NEXUS_MCP_CALL_TIMEOUT", "0.05")
    tool = _FakeTool("run_command", delay=30.0)
    with pytest.raises(ToolCallTimeout) as err:
        await call_tool(tool, {"command": "vol -h"}, label="run_command(vol)")
    assert "run_command(vol)" in str(err.value)
    assert "unresponsive" in str(err.value)


@pytest.mark.asyncio
async def test_timeout_names_the_declared_tool_budget(monkeypatch):
    monkeypatch.setattr(tool_call, "MIN_CALL_TIMEOUT_S", 0.05)
    monkeypatch.setenv("NEXUS_MCP_CALL_MARGIN", "0.05")
    tool = _FakeTool("run_command", delay=30.0)
    with pytest.raises(ToolCallTimeout) as err:
        await call_tool(tool, {"command": "x"}, timeout=0.0, label="run_command(vol)")
    assert "tool budget 0s" in str(err.value)


@pytest.mark.asyncio
async def test_label_falls_back_to_the_tool_name(monkeypatch):
    monkeypatch.setattr(tool_call, "MIN_CALL_TIMEOUT_S", 0.05)
    monkeypatch.setenv("NEXUS_MCP_CALL_TIMEOUT", "0.05")
    tool = _FakeTool("record_finding", delay=30.0)
    with pytest.raises(ToolCallTimeout) as err:
        await call_tool(tool, {})
    assert "record_finding" in str(err.value)
