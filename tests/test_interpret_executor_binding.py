"""WO-R2F item 1 / D41 on the Mode 1 interpret path: ES calls bind to the run's own case.

Reproduced in the 36e real-path test: the interpret loop routed its ES calls through the MCP
tool gate, which follows the examiner's active case, so every call was refused whenever
another case was active. make_interpret_executor sends the ES calls through the backbone,
bound to the run's case_dir; every other tool keeps the MCP path.
"""
from __future__ import annotations

import asyncio

import pytest

from nexus.langgraph import backbone, llm_pipeline


@pytest.fixture
def seen(monkeypatch):
    calls: dict = {"backbone": [], "mcp": []}

    def fake_backbone_call(name, audit=None, **kwargs):
        calls["backbone"].append({"name": name, "audit": audit, "kwargs": kwargs})
        return {"hits": [], "total": 0}

    async def fake_call_tool(tool, payload, label=""):
        calls["mcp"].append({"tool": tool, "payload": payload, "label": label})
        return {"success": True}

    monkeypatch.setattr(backbone, "backbone_call", fake_backbone_call)
    monkeypatch.setattr(llm_pipeline, "call_tool", fake_call_tool)
    return calls


def test_es_calls_go_through_the_backbone_bound_to_the_runs_case(tmp_path, seen):
    case_dir = tmp_path / "CASE-RUN"
    execute = llm_pipeline.make_interpret_executor(case_dir, {"es_search": object()})

    result = asyncio.run(execute("es_search", {"query": "logon", "case_id": "CASE-OTHER"}))

    assert result == {"hits": [], "total": 0}
    assert seen["mcp"] == [], "the MCP tool gate must not see an ES call"
    (call,) = seen["backbone"]
    assert call["name"] == "es_search"
    assert call["kwargs"]["case_dir"] == case_dir
    assert call["kwargs"]["query"] == "logon"
    assert "case_id" not in call["kwargs"], "the run's case is bound by case_dir, not the payload"
    assert call["audit"].mcp_name == "nexus"
    assert call["audit"]._audit_dir_override == case_dir / "audit"


@pytest.mark.parametrize("name", ["es_aggregate", "es_sample"])
def test_every_es_tool_is_bound_the_same_way(tmp_path, seen, name):
    execute = llm_pipeline.make_interpret_executor(tmp_path / "CASE-RUN", {name: object()})
    asyncio.run(execute(name, {}))
    assert [c["name"] for c in seen["backbone"]] == [name]
    assert seen["mcp"] == []


def test_non_es_tools_keep_the_mcp_path(tmp_path, seen):
    tool = object()
    execute = llm_pipeline.make_interpret_executor(tmp_path / "CASE-RUN", {"ti_lookup": tool})

    result = asyncio.run(execute("ti_lookup", {"ioc": "203.0.113.5"}))

    assert result == {"success": True}
    assert seen["backbone"] == []
    assert seen["mcp"][0]["tool"] is tool
    assert seen["mcp"][0]["payload"] == {"ioc": "203.0.113.5"}


def test_a_tool_missing_from_the_run_is_reported_not_raised(tmp_path, seen):
    execute = llm_pipeline.make_interpret_executor(tmp_path / "CASE-RUN", {})
    result = asyncio.run(execute("ti_lookup", {}))
    assert result == {"error": "tool ti_lookup not available"}
    assert seen["mcp"] == []


def test_without_a_case_dir_es_calls_keep_the_mcp_path(seen):
    tool = object()
    execute = llm_pipeline.make_interpret_executor(None, {"es_search": tool})
    asyncio.run(execute("es_search", {"query": "x"}))
    assert seen["backbone"] == []
    assert seen["mcp"][0]["tool"] is tool
