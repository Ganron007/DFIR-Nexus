"""Pipeline mode switch: design (ReAct) vs coverage (tool lane) vs tools (no LLM)."""

from __future__ import annotations

import pytest

from nexus.langgraph.llm_pipeline import (
    build_graph,
    get_mcp_config,
    make_initial_state,
    resolve_pipeline_mode,
)
from nexus.langgraph.tool_lane import plan_sift_triage


def test_resolve_pipeline_mode_defaults_and_aliases(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("NEXUS_PIPELINE_MODE", raising=False)
    assert resolve_pipeline_mode() == "design"
    assert resolve_pipeline_mode("design") == "design"
    assert resolve_pipeline_mode("coverage") == "coverage"
    assert resolve_pipeline_mode("tools") == "tools"
    assert resolve_pipeline_mode("interpret") == "interpret"
    assert resolve_pipeline_mode("react") == "design"
    assert resolve_pipeline_mode("debug") == "coverage"
    assert resolve_pipeline_mode("lane") == "coverage"
    assert resolve_pipeline_mode("tools_only") == "tools"
    assert resolve_pipeline_mode("from_case") == "interpret"
    monkeypatch.setenv("NEXUS_PIPELINE_MODE", "coverage")
    assert resolve_pipeline_mode() == "coverage"
    # explicit arg wins over env
    assert resolve_pipeline_mode("design") == "design"


def test_resolve_pipeline_mode_rejects_unknown():
    with pytest.raises(ValueError, match="Unknown pipeline mode"):
        resolve_pipeline_mode("banana")


def test_make_initial_state_carries_mode():
    st = make_initial_state(pipeline_mode="coverage")
    assert st["pipeline_mode"] == "coverage"
    st2 = make_initial_state(pipeline_mode="react")
    assert st2["pipeline_mode"] == "design"
    st3 = make_initial_state(pipeline_mode="tools")
    assert st3["pipeline_mode"] == "tools"


def test_build_graph_nodes_by_mode():
    class _DummyModel:
        pass

    design = build_graph({}, _DummyModel(), mode="design")
    assert "hunt" in design.nodes
    assert "execute_tool_lane" in design.nodes
    assert "interpret" in design.nodes
    assert "ensure_rag" in design.nodes

    coverage = build_graph({}, _DummyModel(), mode="coverage")
    assert "execute_tool_lane" in coverage.nodes
    assert "interpret" in coverage.nodes
    assert "ensure_rag" in coverage.nodes
    assert "hunt" not in coverage.nodes

    tools = build_graph({}, _DummyModel(), mode="tools")
    assert "execute_tool_lane" in tools.nodes
    assert "emit_tool_report" in tools.nodes
    assert "interpret" not in tools.nodes
    assert "ensure_rag" not in tools.nodes
    assert "await_approval" not in tools.nodes
    assert "generate_report" not in tools.nodes
    assert "hunt" not in tools.nodes

    interpret = build_graph({}, _DummyModel(), mode="interpret")
    assert "load_existing" in interpret.nodes
    assert "interpret" in interpret.nodes
    assert "execute_tool_lane" not in interpret.nodes


def test_finding_payload_keeps_itm():
    from nexus.langgraph.llm_pipeline import _finding_tool_payload

    payload = _finding_tool_payload(
        {
            "title": "USB",
            "observation": "MountPoints2",
            "interpretation": "removable media",
            "itm_stage": "Means",
            "itm_objects": ["Removable Media"],
            "audit_ids": ["abc"],
        },
        [],
    )
    assert payload["itm_stage"] == "Means"
    assert payload["itm_objects"] == ["Removable Media"]
    assert payload["audit_ids"] == ["abc"]

    from nexus.langgraph.hunt_parser import normalize_candidate

    cand = normalize_candidate({
        "title": "USB",
        "observation": "MountPoints2",
        "itm_stage": "Means",
        "itm_objects": ["Removable Media"],
        "audit_ids": ["abc"],
    })
    assert cand["itm_stage"] == "Means"
    assert cand["itm_objects"] == ["Removable Media"]


def test_plan_sift_skips_e01_unless_explicit(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("NEXUS_SIFT_E01", raising=False)
    monkeypatch.delenv("NEXUS_SIFT_MEMORY_FILE", raising=False)
    jobs = plan_sift_triage("/evidence/rocba-500")
    tools = {j.tool for j in jobs}
    assert "vol" in tools
    assert "fls" not in tools

    monkeypatch.setenv("NEXUS_SIFT_E01", "/evidence/rocba-500/C-Drive/x.e01")
    jobs2 = plan_sift_triage("/evidence/rocba-500")
    assert any(j.tool == "fls" for j in jobs2)


def test_get_mcp_config_sse_read_timeout(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("NEXUS_WINDOWS_MCP_URL", "http://127.0.0.1:4508/mcp")
    monkeypatch.setenv("NEXUS_SIFT_MCP_URL", "http://192.168.77.135:4508/mcp")
    monkeypatch.delenv("NEXUS_MCP_SSE_READ_TIMEOUT", raising=False)
    cfg = get_mcp_config()
    assert cfg["nexus-windows"]["sse_read_timeout"] == 7200.0
    assert cfg["nexus-sift"]["sse_read_timeout"] == 7200.0
    monkeypatch.setenv("NEXUS_MCP_SSE_READ_TIMEOUT", "900")
    cfg2 = get_mcp_config()
    assert cfg2["nexus-windows"]["sse_read_timeout"] == 900.0
