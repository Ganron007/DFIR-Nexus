"""Pipeline mode switch: design (ReAct) vs coverage (tool lane) vs tools (no LLM)."""

from __future__ import annotations

from pathlib import Path

import pytest

from nexus.langgraph.llm_pipeline import (
    _fallback_candidates_from_state,
    _is_collection_stub,
    _merge_n4_uncovered,
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
    st4 = make_initial_state(pipeline_mode="interpret", case_id="INC-TEST")
    assert st4["pipeline_mode"] == "interpret"
    assert st4["case_id"] == "INC-TEST"


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


def test_n1_gate_empty_intake_degrades_to_tool_run():
    """N1 leftover: coverage/design with no question+window must degrade to
    TOOL-RUN only (emit_tool_report), not run interpret/hunt."""

    class _DummyModel:
        pass

    for mode in ("coverage", "design"):
        graph = build_graph({}, _DummyModel(), mode=mode)
        # The TOOL-RUN exit node must be present as the empty-intake branch.
        assert "emit_tool_report" in graph.nodes
        # execute_tool_lane must carry the N1 conditional router.
        assert "execute_tool_lane" in graph.branches, f"{mode}: no conditional edge"
        branch = graph.branches["execute_tool_lane"]["_route_after_tool_lane"]
        path_map = branch.ends
        assert path_map["tools_only"] == "emit_tool_report"
        # design routes the interpret path through hunt; coverage straight to interpret
        if mode == "design":
            assert path_map["interpret_path"] == "hunt"
        else:
            assert path_map["interpret_path"] == "interpret"


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


def test_collection_stub_filter():
    assert _is_collection_stub({
        "title": "rocba/pecmd: prefetch",
        "observation": "Tool 'pecmd' on rocba completed OK (audit_id=x).",
        "interpretation": "Coverage/collection evidence for 'prefetch'.",
    })
    assert not _is_collection_stub({
        "title": "sdelete wipe / secure-delete on host",
        "observation": "N4 hits: pecmd sdelete.exe",
        "interpretation": "Insider / data-staging lens.",
    })
    assert _is_collection_stub({
        "title": "Coverage gap: no USB/physical-media artifacts",
        "observation": "mftecmd-usn SKIP",
        "interpretation": "This is a coverage gap, not evidence of compromise.",
    })


def test_merge_n4_adds_usb_when_llm_omitted_it():
    llm = [{
        "title": "sdelete wipe / secure-delete on host",
        "observation": "pecmd hit sdelete.exe",
    }]
    n4 = [
        {"title": "sdelete wipe / secure-delete on host", "observation": "dup"},
        {"title": "USB / USBSTOR activity", "observation": "USBSTOR Disk&Ven"},
    ]
    merged = _merge_n4_uncovered(llm, n4)
    titles = [c["title"] for c in merged]
    assert titles.count("sdelete wipe / secure-delete on host") == 1
    assert any("USB" in t for t in titles)


def test_fallback_uses_n4_hits_not_parser_ok(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from nexus.config import settings

    case_id = "INC-TESTN4"
    case = tmp_path / "cases" / case_id
    pecmd = case / "extractions" / "pecmd"
    pecmd.mkdir(parents=True)
    (pecmd / "prefetch_Timeline.csv").write_text(
        "RunTime,ExecutableName\n"
        "2020-11-14 04:49:43,ACRORD32.EXE\n"
        "2020-11-14 13:42:11,sdelete.exe\n",
        encoding="utf-8",
    )
    (case / "CASE.yaml").write_text(
        "intake:\n  playbooks: data_staging\n  host: rocba\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(settings, "cases_root", tmp_path / "cases")
    ledger = [{
        "status": "OK",
        "tool": "windows/pecmd",
        "audit_id": "win-e-20260101-001",
        "purpose": "prefetch",
        "output_saved_to": str(pecmd / "stdout.txt"),
    }]
    state = {"case_id": case_id, "tool_run_ledger": ledger}
    cands = _fallback_candidates_from_state(state, ["win-e-20260101-001"], "rocba")
    assert cands
    blob = " ".join(f"{c['title']} {c['observation']}" for c in cands).lower()
    assert "sdelete" in blob
    assert "completed ok" not in blob
    assert "acrord32" not in blob
    assert not any(_is_collection_stub(c) for c in cands)
