"""WP 4j.10 — the Mode 2 LLM speaks N4 DSL through the backbone.

Validation wall: every LLM-emitted query parses or degrades to bare terms
(never a silent wrong query). The loop executes each proposal as one complete
DSL query through the audited backbone binding; the allowlist is structural.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

os.environ.setdefault("NEXUS_RAG_PRELOAD", "0")


class _FakeModel:
    """Records prompts; returns a canned JSON response."""

    def __init__(self, payload: dict):
        self.payload = json.dumps(payload)
        self.prompts: list[list[dict]] = []

    def invoke(self, messages):
        self.prompts.append(messages)

        class _R:
            content = self.payload

        return _R()


def _mkcase(tmp_path: Path) -> Path:
    case = tmp_path / "CASE-M2DSL"
    ext = case / "extractions" / "hayabusa"
    ext.mkdir(parents=True)
    (ext / "timeline.csv").write_text(
        "Timestamp,Computer,Channel,EventID,Level,RuleTitle,OtherFields\n"
        "2026-08-10 15:00:00,WS01,Sec,4688,high,Suspicious SDelete Usage,sdelete.exe -p 5\n"
        "2026-08-10 15:05:00,WS01,Sec,4688,high,Suspicious Rundll32 Execution,rundll32.exe\n",
        encoding="utf-8",
    )
    (case / "CASE.yaml").write_text("question: was there destructive activity?\n", encoding="utf-8")
    return case


@pytest.fixture()
def backbone(tmp_path, monkeypatch):
    """Isolated env + live server tools with an ACTIVE case holding evidence."""
    monkeypatch.setenv("NEXUS_CASES_ROOT", str(tmp_path / "cases"))
    monkeypatch.setenv("NEXUS_ACTIVE_CASE_FILE", str(tmp_path / "active_case"))
    (tmp_path / "cases").mkdir(parents=True, exist_ok=True)
    from nexus.app import create_server

    server = create_server()
    tools = server._tool_manager._tools
    r = tools["case_init"].fn("M2 DSL Test", case_id="CASE-M2DSL")
    cid = r["case_id"]
    tools["case_activate"].fn(cid)
    ext = Path(r["case_dir"]) / "extractions" / "hayabusa"
    ext.mkdir(parents=True, exist_ok=True)
    (ext / "timeline.csv").write_text(
        "Timestamp,Computer,Channel,EventID,Level,RuleTitle,OtherFields\n"
        "2026-08-10 15:00:00,WS01,Sec,4688,high,Suspicious SDelete Usage,sdelete.exe -p 5\n"
        "2026-08-10 15:05:00,WS01,Sec,4688,high,Suspicious Rundll32 Execution,rundll32.exe\n",
        encoding="utf-8",
    )
    # expose the active case dir for loop tests
    return tools, cid, Path(r["case_dir"])


# --- grammar + binding in the proposal prompt ------------------------------


def test_propose_prompt_teaches_grammar_and_binds_backbone(tmp_path):
    from nexus.langgraph.mode2 import _propose_with_model

    case = _mkcase(tmp_path)
    hits = [
        {"family": "hayabusa", "file": "a.csv", "line": "1", "text": "sdelete x",
         "terms": "sdelete"},
        {"family": "hayabusa", "file": "a.csv", "line": "2", "text": "rundll32 y",
         "terms": "rundll32"},
    ]
    fake = _FakeModel({"queries": [{"dsl": "family:hayabusa AND sdelete", "why": "w"}],
                       "rationale": "r"})
    out = _propose_with_model(case, hits, [], fake)
    user_prompt = fake.prompts[0][1]["content"]
    # grammar + tool contracts reached the prompt
    assert "family:" in user_prompt
    assert "n4_query" in user_prompt and "family_fields" in user_prompt
    assert "kb_search" in user_prompt
    assert out["source"] == "llm"
    assert out["needles"] == ["family:hayabusa AND sdelete"]
    assert out["dsl_queries"][0]["dsl"] is True


def test_validation_wall_degrades_bad_dsl_to_bare_terms():
    from nexus.langgraph.mode2 import _validate_dsl

    good = _validate_dsl("family:evtx event:4625 AND 10.0.0.5")
    assert good["dsl"] is True and not good["fallback"]

    bad = _validate_dsl("regex:((((a+)+)+)*b)")
    assert bad["fallback"] is True
    assert bad["query"], "bare terms survive the fallback"
    assert "((((a+)+)+)*b" not in bad["query"] or " " in bad["query"], bad


def test_propose_backward_compat_needles_schema(tmp_path):
    from nexus.langgraph.mode2 import _propose_with_model

    case = _mkcase(tmp_path)
    fake = _FakeModel({"needles": ["sdelete"], "rationale": "old schema"})
    out = _propose_with_model(case, [], [], fake)
    assert out["needles"] == ["sdelete"]
    assert out["dsl_queries"][0]["fallback"] is False


# --- loop executes per-proposal DSL queries through the backbone -----------


def test_loop_runs_dsl_queries_through_backbone(backbone):
    from nexus.langgraph.mode2 import run_iterative_loop

    _tools, _cid, case_dir = backbone
    fake = _FakeModel({
        "needles": ["sdelete", "rundll32"],
        "queries": [
            {"dsl": "family:hayabusa AND sdelete", "why": "clearing"},
            {"dsl": "family:hayabusa AND rundll32", "why": "exec"},
        ],
        "rationale": "r",
    })
    result = run_iterative_loop(case_dir, "sdelete rundll32 destructive activity?",
                                model=fake, max_iterations=1, limit=50)
    iters = result["iterations"]
    ran = [i for i in iters if i.get("action") == "proposed_and_ran"]
    assert ran, iters
    queries = ran[0]["queries"]
    assert len(queries) == 2
    assert queries[0]["query"] == "family:hayabusa AND sdelete"
    assert queries[0]["dsl"] is True and not queries[0]["fallback"]
    assert queries[0]["hits"] >= 1, "DSL query must hit the synthetic rows"
    assert queries[0]["audit_id"], "backbone execution must be audited"


def test_loop_falls_back_on_bad_dsl(backbone):
    from nexus.langgraph.mode2 import run_iterative_loop

    _tools, _cid, case_dir = backbone
    fake = _FakeModel({
        "needles": ["sdelete"],
        "queries": [{"dsl": "regex:((((a+)+)+)*b", "why": "bad"}],
        "rationale": "r",
    })
    result = run_iterative_loop(case_dir, "sdelete destructive activity?",
                                model=fake, max_iterations=1, limit=20)
    it1 = next(i for i in result["iterations"] if i.get("action") == "proposed_and_ran")
    q = it1["queries"][0]
    assert q["fallback"] is True
    assert q["fallback_reason"]
    assert q["hits"] >= 0  # bare terms still executed


# --- binding layer: allowlist is structural -------------------------------


def test_backbone_allowlist_refuses_mutating_tools():
    from nexus.langgraph.backbone import backbone_call

    with pytest.raises(PermissionError):
        backbone_call("case_delete")
    with pytest.raises(PermissionError):
        backbone_call("approve")


def test_backbone_allowlist_reads_evidence(backbone):
    from nexus.langgraph.backbone import MODE2_TOOL_ALLOWLIST, backbone_call

    _tools, cid, _case_dir = backbone
    r = backbone_call("n4_query", dsl="sdelete OR rundll32", limit=10)
    assert r["count"] >= 1
    assert r["provenance"]["case_id"] == cid
    assert set(MODE2_TOOL_ALLOWLIST).isdisjoint(
        {"case_delete", "approve", "evidence_register", "record_finding"})


def test_index_mappings_reports_family_fields(backbone):
    from nexus.langgraph.backbone import backbone_call

    r = backbone_call("index_mappings")
    assert "error" not in r, r
    ff = r["family_fields"]
    assert "hayabusa" in ff
    assert any("RuleTitle" in f or "Timestamp" in f for f in ff["hayabusa"]), ff


def test_family_fields_profile(backbone):
    tools, _cid, _case_dir = backbone
    r = tools["family_fields"].fn(family="hayabusa")
    assert r["fields"], "expected hayabusa profile fields"
    assert any("RuleTitle" in f or "EventID" in f for f in r["fields"])
