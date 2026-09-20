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
    prefetch = Path(r["case_dir"]) / "extractions" / "prefetch"
    prefetch.mkdir(parents=True, exist_ok=True)
    (prefetch / "run.csv").write_text(
        "Executable,RunTime\nprefetch-only.exe,2026-08-10 15:06:00\n",
        encoding="utf-8",
    )
    # 4k.5.5: loop evidence access is ES-native; this fixture runs without a
    # live cluster, so the backbone is doubled with a CSV-backed stub that
    # keeps the audit + hit-shape contract identical.
    case_dir = Path(r["case_dir"])

    import nexus.langgraph.backbone as _bb

    _orig_backbone = _bb.backbone_call

    def _fake_backbone(name, audit=None, **kwargs):
        import json as _json
        import re as _re

        from nexus.langgraph.query_pack import n4_hits

        if name not in ("es_fields", "es_search", "es_aggregate", "es_sample",
                        "n4_aggregate"):
            return _orig_backbone(name, audit=audit, **kwargs)
        aid = audit.log(tool=name, params={}, result_summary={}) if audit else None
        if name == "es_search":
            hits, _backend = n4_hits(
                case_dir,
                ["sdelete", "rundll32", "prefetch-only.exe", "4625"],
                (None, None),
                backend="csv",
            )
            # crude filter so "new family" tests behave like a real query
            literals = [
                tok for tok in _re.findall(
                    r'"[a-z0-9_.-]{4,}"', _json.dumps(kwargs.get("query") or {})
                )
                if tok.strip('"') not in {
                    "match_phrase", "match_all", "match", "term", "terms",
                    "bool", "must", "should", "filter", "text", "query", "family",
                    "hayabusa", "wildcard", "range",
                }
            ]
            if literals:
                filtered = [
                    h for h in hits
                    if any(tok.strip('"') in str(h.get("text", "")).lower()
                           for tok in literals)
                ]
                if filtered:
                    hits = filtered
            return {"total": len(hits), "hits": hits, "backend": "elasticsearch",
                    "provenance": {"audit_id": aid, "case_id": case_dir.name}}
        if name == "es_aggregate":
            return {
                "aggregations": {"v": {"buckets": [
                    {"key": "WS01", "doc_count": 2}, {"key": "WS02", "doc_count": 1},
                ]}},
                "next_after_key": None,
                "provenance": {"audit_id": aid},
            }
        if name == "es_sample":
            return {"hits": [], "matched": 0, "provenance": {"audit_id": aid}}
        if name == "n4_aggregate":
            return {"distinct": 2, "top": [{"value": "WS01", "count": 2}],
                    "rows_scanned": 3, "provenance": {"audit_id": aid}}
        return {"error": f"unexpected backbone tool {name}"}

    monkeypatch.setattr("nexus.langgraph.backbone.backbone_call", _fake_backbone)
    return tools, cid, case_dir


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
    # 4k.5.5: the prompt teaches the ES surface (tool contracts + fields)
    assert "es_search" in user_prompt and "es_aggregate" in user_prompt
    assert "kb_search" in user_prompt
    assert "Elasticsearch" in user_prompt
    assert out["source"] == "llm"
    # legacy DSL proposals still validate (backward compat path)
    assert out["needles"] == ["family:hayabusa AND sdelete"]
    assert out["dsl_queries"][0]["dsl"] is True


def test_validation_wall_degrades_bad_dsl_to_bare_terms():
    from nexus.langgraph.mode2 import _validate_dsl

    good = _validate_dsl("family:evtx event:4625 AND 10.0.0.5")
    assert good["dsl"] is True and not good["fallback"]

    bad = _validate_dsl("regex:((((a+)+)+)*b)")
    assert bad["fallback"] is True
    assert bad["query"] == ""


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


def test_loop_reports_newly_discovered_families(backbone):
    from nexus.langgraph.mode2 import run_iterative_loop

    _tools, _cid, case_dir = backbone
    fake = _FakeModel({
        "queries": [{"dsl": "family:prefetch AND prefetch-only.exe", "why": "pivot"}],
        "rationale": "r",
    })
    result = run_iterative_loop(
        case_dir, "sdelete destructive activity?", model=fake,
        max_iterations=1, limit=20,
    )
    ran = next(i for i in result["iterations"] if i.get("action") == "proposed_and_ran")
    assert ran["new_families"] == ["prefetch"]


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
    assert any(i.get("action") == "no_new_proposals" for i in result["iterations"])
    assert not any(i.get("action") == "proposed_and_ran" for i in result["iterations"])


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
    r = backbone_call("es_search", query={"match_all": {}}, size=10)
    assert r["total"] >= 1
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


# --- WP 4j.12 — aggregations as tool calls ---------------------------------


def test_propose_prompt_teaches_aggregations(tmp_path):
    from nexus.langgraph.mode2 import _propose_with_model

    case = _mkcase(tmp_path)
    hits = [{"family": "hayabusa", "file": "a.csv", "line": "1",
             "text": "sdelete x", "terms": "sdelete"}]
    fake = _FakeModel({"queries": [], "aggregations": [], "rationale": "r"})
    _propose_with_model(case, hits, [], fake)
    assert "aggregations" in fake.prompts[0][1]["content"]
    assert "how many" in fake.prompts[0][1]["content"]


def test_propose_validates_aggregations(tmp_path):
    from nexus.langgraph.mode2 import _propose_with_model

    case = _mkcase(tmp_path)
    fake = _FakeModel({
        "queries": [],
        "aggregations": [
            {"dsl": "family:hayabusa AND sdelete", "field": "host", "why": "scope"},
            {"dsl": "regex:((((a+)+)+)*b", "field": "host", "why": "bad dsl"},
            {"dsl": "", "field": "host", "why": "no dsl"},
        ],
        "rationale": "r",
    })
    out = _propose_with_model(case, [], [], fake)
    aggs = out["aggregations"]
    assert len(aggs) == 1, aggs
    assert aggs[0]["field"] == "host"
    assert aggs[0]["fallback"] is False


def test_loop_runs_aggregations_through_backbone(backbone):
    from nexus.langgraph.mode2 import run_iterative_loop

    _tools, _cid, case_dir = backbone
    fake = _FakeModel({
        "needles": ["sdelete"],
        "queries": [{"dsl": "family:hayabusa AND sdelete", "why": "q"}],
        "aggregations": [{"dsl": "family:hayabusa AND sdelete", "field": "host",
                          "why": "how many hosts"}],
        "rationale": "r",
    })
    result = run_iterative_loop(case_dir, "sdelete destructive activity?",
                                model=fake, max_iterations=1, limit=50)
    ran = next(i for i in result["iterations"] if i.get("action") == "proposed_and_ran")
    aggs = ran.get("aggregations") or []
    assert aggs, "expected the proposed aggregation to run"
    a = aggs[0]
    assert a["field"] == "host"
    assert a["rows_scanned"] >= 1
    assert a["audit_id"], "aggregation must be audited (provenance)"


def test_aggregation_absent_when_not_proposed(backbone):
    from nexus.langgraph.mode2 import run_iterative_loop

    _tools, _cid, case_dir = backbone
    fake = _FakeModel({
        "needles": ["sdelete"],
        "queries": [{"dsl": "family:hayabusa AND sdelete", "why": "q"}],
        "rationale": "r",
    })
    result = run_iterative_loop(case_dir, "sdelete destructive activity?",
                                model=fake, max_iterations=1, limit=50)
    ran = next(i for i in result["iterations"] if i.get("action") == "proposed_and_ran")
    assert "aggregations" not in ran or not ran["aggregations"]

def test_iteration_zero_carries_an_audit_id(backbone):
    """The initial hit set is citation material — it must be audited like
    every other iteration (previously queried through query_pack directly)."""
    from nexus.langgraph.mode2 import run_iterative_loop

    _tools, _cid, case_dir = backbone
    fake = _FakeModel({"queries": [], "rationale": "stop"})
    result = run_iterative_loop(
        case_dir, "sdelete destructive activity?", model=fake,
        max_iterations=1, limit=20,
    )
    first = result["iterations"][0]
    assert first["action"] == "initial_query"
    assert first.get("audit_id"), "iteration 0 must carry provenance"
