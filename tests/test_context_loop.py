"""WP 10.53/10.54 — shared bounded context-engineering loop tests."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import patch

from nexus.audit import AuditWriter


class _ScriptedModel:
    """One JSON payload per invoke; records the messages it was given."""

    def __init__(self, payloads: list[dict[str, Any]]):
        self.payloads = list(payloads)
        self.prompts: list[list[dict[str, str]]] = []

    def invoke(self, messages):
        self.prompts.append(messages)

        class _R:
            content = json.dumps(self.payloads.pop(0)) if self.payloads else "{}"

        return _R()


class _RawModel:
    """Returns exact raw strings; used to test malformed JSON recovery."""

    def __init__(self, contents: list[str]):
        self.contents = list(contents)
        self.prompts: list[list[dict[str, str]]] = []

    def invoke(self, messages):
        self.prompts.append(messages)

        class _R:
            content = self.contents.pop(0) if self.contents else "{}"

        return _R()


def _fake_backbone(monkeypatch, calls: list[dict[str, Any]]):
    """Stub the audited backbone with deterministic, provenance-carrying rows."""
    import nexus.langgraph.backbone as bb

    def _fake(name, audit=None, **kwargs):
        calls.append({"tool": name, "kwargs": kwargs})
        if name == "es_mappings":
            result: dict[str, Any] = {
                "case_id": "CASE-LOOP",
                "families": {"hayabusa": 2},
                "core_fields": [{"field": "family"}, {"field": "host"}],
                "parsed_columns": [{"field": "fields.RuleTitle"}],
                "ts_note": "ts is canonical UTC",
            }
        elif name == "es_search":
            result = {
                "total": 2,
                "returned": 2,
                "has_more": False,
                "next_search_after": None,
                "hits": [
                    {"family": "hayabusa", "file": "timeline.csv", "line": "1",
                     "host": "WS01", "text": "sdelete.exe -p 5"},
                    {"family": "hayabusa", "file": "timeline.csv", "line": "2",
                     "host": "WS01", "text": "rundll32.exe"},
                ],
            }
        elif name == "es_aggregate":
            result = {
                "aggregations": {"v": {"buckets": [{"key": "WS01", "doc_count": 2}]}},
                "next_after_key": None,
            }
        elif name == "sample_rows":
            result = {"matched": 2, "sampled": 1, "window_truncated": False,
                      "hits": [{"family": "hayabusa", "file": "timeline.csv",
                                "line": "1", "text": "sdelete.exe -p 5"}]}
        elif name == "run_record":
            result = {"available": True, "counts": {"OK": 1, "SKIP": 0, "FAIL": 0},
                      "entries": [{"tool": "hayabusa", "status": "OK",
                                   "reason": "", "purpose": "evtx",
                                   "output": "timeline.csv", "audit_id": "hay-1"}],
                      "total": 1}
        elif name == "kb_query":
            result = {"available": True,
                      "hits": [{"title": "anti-forensics", "snippet": "check sdelete"}]}
        elif name == "rag_search":
            result = {"status": "ok",
                      "results": [{"id": "sigma-1", "score": 0.91,
                                   "source": "sigma", "title": "SDelete",
                                   "text": "sdelete detection"}]}
        else:
            result = {"error": f"unexpected tool {name}"}
        aid = audit.log(tool=name, params={}, result_summary={}) if audit else None
        result["provenance"] = {"audit_id": aid, "case_id": "CASE-LOOP"}
        return result

    monkeypatch.setattr(bb, "backbone_call", _fake)


def _case(tmp_path: Path) -> Path:
    case = tmp_path / "CASE-LOOP"
    (case / "analysis").mkdir(parents=True)
    return case


def test_context_loop_calls_tools_then_answers(tmp_path, monkeypatch):
    from nexus.langgraph.context_loop import run_context_loop

    case = _case(tmp_path)
    calls: list[dict[str, Any]] = []
    _fake_backbone(monkeypatch, calls)
    model = _ScriptedModel([
        {"tool_calls": [{"tool": "es_mappings", "args": {}, "why": "learn schema"}]},
        {"tool_calls": [{"tool": "es_search",
                         "args": {"query": {"match_all": {}}, "size": 5},
                         "why": "find rows"}]},
        {"answer": "Found 2 rows on WS01.",
         "citations": [{"family": "hayabusa", "file": "timeline.csv", "line": "1"}]},
    ])
    result = run_context_loop(
        case_dir=case,
        case_id="CASE-LOOP",
        question="What happened on WS01?",
        model=model,
        audit=AuditWriter("nexus", audit_dir=case / "audit"),
    )
    assert result["finish_reason"] == "answer"
    assert result["partial"] is False
    assert "Found 2 rows" in result["reply"]
    assert [c["tool"] for c in result["tool_calls"]] == ["es_mappings", "es_search"]
    assert len(result["hits"]) == 2
    assert all(c["audit_id"] for c in result["tool_calls"])
    assert result["audit_id"]
    # No pre-retrieval: the first model prompt carries the pointers, not rows.
    first_prompt = model.prompts[0][-1]["content"]
    assert "TOOL PROTOCOL" in first_prompt
    assert "sdelete.exe" not in first_prompt
    # Successful tool results must be visible in the next round's prompt.
    second_prompt = model.prompts[1][-1]["content"]
    assert "parsed_columns" in second_prompt or "timeline.csv" in second_prompt


def test_context_loop_budget_partial_returns_rows(tmp_path, monkeypatch):
    from nexus.langgraph.context_loop import LoopBudget, run_context_loop

    case = _case(tmp_path)
    calls: list[dict[str, Any]] = []
    _fake_backbone(monkeypatch, calls)
    model = _ScriptedModel([
        {"tool_calls": [{"tool": "es_search",
                         "args": {"query": {"match_phrase": {"text": "sdelete"}}},
                         "why": "find sdelete"}]},
        {"tool_calls": [{"tool": "es_search",
                         "args": {"query": {"match_phrase": {"text": "rundll32"}}},
                         "why": "find rundll32"}]},
    ])
    result = run_context_loop(
        case_dir=case,
        case_id="CASE-LOOP",
        question="Find sdelete and rundll32",
        model=model,
        budget=LoopBudget(rounds=1, seconds=30.0, calls=2),
        audit=AuditWriter("nexus", audit_dir=case / "audit"),
    )
    assert result["partial"] is True
    assert result["partial_reason"] in ("rounds", "calls")
    assert "Partial result" in result["reply"]
    assert "sdelete.exe" in result["reply"]
    assert result["hits"], "budget stop must keep the rows already retrieved"
    assert result["tool_calls"], "budget stop must keep the tool chain"


def test_context_loop_unknown_tool_is_reported_then_recovers(tmp_path, monkeypatch):
    from nexus.langgraph.context_loop import run_context_loop

    case = _case(tmp_path)
    calls: list[dict[str, Any]] = []
    _fake_backbone(monkeypatch, calls)
    model = _ScriptedModel([
        {"tool_calls": [{"tool": "delete_case", "args": {}, "why": "nope"}]},
        {"answer": "No mutation is possible."},
    ])
    result = run_context_loop(
        case_dir=case,
        case_id="CASE-LOOP",
        question="Try a mutating tool",
        model=model,
        audit=AuditWriter("nexus", audit_dir=case / "audit"),
    )
    assert result["finish_reason"] == "answer"
    assert "No mutation" in result["reply"]
    assert result["tool_calls"] == []
    assert calls == [], "a non-allowlisted tool must never reach the backbone"


def test_context_loop_suppresses_duplicate_calls(tmp_path, monkeypatch):
    from nexus.langgraph.context_loop import run_context_loop

    case = _case(tmp_path)
    calls: list[dict[str, Any]] = []
    _fake_backbone(monkeypatch, calls)
    same = {"tool": "es_search",
            "args": {"query": {"match_phrase": {"text": "sdelete"}}},
            "why": "find sdelete"}
    model = _ScriptedModel([
        {"tool_calls": [same]},
        {"tool_calls": [same]},
        {"answer": "Used the first result."},
    ])
    result = run_context_loop(
        case_dir=case,
        case_id="CASE-LOOP",
        question="Find sdelete once",
        model=model,
        audit=AuditWriter("nexus", audit_dir=case / "audit"),
    )
    assert result["finish_reason"] == "answer"
    assert len([c for c in calls if c["tool"] == "es_search"]) == 1
    assert result["duplicate_calls"] == 1
    assert result["hits"]


def test_context_loop_allows_model_supplied_case_id(tmp_path, monkeypatch):
    from nexus.langgraph.context_loop import run_context_loop

    case = _case(tmp_path)
    calls: list[dict[str, Any]] = []
    _fake_backbone(monkeypatch, calls)
    model = _ScriptedModel([
        {"tool_calls": [{"tool": "es_mappings", "args": {"case_id": "CASE-LOOP"}}]},
        {"answer": "Schema read."},
    ])
    result = run_context_loop(
        case_dir=case,
        case_id="CASE-LOOP",
        question="Show schema",
        model=model,
        audit=AuditWriter("nexus", audit_dir=case / "audit"),
    )
    assert result["finish_reason"] == "answer"
    assert result["tool_calls"][0]["tool"] == "es_mappings"


def test_context_loop_force_answer_after_tool_rounds(tmp_path, monkeypatch):
    from nexus.langgraph.context_loop import LoopBudget, run_context_loop

    case = _case(tmp_path)
    calls: list[dict[str, Any]] = []
    _fake_backbone(monkeypatch, calls)
    model = _ScriptedModel([
        {"tool_calls": [{
            "tool": "es_search",
            "args": {"query": {"match_phrase": {"text": "sdelete"}}},
            "why": "find rows",
        }]},
        {"answer": "Answered from the observations already collected."},
    ])
    result = run_context_loop(
        case_dir=case,
        case_id="CASE-LOOP",
        question="Answer after tools",
        model=model,
        budget=LoopBudget(rounds=1, seconds=30.0, calls=4),
        audit=AuditWriter("nexus", audit_dir=case / "audit"),
    )
    assert result["finish_reason"] == "answer_forced"
    assert result["partial"] is False
    assert "Answered from the observations" in result["reply"]
    assert result["tool_calls"]


def test_context_loop_repairs_trailing_comma_tool_call(tmp_path, monkeypatch):
    from nexus.langgraph.context_loop import run_context_loop

    case = _case(tmp_path)
    calls: list[dict[str, Any]] = []
    _fake_backbone(monkeypatch, calls)
    valid = json.dumps({
        "tool_calls": [{
            "tool": "es_search",
            "args": {"query": {"match_phrase": {"text": "sdelete"}}},
            "why": "find",
        }],
    })
    # Trailing comma before the list close — the exact live-model defect.
    malformed = valid.replace("]}", ",]}", 1)
    model = _RawModel([
        malformed,
        '{"answer":"Recovered after a tolerant JSON parse."}',
    ])
    result = run_context_loop(
        case_dir=case,
        case_id="CASE-LOOP",
        question="Find sdelete",
        model=model,
        audit=AuditWriter("nexus", audit_dir=case / "audit"),
    )
    assert result["finish_reason"] == "answer"
    assert result["tool_calls"] and result["tool_calls"][0]["tool"] == "es_search"
    assert result["hits"]


def test_context_loop_malformed_tool_call_is_not_an_answer(tmp_path, monkeypatch):
    from nexus.langgraph.context_loop import run_context_loop

    case = _case(tmp_path)
    calls: list[dict[str, Any]] = []
    _fake_backbone(monkeypatch, calls)
    model = _RawModel([
        '{"tool_calls": [{"tool": "es_search", "args": {',  # unrecoverable
        '{"answer":"Recovered with a valid reply."}',
    ])
    result = run_context_loop(
        case_dir=case,
        case_id="CASE-LOOP",
        question="Find sdelete",
        model=model,
        audit=AuditWriter("nexus", audit_dir=case / "audit"),
    )
    assert result["finish_reason"] == "answer"
    assert "tool_calls" not in result["reply"]
    assert "Recovered" in result["reply"]
    assert calls == [], "malformed tool call must never execute a tool"


def test_context_loop_plain_text_answer_is_accepted(tmp_path, monkeypatch):
    from nexus.langgraph.context_loop import run_context_loop

    case = _case(tmp_path)
    _fake_backbone(monkeypatch, [])

    class _Plain:
        def invoke(self, messages):
            class _R:
                content = "Plain answer without JSON."
            return _R()

    result = run_context_loop(
        case_dir=case,
        case_id="CASE-LOOP",
        question="Answer plainly",
        model=_Plain(),
        audit=AuditWriter("nexus", audit_dir=case / "audit"),
    )
    assert result["finish_reason"] == "answer_text"
    assert result["partial"] is False
    assert "Plain answer" in result["reply"]


def test_run_record_reads_the_tool_lane_ledger(tmp_path, monkeypatch):
    from nexus.tools import evidence_index

    case = tmp_path / "CASE-LEDGER"
    ext = case / "runs" / "RUN-1" / "extractions"
    ext.mkdir(parents=True)
    (ext / "_tool_lane_ledger.json").write_text(json.dumps([
        {"tool": "hayabusa", "status": "OK", "reason": "",
         "purpose": "evtx", "output": "timeline.csv", "audit_id": "hay-1"},
        {"tool": "chainsaw", "status": "SKIP", "reason": "no sigma rules",
         "purpose": "evtx", "output": "", "audit_id": ""},
    ]), encoding="utf-8")
    monkeypatch.setattr(evidence_index, "_resolve_active_case",
                        lambda case_id: (case, ""))
    audit = AuditWriter("nexus", audit_dir=case / "audit")
    result = evidence_index.do_run_record(case_id="CASE-LEDGER", audit=audit)
    assert result["available"] is True
    assert result["counts"] == {"OK": 1, "SKIP": 1, "FAIL": 0}
    assert result["total"] == 2
    assert result["entries"][0]["tool"] == "hayabusa"
    assert result["provenance"]["audit_id"]


def test_full_run_scribe_policy_defaults(monkeypatch):
    from nexus.dashboard.app import _full_run_scribe_policy

    monkeypatch.delenv("NEXUS_FULL_RUN_SCRIBE", raising=False)
    monkeypatch.delenv("NEXUS_FULL_RUN_SCRIBE_MIN_HITS", raising=False)
    assert _full_run_scribe_policy() == ("heuristic", 3)
    monkeypatch.setenv("NEXUS_FULL_RUN_SCRIBE", "signal")
    monkeypatch.setenv("NEXUS_FULL_RUN_SCRIBE_MIN_HITS", "5")
    assert _full_run_scribe_policy() == ("signal", 5)
    monkeypatch.setenv("NEXUS_FULL_RUN_SCRIBE", "not-a-mode")
    assert _full_run_scribe_policy()[0] == "heuristic"


def test_briefing_directions_are_persisted_for_the_report(tmp_path):
    from nexus.integration.dfir_report import _load_briefing_directions

    analysis = tmp_path / "analysis"
    analysis.mkdir()
    (analysis / "briefing_directions.json").write_text(json.dumps({
        "source": "llm",
        "directions": [{"title": "Check sdelete", "why": "anti-forensics",
                        "needles": ["sdelete"], "family": "hayabusa"}],
    }), encoding="utf-8")
    directions = _load_briefing_directions(tmp_path)
    assert directions and directions[0]["title"] == "Check sdelete"


def test_directions_gate_keeps_event_ids_out_of_needles():
    from nexus.langgraph.briefing import _normalize_directions

    out = _normalize_directions({
        "directions": [{
            "title": "t", "why": "w", "family": "evtx",
            "needles": ["mimikatz", "1102", "security.evtx"],
        }],
    })
    assert out and out[0]["needles"] == ["mimikatz"]


def test_context_loop_kill_switch(monkeypatch):
    from nexus.langgraph.steer_agent import _context_loop_enabled

    monkeypatch.delenv("NEXUS_CONTEXT_LOOP", raising=False)
    assert _context_loop_enabled() is True
    for raw in ("0", "false", "no", "off"):
        monkeypatch.setenv("NEXUS_CONTEXT_LOOP", raw)
        assert _context_loop_enabled() is False
    monkeypatch.setenv("NEXUS_CONTEXT_LOOP", "1")
    assert _context_loop_enabled() is True


def test_loop_accepts_every_contract_listed_tool():
    """The prompt's tool contracts must be callable; no listed tool is rejected."""
    from nexus.langgraph.context_loop import _TOOL_ARGS

    listed = {
        "es_mappings", "es_search", "es_aggregate", "sample_rows",
        "kb_query", "kb_read", "kb_cite", "rag_search", "run_record",
    }
    assert listed <= set(_TOOL_ARGS)
    # External TI/web tools stay out of the bounded loop by design; the
    # model cannot choose an outbound value.
    assert {"ti_lookup", "ti_fanout", "web_search", "web_fetch"} & set(_TOOL_ARGS) == set()


def test_result_summary_carries_kb_read_content():
    from nexus.langgraph.context_loop import _result_summary

    summary = _result_summary("kb_read", {
        "chunk_id": "d_abc:c0001",
        "citation": "doc.md:10-20",
        "doc_title": "Procedure",
        "text": "run reg save HKLM\\SAM",
    })
    assert summary["chunk_id"] == "d_abc:c0001"
    assert "reg save" in summary["text"]
    assert summary["citation"] == "doc.md:10-20"


def test_force_answer_rejects_empty_json():
    from nexus.langgraph.context_loop import _force_answer

    class _EmptyModel:
        def invoke(self, _messages):
            class _R:
                content = "{}"
            return _R()

    assert _force_answer(
        model=_EmptyModel(), base_system="x", question="q",
        observations=[], call_chars=1000,
    ) == ""


def test_context_loop_marks_zero_tool_answers_unverified(tmp_path, monkeypatch):
    from nexus.langgraph.context_loop import run_context_loop

    case = _case(tmp_path)
    model = _ScriptedModel([{"answer": "sdelete ran on WS01."}])
    result = run_context_loop(
        case_dir=case,
        case_id="CASE-LOOP",
        question="Did sdelete run?",
        model=model,
        audit=AuditWriter("nexus", audit_dir=case / "audit"),
    )
    assert "No evidence tool was called" in result["reply"]


def test_run_record_uses_real_ledger_field_names(tmp_path, monkeypatch):
    from nexus.tools import evidence_index

    case = tmp_path / "CASE-LEDGER-REAL"
    ext = case / "runs" / "RUN-1" / "extractions"
    ext.mkdir(parents=True)
    (ext / "_tool_lane_ledger.json").write_text(json.dumps([
        {"tool": "hayabusa", "status": "OK", "reason": "",
         "purpose": "evtx", "argv": ["hayabusa", "csv-timeline", "-d", "C:\\ev"],
         "output_saved_to": "hayabusa/evtx-timeline.csv", "audit_id": "hay-1"},
    ]), encoding="utf-8")
    monkeypatch.setattr(evidence_index, "_resolve_active_case",
                        lambda case_id: (case, ""))
    result = evidence_index.do_run_record(case_id="CASE-LEDGER-REAL")
    entry = result["entries"][0]
    assert "csv-timeline" in entry["command"]
    assert entry["output"].endswith("evtx-timeline.csv")
    assert result["counts"] == {"OK": 1, "SKIP": 0, "FAIL": 0}


def test_run_record_counts_all_rows_beyond_entry_cap(tmp_path, monkeypatch):
    from nexus.tools import evidence_index

    case = tmp_path / "CASE-LEDGER-BIG"
    ext = case / "runs" / "RUN-1" / "extractions"
    ext.mkdir(parents=True)
    rows = [{"tool": f"t{i}", "status": "OK"} for i in range(305)]
    rows.append({"tool": "late-fail", "status": "FAIL"})
    (ext / "_tool_lane_ledger.json").write_text(json.dumps(rows), encoding="utf-8")
    monkeypatch.setattr(evidence_index, "_resolve_active_case",
                        lambda case_id: (case, ""))
    result = evidence_index.do_run_record(case_id="CASE-LEDGER-BIG")
    assert result["counts"]["OK"] == 305
    assert result["counts"]["FAIL"] == 1
    assert len(result["entries"]) == 300


def test_mode2_chat_stream_emits_tool_events_and_history(tmp_path):
    from starlette.applications import Starlette
    from starlette.testclient import TestClient

    from nexus.dashboard.app import create_dashboard

    case = tmp_path / "INC-stream-1"
    case.mkdir(parents=True)
    (case / "CASE.yaml").write_text("name: stream\nstatus: open\n", encoding="utf-8")
    (case / "audit").mkdir()
    seen: dict[str, Any] = {}

    def _fake_agent(case_dir, message, history=None, on_event=None, **kwargs):
        seen["history"] = history
        if on_event:
            on_event({"event": "round", "round": 1, "max_rounds": 8})
            on_event({"event": "tool_call", "round": 1, "tool": "es_search",
                      "args": {"query": {"match_all": {}}}, "why": "test"})
            on_event({"event": "tool_result", "round": 1, "tool": "es_search",
                      "audit_id": "a-1", "summary": {"total": 1}})
        return {
            "reply": "Found one row.",
            "queries_executed": [{"tool": "es_search", "dsl": "{...}",
                                  "why": "test", "hits": 1, "audit_id": "a-1"}],
            "tool_calls": [{"tool": "es_search", "why": "test",
                            "audit_id": "a-1", "summary": {"total": 1}}],
            "total_hits": 1,
            "partial": False,
            "hits": [{"family": "hayabusa", "file": "a.csv", "line": "1",
                      "text": "hit"}],
        }

    with patch("nexus.dashboard.app._get_case_dir", return_value=case), \
         patch("nexus.langgraph.steer_agent.run_steer_agent", side_effect=_fake_agent):
        client = TestClient(Starlette(routes=create_dashboard()))
        bodies = [
            client.post(
                "/portal/api/chat/stream",
                json={"message": "find rows", "mode": mode,
                      "history": [{"role": "examiner", "text": "prior"}]},
            )
            for mode in ("mode1", "mode2")
        ]
    for response in bodies:
        assert response.status_code == 200
        body = response.text
        assert "event: round" in body
        assert "event: tool_call" in body
        assert "event: tool_result" in body
        assert "event: done" in body
        assert "Found one row." in body
    assert seen["history"] == [{"role": "examiner", "text": "prior"}]


def test_propose_next_needles_uses_context_loop(tmp_path):
    from nexus.modes import llm_guided as mode2

    case = _case(tmp_path)
    (case / "audit").mkdir(exist_ok=True)
    (case / "CASE.yaml").write_text("name: loop\nstatus: active\n", encoding="utf-8")
    hits = [{"family": "hayabusa", "file": "a.csv", "line": "1", "text": "x"}]
    reply = json.dumps({
        "queries": [{"es": {"query": {"match_all": {}}}, "why": "expand"}],
        "rationale": "context-loop proposal",
    })
    with patch("nexus.langgraph.context_loop.run_context_loop",
               return_value={"reply": reply, "tool_calls": [], "hits": []}), \
         patch.object(mode2, "_propose_with_model",
                      side_effect=AssertionError("one-shot fallback must not run")):
        out = mode2.propose_next_needles(case, "q", hits, [], model=object())
    assert out["source"] == "llm-context-loop"
    assert out["es_queries"] and out["es_queries"][0]["why"] == "expand"


def test_analyze_cluster_uses_context_loop(tmp_path):
    from nexus.langgraph import report_analysis

    case = _case(tmp_path)
    (case / "audit").mkdir(exist_ok=True)
    reply = json.dumps({
        "category": "execution", "what": "w", "why": "y",
        "verify": ["check x"], "caveats": ["benign possibility"],
    })
    cluster = [{"id": "F-1", "title": "t", "severity": "high",
                "mitre_ids": ["T1059"]}]
    rows = [{"time": "2026-01-01T00:00:00Z", "source": "hayabusa",
             "detail": "x"}]
    with patch("nexus.langgraph.context_loop.run_context_loop",
               return_value={"reply": reply, "tool_calls": [], "hits": []}):
        out = report_analysis.analyze_cluster(
            cluster, rows, model=object(), case_dir=case)
    assert out["category"] == "execution"
    assert out["source"] == "llm-context-loop"


def test_case_assessment_uses_context_loop(tmp_path):
    from nexus.langgraph import report_analysis

    case = _case(tmp_path)
    (case / "audit").mkdir(exist_ok=True)
    reply = json.dumps({
        "sequence": "s", "scope": "one host", "confidence": "medium",
        "gaps": ["memory not collected"], "recommended": ["collect memory"],
    })
    clusters = [[{"id": "F-1", "title": "t", "severity": "high"}]]
    analyses = {0: {"category": "execution", "what": "w"}}
    rows_for = {0: [{"time": "2026-01-01T00:00:00Z", "source": "hayabusa"}]}
    with patch("nexus.langgraph.context_loop.run_context_loop",
               return_value={"reply": reply, "tool_calls": [], "hits": []}):
        out = report_analysis.case_assessment(
            clusters, analyses, rows_for, model=object(), case_dir=case)
    assert out["sequence"] == "s"
    assert out["source"] == "llm-context-loop"


def test_full_run_llm_scribe_decision():
    from nexus.dashboard.app import _full_run_llm_scribe

    assert _full_run_llm_scribe("heuristic", 3, [1, 2, 3, 4]) is False
    assert _full_run_llm_scribe("llm", 3, [1]) is True
    assert _full_run_llm_scribe("signal", 3, [1, 2]) is False
    assert _full_run_llm_scribe("signal", 3, [1, 2, 3]) is True


def test_slim_tool_calls_drops_large_catalog():
    from nexus.dashboard.app import _slim_tool_calls

    calls = [{
        "tool": "es_mappings",
        "why": "schema",
        "audit_id": "a-1",
        "elapsed_ms": 12.0,
        "summary": {
            "family_count": 3,
            "parsed_columns": ["c"] * 600,
            "hits": [{"text": "x"}] * 25,
        },
    }]
    out = _slim_tool_calls(calls)
    assert out[0]["summary"]["family_count"] == 3
    assert "parsed_columns" not in out[0]["summary"]
    assert "hits" not in out[0]["summary"] or len(out[0]["summary"]["hits"]) <= 3


def test_interpret_plan_accepts_run_record_tool():
    from nexus.langgraph.interpret_loop import _normalize_plan

    plan = _normalize_plan({
        "tools": [{"tool": "run_record", "args": {}, "why": "check parsers"}],
    })
    assert plan["items"][0]["kind"] == "tool"
    assert plan["items"][0]["tool"] == "run_record"


def test_interpretation_verdict_uses_context_loop(tmp_path):
    import asyncio

    from nexus.langgraph.interpretation import write_interpretation_summary

    case = _case(tmp_path)
    (case / "audit").mkdir(exist_ok=True)
    with patch("nexus.langgraph.context_loop.run_context_loop",
               return_value={"reply": "## Executive verdict\nOK.",
                             "tool_calls": [], "hits": []}):
        out = asyncio.run(write_interpretation_summary(
            case,
            findings=[{"title": "T", "confidence": "medium"}],
            model=object(),
        ))
    assert out is not None
    text = out.read_text(encoding="utf-8")
    assert "Executive verdict" in text


def test_alias_routing_is_read_only_and_documented():
    from nexus.langgraph.backbone import MODE2_TOOL_ALLOWLIST, TOOL_ALIASES

    expected = {
        "es_mappings": "es_fields",
        "kb_query": "kb_search",
        "sample_rows": "es_sample",
        "rag_search": "forensic_rag_search",
        "run_record": "run_record",
    }
    assert expected == TOOL_ALIASES
    for alias, canonical in expected.items():
        assert alias in MODE2_TOOL_ALLOWLIST
        assert canonical in MODE2_TOOL_ALLOWLIST or canonical in (
            "forensic_rag_search", "run_record")
    for forbidden in ("case_delete", "record_finding", "approve_finding",
                      "evidence_register", "case_archive"):
        assert forbidden not in TOOL_ALIASES
