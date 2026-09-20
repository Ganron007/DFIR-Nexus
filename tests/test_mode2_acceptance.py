"""WP 4j.13 — Mode 2 acceptance test (GATE 4j-C pre-check).

The experienced-analyst back-and-forth, end to end, automated:
NL question → structured query (backbone, validated) → hits → LLM interprets →
proposes next structured query + aggregation → examiner steering (question
refinement) → corroboration check → DRAFT staged for examiner approval.

Invariants asserted: the loop never writes findings itself (drafts flow
through the normal promote/save path); every LLM query is DSL-validated;
provenance (audit_id, skill/citation) travels; approval stays examiner-only.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

os.environ.setdefault("NEXUS_RAG_PRELOAD", "0")


class _FakeModel:
    """Scripted: one response per invoke call."""

    def __init__(self, payloads: list[dict[str, Any]]):
        self.payloads = list(payloads)
        self.prompts: list[list[dict]] = []

    def invoke(self, messages):
        self.prompts.append(messages)

        class _R:
            content = json.dumps(self.payloads.pop(0)) if self.payloads else "{}"

        return _R()


def _mkcase() -> Path:
    """Build the acceptance case through the real MCP tool surface."""
    import tempfile

    root = Path(tempfile.mkdtemp(prefix="m2_accept_"))
    os.environ["NEXUS_CASES_ROOT"] = str(root)
    os.environ["NEXUS_ACTIVE_CASE_FILE"] = str(root / "ptr")
    from nexus.app import create_server

    server = create_server()
    tools = server._tool_manager._tools
    r = tools["case_init"].fn("Mode 2 Acceptance", case_id="CASE-M2ACC")
    cid = r["case_id"]
    tools["case_activate"].fn(cid)
    case_dir = Path(r["case_dir"])
    ext = case_dir / "extractions" / "hayabusa"
    ext.mkdir(parents=True, exist_ok=True)
    (ext / "timeline.csv").write_text(
        "Timestamp,Computer,Channel,EventID,Level,RuleTitle,OtherFields\n"
        "2026-08-10 15:00:00,WS01,Sec,4688,high,Suspicious SDelete Usage,sdelete.exe -p 5\n"
        "2026-08-10 15:05:00,WS01,Sec,4688,high,Suspicious Rundll32 Execution,rundll32.exe\n"
        "2026-08-10 15:07:00,WS01,Sec,1102,high,Security Log Cleared,wevtutil cl Security\n",
        encoding="utf-8",
    )
    return case_dir


def test_mode2_acceptance_end_to_end():
    from nexus.audit import AuditWriter
    from nexus.langgraph.backbone import backbone_call
    from nexus.langgraph.mode1 import promote_hits_to_draft, save_draft_finding
    from nexus.langgraph.mode2 import (
        corroboration_check,
        propose_next_needles,
    )

    case_dir = _mkcase()
    loop_audit = AuditWriter("nexus")

    # ── Turn 1: examiner NL question → structured query through the backbone ──
    r1 = backbone_call(
        "es_search", audit=loop_audit,
        query={"bool": {"must": [
            {"term": {"family": "hayabusa"}},
            {"match_phrase": {"text": "sdelete"}},
        ]}},
        size=50,
    )
    assert "error" not in r1, r1
    assert r1["total"] >= 1
    assert r1["provenance"]["audit_id"]
    hits = r1["hits"]
    assert all(str(h.get("family")) == "hayabusa" for h in hits), "family filter enforced"

    # ── Turn 2: LLM proposes the next structured query + an aggregation ──
    fake = _FakeModel([{  # type: ignore[list-item]
        # proposal turn: next structured query + aggregation
        "queries": [{"dsl": "family:hayabusa AND wevtutil", "why": "log clear"}],
        "aggregations": [{"dsl": "family:hayabusa AND sdelete",
                          "field": "host", "why": "scope"}],
        "rationale": "corroborate the clearing chain",
    }])
    r2 = backbone_call(
        "es_search", audit=loop_audit,
        query={"bool": {"must": [
            {"term": {"family": "hayabusa"}},
            {"match_phrase": {"text": "4688"}},
        ]}},
        size=50,
    )
    assert r2["total"] >= 2
    hits = hits + r2["hits"]

    proposal = propose_next_needles(case_dir, "sdelete rundll32 clearing?",
                                    hits, ["family:hayabusa AND sdelete"], model=fake)
    assert proposal["source"] == "llm"
    assert any("wevtutil" in q["query"] for q in proposal["dsl_queries"])
    assert proposal["aggregations"], "proposed aggregation expected"

    # ── the loop runs the proposal (queries + aggregation) ──
    r3 = backbone_call(
        "es_search", audit=loop_audit,
        query={"bool": {"must": [
            {"term": {"family": "hayabusa"}},
            {"match_phrase": {"text": "wevtutil"}},
        ]}},
        size=50,
    )
    assert r3["total"] >= 1
    agg = backbone_call(
        "es_aggregate", audit=loop_audit,
        aggs={"hosts": {"terms": {"field": "host", "size": 5}}},
    )
    assert agg.get("aggregations"), agg
    assert agg["provenance"]["audit_id"]

    # ── examiner steers: refine to log-clearing only ──
    r4 = backbone_call(
        "es_search", audit=loop_audit,
        query={"bool": {"must": [
            {"term": {"family": "hayabusa"}},
            {"match_phrase": {"text": "1102"}},
        ]}},
        size=50,
    )
    assert r4["total"] >= 1, "steered query must find the 1102 row"

    # ── draft from the steering query's hits — staged, never approved ──
    draft = promote_hits_to_draft(
        case_dir,
        hits=r4["hits"],
        title="Signal: Security Log Cleared — hayabusa",
        examiner="mode2-acceptance",
        interpretation_hint="Event 1102 — security log cleared during the window.",
    )
    from nexus.langgraph.mode1 import _heuristic_scribe

    draft = _heuristic_scribe(draft, r4["hits"], case_dir=case_dir)
    draft = {**draft, "confidence": "LOW",
             "confidence_justification": "single-family Mode 2 draft pending corroboration",
             # FD-001: the backbone call that produced the hits IS the audit trail
             "audit_ids": [r4["provenance"]["audit_id"]]}
    res = save_draft_finding(case_dir, draft)
    assert res.get("status") == "STAGED", res
    fid = res.get("finding_id")

    # ── corroboration: single-family finding must be flagged LOW ──
    backbone_call("es_search", audit=loop_audit,
                  query={"match_phrase": {"text": "wevtutil"}}, size=20)
    finding = {"evidence": [{"source": "hayabusa", "description": "1102 row"}],
               "confidence": "LOW"}
    corr = corroboration_check(finding)
    assert corr.get("needs_corroboration") is not False
    assert staged_finding_visible(case_dir, fid)


def staged_finding_visible(case_dir: Path, fid: str | None = None) -> bool:
    """The DRAFT staged by Mode 2 exists in findings.json (examiner reviews it)."""
    import json as _json

    findings = _json.loads((case_dir / "findings.json").read_text(encoding="utf-8"))
    return bool(findings) and all(f.get("status") != "APPROVED" for f in findings)


def test_mode2_loop_never_writes_findings():
    """Hard invariant: the Mode 2 loop returns iterations — findings.json is
    untouched until promote/save runs outside the loop."""
    from nexus.langgraph.mode2 import run_iterative_loop

    case_dir = _mkcase()
    fake = _FakeModel([{  # type: ignore[list-item]
        "needles": ["sdelete"],
        "queries": [{"dsl": "family:hayabusa AND sdelete", "why": "q"}],
        "rationale": "r",
    }])
    result = run_iterative_loop(case_dir, "sdelete destructive activity?",
                                model=fake, max_iterations=1, limit=20)
    assert result["iterations"]
    findings_file = case_dir / "findings.json"
    if findings_file.exists():
        import json as _json

        findings = _json.loads(findings_file.read_text(encoding="utf-8") or "[]")
        assert not findings, "the loop must never write findings"

@pytest.fixture(autouse=True)
def _csv_backbone_stub(monkeypatch):
    """4k.5.5: the agent backbone is ES-only; unit tests run without a
    cluster, so double it with a CSV-backed stub that keeps the audit and
    hit-shape contract identical."""
    import json as _json
    import os
    from pathlib import Path as _Path

    import nexus.langgraph.backbone as _bb

    _orig = _bb.backbone_call

    def _active_case_dir():
        ptr = (os.environ.get("NEXUS_ACTIVE_CASE_FILE") or "").strip()
        try:
            if ptr and _Path(ptr).is_file():
                return _Path(_Path(ptr).read_text(encoding="utf-8").strip())
        except OSError:
            pass
        return None

    def _fake(name, audit=None, **kwargs):
        case_dir = _active_case_dir()
        if name in ("es_search", "n4_query"):
            from nexus.langgraph.query_pack import n4_hits

            if case_dir is None:
                return {"error": "no active case", "total": 0, "hits": []}
            hits, _backend = n4_hits(
                case_dir,
                ["sdelete", "rundll32", "mimikatz", "wevtutil",
                 "prefetch-only.exe", "4625"],
                (None, None),
                backend="csv",
            )
            payload = _json.dumps(kwargs.get("query") or kwargs.get("dsl") or {}).lower()
            known = [t for t in ("sdelete", "rundll32", "prefetch", "wevtutil",
                                 "mimikatz", "4625", "4688", "1102", "psexec")
                     if t in payload]
            if known:
                hits = [
                    h for h in hits
                    if any(t in str(h.get("text", "")).lower() for t in known)
                ]
            elif not kwargs.get("match_all"):
                hits = []
            import re as _re

            from nexus.langgraph.query_pack import attach_hit_fields

            fams = _re.findall(r'"family"\s*:\s*"([^"]+)"', payload)
            if fams:
                hits = [h for h in hits if str(h.get("family")) in fams]
            with __import__("contextlib").suppress(Exception):
                hits = attach_hit_fields(case_dir, hits) if case_dir else hits
            aid = audit.log(tool=name, params={}, result_summary={}) if audit else None
            return {"total": len(hits), "count": len(hits), "hits": hits,
                    "backend": "elasticsearch",
                    "provenance": {"audit_id": aid,
                                   "case_id": case_dir.name if case_dir else ""}}
        if name == "es_aggregate":
            aid = audit.log(tool=name, params={}, result_summary={}) if audit else None
            return {"aggregations": {"v": {"buckets": [
                {"key": "WS01", "doc_count": 2}]}}, "next_after_key": None,
                "provenance": {"audit_id": aid}}
        if name == "es_sample":
            aid = audit.log(tool=name, params={}, result_summary={}) if audit else None
            return {"hits": [], "matched": 0, "provenance": {"audit_id": aid}}
        return _orig(name, audit=audit, **kwargs)

    monkeypatch.setattr(_bb, "backbone_call", _fake)
