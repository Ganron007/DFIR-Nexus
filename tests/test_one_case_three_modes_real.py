"""WO-1C acceptance, real path: one case, Modes 1 -> 2 -> 3 on the same index, then cross-mode.

The scripted models stand in for the LLM and nothing else. Every evidence call is a real
Elasticsearch query through the product's audited backbone, on a real index built from
real EvtxECmd output lines (the operator's ES-Mapping set). Findings are staged by the
product's own staging paths, and `nexus cross-mode --case` reads the stored runs.

Skipped when Elasticsearch or the real output is absent, so the default suite stays
hermetic. The case is throwaway and its index is deleted afterwards.
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import os
import urllib.error
import urllib.request
from pathlib import Path
from types import SimpleNamespace

import pytest

ES = os.environ.get("NEXUS_TEST_ES_URL", "http://localhost:9200").rstrip("/")
REAL = Path(__file__).resolve().parents[1] / "Evidence-files" / "ES-Mapping" / "outputs" / "evtxecmd"
SOURCE = REAL / "20260921194149_EvtxECmd_Output.csv"
# This test writes to the real cluster (it is a real-path test), so its index carries the test-*
# name and its fixture deletes it. The session tripwire (tests/conftest.py) compares the nexus-case-*
# indexes at session start and end. The old name, case-36ereal01, was already on the cluster when a
# run started and was removed by that run's teardown (2026-10-11), which the tripwire reported.
CASE_ID = "TEST-36EREAL01"
INDEX = "nexus-case-test-36ereal01"
SHARED_TITLE = "Event 1004 records from Microsoft-Windows-Security-SPP are present on the host"
SHARED_ENTITY = {"type": "event_id", "value": "1004"}
# fields.EventId is a long in the real mapping (no .kw subfield). The tool text says
# "fields.<Name>.kw"; on a numeric column that matches nothing, silently (register D69).
ES_QUERY = {"bool": {"filter": [{"term": {"fields.EventId": 1004}}]}}  # most common EventId in the 800-row slice


def _es_up() -> bool:
    try:
        with urllib.request.urlopen(ES, timeout=3) as resp:
            return resp.status == 200
    except (urllib.error.URLError, OSError):
        return False


pytestmark = pytest.mark.skipif(
    not (_es_up() and SOURCE.is_file()),
    reason="needs a local Elasticsearch and the operator's real EvtxECmd output",
)


class Scripted:
    """A stand-in for the LLM: one route answers every call. `invoke` serves the context
    loops, `ainvoke` serves the interpret loop."""

    def __init__(self, route):
        self.route = route

    def invoke(self, messages, **_kw):
        return SimpleNamespace(content=self.route(_text(messages)))

    async def ainvoke(self, messages, **_kw):
        return SimpleNamespace(content=self.route(_text(messages)))


def _text(messages) -> str:
    return "\n".join(str(m.get("content") if isinstance(m, dict) else m) for m in messages)


def _audit_ids(case_dir: Path, tool: str) -> list[str]:
    """Audit ids of this case's successful calls to one tool, oldest first (real calls)."""
    out: list[str] = []
    for line in (case_dir / "audit" / "nexus.jsonl").read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        rec = json.loads(line)
        summary = rec.get("result_summary") or {}
        if rec.get("tool") == tool and not summary.get("error") and rec.get("audit_id"):
            out.append(rec["audit_id"])
    return out


def _candidate(audit_id: str) -> dict:
    return {
        "title": SHARED_TITLE,
        "severity": "medium",
        "confidence": "MEDIUM",
        "confidence_justification": "one parser family, rows returned by a real query",
        "observation": "EventID 1004 rows are present in the indexed EvtxECmd output",
        "interpretation": "the event is recorded; its meaning needs the event data",
        "audit_ids": [audit_id],
        "entity": SHARED_ENTITY,
    }


@pytest.fixture
def case(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_CASES_ROOT", str(tmp_path / "cases"))
    monkeypatch.setenv("NEXUS_ACTIVE_CASE_FILE", str(tmp_path / "active_case"))
    monkeypatch.setenv("NEXUS_ES_URL", ES)
    case_dir = tmp_path / "cases" / CASE_ID
    (case_dir / "extractions" / "evtxecmd").mkdir(parents=True)
    (case_dir / "CASE.yaml").write_text(
        f"case_id: {CASE_ID}\nname: WO-1C real path\nintake:\n"
        "  question: Compromise suspected.\n  set_by: operator\n",
        encoding="utf-8",
    )
    with open(SOURCE, encoding="utf-8-sig", errors="replace") as fh:
        head = "".join(next(fh) for _ in range(800))
    (case_dir / "extractions" / "evtxecmd" / "real.csv").write_text(head, encoding="utf-8")
    from nexus.langgraph.case_index import index_case

    index_case(case_dir, incremental=False)
    yield case_dir
    with contextlib.suppress(urllib.error.URLError, OSError):
        urllib.request.urlopen(urllib.request.Request(f"{ES}/{INDEX}", method="DELETE"), timeout=20).read()


def test_one_case_modes_one_two_three_then_cross_mode(case, monkeypatch):
    from typer.testing import CliRunner

    from nexus.audit import AuditWriter
    from nexus.cli.main import app
    from nexus.langgraph.backbone import backbone_call
    from nexus.langgraph.case_digest import build_case_digest, render_digest_markdown
    from nexus.langgraph.interpret_loop import run_interpret_loop
    from nexus.langgraph.llm_pipeline import make_interpret_executor
    from nexus.modes import multi_role
    from nexus.modes.llm_desk import promote_hits_to_draft, save_draft_finding
    from nexus.modes.multi_agent import run_mode3, stage_mode3
    from nexus.modes.multi_role import stage_run_candidates

    audit = AuditWriter("nexus", audit_dir=case / "audit")

    # ---- Mode 1: interpret loop; real digest; each query is a real ES call --------------
    digest = build_case_digest(case)
    digest_md = render_digest_markdown(digest)
    orient = json.dumps({
        "hypotheses": [{"id": "H1", "statement": SHARED_TITLE, "why": "EventID 1004 in the index"}],
        "queries": [{"es": {"query": ES_QUERY}, "why": "process creation rows"}],
    })
    verify = json.dumps({
        "notes": [{"hypothesis": "H1", "status": "confirmed",
                   "evidence": "EventID 1004 rows returned by es_search", "family": "evtxecmd"}],
        "next": [],
    })

    # The production executor (the same object the Mode 1 pipeline gives the loop).
    execute = make_interpret_executor(case, {})
    scripted = [orient, verify, json.dumps([{"title": SHARED_TITLE}])]
    m1 = asyncio.run(run_interpret_loop(
        case_dir=case, case_id=CASE_ID,
        model=Scripted(lambda _t: scripted.pop(0) if len(scripted) > 1 else scripted[0]),
        state={"case_context": {"interpret_rounds": "1"}},
        digest=digest, digest_md=digest_md,
        sections=[(0, "case_digest", digest_md)],
        execute=execute, run_id="M1-36EREAL01", context_policy="independent",
    ))
    m1_audit = _audit_ids(case, "es_search")
    assert m1_audit, "Mode 1 made no real es_search call"
    # Mode 1's real promotion: the examiner picks rows the query returned, and the draft
    # carries those rows as its evidence (D70: the same rows Modes 2 and 3 cite).
    picked = backbone_call("es_search", audit=audit, case_dir=case, query=ES_QUERY)["hits"]
    draft = promote_hits_to_draft(case, picked, SHARED_TITLE, examiner="operator",
                                  entity=SHARED_ENTITY)
    draft.update({
        "severity": "medium", "confidence": "MEDIUM",
        "confidence_justification": "one parser family, rows returned by a real query",
        "observation": "EventID 1004 rows are present in the indexed EvtxECmd output",
        "interpretation": "the event is recorded; its meaning needs the event data",
        "run_id": m1["run_id"], "provenance": {"mode": 1},
    })
    assert draft["evidence"], "Mode 1 promotion must carry the rows it picked"
    save_draft_finding(case, draft)

    # ---- Mode 2: multi-role run; evidence roles query ES through the context loop -------
    def mode2_route(text: str) -> str:
        if "You are the verifier" in text:
            return json.dumps({"verdicts": []})
        if "You are the synthesis agent" in text:
            return json.dumps({"narrative": SHARED_TITLE,
                               "findings": [_candidate(_audit_ids(case, "es_search")[-1])], "gaps": []})
        if "- es_search:" not in text:
            return json.dumps({"tool_calls": [{"tool": "es_search", "why": "1004 rows",
                                               "args": {"query": ES_QUERY}}]})
        return json.dumps({"notes": [], "patterns": [], "corroborated_entities": [],
                           "candidate_findings": [_candidate(_audit_ids(case, "es_search")[-1])]})

    m2 = multi_role.run_mode2(case, "Compromise suspected.", model=Scripted(mode2_route),
                              max_orders=2, resume=False, es_ok=True)
    assert m2.get("status") == "completed", m2.get("status")
    stage2 = stage_run_candidates(case, m2["run_id"])
    assert "error" not in stage2, stage2

    # ---- Mode 3: multi-agent run; seats query ES through the same loop -------------------
    def mode3_route(text: str) -> str:
        if "You supervise a concurrent forensic investigation" in text:
            return json.dumps({"spawns": [{"role": "evidence", "family": "evtxecmd", "why": "event logs"}]})
        if "You are the verifier" in text:
            return json.dumps({"verdicts": []})
        if "- es_search:" not in text:
            return json.dumps({"tool_calls": [{"tool": "es_search", "why": "1004 rows",
                                               "args": {"query": ES_QUERY}}]})
        return json.dumps({"claims": [{
            "entity_type": "event_id", "entity_value": "1004", "claim_kind": "presence",
            "polarity": "affirm", "value": SHARED_TITLE,
            "audit_ids": [_audit_ids(case, "es_search")[-1]],
            "confidence": "MEDIUM",
            "confidence_justification": "rows returned by a real query",
        }], "open_questions": []})

    monkeypatch.setenv("NEXUS_MODE3_MAX_SUPERSTEPS", "3")
    monkeypatch.setenv("NEXUS_MODE3_MAX_AGENTS", "3")
    m3 = run_mode3(case, "Compromise suspected.", model=Scripted(mode3_route),
                   families=[("evtxecmd", 800)], es_ok=True)
    assert m3.get("status") in ("completed", "stopped"), m3.get("status")
    stage3 = stage_mode3(case, m3["run_id"])  # the examiner's Mode 3 staging path
    assert "error" not in stage3, stage3

    # ---- Acceptance: one case, three runs, one DRAFT per claim, every DRAFT attributable -
    runs = {m1["run_id"], m2["run_id"], m3["run_id"]}
    assert {r[:2] for r in runs} == {"M1", "M2", "M3"}, runs
    findings = json.loads((case / "findings.json").read_text(encoding="utf-8"))
    titles = [f["title"].strip().lower() for f in findings]
    assert len(titles) == len(set(titles)), f"duplicate DRAFT titles: {titles}"
    for f in findings:
        assert f.get("provenance", {}).get("mode") in (1, 2, 3), f.get("provenance")
        assert f.get("run_id") in runs or set(f.get("run_ids") or []) <= runs, f
    shared = next(f for f in findings if f["title"].strip().lower() == SHARED_TITLE.lower())
    assert sorted(shared.get("modes") or []) == [1, 2, 3], (
        shared.get("modes"), shared.get("run_ids"), stage3.get("staged"), stage3.get("skipped"),
        [(f.get("title"), f.get("run_id"), f.get("provenance")) for f in findings])

    # ---- cross-mode over the one case reads the stored runs ------------------------------
    out = CliRunner().invoke(app, ["cross-mode", "--case", CASE_ID])
    assert out.exit_code == 0, out.output
    assert "1" in out.output and "2" in out.output and "3" in out.output, out.output
