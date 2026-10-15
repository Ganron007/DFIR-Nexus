"""D130: Mode 1 stages only the interpret run's own candidates, and says what it refused.

The staging step used to stage N4 needle clusters when the model produced no candidate, when
every model candidate was rejected ("N4 hit salvage"), and beside the model's findings, chosen
by a keyword list from earlier cases (sdelete, pst, Google Drive, usb...). That generator
(`n4_finding_candidates`) has since been removed; these drive the real `stage_findings`.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest
import yaml

LLM = {"title": "Encoded PowerShell launched by a service",
       "observation": "4104 script block decodes to a downloader",
       "interpretation": "execution of a staged payload", "confidence": "MEDIUM",
       "confidence_justification": "two rows", "event_timestamp": "2023-07-10T10:00:00Z",
       "audit_ids": ["nexus-test-20261013-002"]}


class _Tool:
    name = "tool"

    def __init__(self, reply):
        self.reply, self.payloads = reply, []

    async def ainvoke(self, payload):
        self.payloads.append(dict(payload))
        return dict(self.reply)


@pytest.fixture()
def case():
    from nexus.config import settings
    from nexus.langgraph.pipeline_runs import create_run

    case_dir = settings.cases_root / "CASE-M1STAGE"
    (case_dir / "analysis").mkdir(parents=True)
    (case_dir / "audit").mkdir()
    (case_dir / "CASE.yaml").write_text(
        yaml.safe_dump({"case_id": case_dir.name, "status": "created"}), encoding="utf-8")
    return case_dir, create_run(case_dir, "interpret")


def _state(case_dir: Path, run_id: str, messages: list) -> dict:
    return {"case_id": case_dir.name, "run_id": run_id, "messages": messages,
            "tool_run_ledger": [], "case_context": {}, "evidence_audit_ids": []}


def _msg(*findings) -> dict:
    return {"role": "assistant", "content": "```json\n" + json.dumps(list(findings)) + "\n```"}


def test_no_candidate_stages_nothing(case):
    from nexus.langgraph.llm_pipeline import stage_findings

    case_dir, run = case
    record = _Tool({"finding_id": "F-1"})
    out = asyncio.run(stage_findings(_state(case_dir, run.run_id, []), {"record_finding": record}))
    assert record.payloads == []
    assert any("no finding candidates" in line for line in out["step_log"])


def test_a_rejected_candidate_is_reported_not_replaced(case):
    from nexus.langgraph.llm_pipeline import stage_findings

    case_dir, run = case
    record = _Tool({"status": "REJECTED", "error": "FD-001: unknown audit id"})
    timeline = _Tool({"event_id": "T-1"})
    out = asyncio.run(stage_findings(_state(case_dir, run.run_id, [_msg(LLM)]),
                                     {"record_finding": record,
                                      "record_timeline_event": timeline}))
    assert [p["title"] for p in record.payloads] == [LLM["title"]]
    assert timeline.payloads == []  # a rejected candidate gets no timeline event
    staging = json.loads((run.analysis / "staging.json").read_text(encoding="utf-8"))
    assert staging["staged"] == []
    assert staging["rejected"] == [{"title": LLM["title"], "reason": "FD-001: unknown audit id"}]
    assert any(line.startswith("Not staged: " + LLM["title"]) for line in out["step_log"])


def test_severity_written_by_the_model_reaches_the_draft(case):
    """D47 (2026-10-14 live run): the model wrote a severity on 9 of 9 findings and none
    reached the DRAFTs, because the parser's normalised candidate had no severity key."""
    from nexus.langgraph.llm_pipeline import stage_findings

    case_dir, run = case
    record = _Tool({"finding_id": "F-SEV"})
    asyncio.run(stage_findings(_state(case_dir, run.run_id, [_msg({**LLM, "severity": "high"})]),
                               {"record_finding": record}))
    assert record.payloads[0]["severity"] == "HIGH"


class _RealRecord:
    """The real MCP ``record_finding`` tool, called the way staging calls it."""

    name = "record_finding"

    def __init__(self, case_dir: Path):
        from mcp.server.fastmcp import FastMCP

        from nexus.audit import AuditWriter
        from nexus.tools import forensic

        server = FastMCP("m1-staging")
        forensic.register_tools(server, AuditWriter("nexus", audit_dir=case_dir / "audit"))
        self.fn = server._tool_manager._tools["record_finding"].fn

    async def ainvoke(self, payload):
        return self.fn(**payload)


def _search(case_dir: Path, rows: list[dict], query: dict) -> str:
    from nexus.audit import AuditWriter

    aid = AuditWriter("nexus", audit_dir=case_dir / "audit").log(
        tool="es_search", params={"case_id": case_dir.name, "query": query},
        result_summary={"evidence_rows": rows})
    assert aid
    return aid


def test_two_claims_on_their_own_rows_are_two_drafts_citing_only_their_own_calls(case):
    """2026-10-14 live run: staging padded every cited candidate with the same "linked" calls,
    and a DRAFT's evidence and entity come from its cited calls. A claim about unattributed
    hashes got the Defender-tamper DRAFT's calls, rows and entity, and was merged into it."""
    from nexus.case_manager import CaseManager
    from nexus.langgraph.llm_pipeline import stage_findings

    case_dir, run = case
    earlier = _search(case_dir, [{"loc": "hayabusa/evtx-timeline.csv:5", "host": "ws01",
                                  "detail": "RuleTitle: Powershell Detect Virtualization Environment"}],
                      {"term": {"family": "hayabusa"}})
    tamper = _search(case_dir, [{"loc": "hayabusa/evtx-timeline.csv:10", "host": "ws01",
                                 "detail": "RuleTitle: Tamper Windows Defender - ScriptBlockLogging"}],
                     {"match": {"text": "DisableRealTimeMonitoring"}})
    hashes = _search(case_dir, [{"loc": "hayabusa/evtx-timeline.csv:20", "host": "ws01",
                                 "detail": "RuleTitle: Suspicious Hashes MD5=9e107d9d372bb6826bd81d3542a419d6"}],
                     {"match": {"text": "MD5"}})
    source = [{"source": "hayabusa/evtx-timeline.csv"}]
    a = {**LLM, "title": "Defender tamper", "audit_ids": [tamper], "evidence": source}
    b = {**LLM, "title": "Unattributed MD5 hashes", "audit_ids": [hashes], "evidence": source}
    asyncio.run(stage_findings(_state(case_dir, run.run_id, [_msg(a, b)]),
                               {"record_finding": _RealRecord(case_dir)}))

    drafts = {f["title"]: f for f in CaseManager()._load_findings(case_dir)}
    assert set(drafts) == {"Defender tamper", "Unattributed MD5 hashes"}
    assert drafts["Defender tamper"]["audit_ids"] == [tamper]
    assert drafts["Unattributed MD5 hashes"]["audit_ids"] == [hashes]
    assert earlier not in drafts["Defender tamper"]["audit_ids"]
    assert [e["loc"] for e in drafts["Unattributed MD5 hashes"]["evidence"]] == [
        "hayabusa/evtx-timeline.csv:20"]


def test_two_claims_that_cite_the_same_large_call_first_are_two_drafts(case):
    """D194 (2026-10-14 run 5): a 63-row call cited first filled every claim's 12 rows, so a second
    claim got the first one's subject and evidence and was linked to its DRAFT."""
    from nexus.case_manager import CaseManager
    from nexus.langgraph.llm_pipeline import stage_findings

    case_dir, run = case
    encoded = _search(case_dir, [{"loc": f"hayabusa/evtx-timeline.csv:{n}", "host": "ws01",
                                  "detail": f"RuleTitle: Potentially Malicious PwSh row {n}"}
                                 for n in range(1, 30)],
                      {"match": {"text": "encodedcommand"}})
    dumper = _search(case_dir, [{"loc": "hayabusa/evtx-timeline.csv:900", "host": "ws01",
                                 "detail": "RuleTitle: Antivirus - Password Dumper Signature"}],
                     {"match_phrase": {"text": "Password Dumper"}})
    sdelete = _search(case_dir, [{"loc": "recmd/reg.csv:44", "host": "ws01",
                                  "detail": "HKU\\.DEFAULT\\Software\\Sysinternals\\SDelete"}],
                      {"match": {"text": "sdelete"}})
    a = {**LLM, "title": "Credential dumping signature", "audit_ids": [encoded, dumper]}
    b = {**LLM, "title": "Secure deletion tool configured", "audit_ids": [encoded, sdelete]}
    asyncio.run(stage_findings(_state(case_dir, run.run_id, [_msg(a, b)]),
                               {"record_finding": _RealRecord(case_dir)}))

    drafts = {f["title"]: f for f in CaseManager()._load_findings(case_dir)}
    assert set(drafts) == {"Credential dumping signature", "Secure deletion tool configured"}
    locs = {t: {e["loc"] for e in d["evidence"]} for t, d in drafts.items()}
    assert "hayabusa/evtx-timeline.csv:900" in locs["Credential dumping signature"]
    assert "recmd/reg.csv:44" in locs["Secure deletion tool configured"]


def test_the_same_claim_on_the_same_rows_is_reported_as_linked_not_staged(case):
    from nexus.langgraph.llm_pipeline import stage_findings

    case_dir, run = case
    tamper = _search(case_dir, [{"loc": "hayabusa/evtx-timeline.csv:10", "host": "ws01",
                                 "detail": "RuleTitle: Tamper Windows Defender"}],
                     {"match": {"text": "DisableRealTimeMonitoring"}})
    claim = {**LLM, "title": "Defender tamper", "audit_ids": [tamper]}
    out = asyncio.run(stage_findings(_state(case_dir, run.run_id, [_msg(claim, claim)]),
                                     {"record_finding": _RealRecord(case_dir)}))
    staging = json.loads((run.analysis / "staging.json").read_text(encoding="utf-8"))
    assert len(staging["staged"]) == 1
    assert staging["linked"] == [{"title": "Defender tamper", "finding_id": staging["staged"][0]}]
    assert any(line.startswith("Linked to existing DRAFT") for line in out["step_log"])


def test_a_coverage_item_is_recorded_not_dropped(case):
    from nexus.langgraph.llm_pipeline import stage_findings

    case_dir, run = case
    stub = {"title": "Malicious IOC contact not established", "observation": "no rows",
            "interpretation": "coverage gap: no network flows in scope", "audit_ids": []}
    record = _Tool({"finding_id": "F-X"})
    asyncio.run(stage_findings(_state(case_dir, run.run_id, [_msg(LLM, stub)]),
                               {"record_finding": record}))
    assert [p["title"] for p in record.payloads] == [LLM["title"]]
    staging = json.loads((run.analysis / "staging.json").read_text(encoding="utf-8"))
    assert [r["title"] for r in staging["rejected"]] == [stub["title"]]
    assert "not a finding" in staging["rejected"][0]["reason"]


def test_only_the_models_findings_are_staged(case):
    from nexus.langgraph.llm_pipeline import stage_findings

    case_dir, run = case
    record = _Tool({"finding_id": "F-2"})
    timeline = _Tool({"event_id": "T-2"})
    asyncio.run(stage_findings(_state(case_dir, run.run_id, [_msg(LLM)]),
                               {"record_finding": record, "record_timeline_event": timeline}))
    assert [p["title"] for p in record.payloads] == [LLM["title"]]
    assert len(timeline.payloads) == 1
    staging = json.loads((run.analysis / "staging.json").read_text(encoding="utf-8"))
    assert staging == {"run_id": run.run_id, "candidates": 1, "staged": ["F-2"], "linked": [],
                       "decided": [], "rejected": [], "dispositions": []}


class _VerdictModel:
    """A model whose only job here is the verdict: one long reply, so a cut would show."""

    def __init__(self, text: str):
        self.text = text

    async def ainvoke(self, messages, **_kw):
        from types import SimpleNamespace
        return SimpleNamespace(content=self.text)

    def invoke(self, messages, **_kw):
        from types import SimpleNamespace
        return SimpleNamespace(content=self.text, tool_calls=[])

    def bind_tools(self, *_a, **_kw):
        return self


def test_dispositions_are_recorded_and_shown_but_never_staged(case):
    """D193: the loop's dispositions reach the run record and the verdict, not record_finding."""
    from nexus.langgraph.llm_pipeline import stage_findings

    case_dir, run = case
    record = _Tool({"finding_id": "F-3"})
    disposition = {"item": "certutil (0 hits)", "status": "not_examined",
                   "reason": "needle checked, no rows", "audit_ids": []}
    state = {**_state(case_dir, run.run_id, [_msg(LLM)]), "dispositions": [disposition]}
    verdict = "Verdict paragraph. " + "| row | covered | basis |\n" * 200 + "LAST-ROW-MARKER"
    asyncio.run(stage_findings(state, {"record_finding": record}, model=_VerdictModel(verdict)))

    assert [p["title"] for p in record.payloads] == [LLM["title"]]
    staging = json.loads((run.analysis / "staging.json").read_text(encoding="utf-8"))
    assert staging["dispositions"] == [disposition]
    text = (case_dir / "analysis" / "interpretation.md").read_text(encoding="utf-8")
    assert "## Dispositions" in text and "certutil (0 hits)" in text and "not_examined" in text
    # Whole and in place: after the header bullets, before the findings table.
    assert "LAST-ROW-MARKER" in text
    assert text.index("## Executive verdict") > text.index("- Findings staged (DRAFT)")
    assert text.index("## Executive verdict") < text.index("## Dispositions")


def test_the_run_writes_no_draft_report_and_its_verdict_covers_its_own_findings(case):
    """D169 (2026-10-14): an independent Mode 1 run's verdict listed 23 findings from four runs,
    and its model-written draft report re-read every DRAFT in the case (21 of 42 minutes)."""
    from nexus.langgraph.llm_pipeline import stage_findings

    case_dir, run = case
    other = {"id": "F-other-001", "title": "Another run's DRAFT", "status": "DRAFT",
             "run_id": "RUN-other", "severity": "high", "confidence": "LOW"}
    (case_dir / "findings.json").write_text(json.dumps([other]), encoding="utf-8")
    tamper = _search(case_dir, [{"loc": "hayabusa/evtx-timeline.csv:10", "host": "ws01",
                                 "detail": "RuleTitle: Tamper Windows Defender"}],
                     {"match": {"text": "DisableRealTimeMonitoring"}})
    claim = {**LLM, "title": "Defender tamper", "audit_ids": [tamper]}
    asyncio.run(stage_findings(_state(case_dir, run.run_id, [_msg(claim)]),
                               {"record_finding": _RealRecord(case_dir)}))

    # No model-written draft report in the run (D169, operator 2026-10-14): the examiner's
    # preview is `nexus report generate`, the report comes from APPROVED findings.
    assert not (run.path / "reports" / "REPORT-DRAFT.md").exists()
    assert not (case_dir / "reports" / "REPORT-DRAFT.md").exists()
    verdict = (case_dir / "analysis" / "interpretation.md").read_text(encoding="utf-8")
    assert verdict.startswith("# Mode 1 interpretation")
    assert f"- Run: `{run.run_id}`" in verdict and "Findings staged (DRAFT): **1**" in verdict
    assert "Another run's DRAFT" not in verdict
