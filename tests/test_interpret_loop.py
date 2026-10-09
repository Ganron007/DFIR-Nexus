"""GATE-B regression tests — the interpret round loop (Orient → Verify →
Reconcile), round artifacts, early stop, and the reconciliation extra pass."""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from nexus.langgraph.interpret_loop import _parse_json_blob, _resolve_rounds, run_interpret_loop


class ScriptedModel:
    """Async fake: returns scripted contents in order, records every call."""

    def __init__(self, responses: list[str]):
        self.responses = list(responses)
        self.calls: list[list[dict[str, str]]] = []

    async def ainvoke(self, messages):
        self.calls.append(messages)
        content = self.responses.pop(0) if self.responses else "[]"
        return SimpleNamespace(content=content)


def _digest() -> dict[str, Any]:
    return {
        "alerts": [
            {"level": "high", "title": "Mimikatz detected", "host": "ws01"},
            {"level": "critical", "title": "Ransomware note", "host": "ws01"},
        ],
        "signal_map": {"with_hits": [{"needle": "psexec", "hits": 9}]},
        "scope": {"explicitly_absent": ["memory images"]},
    }


def _orientation() -> str:
    return json.dumps({
        "hypotheses": [{"id": "H1", "statement": "Credential dumping occurred",
                        "why": "lsass access"}],
        "queries": [{"dsl": "lsass", "why": "find lsass access"},
                    {"dsl": "psexec", "why": "lateral movement"}],
    })


def _verify_settled() -> str:
    return json.dumps({
        "notes": [{"hypothesis": "H1", "status": "confirmed",
                   "evidence": "hayabusa row 2024-01-01 ws01 mimikatz", "family": "hayabusa"}],
        "next": [],
    })


def _verify_more() -> str:
    return json.dumps({
        "notes": [{"hypothesis": "H1", "status": "partial", "evidence": "psexec seen"}],
        "next": [{"dsl": "wevtutil", "why": "check log clearing"}],
    })


def _findings_all_addressed() -> str:
    return json.dumps([
        {"title": "Mimikatz detected on ws01", "observation": "credential dumping",
         "interpretation": "credential theft", "confidence": "HIGH",
         "confidence_justification": "two artifacts",
         "audit_ids": ["n4_query-test-20260918-001"]},
        {"title": "Assessed benign: Ransomware note", "observation": "ransomware note on ws01",
         "interpretation": "benign: lab note file", "confidence": "LOW",
         "confidence_justification": "context",
         "audit_ids": ["n4_query-test-20260918-001"]},
        {"title": "psexec lateral movement", "observation": "psexec 9 hits",
         "interpretation": "admin tooling", "confidence": "MEDIUM",
         "confidence_justification": "counts",
         "audit_ids": ["n4_query-test-20260918-001"]},
    ])


class FakeExecutor:
    """Async fake tool executor; records (name, payload) calls."""

    def __init__(self, results: list[dict] | None = None):
        self.results = list(results) if results is not None else None
        self.calls: list[tuple[str, dict]] = []

    async def __call__(self, name: str, payload: dict) -> dict:
        self.calls.append((name, payload))
        if self.results is not None:
            return self.results.pop(0)
        return {
            "count": 2,
            "provenance": {"audit_id": "n4_query-test-20260918-001"},
            "hits": [{"family": "hayabusa", "ts": "2024-01-01T10:00:00",
                      "host": "ws01", "text": "mimikatz sekurlsa"}],
        }


def test_resolve_rounds_from_options_file(tmp_path):
    (tmp_path / "analysis").mkdir(parents=True)
    (tmp_path / "analysis" / "mode1_run_options.json").write_text(
        json.dumps({"interpret_rounds": 2}), encoding="utf-8"
    )
    assert _resolve_rounds({}, tmp_path, None) == 2
    assert _resolve_rounds({}, tmp_path, 5) == 5
    assert _resolve_rounds({}, tmp_path, 99) == 5  # clamped


def test_parse_json_blob_tolerant():
    assert _parse_json_blob('{"a": 1}') == {"a": 1}
    assert _parse_json_blob('```json\n[{"title": "x"}]\n```') == [{"title": "x"}]
    assert _parse_json_blob('prose before {"a": 1} prose after') == {"a": 1}
    assert _parse_json_blob("no json here") is None


def test_normalize_plan_accepts_dict_shapes_and_bad_n():
    """Id-keyed objects instead of arrays and 'n': '8 rows' must not crash the
    loop — the model was already paid for; parse or ignore, never raise."""
    from nexus.langgraph.interpret_loop import _normalize_plan, _notes_from

    plan = _normalize_plan({
        "hypotheses": {"H1": {"statement": "dumped creds", "why": "lsass"}},
        "queries": ["sdelete"],
        "samples": [{"family": "hayabusa", "n": "8 rows"}],
        "aggregations": [{"field": "host"}],
    })
    assert plan["hypotheses"][0]["statement"] == "dumped creds"
    assert plan["items"][0] == {"kind": "query", "why": "", "dsl": "sdelete"}
    sample = next(i for i in plan["items"] if i["kind"] == "sample")
    assert sample["n"] == 8  # unparsable n falls back to default
    assert any(i["kind"] == "aggregate" and i["field"] == "host"
               for i in plan["items"])

    notes = _notes_from({"notes": {"N1": "confirmed via hayabusa"}})
    assert notes and notes[0]["evidence"] == "confirmed via hayabusa"

    assert _normalize_plan(None)["items"] == []
    assert _notes_from("garbage") == []


def test_loop_does_not_pack_digest_twice(tmp_path):
    """The caller's sections already start with the digest in production; the
    loop must not prepend a second copy (double content + budget)."""
    from nexus.langgraph.prompt_budget import persist_context as real_persist

    seen_packs: list[str] = []

    def _capture(case_dir, name, packed, report, **kwargs):
        seen_packs.append(packed)
        return real_persist(case_dir, name, packed, report, **kwargs)

    model = ScriptedModel([_orientation(), _verify_settled(), _findings_all_addressed()])
    import nexus.langgraph.prompt_budget as pb

    orig = pb.persist_context
    pb.persist_context = _capture
    try:
        asyncio.run(run_interpret_loop(
            case_dir=tmp_path, case_id="CASE-TEST", model=model,
            state={"case_context": {"interpret_rounds": "1"}},
            digest=_digest(), digest_md="# Digest\nTEXT-MARKER",
            sections=[(0, "case_digest", "# Digest\nTEXT-MARKER"),
                      (1, "query_pack", "qp")],
            execute=FakeExecutor(),
        ))
    finally:
        pb.persist_context = orig
    assert seen_packs, "expected persisted packs"
    for packed in seen_packs:
        assert packed.count("# Digest\nTEXT-MARKER") == 1


def test_findings_corrective_retry_recovers_a_malformed_reply(tmp_path):
    """A findings reply that carries the keys but parses to nothing is a
    formatting failure, and it discards everything the loop verified.

    SC1 Mode 1 mode: four hypotheses confirmed on real evidence, 0 findings -
    because the findings call came back unparseable. One bounded retry recovers
    it; a legitimate "no findings" reply is NOT retried.
    """
    from nexus.langgraph.interpret_loop import run_interpret_loop

    malformed = '[{"title": "CobaltStrike", "observation": "beacon",},]'
    good = _findings_all_addressed()
    model = ScriptedModel([
        _orientation(), _verify_settled(), malformed, good,
    ])
    result = asyncio.run(run_interpret_loop(
        case_dir=tmp_path, case_id="CASE-TEST", model=model,
        state={"case_context": {"interpret_rounds": "1"}},
        digest=_digest(), digest_md="# Digest\nMimikatz detected ...",
        sections=[(1, "query_pack", "family:hayabusa ...")],
        execute=FakeExecutor(),
    ))
    assert result["findings_emitted"] == 3, result

    record = json.loads(
        (tmp_path / "analysis" / "interpret_rounds" / "findings-final.json")
        .read_text(encoding="utf-8")
    )
    assert record["corrective_retry_used"] is True
    assert record["candidates_parsed"] == 3
    assert record["chars"] > 0


def test_findings_without_keys_is_not_retried(tmp_path):
    """Prose ("no evidence of compromise") is a legitimate empty result."""
    from nexus.langgraph.interpret_loop import run_interpret_loop

    model = ScriptedModel([
        _orientation(), _verify_settled(),
        "I could not find evidence of compromise on this host.",
    ])
    result = asyncio.run(run_interpret_loop(
        case_dir=tmp_path, case_id="CASE-TEST", model=model,
        state={"case_context": {"interpret_rounds": "1"}},
        digest=_digest(), digest_md="# Digest\nMimikatz detected ...",
        sections=[(1, "query_pack", "family:hayabusa ...")],
        execute=FakeExecutor(),
    ))
    assert result["findings_emitted"] == 0
    record = json.loads(
        (tmp_path / "analysis" / "interpret_rounds" / "findings-final.json")
        .read_text(encoding="utf-8")
    )
    assert record["corrective_retry_used"] is False
    # The prose reply is kept, so the outcome is still inspectable.
    assert "could not find" in record["raw"]


def test_loop_early_stop_and_artifacts(tmp_path):
    model = ScriptedModel([_orientation(), _verify_settled(), _findings_all_addressed()])
    execute = FakeExecutor()
    result = asyncio.run(run_interpret_loop(
        case_dir=tmp_path, case_id="CASE-TEST", model=model,
        state={"case_context": {"interpret_rounds": "3"}},
        digest=_digest(), digest_md="# Digest\nMimikatz detected ...",
        sections=[(1, "query_pack", "family:hayabusa ...")],
        execute=execute,
    ))
    assert result["rounds_requested"] == 3
    assert result["rounds_run"] == 1          # early stop (next=[])
    assert result["stop_reason"] == "settled"
    assert result["findings_emitted"] == 3
    assert result["unaddressed"] == []
    # Query executions went through the injected audited tool
    assert len(execute.calls) == 2
    names = [c[0] for c in execute.calls]
    assert names == ["n4_query", "n4_query"]
    # Round artifacts + summary + persisted LLM contexts
    rounds_dir = tmp_path / "analysis" / "interpret_rounds"
    assert (rounds_dir / "round-0-orient.json").is_file()
    assert (rounds_dir / "round-1-verify.json").is_file()
    assert (rounds_dir / "round-1-notes.json").is_file()
    summary = json.loads((rounds_dir / "summary.json").read_text(encoding="utf-8"))
    assert summary["rounds_run"] == 1
    assert summary["reconciliation"]["unaddressed"] == []
    contexts = list((tmp_path / "analysis" / "llm_context").glob("*.md"))
    assert len(contexts) >= 3
    # Messages carry the audit id + findings JSON for stage_findings
    blob = "\n".join(m["content"] for m in result["messages"])
    assert "n4_query-test-20260918-001" in blob
    assert "Mimikatz detected on ws01" in blob


def test_loop_runs_multiple_rounds(tmp_path):
    model = ScriptedModel([
        _orientation(), _verify_more(),
        _verify_settled(), _findings_all_addressed(),
    ])
    execute = FakeExecutor()
    result = asyncio.run(run_interpret_loop(
        case_dir=tmp_path, case_id="CASE-TEST", model=model,
        state={"case_context": {"interpret_rounds": "3"}},
        digest=_digest(), digest_md="# Digest",
        sections=[], execute=execute,
    ))
    assert result["rounds_run"] == 2
    assert result["stop_reason"] == "settled"
    assert len(execute.calls) == 3  # 2 + 1 planned in round 2
    rounds_dir = tmp_path / "analysis" / "interpret_rounds"
    assert (rounds_dir / "round-2-verify.json").is_file()


def test_loop_reconciliation_extra_pass(tmp_path):
    incomplete = json.dumps([
        {"title": "Mimikatz detected on ws01", "observation": "credential dumping",
         "interpretation": "theft", "confidence": "HIGH",
         "confidence_justification": "x", "audit_ids": ["n4_query-test-20260918-001"]},
    ])
    extra = json.dumps([
        {"title": "Assessed benign: Ransomware note", "observation": "note",
         "interpretation": "benign lab note", "confidence": "LOW",
         "confidence_justification": "context",
         "audit_ids": ["n4_query-test-20260918-001"]},
        {"title": "psexec lateral movement", "observation": "9 hits",
         "interpretation": "admin tooling", "confidence": "MEDIUM",
         "confidence_justification": "counts",
         "audit_ids": ["n4_query-test-20260918-001"]},
    ])
    model = ScriptedModel([_orientation(), _verify_settled(), incomplete, extra])
    execute = FakeExecutor()
    result = asyncio.run(run_interpret_loop(
        case_dir=tmp_path, case_id="CASE-TEST", model=model,
        state={"case_context": {"interpret_rounds": "1"}},
        digest=_digest(), digest_md="# Digest",
        sections=[], execute=execute,
    ))
    assert len(model.calls) == 4                       # orient + verify + reconcile + extra
    assert result["findings_emitted"] == 3
    assert result["unaddressed"] == []
    assert len(result["messages"]) >= 3                # evidence + findings + extra
    assert (tmp_path / "analysis" / "llm_context").is_dir()


def test_loop_tool_error_does_not_kill_round(tmp_path):
    model = ScriptedModel([_orientation(), _verify_settled(), _findings_all_addressed()])
    execute = FakeExecutor(results=[
        {"error": "no active case"},
        {"count": 0, "hits": [], "provenance": {"audit_id": "n4_query-test-20260918-002"}},
    ])
    result = asyncio.run(run_interpret_loop(
        case_dir=tmp_path, case_id="CASE-TEST", model=model,
        state={"case_context": {"interpret_rounds": "1"}},
        digest=_digest(), digest_md="# Digest",
        sections=[], execute=execute,
    ))
    assert result["rounds_run"] == 1
    summary = json.loads(
        (tmp_path / "analysis" / "interpret_rounds" / "summary.json")
        .read_text(encoding="utf-8")
    )
    rounds = json.loads(
        (tmp_path / "analysis" / "interpret_rounds" / "round-1-verify.json")
        .read_text(encoding="utf-8")
    )
    assert rounds["entries"][0]["error"] == "no active case"
    assert summary["rounds_run"] == 1


# ── D47 (WO-R2F item 7): the settle rule and staged severity ─────────────


def _digest_with_crit_leads() -> dict[str, Any]:
    """A digest whose crit/high leads must each get a disposition."""
    return {
        "alerts": [
            {"level": "high", "title": "Mimikatz detected", "host": "ws01"},
            {"level": "critical", "title": "Ransomware note", "host": "ws01"},
        ],
        "signal_map": {"with_hits": [{"needle": "psexec", "hits": 9}]},
        "scope": {"explicitly_absent": ["memory images"]},
        "leads": [
            {"kind": "rule_engine", "subject": "mimikatz.exe", "level": "critical",
             "detail": "mimikatz 3 hits", "crit_high": True},
            {"kind": "rule_engine", "subject": "ransomware", "level": "high",
             "detail": "ransomware 3 hits", "crit_high": True},
        ],
    }


def _seed_leads(tmp_path, digest) -> None:
    """Write the real leads.jsonl the digest's crit/high leads come from."""
    (tmp_path / "analysis").mkdir(parents=True, exist_ok=True)
    (tmp_path / "analysis" / "leads.jsonl").write_text(
        "\n".join(json.dumps({
            "kind": lead["kind"], "subject": lead["subject"],
            "family": "hayabusa", "detail": lead["detail"], "score": 9.0,
            "rows": [], "audit_ids": [],
            "extra": {"crit_high": True, "level": lead["level"],
                      "engine": "hayabusa", "count": 3},
        }) for lead in digest["leads"]) + "\n",
        encoding="utf-8",
    )


def test_a_crit_lead_without_a_disposition_blocks_settle(tmp_path):
    """D47: a round that plans no further queries may NOT settle while a
    crit/high lead has no disposition citing its own rows."""
    _seed_leads(tmp_path, _digest_with_crit_leads())
    # The model tries to settle on round 1; only H1 (mimikatz) has a
    # disposition with evidence, so the `ransomware` crit lead is open.
    settled = json.dumps({
        "notes": [{"hypothesis": "H1", "status": "confirmed",
                   "evidence": "hayabusa row 2024-01-01 ws01 mimikatz",
                   "family": "hayabusa"}],
        "next": [],
    })
    model = ScriptedModel([
        _orientation(), settled, settled, settled, _findings_all_addressed(),
    ])
    execute = FakeExecutor()
    result = asyncio.run(run_interpret_loop(
        case_dir=tmp_path, case_id="CASE-TEST", model=model,
        state={"case_context": {"interpret_rounds": "3"}},
        digest=_digest_with_crit_leads(), digest_md="# Digest",
        sections=[(1, "query_pack", "family:hayabusa ...")], execute=execute,
    ))
    # It did not settle on round 1: the open crit lead forced another round.
    assert result["rounds_run"] > 1
    assert result["stop_reason"] != "settled" or result["rounds_run"] >= 3
    # The evidence for the open lead was actually pulled, not just claimed.
    pulled = " ".join(
        str(payload.get("value") or payload.get("dsl") or "")
        for _name, payload in execute.calls
    )
    assert "ransomware" in pulled


def test_a_dispositioned_crit_lead_lets_the_loop_settle(tmp_path):
    """The mirror: once every crit lead is dispositioned, the early stop works."""
    _seed_leads(tmp_path, _digest_with_crit_leads())
    settled = json.dumps({
        "notes": [
            {"hypothesis": "H1", "status": "confirmed",
             "evidence": "hayabusa row 2024-01-01 ws01 mimikatz",
             "family": "hayabusa"},
            {"hypothesis": "H2", "status": "confirmed",
             "evidence": "hayabusa row 2024-01-02 ws01 ransomware note",
             "family": "hayabusa"},
        ],
        "next": [],
    })
    model = ScriptedModel([_orientation(), settled, _findings_all_addressed()])
    result = asyncio.run(run_interpret_loop(
        case_dir=tmp_path, case_id="CASE-TEST", model=model,
        state={"case_context": {"interpret_rounds": "3"}},
        digest=_digest_with_crit_leads(), digest_md="# Digest",
        sections=[], execute=FakeExecutor(),
    ))
    assert result["stop_reason"] == "settled"
    assert result["rounds_run"] == 1


def test_undispositioned_crit_leads_ignores_a_bare_unknown_note(tmp_path):
    """A note with no evidence text is not a disposition — the D47 hole."""
    from nexus.langgraph.interpret_loop import _undispositioned_crit_leads

    leads = [{"subject": "ransomware", "level": "high", "crit_high": True}]
    digest = {"leads": leads}
    bare = [{"hypothesis": "H2 ransomware", "status": "unknown", "evidence": ""}]
    assert _undispositioned_crit_leads(digest, bare) == [
        {"subject": "ransomware", "kind": "", "level": "high", "detail": ""}
    ]
    with_rows = [{
        "hypothesis": "H2 ransomware", "status": "confirmed",
        "evidence": "hayabusa row ws01 ransomware", "family": "hayabusa",
    }]
    assert _undispositioned_crit_leads(digest, with_rows) == []


def test_finding_tool_payload_carries_severity():
    """D47: every staged Mode 1 DRAFT has a severity (7/7 were empty)."""
    from nexus.langgraph.llm_pipeline import _finding_tool_payload

    payload = _finding_tool_payload({
        "title": "Mimikatz detected on ws01", "observation": "credential dumping",
        "interpretation": "credential theft", "confidence": "HIGH",
        "confidence_justification": "two artifacts",
        "audit_ids": ["n4_query-test-20260918-001"],
        "severity": "critical",
    }, trail=[], linked_ids=set())
    assert payload["severity"] == "CRITICAL"
    # An absent or bogus severity stays absent rather than inventing one.
    assert _finding_tool_payload({"title": "x"}, [], set())["severity"] == ""
    assert _finding_tool_payload(
        {"title": "x", "severity": "bogus"}, [], set()
    )["severity"] == ""


def test_record_finding_mcp_tool_accepts_severity(tmp_path, monkeypatch):
    """D47: the MCP tool signature carries severity, so the payload is not
    silently dropped on the way to CaseManager. Driven through the REAL
    CaseManager and a REAL case, so the stored DRAFT is what is asserted."""
    from nexus.config import settings
    from nexus.tools.forensic import register_tools

    cases_root = tmp_path / "cases"
    cases_root.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("NEXUS_CASES_ROOT", str(cases_root))
    monkeypatch.setenv("NEXUS_DATA_ROOT", str(tmp_path / "data"))
    monkeypatch.setenv("NEXUS_ACTIVE_CASE_FILE", str(tmp_path / "active_case"))

    from nexus.case import CaseManager as SqlCM

    sql = SqlCM(settings.cases_root / "cases.db")
    try:
        case = sql.create_case("Severity Case", created_by="tester")
    finally:
        sql.close()
    case_dir = settings.cases_root / case.id

    audit_dir = case_dir / "audit"
    audit_dir.mkdir(parents=True, exist_ok=True)
    audit_id = "nexus-severity-tst-20261009-001"
    with (audit_dir / "audit_log.jsonl").open("a", encoding="utf-8") as fh:
        fh.write(json.dumps({"audit_id": audit_id, "tool": "es_search",
                             "source": "mcp"}) + "\n")

    # The MCP tool resolves its case through the global active-case pointer
    # (NEXUS_ACTIVE_CASE_FILE), so the pointer is written the way the product
    # writes it. This case was created for this test, so no unrelated case is
    # flipped.
    active = Path(os.environ["NEXUS_ACTIVE_CASE_FILE"])
    active.parent.mkdir(parents=True, exist_ok=True)
    active.write_text(str(case_dir), encoding="utf-8")

    registry: dict[str, Any] = {}

    class _ToolDecorator:
        def __call__(self, fn):
            registry[fn.__name__] = fn
            return fn

    class _Server:
        def tool(self, *args, **kwargs):
            return _ToolDecorator()

    class _Audit:
        def log(self, **kwargs):
            return None

    register_tools(_Server(), _Audit())
    assert "record_finding" in registry
    result = registry["record_finding"](
        title="Mimikatz detected on ws01",
        observation="credential dumping",
        interpretation="credential theft",
        severity="critical",
        audit_ids=[audit_id],
    )
    assert result.get("status") in ("STAGED", "VALIDATION_FAILED"), result
    staged = json.loads((case_dir / "findings.json").read_text(encoding="utf-8"))
    assert staged, staged
    assert staged[0].get("severity") == "critical"


def test_staged_finding_records_unsupported_entities_in_integrity_notes(
    tmp_path, monkeypatch,
):
    """D47: the narrative is never rewritten; the unsupported mention lands in
    integrity_notes on the stored DRAFT."""
    from nexus.case_manager import CaseManager as FlatCM
    from nexus.config import settings

    cases_root = tmp_path / "cases"
    cases_root.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("NEXUS_CASES_ROOT", str(cases_root))
    monkeypatch.setenv("NEXUS_DATA_ROOT", str(tmp_path / "data"))
    monkeypatch.setenv("NEXUS_ACTIVE_CASE_FILE", str(tmp_path / "active_case"))

    from nexus.case import CaseManager as SqlCM

    sql = SqlCM(settings.cases_root / "cases.db")
    try:
        case = sql.create_case("Entity Note Case", created_by="tester")
    finally:
        sql.close()
    case_dir = settings.cases_root / case.id

    audit_dir = case_dir / "audit"
    audit_dir.mkdir(parents=True, exist_ok=True)
    audit_id = "nexus-entity-note-20261009-001"
    with (audit_dir / "audit_log.jsonl").open("a", encoding="utf-8") as fh:
        fh.write(json.dumps({"audit_id": audit_id, "tool": "es_search",
                             "source": "mcp"}) + "\n")

    observation = (
        "powershell.exe ran from C:\\Program Files\\Asset Management\\tool.exe "
        "on host ws01.cadre.local while msmpeng.exe was not running."
    )
    rows = [{
        "time": "2020-11-02T18:38:46",
        "source": "hayabusa/evtx-timeline.csv",
        "artifact": "hayabusa/evtx-timeline.csv",
        "detail": "RuleTitle: Potentially Malicious PwSh - powershell.exe -EncodedCommand",
        "loc": "hayabusa/evtx-timeline.csv:41",
        "fields": {"EventId": "4104"},
    }]
    result = FlatCM().record_finding({
        "title": "suspicious script block",
        "observation": observation,
        "interpretation": "encoded command execution",
        "confidence": "LOW",
        "confidence_justification": "single family",
        "audit_ids": [audit_id],
        "evidence": rows,
    }, case_dir=case_dir)
    assert result["status"] == "STAGED", result
    entry = json.loads((case_dir / "findings.json").read_text(encoding="utf-8"))[0]
    # The narrative is byte-identical to what was staged.
    assert entry["observation"] == observation
    assert "unsupported by the cited rows" not in entry["observation"]
    # The unsupported mentions are recorded for the examiner.
    notes = "\n".join(entry.get("integrity_notes") or [])
    assert "msmpeng.exe" in notes
    # A Windows path with spaces is ONE entity and is matched, not truncated.
    assert "c:\\program" not in notes.replace(
        "c:\\program files\\asset management\\tool.exe", ""
    )


def test_rounds_endpoint_reads_artifacts(tmp_path):
    from unittest.mock import patch

    from starlette.applications import Starlette
    from starlette.testclient import TestClient

    from nexus.dashboard.app import create_dashboard

    rounds_dir = tmp_path / "analysis" / "interpret_rounds"
    rounds_dir.mkdir(parents=True)
    (rounds_dir / "round-0-orient.json").write_text(
        json.dumps({"round": 0, "kind": "orient"}), encoding="utf-8"
    )
    (rounds_dir / "summary.json").write_text(
        json.dumps({
            "rounds_requested": 3, "rounds_run": 1, "stop_reason": "settled",
            "hypotheses": [], "notes": [], "findings_emitted": 2,
            "reconciliation": {"addressed": 2, "unaddressed": []},
        }),
        encoding="utf-8",
    )
    with patch("nexus.dashboard.app._get_case_dir", return_value=tmp_path):
        app = Starlette(routes=create_dashboard())
        client = TestClient(app)
        resp = client.get("/portal/api/case/rounds")
    assert resp.status_code == 200
    data = resp.json()
    assert data["summary"]["rounds_run"] == 1
    assert data["summary"]["findings_emitted"] == 2
    assert len(data["rounds"]) == 1


def test_rounds_endpoint_empty_when_no_loop_ran(tmp_path):
    from unittest.mock import patch

    from starlette.applications import Starlette
    from starlette.testclient import TestClient

    from nexus.dashboard.app import create_dashboard

    with patch("nexus.dashboard.app._get_case_dir", return_value=tmp_path):
        app = Starlette(routes=create_dashboard())
        client = TestClient(app)
        resp = client.get("/portal/api/case/rounds")
    assert resp.status_code == 200
    assert resp.json() == {"summary": None, "rounds": []}
