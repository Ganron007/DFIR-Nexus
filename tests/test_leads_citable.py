"""A lead can be cited (2026-10-14).

CASE-C5B04D31 held 140 leads and none had an audit id: rule-engine and analytic leads were built with
none, and the probe that audits aggregations was never handed a writer. The digest showed every mode
the top 40 with no citation, so a Mode 1 finding drawn from a lead was refused under FD-001 or cited a
query that did not show it. These drive the real lead builder over real rule-engine output, the real
audit trail and the real MCP ``record_finding``.
"""
from __future__ import annotations

import json
from pathlib import Path

import yaml
from test_rule_leads import _case_with_rule_output

from nexus.analysis.leads import build_leads


class _NoIndex:
    """The case has rule-engine output and no index: only the rule leads exist."""

    def aggregate(self, **_kw):
        return {}

    def observed_calls(self, *_a, **_kw):
        return []

    def process_check(self, **_kw):
        return {}

    def count_analytic(self, _clause):
        return 0


def _audit_lines(case: Path) -> list[dict]:
    path = case / "audit" / "nexus.jsonl"
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _case(root: Path) -> Path:
    case = _case_with_rule_output(root)
    (case / "audit").mkdir(exist_ok=True)
    (case / "CASE.yaml").write_text(yaml.safe_dump({"case_id": case.name, "status": "open"}),
                                    encoding="utf-8")
    return case


def test_a_rule_lead_cites_a_call_that_holds_its_own_rows(tmp_path):
    from nexus.langgraph.evidence_rows import evidence_rows_for_audit_ids

    case = _case(tmp_path)
    leads = build_leads(case, probe=_NoIndex(), known_fields=set())
    cleared = next(lead for lead in leads if lead.subject == "Log Cleared")
    assert cleared.audit_ids, "a rule-engine lead had no audit id"
    rows = evidence_rows_for_audit_ids(case, [cleared.audit_ids[0]])
    assert rows and all("Log Cleared" in row["detail"] for row in rows)
    # The index's own names for the file and line, so the same row cited through a query matches.
    assert rows[0]["loc"].startswith("hayabusa/evtx-timeline.csv:")
    assert rows[0]["source"] == "hayabusa/hayabusa/evtx-timeline.csv"
    assert rows[0]["host"] == "WS01" and rows[0]["event_id"] == "1102"
    others = [lead for lead in leads if lead.subject != "Log Cleared" and lead.audit_ids]
    assert others and all(lead.audit_ids[0] != cleared.audit_ids[0] for lead in others)


def test_rebuilding_the_same_leads_reuses_their_audit_ids(tmp_path):
    case = _case(tmp_path)
    first = {lead.subject: lead.audit_ids for lead in build_leads(case, probe=_NoIndex(), known_fields=set())}
    written = len(_audit_lines(case))
    second = {lead.subject: lead.audit_ids for lead in build_leads(case, probe=_NoIndex(), known_fields=set())}
    assert second == first
    assert len(_audit_lines(case)) == written, "a rebuild logged the same leads again"


def test_a_mode1_finding_citing_a_lead_stands_on_that_leads_rows():
    import asyncio

    from test_mode1_staging import _RealRecord

    from nexus.case_manager import CaseManager
    from nexus.config import settings
    from nexus.langgraph.evidence_rows import evidence_rows_for_audit_ids
    from nexus.langgraph.llm_pipeline import stage_findings
    from nexus.langgraph.pipeline_runs import create_run

    case = _case(settings.cases_root)
    lead = next(item for item in build_leads(case, probe=_NoIndex(), known_fields=set())
                if item.subject == "Log Cleared")
    run = create_run(case, "interpret")
    candidate = {"title": "Security log cleared on WS01", "observation": "1102 at 00:00",
                 "interpretation": "anti-forensics", "confidence": "LOW",
                 "confidence_justification": "one row", "audit_ids": [lead.audit_ids[0]]}
    state = {"case_id": case.name, "run_id": run.run_id, "tool_run_ledger": [], "case_context": {},
             "evidence_audit_ids": [],
             "messages": [{"role": "assistant",
                           "content": "```json\n" + json.dumps([candidate]) + "\n```"}]}
    asyncio.run(stage_findings(state, {"record_finding": _RealRecord(case)}))
    staging = json.loads((run.analysis / "staging.json").read_text(encoding="utf-8"))
    assert len(staging["staged"]) == 1, staging

    draft = next(f for f in CaseManager()._load_findings(case) if f["id"] == staging["staged"][0])
    lead_rows = evidence_rows_for_audit_ids(case, [lead.audit_ids[0]])
    assert [row["loc"] for row in draft["evidence"]] == [row["loc"] for row in lead_rows]
    assert all("Log Cleared" in row["detail"] for row in draft["evidence"])
    assert draft["entity"] == {"type": "host", "value": "ws01"}  # identities are case-blind


def test_the_digest_shows_each_lead_with_its_citation(tmp_path):
    from nexus.langgraph.case_digest import _top_leads, render_digest_markdown

    case = _case(tmp_path)
    build_leads(case, probe=_NoIndex(), known_fields=set())
    top = _top_leads(case)
    assert top and all(lead["audit_ids"] for lead in top)
    text = render_digest_markdown({"case_id": case.name, "top_leads": top})
    cleared = next(lead for lead in top if lead["subject"] == "Log Cleared")
    line = next(row for row in text.splitlines() if "Log Cleared" in row)
    assert line.endswith(f"[audit_id {cleared['audit_ids'][0]}]")


def test_mode2_workers_see_the_level_and_citation_and_no_line_is_cut():
    from nexus.modes.multi_role import _digest_summary

    leads = [{"subject": f"Rule {n}", "detail": "x" * 150, "level": "crit",
              "audit_ids": [f"nexus-t-20261014-{n:03d}"]} for n in range(30)]
    text = _digest_summary({"top_leads": leads}, limit=2400)
    shown = [row for row in text.splitlines() if row.startswith("- ")]
    assert shown and all(row.startswith("- [CRIT] ") for row in shown)
    assert all(row.endswith("]") and "[audit_id nexus-t-20261014-" in row for row in shown)
    assert "more line(s) not shown" in text.splitlines()[-1]
    assert len(text) <= 2400 + 60
