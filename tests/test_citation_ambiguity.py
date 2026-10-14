"""A citation must identify one call (2026-10-14, D155 and D178).

Two writers once numbered audit ids each on their own. In CASE-C5B04D31 one id names an es_search
and a record_finding, and 229 of 285 lane-ledger ids name a tool run in the ledger and an
es_search or ingest_auto in the case log. FD-001's existence check passed such a citation, and
staging read the other call's rows as the finding's evidence.
"""
from __future__ import annotations

import json
from pathlib import Path

from nexus.analysis.integrity import ambiguous_audit_ids, enforce_submission_integrity
from nexus.audit import AuditWriter


def _case(tmp_path: Path) -> Path:
    case = tmp_path / "CASE-AMB"
    (case / "audit").mkdir(parents=True)
    (case / "runs" / "RUN-1" / "extractions").mkdir(parents=True)
    return case


def _log(case: Path, tool: str, audit_id: str) -> None:
    AuditWriter("nexus", audit_dir=case / "audit").log(
        tool=tool, params={"case_id": case.name}, audit_id=audit_id)


def _ledger(case: Path, rows: list[dict]) -> None:
    (case / "runs" / "RUN-1" / "extractions" / "_tool_lane_ledger.json").write_text(
        json.dumps(rows), encoding="utf-8")


def _finding(*audit_ids: str) -> dict:
    return {"title": "t", "observation": "o", "interpretation": "i", "audit_ids": list(audit_ids)}


def test_an_id_two_log_entries_give_to_different_calls_is_refused(tmp_path):
    case = _case(tmp_path)
    _log(case, "es_search", "nexus-x-20261013-036")
    _log(case, "record_finding", "nexus-x-20261013-036")
    _log(case, "es_search", "nexus-x-20261013-040")
    out = enforce_submission_integrity(_finding("nexus-x-20261013-036", "nexus-x-20261013-040"), case)
    assert out["ok"] is False
    assert "nexus-x-20261013-036 (es_search, record_finding)" in out["errors"][0]
    assert out["citations"]["ambiguous"] == ["nexus-x-20261013-036"]


def test_a_ledger_id_the_log_gives_to_another_call_is_refused(tmp_path):
    case = _case(tmp_path)
    _ledger(case, [{"tool": "hayabusa", "status": "OK", "audit_id": "nexus-x-20261010-1068"},
                   {"tool": "vol", "status": "OK", "audit_id": "nexus-x-20261010-1200"}])
    _log(case, "ingest_auto", "nexus-x-20261010-1068")
    _log(case, "remote_vol", "nexus-x-20261010-1200")
    assert ambiguous_audit_ids(case, ["nexus-x-20261010-1068", "nexus-x-20261010-1200"]) == {
        "nexus-x-20261010-1068": ["a tool-lane run (ledger)", "ingest_auto"]}
    assert enforce_submission_integrity(_finding("nexus-x-20261010-1068"), case)["ok"] is False


def test_a_citation_that_names_one_call_still_passes(tmp_path):
    case = _case(tmp_path)
    _ledger(case, [{"tool": "mftecmd", "status": "OK", "audit_id": "nexus-x-20261014-002"}])
    _log(case, "run_windows_command", "nexus-x-20261014-002")
    _log(case, "es_search", "nexus-x-20261014-003")
    out = enforce_submission_integrity(_finding("nexus-x-20261014-002", "nexus-x-20261014-003"), case)
    assert out["ok"] is True, out["errors"]
    assert out["citations"]["ambiguous"] == []


def test_a_refused_query_is_recorded_as_refused_not_as_an_empty_result(monkeypatch):
    """2026-10-14, Mode 1 run 4: the loop saw "query references fields that cannot match", and
    the audit row said total 0 and nothing else."""
    import yaml

    from nexus.config import settings
    from nexus.langgraph import backbone, es_native

    case = settings.cases_root / "CASE-REFUSED"
    (case / "audit").mkdir(parents=True)
    (case / "CASE.yaml").write_text(yaml.safe_dump({"case_id": case.name, "status": "open"}),
                                    encoding="utf-8")
    monkeypatch.setattr(es_native, "es_search", lambda case_id, query, **kw: {
        "case_id": case_id, "error": "query references fields that cannot match: details",
        "degraded": True, "failed_terms": [{"field": "details", "reason": "unknown_field"}],
        "total": 0, "returned": 0, "hits": []})
    out = backbone.backbone_call("es_search", audit=AuditWriter("nexus", audit_dir=case / "audit"),
                                 case_dir=case, query={"term": {"details": "x"}})
    aid = out["provenance"]["audit_id"]
    row = next(json.loads(line) for line in (case / "audit" / "nexus.jsonl").read_text(
        encoding="utf-8").splitlines() if json.loads(line)["audit_id"] == aid)
    assert row["result_summary"]["degraded"] is True
    assert "cannot match" in row["result_summary"]["error"]


def _search_row(case: Path, audit_id: str, **summary) -> None:
    AuditWriter("nexus", audit_dir=case / "audit").log(
        tool="es_search", params={"case_id": case.name}, result_summary=summary, audit_id=audit_id)


def test_a_finding_whose_every_citation_found_nothing_is_refused(tmp_path):
    """F-gate-bot-024 (2026-10-14) was staged on two refused queries, total 0: its only evidence
    was the model's own wording."""
    case = _case(tmp_path)
    _search_row(case, "nexus-x-20261014-211", total=0, returned=0, evidence_rows=[])
    _search_row(case, "nexus-x-20261014-217", total=0, error="cannot match: details", degraded=True)
    out = enforce_submission_integrity(_finding("nexus-x-20261014-211", "nexus-x-20261014-217"), case)
    assert out["ok"] is False
    assert "every cited call returned no rows" in out["errors"][0]


def test_one_citation_that_returned_rows_or_a_tool_run_grounds_the_finding(tmp_path):
    case = _case(tmp_path)
    _search_row(case, "nexus-x-20261014-211", total=0, returned=0, evidence_rows=[])
    _search_row(case, "nexus-x-20261014-220", total=3, returned=3,
                evidence_rows=[{"source": "hayabusa/x.csv", "detail": "row", "loc": "x.csv:2"}])
    _log(case, "run_windows_command", "nexus-x-20261014-230")
    assert enforce_submission_integrity(
        _finding("nexus-x-20261014-211", "nexus-x-20261014-220"), case)["ok"] is True
    assert enforce_submission_integrity(_finding("nexus-x-20261014-230"), case)["ok"] is True


def test_run_record_withholds_ledger_ids_that_name_another_call():
    """2026-10-14, Mode 2 run 2: a worker cited two lane-ledger ids from run_record instead of its
    own twenty queries; both name another call in CASE-C5B04D31's log (D178) and staging refuses
    them. The tool the model reads them from withholds them."""
    import yaml

    from nexus.config import settings
    from nexus.tools.evidence_index import do_run_record

    case = settings.cases_root / "CASE-RUNREC"
    (case / "audit").mkdir(parents=True)
    (case / "runs" / "RUN-1" / "extractions").mkdir(parents=True)
    (case / "CASE.yaml").write_text(yaml.safe_dump({"case_id": case.name, "status": "open"}),
                                    encoding="utf-8")
    _ledger(case, [{"tool": "hayabusa", "status": "OK", "audit_id": "nexus-x-20261011-378"},
                   {"tool": "mftecmd", "status": "OK", "audit_id": "nexus-x-20261014-002"}])
    _log(case, "es_search", "nexus-x-20261011-378")
    _log(case, "run_windows_command", "nexus-x-20261014-002")
    out = do_run_record(case_id=case.name, case_dir=case)
    by_tool = {e["tool"]: e for e in out["entries"]}
    assert by_tool["hayabusa"]["audit_id"] == ""
    assert "not citable" in by_tool["hayabusa"]["audit_id_note"]
    assert by_tool["mftecmd"]["audit_id"] == "nexus-x-20261014-002"
    assert "audit_id_note" not in by_tool["mftecmd"]
