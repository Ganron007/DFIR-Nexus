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
