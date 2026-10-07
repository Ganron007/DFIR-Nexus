"""WO-R1F item 4 — no duplicate staging.

SC1 was staged four times over: a re-run, and each mode, produced findings whose
title and evidence already existed, and every one became a new DRAFT. The rule is
that a finding identical in title and evidence LINKS to the existing DRAFT (its
run id appended to the lineage) instead of minting a second copy.

These tests drive the real `record_finding` path, not the helper alone.
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml


def _case(tmp_path: Path) -> Path:
    case = tmp_path / "CASE-DUP00001"
    case.mkdir(parents=True)
    (case / "CASE.yaml").write_text(
        yaml.safe_dump(
            {
                "case_id": "CASE-DUP00001",
                "name": "duplicate staging",
                "status": "created",
                "severity": "medium",
            }
        ),
        encoding="utf-8",
    )
    (case / "findings.json").write_text("[]", encoding="utf-8")
    # A REAL audit entry, because staging enforces citation integrity: a finding
    # citing an audit_id that is not in the case's audit log is rejected (WP 10.4).
    audit_dir = case / "audit"
    audit_dir.mkdir(parents=True, exist_ok=True)
    (audit_dir / "nexus.jsonl").write_text(
        json.dumps({
            "audit_id": AUDIT_ID,
            "tool": "es_search",
            "case_id": "CASE-DUP00001",
        }) + "\n",
        encoding="utf-8",
    )
    return case


#: The one real audit id the fixture's findings cite. It must match
#: `case_manager._AUDIT_ID_PATTERN` (`<origin>-<name>-<yyyymmdd>-<seq>`), or the
#: provenance check rejects the finding before the dedupe is reached.
AUDIT_ID = "nexus-gate-bot-20260101-001"


def _draft(**over) -> dict:
    body = {
        "title": "PowerShell EncodedCommand",
        "observation": "A base64 encoded PowerShell command was executed.",
        "interpretation": "An encoded command is consistent with deliberate obfuscation.",
        "confidence": "LOW",
        "confidence_justification": "one source",
        "severity": "MEDIUM",
        "audit_ids": [AUDIT_ID],
        "evidence": [{"detail": "evtxecmd row 140298"}],
    }
    body.update(over)
    return body


def _mgr(tmp_path: Path):
    """The real manager. `cases_root` comes from settings, which conftest redirects."""
    from nexus.case_manager import CaseManager

    return CaseManager()


def test_an_identical_second_stage_links_instead_of_duplicating(tmp_path: Path):
    case = _case(tmp_path)
    mgr = _mgr(tmp_path)

    first = mgr.record_finding(_draft(run_id="M2-run-1"), case_dir=case)
    assert first["status"] not in ("ERROR", "VALIDATION_FAILED"), first
    second = mgr.record_finding(_draft(run_id="M2-run-2"), case_dir=case)

    assert second.get("duplicate") is True, second
    assert second["finding_id"] == first["finding_id"]

    stored = mgr._load_findings(case)
    assert len(stored) == 1, stored


def test_the_second_run_is_recorded_in_the_lineage(tmp_path: Path):
    case = _case(tmp_path)
    mgr = _mgr(tmp_path)

    mgr.record_finding(_draft(run_id="M2-run-1"), case_dir=case)
    mgr.record_finding(_draft(run_id="M2-run-2"), case_dir=case)

    stored = mgr._load_findings(case)
    assert stored[0]["run_ids"] == ["M2-run-1", "M2-run-2"], stored[0].get("run_ids")
    # The single-valued field stays the FIRST run that raised it.
    assert stored[0]["run_id"] == "M2-run-1"


def test_a_third_stage_does_not_duplicate_the_lineage(tmp_path: Path):
    case = _case(tmp_path)
    mgr = _mgr(tmp_path)

    for run in ("M2-run-1", "M2-run-2", "M2-run-2", "M3-run-9"):
        mgr.record_finding(_draft(run_id=run), case_dir=case)

    stored = mgr._load_findings(case)
    assert len(stored) == 1
    assert stored[0]["run_ids"] == ["M2-run-1", "M2-run-2", "M3-run-9"]


def test_the_same_title_with_different_evidence_is_a_second_finding(tmp_path: Path):
    """A re-run that found more is a better finding, not a duplicate."""
    case = _case(tmp_path)
    mgr = _mgr(tmp_path)

    mgr.record_finding(_draft(), case_dir=case)
    mgr.record_finding(
        _draft(evidence=[{"detail": "a genuinely different row"}]),
        case_dir=case,
    )

    stored = mgr._load_findings(case)
    assert len(stored) == 2, [f.get("title") for f in stored]


def test_evidence_order_and_whitespace_do_not_defeat_the_dedupe(tmp_path: Path):
    case = _case(tmp_path)
    mgr = _mgr(tmp_path)

    mgr.record_finding(
        _draft(evidence=[{"detail": "row one"}, {"detail": "row two"}]),
        case_dir=case,
    )
    second = mgr.record_finding(
        _draft(
            title="  PowerShell   EncodedCommand ",
            evidence=[{"detail": "row  two "}, {"detail": " row one"}],
        ),
        case_dir=case,
    )

    assert second.get("duplicate") is True, second
    assert len(mgr._load_findings(case)) == 1


def test_a_rejected_finding_is_not_a_link_target(tmp_path: Path):
    """A rejection is an examiner decision, not a duplicate to link to."""
    case = _case(tmp_path)
    mgr = _mgr(tmp_path)

    first = mgr.record_finding(_draft(), case_dir=case)
    stored = mgr._load_findings(case)
    for f in stored:
        if f["id"] == first["finding_id"]:
            f["status"] = "REJECTED"
    mgr._save_findings(case, stored)

    second = mgr.record_finding(_draft(), case_dir=case)
    assert not second.get("duplicate"), second
    assert len(mgr._load_findings(case)) == 2
