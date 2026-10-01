"""WO-A7 (WP 10.44): negative-space events — the examiner's and verifier's
"no" are audited as events, never staged as findings."""

from __future__ import annotations

import json
from pathlib import Path

import pytest


@pytest.fixture()
def case_dir(tmp_path, monkeypatch) -> Path:
    from nexus.config import settings

    monkeypatch.setattr(settings, "cases_root", tmp_path)
    monkeypatch.setenv("NEXUS_EXAMINER", "negspace_test")
    root = tmp_path / "CASE-NEGSPACE-0001"
    root.mkdir()
    from nexus.case.manager import CaseManager
    from nexus.case.schemas import FindingSeverity

    mgr = CaseManager(settings.cases_root / "cases.db")
    mgr.create_case(
        name="Negative Space Fixture", description="WO-A7 fixture",
        severity=FindingSeverity.LOW, created_by="negspace_test",
        metadata={"synthetic": True}, case_id=root.name,
    )
    mgr.close()
    return root


def _stage_draft(case_dir: Path, title: str = "F fixture") -> str:
    """Stage one DRAFT through the real path so reject has something to reject."""
    from nexus.case_manager import CaseManager

    result = CaseManager().record_finding(
        {
            "title": title,
            "observation": "observed",
            "interpretation": "interpreted",
            "confidence": "LOW",
            "confidence_justification": "fixture",
            "audit_ids": [],
            "technique_ids": [],
        },
        examiner_override="negspace_test",
        artifacts=[{"type": "audit", "audit_id": "A-test-1", "value": "A-test-1", "source": ""}],
        case_dir=case_dir,
    )
    # the fixture has no real audit entries, so citation integrity refuses —
    # write a minimal DRAFT directly instead (reject is the surface under test)
    if result.get("status") != "STAGED":
        findings_path = case_dir / "findings.json"
        findings = json.loads(findings_path.read_text(encoding="utf-8")) \
            if findings_path.is_file() else []
        fid = "F-negspace_test-001"
        findings.append({
            "id": fid, "case_id": case_dir.name, "status": "DRAFT",
            "title": title, "observation": "o", "interpretation": "i",
            "confidence": "LOW", "confidence_justification": "fixture",
            "audit_ids": [], "artifacts": [],
        })
        findings_path.write_text(json.dumps(findings, indent=2), encoding="utf-8")
        return fid
    return result["finding_id"]


def _findings(case_dir: Path) -> list:
    """The case's findings list (empty when the file is absent)."""
    path = case_dir / "findings.json"
    if not path.is_file():
        return []
    return json.loads(path.read_text(encoding="utf-8"))


def test_record_round_trips_one_event(case_dir: Path):
    from nexus.analysis.negative_space import KINDS, read_events, record

    assert record(case_dir, "not-a-kind", "x", "y") is None  # unknown kind refused

    aid = record(
        case_dir, "false_positive_dismissed", "F-1",
        "examiner dismissed with a reason", refs=["F-1", "run-9"],
    )
    assert aid
    events = read_events(case_dir)
    assert len(events) == 1
    e = events[0]
    assert e["kind"] == "false_positive_dismissed"
    assert e["subject"] == "F-1"
    assert e["refs"] == ["F-1", "run-9"]
    assert e["tool"] == "negative_space"
    assert e["sha256"]  # chained through the real AuditWriter
    assert KINDS  # the kind vocabulary is pinned by import


def test_cli_reject_emits_dismissal(case_dir: Path):
    from nexus.analysis.negative_space import read_events
    from nexus.cli.main import _reject_finding

    fid = _stage_draft(case_dir)
    result = _reject_finding(case_dir, fid, "negspace_test", "tool false positive")
    assert result.get("status") == "REJECTED"

    events = [e for e in read_events(case_dir) if e["kind"] == "false_positive_dismissed"]
    assert len(events) == 1
    assert events[0]["subject"] == fid
    assert "false positive" in events[0]["detail"]

    # nothing staged as a finding by the emission
    findings = json.loads((case_dir / "findings.json").read_text(encoding="utf-8"))
    assert len(findings) == 1  # only the (now REJECTED) original
    assert findings[0]["status"] == "REJECTED"


def test_verifier_refuted_and_ledger_flags_emit(case_dir: Path):
    from nexus.analysis.negative_space import (
        read_events,
        record_ledger_flags,
        record_refuted_verdicts,
    )

    n = record_refuted_verdicts(case_dir, "M3-run-1", ["mimikatz ran", "", "  "])
    assert n == 1  # blank titles are not events

    ledger = {
        "claims": [
            {
                "id": "F-1", "title": "unverifiable one", "verdict": "UNVERIFIABLE",
                "checks": {"L1.3": {"status": "fail", "detail": "entity invented"}},
            },
            {"id": "F-2", "title": "clean", "verdict": "PROVEN", "checks": {}},
        ],
    }
    assert record_ledger_flags(case_dir, ledger) == 2

    kinds = [e["kind"] for e in read_events(case_dir)]
    assert kinds.count("refuted") == 1
    assert kinds.count("human_review_recommended") == 1
    assert kinds.count("hallucination_suspected") == 1

    # the emissions are audit events, never findings: nothing is staged
    assert _findings(case_dir) == []


def test_coverage_gaps_emit_missing_evidence(case_dir: Path):
    from nexus.analysis.negative_space import (
        read_events,
        record_missing_evidence,
    )

    assert record_missing_evidence(case_dir, {"overall": "complete"}) == 0
    assert record_missing_evidence(case_dir, {
        "overall": "gaps",
        "sections": {"needles": {"status": "gaps"}, "tools": {"status": "complete"}},
    }) == 1
    events = [e for e in read_events(case_dir) if e["kind"] == "missing_evidence"]
    assert len(events) == 1
    assert "needles" in events[0]["refs"]


def test_report_tail_renders_and_grade_is_untouched(case_dir: Path):
    from nexus.analysis.negative_space import (
        read_events,
        record,
        render_markdown,
    )

    record(case_dir, "refuted", "claim X", "verifier refuted")
    section = render_markdown(case_dir)
    assert section.startswith("## Negative space")
    assert "claim X" in section

    before = len(read_events(case_dir))
    # a second render never duplicates events
    render_markdown(case_dir)
    assert len(read_events(case_dir)) == before


def test_read_events_skips_a_malformed_audit_line(case_dir: Path):
    """A torn audit line must not resurrect the previous event or crash."""
    from nexus.analysis.negative_space import read_events, record

    record(case_dir, "refuted", "claim A", "first")
    record(case_dir, "refuted", "claim B", "second")
    path = case_dir / "audit" / "negative_space.jsonl"
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text(
        "\n".join([lines[0], "{not json", lines[1]]) + "\n", encoding="utf-8"
    )

    assert [e["subject"] for e in read_events(case_dir)] == ["claim A", "claim B"]


# --------------------------------------------------------------------------
# portal reject: one event per dismissal
# --------------------------------------------------------------------------


@pytest.fixture()
def client(tmp_path, monkeypatch):
    from starlette.applications import Starlette
    from starlette.testclient import TestClient

    from nexus.dashboard.app import create_dashboard

    monkeypatch.setenv("NEXUS_CASES_ROOT", str(tmp_path / "cases"))
    monkeypatch.setenv("NEXUS_DATA_ROOT", str(tmp_path / "data"))
    monkeypatch.setenv("NEXUS_ACTIVE_CASE_FILE", str(tmp_path / "active_case"))
    (tmp_path / "cases").mkdir(parents=True, exist_ok=True)
    (tmp_path / "data").mkdir(parents=True, exist_ok=True)
    return TestClient(Starlette(routes=create_dashboard()))


def test_portal_reject_emits_one_event_per_dismissal(client, tmp_path):
    """The portal dismissal path emits exactly one event per rejected finding."""
    from nexus.analysis.negative_space import read_events

    seeded = client.post("/portal/api/case/seed-demo", json={"activate": True})
    assert seeded.status_code == 200, seeded.text
    case_dir = tmp_path / "cases" / seeded.json()["case_id"]

    drafts = [
        f["id"] for f in client.get("/portal/api/findings").json()["findings"]
        if f["status"] == "DRAFT"
    ]
    assert len(drafts) >= 2

    # The seeder already rejected one finding through the real reject path, so
    # the delta is what this call must add - not the absolute count.
    before = len(read_events(case_dir))
    findings_before = len(_findings(case_dir))

    r = client.post("/portal/api/findings/reject", json={
        "finding_ids": drafts[:2], "reason": "explainer misread the row",
    })
    assert r.status_code == 200, r.text

    events = read_events(case_dir)
    assert len(events) == before + 2
    added = events[before:]  # audit order: exactly what this call appended
    assert {e["subject"] for e in added} == set(drafts[:2])
    for e in added:
        assert e["kind"] == "false_positive_dismissed"
        assert e["refs"] == [e["subject"]]
        assert "explainer misread the row" in e["detail"]

    # nothing staged as a finding by the emission
    assert len(_findings(case_dir)) == findings_before


# --------------------------------------------------------------------------
# Mode 3: a disputed claim is the refutation (WO-A7 emit point)
# --------------------------------------------------------------------------


def _board_with_dispute() -> tuple[list, list]:
    """Two seats, one entity, opposite polarity - a real board dispute."""
    from nexus.modes.multi_agent import find_disputes

    board = [
        {"agent_id": "seat-a", "role": "evidence", "claims": [{
            "entity_type": "file", "entity_value": "C:/tmp/a.exe",
            "claim_kind": "presence", "polarity": "affirm", "value": "present",
            "confidence": "MEDIUM", "confidence_justification": "the MFT row",
            "audit_ids": ["nx-audit-0001"],
        }]},
        {"agent_id": "seat-b", "role": "pattern", "claims": [{
            "entity_type": "file", "entity_value": "C:/tmp/a.exe",
            "claim_kind": "presence", "polarity": "deny", "value": "absent",
            "confidence": "LOW", "confidence_justification": "prefetch says never run",
            "audit_ids": ["nx-audit-0002"],
        }]},
    ]
    return board, find_disputes(board)


def test_mode3_disputed_claims_are_recorded_as_refuted(case_dir: Path):
    from nexus.analysis.negative_space import read_events
    from nexus.modes.multi_agent import settled_candidates

    board, disputes = _board_with_dispute()
    assert disputes, "the fixture must produce a dispute"

    # pure call: no audit emission when no case_dir is given
    candidates, _gaps = settled_candidates(board, disputes)
    assert candidates == []
    assert read_events(case_dir) == []

    candidates, _gaps = settled_candidates(board, disputes, case_dir=case_dir)
    assert candidates == []
    events = [e for e in read_events(case_dir) if e["kind"] == "refuted"]
    assert len(events) == 2  # one per disputed claim, never a finding
    assert {tuple(e["refs"]) for e in events} == {
        ("nx-audit-0001",), ("nx-audit-0002",)
    }
    assert all("disputed" in e["detail"] for e in events)
    assert _findings(case_dir) == []


# --------------------------------------------------------------------------
# report tail + grade isolation (D12 = A: the grade never reads this)
# --------------------------------------------------------------------------

_REPORT_MD = (
    "## Scope\n\n12 files were registered from evtx and tasks; 40 items were "
    "unparsed.\n\n## Findings\n\nNothing survived verification in this fixture.\n\n"
    "## Limitations\n\nPrefetch deletion means execution counts are a lower "
    "bound; no memory image was acquired, so injected code is not covered.\n\n"
    "## Next steps\n\nPreserve the endpoint and recommend imaging memory.\n"
)


def test_report_tail_renders_and_the_grade_never_reads_it(tmp_path, monkeypatch):
    from nexus.analysis.negative_space import record
    from nexus.dashboard import app as app_mod

    case = tmp_path / "CASE-NEGRPT01"
    case.mkdir()
    (case / "CASE.yaml").write_text(
        "case_id: CASE-NEGRPT01\nstatus: open\n", encoding="utf-8"
    )
    (case / "findings.json").write_text("[]", encoding="utf-8")
    out_file = case / "reports" / "REPORT.md"
    out_file.parent.mkdir(parents=True, exist_ok=True)

    def _render() -> tuple[dict, str]:
        app_mod._augment_report_with_grade(
            case, out_file, _REPORT_MD, [], [{"name": f"e{i}"} for i in range(12)],
        )
        grade = json.loads(
            (case / "analysis" / "report_grade.json").read_text(encoding="utf-8")
        )
        return grade, out_file.read_text(encoding="utf-8")

    grade_before, report_before = _render()
    assert "## Negative space" not in report_before

    record(case, "refuted", "claim X", "the verifier refuted this")
    record(case, "missing_evidence", "coverage", "coverage audit reports gaps")

    grade_after, report_after = _render()
    assert "## Negative space" in report_after
    assert "claim X" in report_after

    # D12 = A unchanged: the grade is byte-identical with and without the tail
    assert json.dumps(grade_after, sort_keys=True) == json.dumps(
        grade_before, sort_keys=True
    )
    # rendering the report twice never duplicates the section's events
    assert _findings(case) == []
