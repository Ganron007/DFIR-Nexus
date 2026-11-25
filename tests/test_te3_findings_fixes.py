"""Regression tests for TE-3 findings (evidence verify exit code & canonical approval count)."""

from __future__ import annotations

from datetime import UTC, datetime

from starlette.applications import Starlette
from starlette.testclient import TestClient
from typer.testing import CliRunner

from nexus.case.approval_service import commit_approval, commit_rejection
from nexus.case.manager import CaseManager
from nexus.case.records import save_findings
from nexus.case.schemas import FindingSeverity
from nexus.cli.main import app as cli_app
from nexus.dashboard.app import create_dashboard


def test_te3_evidence_verify_exits_nonzero_on_hash_mismatch_and_missing(tmp_path, monkeypatch):
    """nexus evidence verify exits non-zero when an artifact is tampered or missing."""
    cases_root = tmp_path / "cases"
    cases_root.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("NEXUS_CASES_ROOT", str(cases_root))
    from nexus.config import settings

    monkeypatch.setattr(settings, "cases_root", cases_root)

    ev_file = tmp_path / "sample.csv"
    ev_file.write_text("col1,col2\na,b\n", encoding="utf-8")

    runner = CliRunner()
    res_init = runner.invoke(cli_app, ["case", "init", "Verify Test", "--case-id", "CASE-VER01"])
    assert res_init.exit_code == 0
    res_reg = runner.invoke(cli_app, ["evidence", "register", str(ev_file), "--case", "CASE-VER01"])
    assert res_reg.exit_code == 0

    res_ok = runner.invoke(cli_app, ["evidence", "verify", "--case", "CASE-VER01"])
    assert res_ok.exit_code == 0
    assert "All evidence verified OK" in res_ok.output

    # Tamper -> non-zero exit
    ev_file.write_text("col1,col2\na,TAMPERED\n", encoding="utf-8")
    res_tamper = runner.invoke(cli_app, ["evidence", "verify", "--case", "CASE-VER01"])
    assert res_tamper.exit_code != 0
    assert "HASH MISMATCH" in res_tamper.output

    # Missing -> non-zero exit
    ev_file.unlink()
    res_missing = runner.invoke(cli_app, ["evidence", "verify", "--case", "CASE-VER01"])
    assert res_missing.exit_code != 0
    assert "MISSING:" in res_missing.output


def test_te3_commit_approval_syncs_portal_cases_approved_count(tmp_path, monkeypatch):
    """CLI/service approval immediately updates /portal/api/cases approved_count and SQLite findings."""
    cases_root = tmp_path / "cases"
    case_dir = cases_root / "CASE-SYNC01"
    case_dir.mkdir(parents=True)
    (case_dir / "CASE.yaml").write_text("id: CASE-SYNC01\nname: Sync Test\n", encoding="utf-8")
    monkeypatch.setenv("NEXUS_CASES_ROOT", str(cases_root))
    from nexus.config import settings

    monkeypatch.setattr(settings, "cases_root", cases_root)

    mgr = CaseManager(cases_root / "cases.db")
    try:
        mgr.create_case("Sync Test", case_id="CASE-SYNC01")
        f1 = mgr.add_finding(
            case_id="CASE-SYNC01",
            title="Approve Target",
            description="Test observation",
            severity=FindingSeverity.MEDIUM,
        )
        f2 = mgr.add_finding(
            case_id="CASE-SYNC01",
            title="Reject Target",
            description="Benign item",
            severity=FindingSeverity.LOW,
        )
    finally:
        mgr.close()

    assert f1 is not None and f2 is not None
    fid1, fid2 = f1.id, f2.id
    save_findings(
        case_dir,
        [
            {
                "id": fid1,
                "finding_id": fid1,
                "title": "Approve Target",
                "observation": "Test observation",
                "interpretation": "Interpreted",
                "severity": "MEDIUM",
                "confidence": "LOW",
                "confidence_justification": "Verified single source",
                "status": "DRAFT",
                "created_at": datetime.now(UTC).isoformat(),
            },
            {
                "id": fid2,
                "finding_id": fid2,
                "title": "Reject Target",
                "observation": "Benign item",
                "interpretation": "Noise",
                "severity": "LOW",
                "confidence": "LOW",
                "confidence_justification": "Low risk",
                "status": "DRAFT",
                "created_at": datetime.now(UTC).isoformat(),
            },
        ],
    )

    out_app = commit_approval(
        case_dir,
        fid1,
        "examiner",
        l1_verdict="PROVEN",
        signing_key=b"test-key",
        salt="00",
    )
    assert out_app["status"] == "APPROVED"

    out_rej = commit_rejection(case_dir, fid2, "examiner", "false positive")
    assert out_rej["status"] == "REJECTED"

    # Legacy SQLite findings table must reflect both transitions immediately
    mgr2 = CaseManager(cases_root / "cases.db")
    try:
        states = {f.id: f.approval_state.value for f in mgr2.list_findings("CASE-SYNC01")}
    finally:
        mgr2.close()
    assert states == {fid1: "approved", fid2: "rejected"}

    # Portal /portal/api/cases summary must reflect exact counts
    client = TestClient(Starlette(routes=create_dashboard()))
    resp = client.get("/portal/api/cases")
    assert resp.status_code == 200
    detail = resp.json()["details"]["CASE-SYNC01"]
    assert detail["findings_count"] == 2
    assert detail["approved_count"] == 1
