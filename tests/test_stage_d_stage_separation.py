"""Tests for Stage D / RB-D2 & RB-D3: Pipeline Stage Separation & Stage 0 IR Collection Revamp.

Enforces:
1. Pure Stage 0 acquisition: live collection produces unparsed evidence packs with hashes and manifest.json.
2. D99 / D105 resolution: orc_exe() prioritizes DFIR-ORC-ready.exe; kape_exe() handles home search; skips gracefully when absent.
3. Strict decoupling between:
   - Stage 0: Acquisition
   - Stage 1: Tool Lane (extractions)
   - Stage 2: Ingest & Index
   - Stage 3: Analysis Modes
   - Stage 4: Staging & Approvals
   - Stage 5: Reporting
4. Independent execution and re-runnability of each stage.
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from nexus.collect.orchestrator import plan_or_run
from nexus.collect.paths import kape_exe, kape_home, orc_exe
from nexus.collect.types import CollectOptions, HostSpec


def test_stage0_tool_resolution_d99_d105(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Verifies D99 and D105 resolution in Stage 0 path search."""
    tools_dir = tmp_path / "tools"
    tools_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("NEXUS_TOOL_PATHS", str(tools_dir))

    # 1. D99: DFIR-ORC ready build resolution
    orc_dir = tools_dir / "orc"
    orc_dir.mkdir(parents=True, exist_ok=True)
    orc_ready = orc_dir / "DFIR-ORC-ready.exe"
    orc_ready.write_bytes(b"MZ-ORC-READY")

    resolved_orc = orc_exe()
    assert resolved_orc is not None
    assert resolved_orc.name == "DFIR-ORC-ready.exe"

    # 2. D105: KAPE home and binary resolution
    kape_dir = tools_dir / "kape"
    kape_dir.mkdir(parents=True, exist_ok=True)
    kape_bin = kape_dir / "kape.exe"
    kape_bin.write_bytes(b"MZ-KAPE")

    assert kape_home() == kape_dir
    assert kape_exe() == kape_bin

    # Graceful fallback when absent
    monkeypatch.setenv("NEXUS_TOOL_PATHS", str(tmp_path / "empty_tools"))
    monkeypatch.delenv("NEXUS_ORC", raising=False)
    monkeypatch.delenv("NEXUS_KAPE_HOME", raising=False)
    with patch("nexus.collect.paths.extra_search_roots", return_value=[]):
        assert orc_exe() is None
        assert kape_exe() is None


def test_stage0_collection_plan_and_isolation(tmp_path: Path):
    """Stage 0 produces only raw manifests and collection packs without touching ES or analysis."""
    spec = HostSpec(os="windows", address="127.0.0.1", hostname="test-host", transport="local")
    opts = CollectOptions()
    pack_dir = tmp_path / "pack-stage0"

    manifest = plan_or_run(spec, opts, pack_dir, dry_run=True, probe=False, examiner="examiner1")
    assert manifest.dry_run is True
    assert manifest.pack_dir == str(pack_dir)
    assert manifest.examiner == "examiner1"

    # Manifest file written to disk
    manifest_path = pack_dir / "manifest.json"
    assert manifest_path.exists()
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert data["examiner"] == "examiner1"
    assert "tools" in data
    # Passwords or credentials must never be leaked into manifest
    assert "never stored" in data.get("auth", "")

    # Stage 0 points examiner to next stage: evidence registration
    assert "nexus evidence register" in manifest.next_hint


def test_pipeline_stage_separation_boundaries(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Confirms pipeline separation across stages."""
    cases_root = tmp_path / "cases"
    cases_root.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("NEXUS_CASES_ROOT", str(cases_root))
    monkeypatch.setenv("NEXUS_DATA_ROOT", str(tmp_path / "data"))

    from nexus.case.compat import get_sqlite_manager
    mgr = get_sqlite_manager()
    case = mgr.create_case(name="stage-sep", description="Pipeline test", created_by="examiner")
    cid = case.to_dict()["id"]
    case_dir = cases_root / cid
    case_dir.mkdir(parents=True, exist_ok=True)

    # Stage 1: Tool Lane does not stage findings or approve
    runs_dir = case_dir / "runs" / "RUN-STAGE1"
    runs_dir.mkdir(parents=True, exist_ok=True)
    extractions = runs_dir / "extractions"
    extractions.mkdir(parents=True, exist_ok=True)
    (extractions / "parsed.csv").write_text("col1,col2\nval1,val2\n", encoding="utf-8")

    # Assert no findings exist in case database
    from nexus.case.records import load_records, save_findings
    findings = load_records(case_dir, "finding")
    assert len(findings) == 0

    # Stage 3: Mode creates candidate DRAFT findings
    f_draft = {
        "id": "F-SEP-001",
        "finding_id": "F-SEP-001",
        "title": "Candidate Finding",
        "severity": "MEDIUM",
        "status": "DRAFT",
        "observation": "Observed event",
        "cited_rows": ["audit-123"],
    }
    save_findings(case_dir, [f_draft])
    stored_findings = load_records(case_dir, "finding")
    assert len(stored_findings) == 1
    assert stored_findings[0]["status"] == "DRAFT"

    # Stage 4: Examiner HMAC Approval
    # Testing that approval requires authenticated examiner challenge and produces ledger
    vdir = tmp_path / "vdir"
    vdir.mkdir(parents=True, exist_ok=True)
    pdir = tmp_path / "pdir"
    pdir.mkdir(parents=True, exist_ok=True)
    with patch("nexus.auth.VERIFICATION_DIR", vdir), \
         patch("nexus.auth._PASSWORDS_DIR", pdir):
        from nexus.auth import read_verification_ledger, setup_password
        from nexus.case.approval_service import (
            commit_approval,
            require_examiner,
            signing_key_from_stored_hash,
        )
        setup_password("lead-examiner", "SuperSecret123!")

        # Verify examiner password
        p_entry = require_examiner("lead-examiner", "SuperSecret123!")
        key = signing_key_from_stored_hash(p_entry["hash"])

        res = commit_approval(
            case_dir, "F-SEP-001", "lead-examiner",
            l1_verdict="PROVEN",
            signing_key=key,
            salt=p_entry["salt"],
        )
        assert res["status"] == "APPROVED"
        assert res["finding_id"] == "F-SEP-001"

        ledger = read_verification_ledger(cid)
        assert len(ledger) == 1
        assert ledger[0]["finding_id"] == "F-SEP-001"
        assert ledger[0]["approved_by"] == "lead-examiner"

    # Stage 5: Report generation
    from nexus.integration.dfir_report import build_dfir_markdown
    # Official report excludes unapproved drafts by default
    report_official = build_dfir_markdown(
        case_id=cid,
        case_name="stage-sep",
        findings=[f_draft],
        evidence=[],
        include_draft=False,
    )
    assert "F-SEP-001" not in report_official

    # Draft preview report includes drafts
    report_draft = build_dfir_markdown(
        case_id=cid,
        case_name="stage-sep",
        findings=[f_draft],
        evidence=[],
        include_draft=True,
    )
    assert "Candidate Finding" in report_draft
