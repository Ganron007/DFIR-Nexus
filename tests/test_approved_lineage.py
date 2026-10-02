"""Tier 1 exit criterion 4: an approved finding carries its full lineage.

Phase 6 produces the case; this proves the *fields* are produced and survive
approval, without depending on a live case. The four pieces the criterion
names:

* the L1 verdict recorded at the moment of signing,
* the seal state (verified, or an explicit absent override),
* origin + mode + run lineage,
* the tool lineage (version + argv) behind the cited rows.
"""
from __future__ import annotations

import json

from nexus.auth import setup_password
from nexus.case import approval_service
from nexus.case.records import load_records


def _isolate(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "nexus.case.records.records_db_path", lambda: tmp_path / "cases.db"
    )
    monkeypatch.setattr("nexus.transparency.TRANSPARENCY_DIR", tmp_path / "transparency")
    monkeypatch.setattr("nexus.auth.VERIFICATION_DIR", tmp_path / "verification")
    monkeypatch.setattr("nexus.auth._PASSWORDS_DIR", tmp_path / "passwords")
    monkeypatch.setattr("nexus.auth._LOCKOUT_FILE", tmp_path / "lockout")


def test_an_approved_finding_keeps_verdict_seal_origin_and_tool_lineage(
    tmp_path, monkeypatch
):
    _isolate(monkeypatch, tmp_path)
    setup_password("examiner", "test-password")

    case = tmp_path / "CASE-LIN"
    case.mkdir()
    # A Mode 2 staged candidate: agent origin, its run id, the tool-lane audits
    # behind its rows, and a submission seal.
    draft = {
        "id": "F-LIN-1",
        "case_id": "CASE-LIN",
        "title": "SMB lateral movement from the provisioning host",
        "status": "DRAFT",
        "severity": "HIGH",
        "provenance": {"mode": 2, "origin": "agent", "run_id": "M2-20261002T000000-abc123"},
        "examiner_selected": False,
        "audit_ids": ["aud-1", "aud-2"],
    }
    (case / "findings.json").write_text(json.dumps([draft]), encoding="utf-8")

    entry = approval_service.require_examiner("examiner", "test-password")
    result = approval_service.commit_approval(
        case,
        "F-LIN-1",
        "examiner",
        l1_verdict="INFERRED",
        override_reason="examiner accepted: corroborated by two families",
        signing_key=approval_service.signing_key_from_stored_hash(entry["hash"]),
        salt=entry["salt"],
    )
    assert result["status"] == "APPROVED", result

    # The record store is canonical; the flat file is its mirror.
    stored = load_records(case, "finding")[0]
    mirrored = json.loads((case / "findings.json").read_text(encoding="utf-8"))[0]
    for approved in (stored, mirrored):
        # 1. the L1 verdict at the moment of signing
        assert approved["l1_verdict_at_approval"] == "INFERRED"
        # 2. the seal state (no seal on this draft -> an explicit "absent")
        assert approved["seal_state"] == "absent"
        # 3. origin + mode + run lineage
        assert approved["provenance"]["origin"] == "agent"
        assert approved["provenance"]["mode"] == 2
        assert approved["provenance"]["run_id"].startswith("M2-")
        assert approved["examiner_selected"] is False
        # 4. the tool-lane audits behind the cited rows
        assert approved["audit_ids"] == ["aud-1", "aud-2"]
        assert approved["override_reason"].startswith("examiner accepted")

    # And the approval is in the ledger, which is what verify reads.
    ok, errors = approval_service.approval_ledger_status(case)
    assert ok, errors
