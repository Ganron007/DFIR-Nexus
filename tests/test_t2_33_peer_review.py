"""Tests for Technical (Peer) Review Signature (T2-33 / WP 13.13 / TC-4 / ISO 17025)."""

import json
from pathlib import Path
from unittest.mock import patch

import pytest
from starlette.testclient import TestClient

from nexus.auth import (
    setup_password,
    sign_peer_review,
    verify_peer_review_status,
)
from nexus.dashboard.app import create_dashboard


@pytest.fixture
def auth_env(tmp_path: Path):
    vdir = tmp_path / "verification"
    vdir.mkdir(parents=True, exist_ok=True)
    pdir = tmp_path / "passwords"
    pdir.mkdir(parents=True, exist_ok=True)

    with patch("nexus.auth.VERIFICATION_DIR", vdir), \
         patch("nexus.auth._PASSWORDS_DIR", pdir):
        # Configure passwords for primary approver and independent peer reviewer
        setup_password("primary_examiner", "PrimarySecret123!")
        setup_password("senior_peer_reviewer", "SeniorSecret456!")
        yield {"vdir": vdir, "pdir": pdir}


def test_peer_review_success_and_invalidation(auth_env, tmp_path: Path):
    finding = {
        "id": "F-001",
        "title": "Cobalt Strike Beacon Injected into svchost",
        "severity": "CRITICAL",
        "approved_by": "primary_examiner",
        "revision_id": "rev-001",
        "description": "Found injection at PID 4412",
    }

    # 1. Sign peer review with senior reviewer
    record = sign_peer_review(
        case_id="CASE-PEER-01",
        finding_id="F-001",
        reviewer="senior_peer_reviewer",
        password="SeniorSecret456!",
        finding_data=finding,
    )
    assert record["finding_id"] == "F-001"
    assert record["reviewed_by"] == "senior-peer-reviewer"
    assert record["type"] == "peer_review"

    # 2. Verify status on unmodified finding
    status = verify_peer_review_status("CASE-PEER-01", "F-001", finding)
    assert status["status"] == "VERIFIED"
    assert status["reviewed_by"] == "senior-peer-reviewer"

    # 3. Modify finding (simulating post-review edit)
    modified_finding = dict(finding)
    modified_finding["description"] = "Altered description after review"
    mod_status = verify_peer_review_status("CASE-PEER-01", "F-001", modified_finding)
    assert mod_status["status"] == "INVALIDATED"
    assert "modified after technical review" in mod_status["detail"]


def test_peer_review_self_review_prohibited(auth_env):
    finding = {
        "id": "F-002",
        "title": "Lateral Movement via SMB",
        "severity": "HIGH",
        "approved_by": "primary_examiner",
    }
    with pytest.raises(ValueError, match="cannot be the primary approver"):
        sign_peer_review(
            case_id="CASE-PEER-02",
            finding_id="F-002",
            reviewer="primary_examiner",  # Attempting to peer-review own finding
            password="PrimarySecret123!",
            finding_data=finding,
        )


def test_peer_review_invalid_password(auth_env):
    finding = {
        "id": "F-003",
        "title": "Suspicious Run Key",
        "severity": "HIGH",
        "approved_by": "primary_examiner",
    }
    with pytest.raises(ValueError, match="Password verification failed"):
        sign_peer_review(
            case_id="CASE-PEER-03",
            finding_id="F-003",
            reviewer="senior_peer_reviewer",
            password="WrongPassword999!",
            finding_data=finding,
        )


def test_api_finding_peer_review_endpoint(auth_env, tmp_path: Path):
    case_dir = tmp_path / "cases" / "CASE-API-PEER"
    case_dir.mkdir(parents=True)
    findings = [{
        "id": "F-100",
        "title": "Domain Admin Compromise",
        "severity": "CRITICAL",
        "status": "APPROVED",
        "approved_by": "primary_examiner",
    }]
    (case_dir / "findings.json").write_text(json.dumps(findings), encoding="utf-8")

    from starlette.applications import Starlette
    app = Starlette(routes=create_dashboard())

    with patch("nexus.dashboard.app._get_case_dir", return_value=case_dir):
        client = TestClient(app)
        resp = client.post("/portal/api/finding/peer-review", json={
            "finding_id": "F-100",
            "reviewer": "senior_peer_reviewer",
            "password": "SeniorSecret456!",
        })
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["status"] == "ok"
        assert data["peer_review"]["status"] == "VERIFIED"
        assert data["peer_review"]["reviewed_by"] == "senior-peer-reviewer"

        # Check that findings.json on disk was updated
        updated = json.loads((case_dir / "findings.json").read_text(encoding="utf-8"))
        assert updated[0]["peer_review"]["reviewed_by"] == "senior-peer-reviewer"
