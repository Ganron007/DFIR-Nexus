"""Unit tests for report downloads (markdown, html, docx, stix, zip) and case bundle export."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest
from starlette.applications import Starlette
from starlette.testclient import TestClient

from nexus.dashboard.app import create_dashboard


@pytest.fixture
def mock_case(tmp_path: Path):
    case_dir = tmp_path / "cases" / "CASE-TEST001"
    case_dir.mkdir(parents=True, exist_ok=True)
    (case_dir / "reports").mkdir(exist_ok=True)
    (case_dir / "analysis").mkdir(exist_ok=True)
    (case_dir / "audit").mkdir(exist_ok=True)

    case_yaml = (
        "id: CASE-TEST001\n"
        "name: Test Investigation Case\n"
        "status: open\n"
        "severity: high\n"
        "created_by: examiner\n"
        "description: Synthetic case for download tests\n"
        "intake:\n"
        "  question: Who accessed the system?\n"
    )
    (case_dir / "CASE.yaml").write_text(case_yaml, encoding="utf-8")

    findings = [
        {
            "id": "FIND-001",
            "title": "Suspicious PowerShell Execution",
            "observation": "Encoded command executed by user admin",
            "interpretation": "Possible initial access stager",
            "severity": "high",
            "status": "APPROVED",
            "approval_state": "APPROVED",
            "created_by": "examiner",
            "mitre_ids": ["T1059.001"],
            "technique_ids": ["T1059.001"],
            "metadata": {"host": "workstation-01"},
        }
    ]
    (case_dir / "findings.json").write_text(json.dumps(findings), encoding="utf-8")

    evidence = [
        {
            "id": "EV-001",
            "name": "Security.evtx",
            "path": "Security.evtx",
            "sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            "description": "Windows Security Event Log",
        }
    ]
    (case_dir / "evidence.json").write_text(json.dumps(evidence), encoding="utf-8")

    timeline = [
        {
            "id": "TL-001",
            "ts": "2026-11-01T10:00:00Z",
            "timestamp": "2026-11-01T10:00:00Z",
            "description": "Logon event 4624",
            "status": "APPROVED",
        }
    ]
    (case_dir / "timeline.json").write_text(json.dumps(timeline), encoding="utf-8")
    (case_dir / "todos.json").write_text("[]", encoding="utf-8")
    (case_dir / "iocs.json").write_text("[]", encoding="utf-8")

    return case_dir


@pytest.fixture
def client(mock_case: Path):
    app = Starlette(routes=create_dashboard())
    with patch("nexus.dashboard.app._get_case_dir", return_value=mock_case):
        yield TestClient(app)


def test_report_generate_executive_profile(client: TestClient, mock_case: Path):
    """POST /portal/api/report/generate with profile=executive writes executive report."""
    resp = client.post("/portal/api/report/generate", json={"profile": "executive", "llm": False})
    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is True
    assert data["profile"] == "executive"
    report_file = mock_case / "reports" / "REPORT.md"
    assert report_file.is_file()
    content = report_file.read_text(encoding="utf-8")
    assert "Executive Summary:" in content
    assert "Suspicious PowerShell Execution" in content


def test_report_download_markdown(client: TestClient, mock_case: Path):
    """GET /portal/api/report/download?format=markdown returns REPORT.md text."""
    (mock_case / "reports" / "REPORT.md").write_text("# Case Report Header\nFindings details here.", encoding="utf-8")
    resp = client.get("/portal/api/report/download?format=markdown")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/markdown")
    assert "CASE-TEST001-report.md" in resp.headers["content-disposition"]
    assert "Case Report Header" in resp.text


def test_report_download_html(client: TestClient):
    """GET /portal/api/report/download?format=html returns styled HTML."""
    resp = client.get("/portal/api/report/download?format=html")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/html")
    assert "<!DOCTYPE html>" in resp.text
    assert "Test Investigation Case" in resp.text


def test_report_download_docx(client: TestClient):
    """GET /portal/api/report/download?format=docx returns OOXML bytes."""
    resp = client.get("/portal/api/report/download?format=docx")
    assert resp.status_code == 200
    assert resp.content[:2] == b"PK"
    assert "CASE-TEST001-report.docx" in resp.headers["content-disposition"]


def test_report_download_stix(client: TestClient):
    """GET /portal/api/report/download?format=stix returns STIX bundle JSON."""
    resp = client.get("/portal/api/report/download?format=stix")
    assert resp.status_code == 200
    data = resp.json()
    assert data.get("type") == "bundle"
    assert len(data.get("objects", [])) >= 1


def test_report_download_zip(client: TestClient):
    """GET /portal/api/report/download?format=zip returns package ZIP bytes."""
    resp = client.get("/portal/api/report/download?format=zip")
    assert resp.status_code == 200
    assert resp.content[:2] == b"PK"
    assert "CASE-TEST001-report.zip" in resp.headers["content-disposition"]


def test_report_download_unsupported_format(client: TestClient):
    """GET /portal/api/report/download?format=pdf returns 400 with helpful error."""
    resp = client.get("/portal/api/report/download?format=pdf")
    assert resp.status_code == 400
    assert "Unsupported format" in resp.json()["error"]


def test_case_bundle_export(client: TestClient):
    """GET /portal/api/case/bundle returns JSON bundle with findings and timeline."""
    resp = client.get("/portal/api/case/bundle")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/json")
    assert "CASE-TEST001-bundle.json" in resp.headers["content-disposition"]
    data = resp.json()
    assert data["version"] == 1
    assert data["case_id"] == "CASE-TEST001"
    assert len(data["findings"]) == 1
    assert data["findings"][0]["id"] == "FIND-001"
    assert len(data["timeline"]) == 1
