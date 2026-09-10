"""Tests for Phase 4 CLI/UI parity and verification endpoints.

Covers:
- POST /portal/api/case/seed-demo
- POST /portal/api/findings/reject
- POST /portal/api/report/generate + GET /portal/api/report/view
- POST /portal/api/evidence/verify
"""
import pytest
from starlette.applications import Starlette
from starlette.testclient import TestClient

from nexus.dashboard.app import create_dashboard


@pytest.fixture()
def client(tmp_path, monkeypatch):
    """TestClient with isolated case root."""
    monkeypatch.setenv("NEXUS_CASES_ROOT", str(tmp_path / "cases"))
    monkeypatch.setenv("NEXUS_DATA_ROOT", str(tmp_path / "data"))
    monkeypatch.setenv("NEXUS_ACTIVE_CASE_FILE", str(tmp_path / "active_case"))
    (tmp_path / "cases").mkdir(parents=True, exist_ok=True)
    (tmp_path / "data").mkdir(parents=True, exist_ok=True)
    dashboard = create_dashboard()
    app = Starlette(routes=dashboard)
    return TestClient(app)


def test_seed_demo_api(client):
    """POST /portal/api/case/seed-demo populates complete case."""
    r = client.post("/portal/api/case/seed-demo", json={"name": "Demo Incident Test"})
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert body["case_id"] == "CASE-DEMO-001"
    assert body["evidence_count"] >= 4
    assert body["findings_count"] >= 5

    # Check case details
    det = client.get("/portal/api/case/details?case_id=CASE-DEMO-001")
    assert det.status_code == 200
    db = det.json()
    assert db["pipeline_complete"] is True
    assert db["investigation_mode"] == "1"


def test_findings_reject_api(client):
    """POST /portal/api/findings/reject marks findings REJECTED with reason."""
    # Seed case (activate for this legacy active-case flow)
    client.post("/portal/api/case/seed-demo", json={"activate": True})

    # Reject without reason fails
    r_bad = client.post("/portal/api/findings/reject", json={"finding_ids": ["F-DEMO-001"]})
    assert r_bad.status_code == 400
    assert "reason" in r_bad.json()["error"].lower()

    # Reject with reason succeeds
    r_good = client.post("/portal/api/findings/reject", json={
        "finding_ids": ["F-DEMO-001"],
        "reason": "Administrative tool false positive",
        "examiner": "test_examiner",
    })
    assert r_good.status_code == 200
    assert r_good.json()["ok"] is True
    assert "F-DEMO-001" in r_good.json()["rejected"]

    # Verify status changed in findings list
    f_res = client.get("/portal/api/findings?status=REJECTED")
    assert f_res.status_code == 200
    rejected_ids = [f["id"] for f in f_res.json().get("findings", [])]
    assert "F-DEMO-001" in rejected_ids


def test_report_generate_and_view_api(client):
    """POST /portal/api/report/generate compiles report and GET /portal/api/report/view serves it."""
    # Seed case (activate for this legacy active-case flow)
    client.post("/portal/api/case/seed-demo", json={"activate": True})

    # Generate report
    gen_res = client.post("/portal/api/report/generate", json={"profile": "markdown"})
    assert gen_res.status_code == 200
    gen_body = gen_res.json()
    assert gen_body["ok"] is True
    assert gen_body["findings_count"] >= 2

    # View report
    view_res = client.get("/portal/api/report/view")
    assert view_res.status_code == 200
    view_body = view_res.json()
    assert view_body["ok"] is True
    assert len(view_body["markdown"]) > 50
    assert "DFIR Investigation Report" in view_body["markdown"] or "Findings" in view_body["markdown"]


def test_evidence_verify_api(client):
    """POST /portal/api/evidence/verify checks cryptographic file integrity."""
    # Seed case (activate for this legacy active-case flow)
    client.post("/portal/api/case/seed-demo", json={"activate": True})

    # Run verification
    v_res = client.post("/portal/api/evidence/verify")
    assert v_res.status_code == 200
    v_body = v_res.json()
    assert v_body["ok"] is True
    assert len(v_body["results"]) >= 4
    # All seeded files should match their calculated sha256
    for item in v_body["results"]:
        assert item["valid"] is True, f"File {item['name']} failed verification: {item.get('error')}"
