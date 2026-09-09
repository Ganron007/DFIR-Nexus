"""Tests for Phase 4b workflow-driven cockpit APIs.

Covers:
- WP 4b.1: POST /portal/api/case/create
- WP 4b.2: POST /portal/api/pipeline/run + GET /portal/api/pipeline/status
- WP 4b.7: GET /portal/api/playbook/needles
- WP 4b.6: POST/GET /portal/api/case/mode
- WP 4b.1: GET /portal/api/case/details
"""
import json
from pathlib import Path

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


def test_case_create(client):
    """WP 4b.1: Case creation API creates a case and activates it."""
    r = client.post("/portal/api/case/create", json={
        "name": "Test Case",
        "description": "Phase 4b test",
        "examiner": "tester",
        "mode": "1",
    })
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert body["case_id"]
    assert body["active"] == body["case_id"]


def test_case_create_missing_name(client):
    """WP 4b.1: Missing name returns 400."""
    r = client.post("/portal/api/case/create", json={})
    assert r.status_code == 400
    assert "name" in r.json()["error"].lower()


def test_case_details(client):
    """WP 4b.1: Case details endpoint returns metadata."""
    # Create a case first
    r = client.post("/portal/api/case/create", json={
        "name": "Details Test",
        "mode": "2",
    })
    case_id = r.json()["case_id"]

    r = client.get(f"/portal/api/case/details?case_id={case_id}")
    assert r.status_code == 200
    body = r.json()
    assert body["case_id"] == case_id
    assert body["name"] == "Details Test"
    assert body["investigation_mode"] == "2"
    assert body["evidence_count"] == 0
    assert body["findings_count"] == 0


def test_case_mode_set_get(client):
    """WP 4b.6: Set and get investigation mode."""
    client.post("/portal/api/case/create", json={"name": "Mode Test"})
    # Set mode
    r = client.post("/portal/api/case/mode", json={"mode": "3"})
    assert r.status_code == 200
    assert r.json()["ok"] is True
    assert r.json()["mode"] == "3"
    # Get mode
    r = client.get("/portal/api/case/mode")
    assert r.status_code == 200
    assert r.json()["mode"] == "3"


def test_case_mode_invalid(client):
    """WP 4b.6: Invalid mode returns 400."""
    client.post("/portal/api/case/create", json={"name": "Bad Mode"})
    r = client.post("/portal/api/case/mode", json={"mode": "9"})
    assert r.status_code == 400


def test_playbook_needles(client):
    """WP 4b.7: Playbook needles endpoint returns suggestions."""
    r = client.get("/portal/api/playbook/needles")
    assert r.status_code == 200
    body = r.json()
    assert "suggestions" in body
    assert "total" in body
    assert body["total"] >= 0
    if body["suggestions"]:
        s = body["suggestions"][0]
        assert "playbook" in s
        assert "needles" in s
        assert isinstance(s["needles"], list)


def test_pipeline_run_invalid_mode(client):
    """WP 4b.2: Invalid pipeline mode returns 400."""
    client.post("/portal/api/case/create", json={"name": "Pipe Test"})
    r = client.post("/portal/api/pipeline/run", json={"mode": "invalid"})
    assert r.status_code == 400


def test_pipeline_run_no_case(client, tmp_path, monkeypatch):
    """WP 4b.2: Pipeline run without active case returns 404."""
    monkeypatch.setenv("NEXUS_ACTIVE_CASE_FILE", str(tmp_path / "nonexistent"))
    r = client.post("/portal/api/pipeline/run", json={"mode": "tools"})
    assert r.status_code == 404


def test_pipeline_status_not_found(client):
    """WP 4b.2: Status for unknown run_id returns 404."""
    r = client.get("/portal/api/pipeline/status?run_id=nonexistent")
    assert r.status_code == 404
