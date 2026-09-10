"""Phase 4g-F — examiner feedback + local needle overlay."""

from __future__ import annotations

import pytest
from starlette.applications import Starlette
from starlette.testclient import TestClient

from nexus.config import settings
from nexus.knowledge import needle_overlay


@pytest.fixture()
def overlay(tmp_path, monkeypatch):
    path = tmp_path / "overlay.yaml"
    monkeypatch.setenv("NEXUS_NEEDLE_OVERLAY", str(path))
    return path


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_CASES_ROOT", str(tmp_path / "cases"))
    monkeypatch.setenv("NEXUS_DATA_ROOT", str(tmp_path / "data"))
    monkeypatch.setenv("NEXUS_ACTIVE_CASE_FILE", str(tmp_path / "active_case"))
    (tmp_path / "cases").mkdir(parents=True, exist_ok=True)
    (tmp_path / "data").mkdir(parents=True, exist_ok=True)

    from nexus.dashboard.app import create_dashboard

    return TestClient(Starlette(routes=create_dashboard()))


def test_promote_and_load_overlay(overlay):
    result = needle_overlay.promote_needles("evtx", ["badguy.exe", "evil.example.com"])
    assert result["count"] == 2
    assert overlay.is_file()
    assert needle_overlay.overlay_terms_for_families({"evtx"}) == [
        "badguy.exe",
        "evil.example.com",
    ]

    # idempotent merge
    needle_overlay.promote_needles("evtx", ["badguy.exe", "newterm"])
    assert needle_overlay.overlay_terms_for_families({"evtx"}) == [
        "badguy.exe",
        "evil.example.com",
        "newterm",
    ]


def test_feedback_endpoint_records_and_promotes(client, overlay, tmp_path):
    created = client.post("/portal/api/case/create", json={"name": "Feedback Case"})
    case_id = created.json()["case_id"]

    r = client.post(
        "/portal/api/needles/feedback",
        headers={"X-Nexus-Case": case_id},
        json={"needles": ["evil.exe"], "family": "evtx", "source": "mitre", "verdict": "promote"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["promoted"]["count"] == 1

    # suggestions now include the promoted overlay for that family
    r = client.get(
        "/portal/api/playbook/needles?families=evtx",
        headers={"X-Nexus-Case": case_id},
    )
    suggestions = r.json()["suggestions"]
    assert any(s.get("source") == "overlay" and "evil.exe" in s["needles"] for s in suggestions)

    # verdict recorded in the case's feedback log
    assert (settings.cases_root / case_id / "needle_feedback.jsonl").is_file()


def test_feedback_rejects_bad_verdict(client):
    created = client.post("/portal/api/case/create", json={"name": "FB2"})
    case_id = created.json()["case_id"]
    r = client.post(
        "/portal/api/needles/feedback",
        headers={"X-Nexus-Case": case_id},
        json={"needles": ["x"], "verdict": "maybe"},
    )
    assert r.status_code == 400
