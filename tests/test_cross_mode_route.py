"""WO-1C item 5: the cross-mode view inside the case is served by the portal.

The route is the HTTP form of `nexus cross-mode --case`: the same comparison over the case's
own runs and DRAFTs, addressed by the request's case header, never the global active case.
"""
from __future__ import annotations

import json

import pytest
from starlette.applications import Starlette
from starlette.testclient import TestClient


@pytest.fixture
def client(tmp_path, monkeypatch):
    from nexus.config import settings

    monkeypatch.setattr(settings, "cases_root", tmp_path / "cases")
    case = tmp_path / "cases" / "CASE-XMODE01"
    (case / "audit").mkdir(parents=True)
    (case / "CASE.yaml").write_text("case_id: CASE-XMODE01\n", encoding="utf-8")
    (case / "findings.json").write_text("[]", encoding="utf-8")

    from nexus.dashboard.app import create_dashboard

    return TestClient(Starlette(routes=create_dashboard()))


def test_the_cross_mode_view_answers_for_the_case_named_in_the_request(client):
    response = client.get("/portal/api/cross-mode", headers={"X-Nexus-Case": "CASE-XMODE01"})
    assert response.status_code == 200, response.text
    body = response.json()
    assert isinstance(body, dict)
    json.dumps(body)  # the report is plain JSON, nothing the encoder would reject


def test_an_unknown_case_is_refused_rather_than_compared(client):
    response = client.get("/portal/api/cross-mode", headers={"X-Nexus-Case": "CASE-NOPE0001"})
    assert response.status_code == 404
