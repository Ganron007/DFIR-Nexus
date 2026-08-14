"""Portal steer routes exist (case pick / intake / N4 rerun)."""

from __future__ import annotations

import pytest

starlette = pytest.importorskip("starlette")
from starlette.applications import Starlette
from starlette.testclient import TestClient

from nexus.dashboard.app import create_dashboard


def test_steer_page_and_cases_api():
    app = Starlette(routes=create_dashboard())
    client = TestClient(app)
    r = client.get("/portal/steer")
    assert r.status_code == 200
    assert b"Steer case" in r.content
    assert b"Re-run query pack" in r.content
    r2 = client.get("/portal/api/cases")
    assert r2.status_code == 200
    assert "cases" in r2.json()
    assert "active" in r2.json()


def test_query_page_renders_without_active_case():
    app = Starlette(routes=create_dashboard())
    client = TestClient(app)
    r = client.get("/portal/query")
    assert r.status_code == 200
    assert b"Query processed evidence" in r.content
    assert b"INSUFFICIENT" in r.content
