"""Portal steer routes exist (case pick / intake / N4 rerun)."""

from __future__ import annotations

import pytest

starlette = pytest.importorskip("starlette")
from starlette.applications import Starlette
from starlette.testclient import TestClient

from nexus.dashboard.app import create_dashboard


def test_steer_page_redirects_to_spa():
    """WO-U7: legacy page URLs 302 to their SPA routes; the cases API stays."""
    app = Starlette(routes=create_dashboard())
    client = TestClient(app)
    r = client.get("/portal/steer", follow_redirects=False)
    assert r.status_code == 302
    assert r.headers["location"] == "/portal/app/steer"
    r2 = client.get("/portal/api/cases")
    assert r2.status_code == 200
    assert "cases" in r2.json()
    assert "active" in r2.json()


def test_query_page_redirects_to_spa():
    app = Starlette(routes=create_dashboard())
    client = TestClient(app)
    r = client.get("/portal/query", follow_redirects=False)
    assert r.status_code == 302
    assert r.headers["location"] == "/portal/app/explore"


ALL_LEGACY_PAGE_ROUTES = {
    "/dashboard": "/portal/app/",
    "/portal/ask": "/portal/app/steer",
    "/portal/findings": "/portal/app/findings",
    "/portal/approve": "/portal/app/approve",
    "/portal/timeline": "/portal/app/timeline",
    "/portal/evidence": "/portal/app/evidence",
    "/portal/iocs": "/portal/app/iocs",
    "/portal/todos": "/portal/app/todos",
    "/portal/steer": "/portal/app/steer",
    "/portal/query": "/portal/app/explore",
    "/portal/explore": "/portal/app/explore",
    "/portal/workbench": "/portal/app/workbench",
}


def test_every_legacy_page_url_redirects_to_the_spa():
    """WO-U7: every retired server-rendered page 302s to its SPA route."""
    app = Starlette(routes=create_dashboard())
    client = TestClient(app)
    for legacy, spa in ALL_LEGACY_PAGE_ROUTES.items():
        r = client.get(legacy, follow_redirects=False)
        assert r.status_code == 302, legacy
        assert r.headers["location"] == spa, legacy


def test_no_approval_ui_outside_the_spa():
    """WO-U7: no legacy page renders HTML approval UI any more — every page
    route is a redirect handler, so nothing HTML-bearing remains behind them."""
    routes = {r.path: r.endpoint for r in create_dashboard()}
    import asyncio

    for legacy, spa in ALL_LEGACY_PAGE_ROUTES.items():
        endpoint = routes[legacy]
        # a redirect handler serves each legacy page: calling it yields a 302
        response = asyncio.run(endpoint(type("R", (), {"path_params": {}})()))
        assert response.status_code == 302
        assert response.headers["location"] == spa
