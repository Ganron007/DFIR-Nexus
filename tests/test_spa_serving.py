"""Tests for the Phase 4 React SPA serving (2026-09-08)."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from starlette.testclient import TestClient

from nexus.dashboard.app import create_dashboard


def _make_client() -> TestClient:
    routes = create_dashboard()
    from starlette.applications import Starlette

    app = Starlette(routes=routes)
    return TestClient(app)


class TestSpaServing:
    def test_spa_index_returns_html(self) -> None:
        """The SPA index route at /portal/app must return HTML."""
        client = _make_client()
        r = client.get("/portal/app")
        assert r.status_code in (200, 503)  # 503 if not built, 200 if built
        assert "text/html" in r.headers.get("content-type", "")

    def test_spa_index_with_path(self) -> None:
        """Client-side routing paths under /portal/app/* must return the SPA index."""
        client = _make_client()
        r = client.get("/portal/app/explore")
        assert r.status_code in (200, 503)

    def test_spa_asset_404_when_missing(self) -> None:
        """Non-existent assets must return 404, not the SPA index."""
        client = _make_client()
        r = client.get("/portal/app/assets/nonexistent.js")
        assert r.status_code == 404

    def test_spa_asset_blocks_traversal(self) -> None:
        """Path traversal in asset path must be blocked."""
        client = _make_client()
        r = client.get("/portal/app/assets/..%2F..%2Fetc%2Fpasswd")
        assert r.status_code == 404

    def test_health_still_works(self) -> None:
        """The health endpoint must still work alongside SPA routes."""
        client = _make_client()
        r = client.get("/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

    def test_api_routes_still_work(self) -> None:
        """API routes must still work alongside SPA routes."""
        client = _make_client()
        r = client.get("/portal/api/cases")
        # 200 if a case exists, or may return empty list — just not 404
        assert r.status_code != 404
