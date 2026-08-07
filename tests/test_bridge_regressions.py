"""Regression tests for the B4 (case-state bridge) and B5 (MCP HTTP mount) fixes."""

from __future__ import annotations

import json

import pytest

from nexus.case import get_sqlite_manager
from nexus.case.manager import materialize_case_dir
from nexus.config import settings


@pytest.fixture()
def cases_root(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "cases_root", tmp_path / "cases")
    return settings.cases_root


class TestB4CaseBridge:
    def test_create_case_materializes_dir_and_yaml(self, cases_root):
        mgr = get_sqlite_manager(cases_root / "cases.db")
        case = mgr.create_case(name="bridge", created_by="tester")
        case_dir = cases_root / case.id
        assert case_dir.is_dir()
        meta = (case_dir / "CASE.yaml").read_text(encoding="utf-8")
        assert case.id in meta
        assert "name: bridge" in meta
        mgr.close()

    def test_create_case_honors_custom_id(self, cases_root):
        mgr = get_sqlite_manager(cases_root / "cases.db")
        case = mgr.create_case(name="custom", case_id="CUSTOM-001")
        assert case.id == "CUSTOM-001"
        assert (cases_root / "CUSTOM-001" / "CASE.yaml").exists()
        mgr.close()

    def test_create_case_rejects_duplicate_id(self, cases_root):
        mgr = get_sqlite_manager(cases_root / "cases.db")
        mgr.create_case(name="first", case_id="DUP-001")
        with pytest.raises(ValueError):
            mgr.create_case(name="second", case_id="DUP-001")
        mgr.close()

    def test_create_case_rejects_traversal_id(self, cases_root):
        mgr = get_sqlite_manager(cases_root / "cases.db")
        with pytest.raises(ValueError):
            mgr.create_case(name="evil", case_id="../evil")
        mgr.close()

    def test_close_case_syncs_yaml_status(self, cases_root):
        mgr = get_sqlite_manager(cases_root / "cases.db")
        case = mgr.create_case(name="closer", case_id="CLOSE-001")
        mgr.close_case(case.id, closed_by="tester")
        meta = (cases_root / "CLOSE-001" / "CASE.yaml").read_text(encoding="utf-8")
        assert "status: closed" in meta
        mgr.close()

    def test_materialize_is_idempotent(self, cases_root):
        mgr = get_sqlite_manager(cases_root / "cases.db")
        case = mgr.create_case(name="idem", case_id="IDEM-001")
        materialize_case_dir(case)
        materialize_case_dir(case)
        assert (cases_root / "IDEM-001" / "CASE.yaml").exists()
        mgr.close()


class TestB5HttpMount:
    def test_mcp_initialize_at_mcp_path(self):
        from starlette.testclient import TestClient

        from nexus.app import create_server
        from nexus.cli.main import build_http_app

        app = build_http_app(create_server())
        with TestClient(app) as client:
            resp = client.post(
                "/mcp",
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {},
                        "clientInfo": {"name": "regression", "version": "1.0"},
                    },
                },
                headers={
                    "Accept": "application/json, text/event-stream",
                    # mcp SDK DNS-rebinding protection allows loopback with
                    # wildcard port only ("127.0.0.1:*"); bare host or
                    # TestClient's "testserver" are rejected with 421.
                    "Host": "127.0.0.1:4508",
                },
            )
            assert resp.status_code == 200, resp.text[:300]
            body = resp.text
            if body.startswith("event:") or "data:" in body[:20]:
                payload = json.loads(
                    next(ln for ln in body.splitlines() if ln.startswith("data:"))[5:].strip()
                )
            else:
                payload = resp.json()
            assert payload["result"]["serverInfo"]["name"] == "dfir-nexus"

    def test_portal_still_served(self):
        from starlette.testclient import TestClient

        from nexus.app import create_server
        from nexus.cli.main import build_http_app

        app = build_http_app(create_server())
        with TestClient(app) as client:
            resp = client.get("/portal/")
            assert resp.status_code == 200
