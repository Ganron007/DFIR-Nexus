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

    def test_health_route_ok(self):
        from starlette.testclient import TestClient

        from nexus.app import create_server
        from nexus.cli.main import build_http_app

        app = build_http_app(create_server())
        with TestClient(app) as client:
            resp = client.get("/health")
            assert resp.status_code == 200
            body = resp.json()
            assert body["status"] == "ok"
            assert body["service"] == "dfir-nexus"

    def test_official_mcp_client_handshake(self):
        """Official MCP SDK ClientSession initialize + tools/list against /mcp."""
        import asyncio
        import socket
        import threading
        import time

        import httpx
        import pytest

        pytest.importorskip("uvicorn")
        uvicorn = pytest.importorskip("uvicorn")
        from mcp.client.session import ClientSession
        from mcp.client.streamable_http import streamable_http_client

        from nexus.app import create_server
        from nexus.cli.main import build_http_app

        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()

        asgi = build_http_app(create_server(host="127.0.0.1"), host="127.0.0.1", port=port)
        config = uvicorn.Config(asgi, host="127.0.0.1", port=port, log_level="warning")
        uv = uvicorn.Server(config)
        thread = threading.Thread(target=uv.run, daemon=True)
        thread.start()
        try:
            deadline = time.time() + 45
            while time.time() < deadline:
                if uv.started:
                    try:
                        r = httpx.get(f"http://127.0.0.1:{port}/health", timeout=1.0)
                        if r.status_code == 200:
                            break
                    except httpx.HTTPError:
                        pass
                time.sleep(0.2)
            else:
                pytest.fail("HTTP server did not become ready for MCP handshake")

            async def _handshake() -> int:
                url = f"http://127.0.0.1:{port}/mcp"
                async with streamable_http_client(url) as streams:
                    read, write = streams[0], streams[1]
                    async with ClientSession(read, write) as session:
                        result = await session.initialize()
                        assert result.serverInfo.name == "dfir-nexus"
                        listed = await session.list_tools()
                        return len(listed.tools)

            n = asyncio.run(_handshake())
            assert n > 0
        finally:
            uv.should_exit = True
            thread.join(timeout=15)

    def test_portal_still_served(self):
        from starlette.testclient import TestClient

        from nexus.app import create_server
        from nexus.cli.main import build_http_app

        app = build_http_app(create_server())
        with TestClient(app) as client:
            resp = client.get("/portal/")
            assert resp.status_code == 200
