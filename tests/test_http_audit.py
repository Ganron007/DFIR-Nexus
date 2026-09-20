"""Phase 4k.3 — HTTP audit trail: middleware entries, redaction, log config."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.responses import JSONResponse
from starlette.routing import Route

from nexus.portal.http_audit import (
    HttpAuditMiddleware,
    http_log_config,
    redact_query,
)


async def _ok(request):
    # Real handlers (and MCP) read the body; do the same so the middleware's
    # pass-through capture sees it.
    await request.body()
    return JSONResponse({"ok": True})


def _app() -> Starlette:
    return Starlette(
        routes=[
            Route("/portal/api/test", _ok, methods=["GET", "POST"]),
            Route("/mcp", _ok, methods=["POST"]),
            Route("/other", _ok, methods=["GET"]),
        ],
        middleware=[Middleware(HttpAuditMiddleware)],
    )


async def _call(app, method: str, path: str, body: bytes = b"") -> list[dict]:
    qs = path.split("?", 1)[1].encode() if "?" in path else b""
    plain = path.split("?", 1)[0]
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": plain,
        "raw_path": plain.encode(),
        "query_string": qs,
        "headers": [(b"host", b"test")],
        "client": ("127.0.0.1", 12345),
        "server": ("test", 80),
    }
    messages = [{"type": "http.request", "body": body, "more_body": False}]
    sent: list[dict] = []

    async def receive():
        return messages.pop(0) if messages else {"type": "http.disconnect"}

    async def send(message):
        sent.append(message)

    await app(scope, receive, send)
    return sent


@pytest.fixture
def case_env(tmp_path, monkeypatch):
    from nexus.config import settings

    case_dir = tmp_path / "CASE-H"
    (case_dir / "audit").mkdir(parents=True)
    monkeypatch.setattr(settings, "cases_root", tmp_path, raising=False)
    monkeypatch.setenv("NEXUS_ACTIVE_CASE", "CASE-H")
    monkeypatch.delenv("NEXUS_HTTP_AUDIT", raising=False)
    monkeypatch.delenv("NEXUS_HTTP_AUDIT_GLOBAL", raising=False)
    return case_dir


def _entries(case_dir: Path) -> list[dict]:
    path = case_dir / "audit" / "http.jsonl"
    if not path.is_file():
        return []
    return [json.loads(ln) for ln in path.read_text(encoding="utf-8").splitlines() if ln]


@pytest.mark.asyncio
async def test_mutating_portal_request_is_audited(case_env):
    sent = await _call(_app(), "POST", "/portal/api/test?token=supersecret&q=sdelete")
    assert sent and sent[0]["status"] == 200
    rows = _entries(case_env)
    assert len(rows) == 1
    row = rows[0]
    assert row["tool"] == "http_request"
    assert row["params"]["method"] == "POST"
    assert row["params"]["status"] == 200
    assert "supersecret" not in json.dumps(row)
    assert "token=***" in row["params"]["query"]
    assert row["http_audit"] is True
    assert row["sha256"]


@pytest.mark.asyncio
async def test_read_request_skipped_unless_env(case_env, monkeypatch, tmp_path):
    # resolution via header on the second call (no env active-case dependency)
    plain = _app()
    await _call(plain, "GET", "/portal/api/test?case_id=CASE-H")
    assert _entries(case_env) == []

    monkeypatch.setenv("NEXUS_HTTP_AUDIT", "all")
    app2 = _app()
    await _call(app2, "GET", "/portal/api/test?case_id=CASE-H")
    assert len(_entries(case_env)) == 1


@pytest.mark.asyncio
async def test_non_portal_paths_are_not_audited(case_env):
    await _call(_app(), "POST", "/other")
    assert _entries(case_env) == []


@pytest.mark.asyncio
async def test_mcp_call_records_tool_name(case_env):
    body = json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "n4_query", "arguments": {}},
    }).encode()
    await _call(_app(), "POST", "/mcp", body)
    rows = _entries(case_env)
    assert len(rows) == 1
    assert rows[0]["tool"] == "mcp:tools/call:n4_query"


@pytest.mark.asyncio
async def test_no_case_no_global_chain_by_default(tmp_path, monkeypatch):
    from nexus.config import settings

    monkeypatch.setattr(settings, "cases_root", tmp_path, raising=False)
    monkeypatch.delenv("NEXUS_ACTIVE_CASE", raising=False)
    monkeypatch.delenv("NEXUS_HTTP_AUDIT_GLOBAL", raising=False)
    sent = await _call(_app(), "POST", "/portal/api/test")
    assert sent and sent[0]["status"] == 200


def test_redact_query_masks_secret_values():
    out = redact_query("case_id=CASE-1&api_key=abc123&q=hello")
    assert "abc123" not in out
    assert "api_key=***" in out
    assert "case_id=CASE-1" in out


def test_http_log_config_writes_file(tmp_path):
    import logging.config

    cfg = http_log_config(tmp_path)
    logging.config.dictConfig(cfg)
    logging.getLogger("uvicorn.access").info("test access line")
    logs = list(tmp_path.glob("nexus-http-*.log"))
    assert logs
    assert "test access line" in logs[0].read_text(encoding="utf-8")
