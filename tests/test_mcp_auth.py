"""Register D28 — the MCP endpoint must actually require its bearer token.

`verify_bearer_token` (auth.py) had no callers and no middleware read an
`Authorization` header, so `NEXUS_BEARER_TOKEN` was documented in SETUP §6 as
required protection while enforcing nothing. Measured before the fix: the SIFT
MCP on `0.0.0.0:4508` returned 132 tools and executed `id -un` both with no
header and with a bogus token.

The endpoint is a remote-execution surface (`run_command` runs host binaries),
so a bind that reaches beyond this machine now requires a matching token, and a
remote bind with no token refuses to start.
"""
from __future__ import annotations

import pytest
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from nexus.mcp_security import (
    McpBearerAuthMiddleware,
    bearer_token,
    is_remote_bind,
)
from nexus.utils.constants import (
    REQUIRED_FOR_PROD,
    MissingProductionEnvError,
    check_required_env,
)

TOKEN = "test-token-0123456789abcdef"


def _app(token: str = TOKEN) -> Starlette:
    """A minimal app with the middleware and an MCP-like path plus a portal path."""

    async def mcp(_request):
        return JSONResponse({"ok": True})

    async def portal(_request):
        return JSONResponse({"ok": True})

    return Starlette(
        routes=[
            Route("/mcp", mcp, methods=["GET", "POST"]),
            Route("/portal/api/summary", portal, methods=["GET", "POST"]),
        ],
        # The same wiring production uses: Middleware(Cls, **kwargs), not a
        # bare instance (Starlette instantiates with `app` itself).
        middleware=[Middleware(McpBearerAuthMiddleware, token=token, path_prefix="/mcp")],
    )


def test_the_mcp_path_refuses_a_missing_or_wrong_token():
    client = TestClient(_app())
    assert client.post("/mcp").status_code == 401
    assert client.post("/mcp", headers={"Authorization": "Bearer nope"}).status_code == 401
    # A malformed header is not a token.
    assert client.post("/mcp", headers={"Authorization": TOKEN}).status_code == 401
    assert client.post("/mcp", headers={"Authorization": "Basic cmVhbA=="}).status_code == 401


def test_the_mcp_path_accepts_the_configured_token():
    client = TestClient(_app())
    ok = client.post("/mcp", headers={"Authorization": f"Bearer {TOKEN}"})
    assert ok.status_code == 200, ok.text
    # Case-insensitive scheme, which is what RFC 7235 requires.
    lower = client.post("/mcp", headers={"Authorization": f"bearer {TOKEN}"})
    assert lower.status_code == 200, lower.text


def test_the_portal_is_not_gated_by_the_mcp_token():
    """The portal keeps its own credentials and must stay browsable."""
    client = TestClient(_app())
    assert client.get("/portal/api/summary").status_code == 200


def test_the_middleware_fails_closed_when_no_token_is_configured():
    """No token configured means no token can be accepted.

    A remote bind without a token is refused at startup; this covers a direct
    app construction that skipped that check.
    """
    client = TestClient(_app(token=""))
    assert client.post("/mcp").status_code == 401
    assert client.post("/mcp", headers={"Authorization": "Bearer "}).status_code == 401


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "::1"])
def test_loopback_is_not_remote(host):
    assert is_remote_bind(host) is False


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "192.168.77.135", "10.0.0.5"])
def test_anything_else_is_remote(host):
    assert is_remote_bind(host) is True


def test_a_remote_bind_without_a_token_refuses_to_start(monkeypatch):
    """Fail closed: refuse rather than expose an unauthenticated execution surface."""
    for name in REQUIRED_FOR_PROD:
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(MissingProductionEnvError) as exc:
        check_required_env(host="0.0.0.0", port=4508)
    assert "NEXUS_BEARER_TOKEN" in str(exc.value)

    # With every required var set, it starts.
    for name in REQUIRED_FOR_PROD:
        monkeypatch.setenv(name, "x")
    assert check_required_env(host="0.0.0.0", port=4508) == []


def test_a_loopback_bind_only_warns(monkeypatch):
    for name in REQUIRED_FOR_PROD:
        monkeypatch.delenv(name, raising=False)
    missing = check_required_env(host="127.0.0.1", port=4508)
    assert "NEXUS_BEARER_TOKEN" in missing  # reported, not fatal
    assert missing == list(REQUIRED_FOR_PROD)


def test_bearer_token_reads_the_env(monkeypatch):
    monkeypatch.setenv("NEXUS_BEARER_TOKEN", "  spaced-token  ")
    assert bearer_token() == "spaced-token", "surrounding whitespace must not matter"
    monkeypatch.delenv("NEXUS_BEARER_TOKEN", raising=False)
    assert bearer_token() == ""
