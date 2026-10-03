"""MCP transport security helpers (DNS-rebinding Host allowlist).

FastMCP defaults ``host=127.0.0.1`` and then only allows localhost Host
headers. When we bind ``0.0.0.0`` for SIFT/lab clients, remote Host
values (e.g. ``192.168.77.135:4508``) return HTTP 421 Invalid Host header.

Wire ``create_server(host=...)`` + ``NEXUS_MCP_ALLOWED_HOSTS`` so lab
clients can reach ``/mcp`` without disabling DNS-rebinding protection.
"""

from __future__ import annotations

import hmac
import os
import socket
from collections.abc import Callable
from typing import Any, cast

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response


def _normalize_host_pattern(value: str) -> str:
    v = value.strip()
    if not v:
        return ""
    # Accept "host", "host:port", "host:*"
    if v.endswith(":*") or ":" in v.split("]")[-1]:
        # already has port or wildcard (or IPv6 bracket form)
        if v.endswith(":*") or v.count(":") == 1 or (v.startswith("[") and "]:*" in v):
            return v
        # host:4508 → keep exact; also add host:* via caller
        return v
    return f"{v}:*"


def detect_local_ipv4() -> list[str]:
    """Best-effort non-loopback IPv4 addresses for this host."""
    found: set[str] = set()
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            ip = info[4][0]
            if ip and not ip.startswith("127."):
                found.add(ip)
    except OSError:
        pass
    try:
        # Route trick: no packets sent
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            if ip and not ip.startswith("127."):
                found.add(ip)
        finally:
            s.close()
    except OSError:
        pass
    return sorted(found)


def build_allowed_hosts(
    bind_host: str = "127.0.0.1",
    extra: list[str] | None = None,
) -> list[str]:
    """Build Host allowlist for MCP DNS-rebinding protection."""
    hosts: list[str] = [
        "127.0.0.1:*",
        "localhost:*",
        "[::1]:*",
        "127.0.0.1",
        "localhost",
        "[::1]",
    ]
    env = os.environ.get("NEXUS_MCP_ALLOWED_HOSTS", "")
    for part in env.split(","):
        pat = _normalize_host_pattern(part)
        if pat:
            hosts.append(pat)
            # also bare host without port
            bare = part.strip().split(":")[0].strip("[]")
            if bare and bare not in hosts:
                hosts.append(bare)
    if extra:
        for part in extra:
            pat = _normalize_host_pattern(part)
            if pat:
                hosts.append(pat)
    if bind_host not in ("127.0.0.1", "localhost", "::1", "0.0.0.0", "::"):
        hosts.append(f"{bind_host}:*")
        hosts.append(bind_host)
    if bind_host in ("0.0.0.0", "::"):
        for ip in detect_local_ipv4():
            hosts.append(f"{ip}:*")
            hosts.append(ip)
    # de-dupe preserving order
    out: list[str] = []
    seen: set[str] = set()
    for h in hosts:
        if h not in seen:
            seen.add(h)
            out.append(h)
    return out


def build_allowed_origins(allowed_hosts: list[str]) -> list[str]:
    origins = [
        "http://127.0.0.1:*",
        "http://localhost:*",
        "http://[::1]:*",
    ]
    for h in allowed_hosts:
        base = h[:-2] if h.endswith(":*") else h.split(":")[0]
        if base.startswith("[") or base and base not in ("127.0.0.1", "localhost"):
            origins.append(f"http://{base}:*")
    out: list[str] = []
    seen: set[str] = set()
    for o in origins:
        if o not in seen:
            seen.add(o)
            out.append(o)
    return out


def build_transport_security(bind_host: str = "127.0.0.1") -> Any:
    """Return TransportSecuritySettings for FastMCP HTTP transport."""
    from mcp.server.transport_security import TransportSecuritySettings

    allowed_hosts = build_allowed_hosts(bind_host)
    return TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=allowed_hosts,
        allowed_origins=build_allowed_origins(allowed_hosts),
    )


# ---------------------------------------------------------------------------
# Bearer authentication for the MCP endpoint
# ---------------------------------------------------------------------------
#
# The MCP endpoint is a remote-execution surface: `run_command` (and the
# Windows `run_windows_command` on a Windows host) runs host binaries with the
# server's privileges. It used to be unauthenticated even when bound to a
# network address, while `Docs/SETUP.md` §6 told operators to "always configure
# a bearer token before exposing DFIR-Nexus over the network" — so the
# documented protection did not exist (register D28).
#
# `verify_bearer_token` (auth.py) had no callers and no middleware read an
# `Authorization` header. This is the missing enforcement: anything but a
# loopback bind requires a matching token on the MCP path, and a non-loopback
# bind without one fails closed at startup (`check_required_env`).

LOOPBACK_BINDS = frozenset({"127.0.0.1", "localhost", "::1"})


def is_remote_bind(host: str) -> bool:
    """True when the bind reaches beyond this machine (including `0.0.0.0`)."""
    return (host or "").strip() not in LOOPBACK_BINDS


def bearer_token() -> str:
    """The configured MCP bearer token, or "" when unset."""
    return os.environ.get("NEXUS_BEARER_TOKEN", "").strip()


class McpBearerAuthMiddleware(BaseHTTPMiddleware):
    """Require ``Authorization: Bearer <NEXUS_BEARER_TOKEN>`` on the MCP path.

    Scoped to the MCP endpoint on purpose: that is the execution surface. The
    portal keeps its own credentials (password + rate limit + security headers)
    and must stay reachable from a browser, which cannot send a bearer header on
    a navigation.

    Mounted only for a remote bind (see :func:`build_http_app`), so a loopback
    server behaves exactly as before.
    """

    def __init__(
        self,
        app: Callable[..., Any],
        *,
        token: str = "",
        path_prefix: str = "/mcp",
    ) -> None:
        super().__init__(app)
        self._token = (token or "").strip()
        self._path_prefix = path_prefix

    async def dispatch(self, request: Request, call_next: Callable[..., Any]) -> Response:
        if not request.url.path.startswith(self._path_prefix):
            return cast(Response, await call_next(request))
        presented = ""
        header = request.headers.get("authorization") or ""
        if header[:7].lower() == "bearer ":
            presented = header[7:].strip()
        # Fail closed: no configured token means no token can be accepted. A
        # remote bind without one is refused at startup; this covers a direct
        # app construction (tests, embedding) that skipped that check.
        if not self._token or not hmac.compare_digest(presented, self._token):
            return JSONResponse(
                {"error": "unauthorized", "detail": "missing or invalid bearer token"},
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"},
            )
        return cast(Response, await call_next(request))
