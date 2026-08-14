"""MCP transport security helpers (DNS-rebinding Host allowlist).

FastMCP defaults ``host=127.0.0.1`` and then only allows localhost Host
headers. When we bind ``0.0.0.0`` for SIFT/lab clients, remote Host
values (e.g. ``192.168.77.135:4508``) return HTTP 421 Invalid Host header.

Wire ``create_server(host=...)`` + ``NEXUS_MCP_ALLOWED_HOSTS`` so lab
clients can reach ``/mcp`` without disabling DNS-rebinding protection.
"""

from __future__ import annotations

import os
import socket
from typing import Any


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
