"""Gated internet access — opt-in web_search / web_fetch MCP tools.

Offline-first by design: both tools refuse unless the examiner explicitly
sets ``NEXUS_WEB_ALLOW=1`` (OPSEC — investigations must not reach the
internet by default). web_fetch blocks loopback/private targets.

Results are external context, never case evidence (FD-001).
"""
from __future__ import annotations

import html
import ipaddress
import logging
import re
import socket
import urllib.parse
from typing import Any

import httpx
from mcp.server.fastmcp import FastMCP

from nexus.audit import AuditWriter

log = logging.getLogger(__name__)

_TIMEOUT = 15.0
_MAX_FETCH_CHARS = 20000
_TAG_RE = re.compile(r"<[^>]+>")
_DDG_LINK_RE = re.compile(
    r'<a[^>]+class="result__a"[^>]+href="([^"]+)"[^>]*>(.*?)</a>',
    re.IGNORECASE | re.DOTALL,
)
_DDG_SNIPPET_RE = re.compile(
    r'<a[^>]+class="result__snippet"[^>]*>(.*?)</a>', re.IGNORECASE | re.DOTALL
)
_LITE_LINK_RE = re.compile(
    r'<a[^>]+href="(https?://[^"]+)"[^>]*>(.*?)</a>', re.IGNORECASE | re.DOTALL
)


def web_allowed() -> bool:
    import os

    return os.environ.get("NEXUS_WEB_ALLOW", "").strip().lower() in ("1", "true", "yes")


def _audit_result(
    result: dict[str, Any], audit: AuditWriter | None, tool: str, params: dict[str, Any]
) -> dict[str, Any]:
    if audit is None:
        return result
    audit_id = audit.log(tool=tool, params=params, result_summary={
        "error": str(result.get("error") or "")[:200],
        "hits": len(result.get("hits") or []),
        "chars": len(str(result.get("text") or "")),
    })
    # Always carry the provenance key when an audit writer was supplied (the
    # id may be None if the case audit dir is unavailable) — matches the other
    # tool cores, so callers can rely on the shape.
    return {**result, "provenance": {"audit_id": audit_id}}


def do_web_status(audit: AuditWriter | None = None) -> dict[str, Any]:
    allowed = web_allowed()
    result = {
        "allowed": allowed,
        "note": (
            "enabled by NEXUS_WEB_ALLOW=1 — external context only, never evidence"
            if allowed
            else "disabled — set NEXUS_WEB_ALLOW=1 to enable (OPSEC opt-in)"
        ),
    }
    return _audit_result(result, audit, "web_status", {})


def _strip_tags(fragment: str) -> str:
    return html.unescape(_TAG_RE.sub(" ", fragment or "")).strip()


def _clean_ddg_url(url: str) -> str:
    """DuckDuckGo wraps links as //duckduckgo.com/l/?uddg=<encoded>."""
    if url.startswith("//"):
        url = "https:" + url
    parsed = urllib.parse.urlparse(url)
    if "duckduckgo.com" in parsed.netloc and parsed.path.startswith("/l/"):
        qs = urllib.parse.parse_qs(parsed.query)
        target = (qs.get("uddg") or [""])[0]
        if target:
            return urllib.parse.unquote(target)
    return url


def _resolved_ips(host: str) -> list[str]:
    return sorted({
        str(item[4][0]).split("%", 1)[0]
        for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        if item[4]
    })


def _is_blocked_host(host: str) -> bool:
    if not host:
        return True
    low = host.lower().strip(".")
    if low in ("localhost", "localhost.localdomain") or low.endswith(".local"):
        return True
    try:
        addresses = [low] if ipaddress.ip_address(low) else []
    except ValueError:
        try:
            addresses = _resolved_ips(low)
        except OSError:
            return True
    if not addresses:
        return True
    try:
        return any(not ipaddress.ip_address(value).is_global for value in addresses)
    except ValueError:
        return True


def _public_url_error(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return "only http(s) URLs are allowed"
    if parsed.username is not None or parsed.password is not None:
        return "URLs containing credentials are not allowed"
    if _is_blocked_host(parsed.hostname or ""):
        return "loopback/private/reserved addresses are blocked"
    return ""


def _http_get(url: str, *, params: dict[str, Any] | None = None) -> str:
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) DFIR-Nexus/2.0 "
            "(examiner-opt-in research)"
        )
    }
    current = url
    with httpx.Client(timeout=_TIMEOUT, follow_redirects=False, headers=headers) as client:
        for redirect in range(6):
            problem = _public_url_error(current)
            if problem:
                raise ValueError(problem)
            resp = client.get(current, params=params if redirect == 0 else None)
            if resp.is_redirect:
                location = resp.headers.get("location")
                if not location or redirect >= 5:
                    raise ValueError("too many or invalid redirects")
                current = urllib.parse.urljoin(current, location)
                continue
            resp.raise_for_status()
            return resp.text
    raise ValueError("too many redirects")


def do_web_search(
    query: str, max_results: int = 5, audit: AuditWriter | None = None
) -> dict[str, Any]:
    """DuckDuckGo lite search — returns [{title, url, snippet}]."""
    query = (query or "").strip()
    params = {"query": query[:200]}
    if not query:
        return _audit_result({"error": "query is required"}, audit, "web_search", params)
    if not web_allowed():
        return _audit_result({
            "error": "web access disabled — set NEXUS_WEB_ALLOW=1 to enable "
                     "(examiner opt-in; OPSEC)",
            "hits": [],
        }, audit, "web_search", params)
    try:
        body = _http_get("https://html.duckduckgo.com/html/", params={"q": query})
    except Exception as exc:  # noqa: BLE001
        return _audit_result(
            {"error": f"web search failed: {exc}", "hits": []},
            audit, "web_search", params,
        )
    limit = max(1, min(int(max_results or 5), 10))
    hits: list[dict[str, str]] = []
    snippets = [_strip_tags(s) for s in _DDG_SNIPPET_RE.findall(body)]
    for i, (url, title) in enumerate(_DDG_LINK_RE.findall(body)):
        if len(hits) >= limit:
            break
        clean = _clean_ddg_url(html.unescape(url))
        if not clean.startswith("http"):
            continue
        snippet = snippets[i] if i < len(snippets) else ""
        hits.append({
            "title": _strip_tags(title)[:200],
            "url": clean[:300],
            "snippet": snippet[:400],
        })
    if not hits:
        # Fallback: lite endpoint shape
        for url, title in _LITE_LINK_RE.findall(body):
            if len(hits) >= limit:
                break
            if "duckduckgo.com" in url:
                continue
            hits.append({"title": _strip_tags(title)[:200], "url": url[:300], "snippet": ""})
    result = {"query": query, "hits": hits, "note": "external context — never evidence (FD-001)"}
    return _audit_result(result, audit, "web_search", params)


def do_web_fetch(
    url: str, max_chars: int = 4000, audit: AuditWriter | None = None
) -> dict[str, Any]:
    """Fetch a URL and return readable text (loopback/private blocked)."""
    raw = (url or "").strip()
    params = {"url": raw[:200]}
    if not raw:
        return _audit_result({"error": "url is required"}, audit, "web_fetch", params)
    if not web_allowed():
        return _audit_result({
            "error": "web access disabled — set NEXUS_WEB_ALLOW=1 to enable "
                     "(examiner opt-in; OPSEC)",
        }, audit, "web_fetch", params)
    problem = _public_url_error(raw)
    if problem:
        return _audit_result({"error": problem}, audit, "web_fetch", params)
    try:
        body = _http_get(raw)
    except Exception as exc:  # noqa: BLE001
        return _audit_result(
            {"error": f"fetch failed: {exc}"}, audit, "web_fetch", params,
        )
    text = _strip_tags(body)
    text = re.sub(r"\s+", " ", text).strip()
    limit = max(500, min(int(max_chars or 4000), _MAX_FETCH_CHARS))
    result = {
        "url": raw,
        "text": text[:limit],
        "truncated": len(text) > limit,
        "note": "external context — never evidence (FD-001)",
    }
    return _audit_result(result, audit, "web_fetch", params)


def register_tools(server: FastMCP, audit: AuditWriter) -> None:
    @server.tool()
    def web_status() -> dict:
        """Whether examiner-opt-in web access is enabled (NEXUS_WEB_ALLOW)."""
        return do_web_status(audit=audit)

    @server.tool()
    def web_search(query: str, max_results: int = 5) -> dict:
        """Search the web (DuckDuckGo) for external context — opt-in only.

        Blocked unless NEXUS_WEB_ALLOW=1. Use for tool/technique/software
        research the examiner explicitly asked about; results are context,
        never case evidence.
        """
        return do_web_search(query, max_results=max_results, audit=audit)

    @server.tool()
    def web_fetch(url: str, max_chars: int = 4000) -> dict:
        """Fetch a URL as text — opt-in only (NEXUS_WEB_ALLOW=1)."""
        return do_web_fetch(url, max_chars=max_chars, audit=audit)
