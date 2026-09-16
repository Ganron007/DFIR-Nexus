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


def _http_get(url: str, *, params: dict[str, Any] | None = None) -> str:
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) DFIR-Nexus/2.0 "
            "(examiner-opt-in research)"
        )
    }
    with httpx.Client(timeout=_TIMEOUT, follow_redirects=True, headers=headers) as client:
        resp = client.get(url, params=params)
        resp.raise_for_status()
        return resp.text


def do_web_search(query: str, max_results: int = 5) -> dict[str, Any]:
    """DuckDuckGo lite search — returns [{title, url, snippet}]."""
    query = (query or "").strip()
    if not query:
        return {"error": "query is required"}
    if not web_allowed():
        return {
            "error": "web access disabled — set NEXUS_WEB_ALLOW=1 to enable "
                     "(examiner opt-in; OPSEC)",
            "hits": [],
        }
    try:
        body = _http_get("https://html.duckduckgo.com/html/", params={"q": query})
    except Exception as exc:  # noqa: BLE001
        return {"error": f"web search failed: {exc}", "hits": []}
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
    return {"query": query, "hits": hits, "note": "external context — never evidence (FD-001)"}


def _is_blocked_host(host: str) -> bool:
    if not host:
        return True
    low = host.lower().strip(".")
    if low in ("localhost", "localhost.localdomain") or low.endswith(".local"):
        return True
    try:
        ip = ipaddress.ip_address(low)
    except ValueError:
        return False  # hostname — allow (DNS rebinding out of scope here)
    return not ip.is_global


def do_web_fetch(url: str, max_chars: int = 4000) -> dict[str, Any]:
    """Fetch a URL and return readable text (loopback/private blocked)."""
    raw = (url or "").strip()
    if not raw:
        return {"error": "url is required"}
    if not web_allowed():
        return {
            "error": "web access disabled — set NEXUS_WEB_ALLOW=1 to enable "
                     "(examiner opt-in; OPSEC)",
        }
    parsed = urllib.parse.urlparse(raw)
    if parsed.scheme not in ("http", "https"):
        return {"error": "only http(s) URLs are allowed"}
    if _is_blocked_host(parsed.hostname or ""):
        return {"error": "loopback/private addresses are blocked"}
    try:
        body = _http_get(raw)
    except Exception as exc:  # noqa: BLE001
        return {"error": f"fetch failed: {exc}"}
    text = _strip_tags(body)
    text = re.sub(r"\s+", " ", text).strip()
    limit = max(500, min(int(max_chars or 4000), _MAX_FETCH_CHARS))
    return {
        "url": raw,
        "text": text[:limit],
        "truncated": len(text) > limit,
        "note": "external context — never evidence (FD-001)",
    }


def register_tools(server: FastMCP, audit: AuditWriter) -> None:
    @server.tool()
    def web_status() -> dict:
        """Whether examiner-opt-in web access is enabled (NEXUS_WEB_ALLOW)."""
        return {
            "allowed": web_allowed(),
            "note": (
                "enabled by NEXUS_WEB_ALLOW=1 — external context only, never evidence"
                if web_allowed()
                else "disabled — set NEXUS_WEB_ALLOW=1 to enable (OPSEC opt-in)"
            ),
        }

    @server.tool()
    def web_search(query: str, max_results: int = 5) -> dict:
        """Search the web (DuckDuckGo) for external context — opt-in only.

        Blocked unless NEXUS_WEB_ALLOW=1. Use for tool/technique/software
        research the examiner explicitly asked about; results are context,
        never case evidence.
        """
        result = do_web_search(query, max_results=max_results)
        audit.log(tool="web_search", params={"query": query[:200]},
                  result_summary={"hits": len(result.get("hits") or [])})
        return result

    @server.tool()
    def web_fetch(url: str, max_chars: int = 4000) -> dict:
        """Fetch a URL as text — opt-in only (NEXUS_WEB_ALLOW=1)."""
        result = do_web_fetch(url, max_chars=max_chars)
        audit.log(tool="web_fetch", params={"url": url[:200]},
                  result_summary={"chars": len(str(result.get("text") or ""))})
        return result
