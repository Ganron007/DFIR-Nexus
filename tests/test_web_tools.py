"""Web tools — examiner opt-in gating + parsing (no live network)."""
from __future__ import annotations

from nexus.tools import web


def test_web_disabled_by_default(monkeypatch):
    monkeypatch.delenv("NEXUS_WEB_ALLOW", raising=False)
    res = web.do_web_search("mimikatz")
    assert "disabled" in res["error"]
    assert web.do_web_fetch("https://example.com")["error"]


def test_web_search_parses_ddg(monkeypatch):
    monkeypatch.setenv("NEXUS_WEB_ALLOW", "1")
    html = """
    <div class="result">
      <a rel="nofollow" class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Fmimikatz">Mimikatz overview</a>
      <a class="result__snippet">A tool that extracts credentials from memory.</a>
    </div>
    """
    monkeypatch.setattr(web, "_http_get", lambda url, params=None: html)
    res = web.do_web_search("mimikatz", max_results=3)
    assert res["hits"], res
    assert res["hits"][0]["url"] == "https://example.com/mimikatz"
    assert "Mimikatz" in res["hits"][0]["title"]
    assert "credentials" in res["hits"][0]["snippet"]


def test_web_fetch_strips_tags_and_blocks_private(monkeypatch):
    monkeypatch.setenv("NEXUS_WEB_ALLOW", "1")
    monkeypatch.setattr(web, "_http_get", lambda url, params=None: "<h1>Title</h1><p>Body text</p>")
    ok = web.do_web_fetch("https://example.com/page")
    assert "Title" in ok["text"] and "Body text" in ok["text"]
    assert web.do_web_fetch("http://127.0.0.1:4508/portal")["error"]
    assert web.do_web_fetch("http://localhost/x")["error"]
    assert web.do_web_fetch("ftp://example.com/x")["error"]


def test_web_status(monkeypatch):
    monkeypatch.delenv("NEXUS_WEB_ALLOW", raising=False)
    assert web.web_allowed() is False
    monkeypatch.setenv("NEXUS_WEB_ALLOW", "1")
    assert web.web_allowed() is True
