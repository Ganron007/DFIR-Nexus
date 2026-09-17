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
    monkeypatch.setattr(web, "_resolved_ips", lambda _host: ["93.184.216.34"])
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


def test_web_fetch_blocks_private_dns_and_resolution_failure(monkeypatch):
    monkeypatch.setenv("NEXUS_WEB_ALLOW", "1")
    monkeypatch.setattr(web, "_resolved_ips", lambda _host: ["127.0.0.1"])
    assert "blocked" in web.do_web_fetch("https://attacker.example/x")["error"]

    def failed(_host):
        raise OSError("dns failed")

    monkeypatch.setattr(web, "_resolved_ips", failed)
    assert "blocked" in web.do_web_fetch("https://missing.example/x")["error"]


def test_web_fetch_blocks_redirect_to_private_address(monkeypatch):
    monkeypatch.setenv("NEXUS_WEB_ALLOW", "1")
    monkeypatch.setattr(web, "_resolved_ips", lambda _host: ["93.184.216.34"])

    class Response:
        is_redirect = True
        headers = {"location": "http://169.254.169.254/latest/meta-data"}
        text = ""

        def raise_for_status(self):
            return None

    class Client:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def get(self, *_args, **_kwargs):
            return Response()

    monkeypatch.setattr(web.httpx, "Client", lambda **_kwargs: Client())
    result = web.do_web_fetch("https://public.example/start")
    assert "blocked" in result["error"]


def test_backbone_web_status_is_bound_and_audited(tmp_path, monkeypatch):
    from nexus.audit import AuditWriter
    from nexus.langgraph.backbone import backbone_call

    # The audit writer resolves the active case's audit dir — give it one.
    monkeypatch.setenv("NEXUS_CASES_ROOT", str(tmp_path / "cases"))
    monkeypatch.setenv("NEXUS_ACTIVE_CASE_FILE", str(tmp_path / "active_case"))
    case = tmp_path / "cases" / "CASE-WEBTEST"
    case.mkdir(parents=True)
    (tmp_path / "active_case").write_text(str(case), encoding="utf-8")

    monkeypatch.delenv("NEXUS_WEB_ALLOW", raising=False)
    result = backbone_call("web_status", audit=AuditWriter("nexus"))
    assert result["allowed"] is False
    assert result["provenance"]["audit_id"]
    assert (case / "audit" / "nexus.jsonl").is_file()
