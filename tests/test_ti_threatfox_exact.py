"""D200: a ThreatFox verdict needs an IOC that IS the value; search_ioc is a substring search.

Live on 2026-10-15, search_ioc for "github.com" returned 11 IOCs, every one a URL hosted on GitHub
and none the domain. Each counted as a hit, so CASE-C5B04D31's threat-intel context told every
mode that github.com is MALICIOUS (payload_delivery / win.overlord).
"""
from __future__ import annotations

import asyncio

from nexus.ti.providers import abuse_ch

GITHUB_URLS = {"query_status": "ok", "data": [
    {"ioc": "https://github.com/mariaaefyw/fileserver/releases/download/v1005/fileserver-update.dat",
     "ioc_type": "url", "threat_type": "payload_delivery", "malware": "win.overlord"},
    {"ioc": "https://github.com/Siphodhl1980/nbew/releases/download/new/main.exe",
     "ioc_type": "url", "threat_type": "payload_delivery", "malware": "unknown_stealer"},
]}


def _query(monkeypatch, value: str, response: dict):
    async def fake_post(url, payload, api_key):
        assert payload == {"query": "search_ioc", "search_term": value}
        return response

    monkeypatch.setattr(abuse_ch, "_post_json", fake_post)
    return asyncio.run(abuse_ch.query_threatfox(value, mock=False, api_key="k"))


def test_iocs_that_only_contain_the_value_are_context_not_a_verdict(monkeypatch):
    result = _query(monkeypatch, "github.com", GITHUB_URLS)
    assert result.malicious is None
    assert result.confidence == 0.0
    assert "no IOC is this value; 2 IOC(s) contain it" in result.summary
    assert result.tags == []


def test_an_ioc_that_is_the_value_is_a_verdict(monkeypatch):
    listed = {"query_status": "ok", "data": [
        {"ioc": "evil-c2.example", "ioc_type": "domain", "threat_type": "botnet_cc",
         "malware": "win.cobalt_strike"},
        *GITHUB_URLS["data"],
    ]}
    result = _query(monkeypatch, "EVIL-C2.example", listed)
    assert result.malicious is True
    assert result.summary == "ThreatFox: botnet_cc / win.cobalt_strike"
    assert result.tags == ["win.cobalt_strike"]


def test_an_ip_port_ioc_is_its_address():
    assert abuse_ch._same_ioc("203.0.113.7:443", "203.0.113.7")
    assert not abuse_ch._same_ioc("203.0.113.70:443", "203.0.113.7")
    assert not abuse_ch._same_ioc("https://203.0.113.7/x", "203.0.113.7")
