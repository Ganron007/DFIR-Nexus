"""D201: OTX pulses mention an indicator; they are not a verdict. OTX's allowlist is one.

Live on 2026-10-15: poshcode.org had 7 pulses, all automated feeds naming it as a related domain
("VirusTotal report for msoidcliL.dll", a filescan.io feed), and no allowlist entry; the case's
threat-intel context reported it MALICIOUS. github.com returned 0 pulses and five allowlist
entries (Akamai, Alexa, Majestic, whitelist, known false positive).
"""
from __future__ import annotations

import asyncio

import httpx

from nexus.ti.providers import optional

POSHCODE = {"indicator": "poshcode.org", "validation": [], "false_positive": [],
            "pulse_info": {"count": 7, "pulses": [{"name": "www.filescan.io feed 6/6/25"},
                                                  {"name": "VirusTotal report for msoidcliL.dll"}]}}
GITHUB = {"indicator": "github.com", "pulse_info": {"count": 0, "pulses": []},
          "validation": [{"source": "alexa", "message": "Alexa rank: #87", "name": "Listed on Alexa"},
                         {"source": "whitelist", "message": "Whitelisted domain github.com",
                          "name": "Whitelisted domain"}],
          "false_positive": [{"assessment": "accepted", "assessment_date": "2021-05-19T15:36:56"}]}


def _otx(monkeypatch, answer: dict):
    class _Resp:
        def raise_for_status(self):
            return None

        def json(self):
            return answer

    class _Client:
        def __init__(self, *a, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def get(self, url, headers=None):
            return _Resp()

    monkeypatch.setenv(optional.ENV_OTX_API_KEY, "k")
    monkeypatch.setattr(httpx, "AsyncClient", _Client)
    return asyncio.run(optional.query_otx(answer["indicator"], mock=False, ioc_type="domain"))


def test_pulses_are_context_not_a_verdict(monkeypatch):
    result = _otx(monkeypatch, POSHCODE)
    assert result.malicious is None
    assert result.summary == "OTX: 7 pulse(s) mention it (context, not a verdict)"


def test_an_otx_allowlist_says_not_malicious(monkeypatch):
    result = _otx(monkeypatch, GITHUB)
    assert result.malicious is False
    assert result.summary.startswith("OTX: allowlisted (Listed on Alexa, Whitelisted domain, "
                                     "accepted false positive)")
