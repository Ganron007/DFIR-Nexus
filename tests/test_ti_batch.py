"""D452: TI failures retain their reason before any concurrent batching change."""
from __future__ import annotations

import asyncio

import httpx
import pytest

from nexus.ti import router as ti_router
from nexus.ti.schemas import IOCType, ProviderMode


@pytest.mark.asyncio
async def test_empty_provider_timeout_keeps_its_exception_reason(monkeypatch):
    router = ti_router.TIRouter(force_mock=False)
    monkeypatch.setattr(router, "_provider_mode", lambda _: ProviderMode.LIVE)

    async def timeout(*args, **kwargs):
        request = httpx.Request("GET", "https://otx.alienvault.com/api/v1/indicators/IPv4/8.8.8.8/general")
        raise httpx.ReadTimeout("", request=request)

    monkeypatch.setattr(ti_router.optional, "query_otx", timeout)
    result = await router._dispatch("otx", "8.8.8.8", IOCType.IP)
    assert result.status == "error"
    assert result.error
    assert "ReadTimeout" in result.error
    assert result.provider == "otx"
    assert result.value == "8.8.8.8"


def test_enrichment_batches_all_iocs_concurrently_and_preserves_output_order(monkeypatch):
    from nexus.langgraph import ti_context

    router = ti_router.TIRouter(force_mock=True)
    values = [f"ioc-{index}.example.org" for index in range(20)]
    active = 0
    peak = 0
    seen = []

    async def lookup(value):
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        seen.append(value)
        try:
            await asyncio.sleep(0.001 * (4 - int(value.split("-")[1].split(".")[0]) % 4))
            return {"value": value, "providers_queried": ["otx"], "results": []}
        finally:
            active -= 1

    monkeypatch.setattr(router, "lookup", lookup)
    monkeypatch.setattr("nexus.ti.create_default_router", lambda: router)
    result = ti_context.enrich_iocs(values)
    assert [item["value"] for item in result] == values
    assert sorted(seen) == sorted(values)
    assert all(item["providers_queried"] == ["otx"] for item in result)
    assert 1 < peak <= 4, "one bounded batch must overlap IOCs without spawning unbounded tasks"


def test_written_ti_context_keeps_each_provider_failure_reason(tmp_path):
    from nexus.langgraph.ti_context import render_ti_markdown, write_ti_context

    failures = [
        {"provider": "otx", "status": "error", "error": "ReadTimeout: no exception message supplied"},
        {"provider": "shodan", "status": "error", "error": "HTTPStatusError: 429 Too Many Requests"},
    ]
    selection = {"leads": 1, "lead_rows": 1, "rows_found": 1, "iocs": {"ipv4": ["8.8.8.8"]}, "sources": {}}
    results = [{"value": "8.8.8.8", "ioc_type": "ip", "malicious_count": 0,
                "providers_queried": ["otx", "shodan"], "results": failures}]
    context = {"markdown": render_ti_markdown(selection, {}, results)}
    path = write_ti_context(tmp_path, context)
    assert path
    written = path.read_text(encoding="utf-8")
    for failure in failures:
        assert failure["provider"] in written
        assert failure["error"] in written


@pytest.mark.asyncio
async def test_undocumented_provider_retries_once_for_header_within_timeout(monkeypatch):
    from nexus.ti import scheduling
    from nexus.ti.schemas import TIResult

    scheduling._pacing.clear()
    now = [0.0]
    sleeps = []
    calls = []
    monkeypatch.setattr(scheduling.time, "monotonic", lambda: now[0])

    async def sleep(delay):
        sleeps.append(delay)
        now[0] += delay

    monkeypatch.setattr(scheduling.asyncio, "sleep", sleep)

    async def request():
        calls.append(now[0])
        return TIResult(provider="urlhaus", ioc_type="url", value="https://example.org/",
                        status="error", error="HTTPStatusError: 503 Service Unavailable",
                        raw={"nexus_failure": {"http_status": 503, "retry_after": "2"}})

    result = await scheduling.run_provider_lookup("urlhaus", "unit-account", request, lambda exc: None)
    assert calls == [0.0, 2.0]
    assert sleeps == [2.0]
    assert result.status == "error"
    failures = result.raw["nexus_attempt_failures"]
    assert len(failures) == 2
    assert all(f["provider"] == "urlhaus" and f["ioc"] == "https://example.org/" for f in failures)
    assert all(f["http_status"] == 503 and f["retry_after"] == "2" and f["reason"] for f in failures)


@pytest.mark.parametrize("header", [None, "invalid", "31"])
@pytest.mark.asyncio
async def test_undocumented_provider_never_invents_delay_or_extends_timeout(monkeypatch, header):
    from nexus.ti import scheduling
    from nexus.ti.constants import TI_LOOKUP_TIMEOUT_SECONDS
    from nexus.ti.schemas import TIResult

    assert TI_LOOKUP_TIMEOUT_SECONDS == 30.0
    scheduling._pacing.clear()
    now = [0.0]
    calls = []
    sleeps = []
    monkeypatch.setattr(scheduling.time, "monotonic", lambda: now[0])

    async def sleep(delay):
        sleeps.append(delay)
        now[0] += delay

    monkeypatch.setattr(scheduling.asyncio, "sleep", sleep)

    async def request():
        calls.append(now[0])
        return TIResult(provider="yaraify", ioc_type="hash", value="a" * 64,
                        status="error", error="HTTPStatusError: 429 Too Many Requests",
                        raw={"nexus_failure": {"http_status": 429, "retry_after": header}})

    result = await scheduling.run_provider_lookup("yaraify", "unit-account", request, lambda exc: None)
    assert calls == [0.0]
    assert sleeps == []
    assert result.status == "error"
    failure = result.raw["nexus_attempt_failures"][0]
    assert failure["provider"] == "yaraify"
    assert failure["ioc"] == "a" * 64
    assert failure["http_status"] == 429
    assert failure["retry_after"] == header
    assert failure["reason"]


@pytest.mark.asyncio
async def test_batched_lookup_preserves_router_provider_selection_and_ioc_order(monkeypatch):
    from nexus.ti.schemas import TIResult

    router = ti_router.TIRouter(force_mock=False)
    live = {"threatfox", "malware_bazaar", "urlhaus", "yaraify", "otx", "shodan"}
    monkeypatch.setattr(router, "_provider_mode", lambda name: ProviderMode.LIVE if name in live else ProviderMode.UNCONFIGURED)

    async def dispatch(provider, value, ioc_type):
        return TIResult(provider=provider, ioc_type=ioc_type.value, value=value, status="ok")

    monkeypatch.setattr(router, "_dispatch", dispatch)
    values = ["a" * 64, "8.8.8.8", "example.org", "https://example.org/", "8.8.8.8"]
    baseline = [await router.lookup(value) for value in values]
    actual = await router.lookup_many(values)
    assert [(r["value"], r["providers_queried"]) for r in actual] == [
        (r["value"], r["providers_queried"]) for r in baseline
    ]
    assert all(len(r["results"]) == len(r["providers_queried"]) for r in actual)


@pytest.mark.asyncio
async def test_undocumented_providers_are_single_flight_independently():
    from nexus.ti import scheduling
    from nexus.ti.schemas import TIResult

    scheduling._pacing.clear()
    active = {"urlhaus": 0, "yaraify": 0}
    peak = {"urlhaus": 0, "yaraify": 0}
    combined_peak = 0

    async def lookup(provider, value):
        async def request():
            nonlocal combined_peak
            active[provider] += 1
            peak[provider] = max(peak[provider], active[provider])
            combined_peak = max(combined_peak, sum(active.values()))
            try:
                await asyncio.sleep(0.01)
                return TIResult(provider=provider, ioc_type="hash", value=value, status="no_result")
            finally:
                active[provider] -= 1

        return await scheduling.run_provider_lookup(provider, "unit-account", request, lambda exc: None)

    results = await asyncio.gather(*(lookup(provider, str(index)) for index in range(3) for provider in active))
    assert len(results) == 6
    assert peak == {"urlhaus": 1, "yaraify": 1}
    assert combined_peak == 2


@pytest.mark.parametrize("provider,value,path,fields", [
    ("malware_bazaar", "06f1aa330b927b753a40e68cdf22e34bcbef3352", "/api/v1/",
     {"query": ["get_info"], "hash": ["06f1aa330b927b753a40e68cdf22e34bcbef3352"]}),
    ("urlhaus", "https://example.org/", "/v1/url/", {"url": ["https://example.org/"]}),
])
@pytest.mark.asyncio
async def test_provider_request_matches_published_lookup_contract(monkeypatch, provider, value, path, fields):
    from urllib.parse import parse_qs

    from nexus.ti.providers import abuse_ch

    captured = []
    original = httpx.AsyncClient

    def handle(request):
        captured.append(request)
        return httpx.Response(200, json={"query_status": "hash_not_found" if provider == "malware_bazaar" else "no_results"})

    def client(**kwargs):
        return original(transport=httpx.MockTransport(handle), **kwargs)

    monkeypatch.setattr(abuse_ch.httpx, "AsyncClient", client)
    query = abuse_ch.query_malware_bazaar if provider == "malware_bazaar" else abuse_ch.query_urlhaus
    await query(value, mock=False, api_key="unit-key")
    assert len(captured) == 1
    assert captured[0].url.path == path
    assert captured[0].headers["content-type"].startswith("application/x-www-form-urlencoded")
    assert parse_qs(captured[0].content.decode()) == fields
    assert captured[0].headers["Auth-Key"] == "unit-key"


@pytest.mark.asyncio
async def test_api_error_at_http_200_is_never_clean_or_absent(monkeypatch):
    from nexus.ti.providers import abuse_ch

    original = httpx.AsyncClient

    def handle(request):
        return httpx.Response(200, json={"query_status": "unknown_auth_key"})

    monkeypatch.setattr(abuse_ch.httpx, "AsyncClient", lambda **kwargs: original(transport=httpx.MockTransport(handle), **kwargs))
    router = ti_router.TIRouter(force_mock=False)
    monkeypatch.setattr(router, "_provider_mode", lambda _: ProviderMode.LIVE)
    result = await router._dispatch("urlhaus", "https://example.org/", IOCType.URL)
    assert result.status == "error"
    assert result.malicious is None
    assert "unknown_auth_key" in result.error
    assert result.raw["nexus_failure"]["http_status"] == 200
