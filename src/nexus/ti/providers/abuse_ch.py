"""abuse.ch TI cluster — ThreatFox, Malware Bazaar, URLhaus, YARAify."""

from __future__ import annotations

import logging
from typing import Any

import httpx

from nexus.ti import mock_data
from nexus.ti.constants import (
    ABUSE_CH_MALWARE_BAZAAR_URL,
    ABUSE_CH_THREATFOX_URL,
    ABUSE_CH_URLHAUS_URL,
    ABUSE_CH_YARAIFY_URL,
    ENV_ABUSECH_KEY,
)
from nexus.ti.schemas import TIResult

log = logging.getLogger(__name__)


def _headers(api_key: str | None) -> dict[str, str]:
    h = {"Content-Type": "application/json"}
    if api_key:
        h["Auth-Key"] = api_key
    return h


async def _post_json(url: str, payload: dict[str, Any], api_key: str | None) -> dict[str, Any]:
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(url, json=payload, headers=_headers(api_key))
        resp.raise_for_status()
        data = resp.json()
        if not isinstance(data, dict):
            return {"query_status": "error", "raw": data}
        return data


def _abuse_result(
    provider: str,
    ioc_type: str,
    value: str,
    raw: dict[str, Any],
    *,
    malicious: bool | None,
    confidence: float,
    summary: str,
    tags: list[str] | None = None,
) -> TIResult:
    refs: list[str] = []
    if provider == "urlhaus" and raw.get("urlhaus_reference"):
        refs.append(str(raw["urlhaus_reference"]))
    return TIResult(
        provider=provider,
        ioc_type=ioc_type,
        value=value,
        status="ok" if raw.get("query_status") == "ok" else "no_result",
        malicious=malicious,
        confidence=confidence,
        summary=summary,
        raw=raw,
        references=refs,
        tags=tags or [],
    )


async def query_threatfox(
    value: str,
    *,
    mock: bool,
    api_key: str | None,
    ioc_type: str = "auto",
) -> TIResult:
    if ioc_type and ioc_type not in ("auto", ""):
        tf_type = ioc_type
    elif len(value) == 64 and all(c in "0123456789abcdefABCDEF" for c in value):
        tf_type = "hash"
    elif value.startswith(("http://", "https://")):
        tf_type = "url"
    elif "." in value and not value.replace(".", "").isdigit():
        tf_type = "domain"
    else:
        tf_type = "ip"
    if mock:
        raw = mock_data.mock_threatfox(value)
    else:
        raw = await _post_json(
            ABUSE_CH_THREATFOX_URL,
            {"query": "search_ioc", "search_term": value},
            api_key,
        )
    hits = raw.get("data") or []
    if isinstance(hits, str):
        hits = []
    if not isinstance(hits, list):
        hits = []
    first = hits[0] if hits and isinstance(hits[0], dict) else {}
    mal = bool(hits)
    summary = f"ThreatFox: {len(hits)} hit(s)" if hits else "ThreatFox: no hits"
    if first:
        summary = f"ThreatFox: {first.get('threat_type', 'unknown')} / {first.get('malware', 'n/a')}"
    return _abuse_result(
        "threatfox",
        tf_type,
        value,
        raw,
        malicious=mal if hits else None,
        confidence=0.75 if hits else 0.0,
        summary=summary,
        tags=[str(first.get("malware"))] if first.get("malware") else [],
    )


async def query_malware_bazaar(value: str, *, mock: bool, api_key: str | None) -> TIResult:
    if mock:
        raw = mock_data.mock_malware_bazaar(value)
    else:
        raw = await _post_json(
            ABUSE_CH_MALWARE_BAZAAR_URL,
            {"query": "get_info", "hash": value},
            api_key,
        )
    rows = raw.get("data") or []
    sig = rows[0].get("signature") if rows else None
    return _abuse_result(
        "malware_bazaar",
        "hash",
        value,
        raw,
        malicious=bool(sig),
        confidence=0.85 if sig else 0.0,
        summary=f"Malware Bazaar: {sig}" if sig else "Malware Bazaar: unknown hash",
        tags=list(rows[0].get("tags", [])) if rows else [],
    )


async def query_urlhaus(value: str, *, mock: bool, api_key: str | None) -> TIResult:
    if mock:
        raw = mock_data.mock_urlhaus(value)
    else:
        raw = await _post_json(
            ABUSE_CH_URLHAUS_URL,
            {"url": value},
            api_key,
        )
    threat = raw.get("threat")
    return _abuse_result(
        "urlhaus",
        "url",
        value,
        raw,
        malicious=bool(threat),
        confidence=0.9 if threat else 0.0,
        summary=f"URLhaus: {threat or 'not listed'}",
        tags=list(raw.get("tags", [])),
    )


async def query_yaraify(value: str, *, mock: bool, api_key: str | None) -> TIResult:
    if mock:
        raw = mock_data.mock_yaraify(value)
    else:
        raw = await _post_json(
            ABUSE_CH_YARAIFY_URL,
            {"query": "lookup", "hash": value},
            api_key,
        )
    rows = raw.get("data") or []
    rules = rows[0].get("yara_rules", []) if rows else []
    return _abuse_result(
        "yaraify",
        "hash",
        value,
        raw,
        malicious=bool(rules),
        confidence=0.8 if rules else 0.0,
        summary=f"YARAify: {len(rules)} rule(s)" if rules else "YARAify: no rules",
        tags=[r.get("rule_name", "") for r in rules if r.get("rule_name")],
    )


def abusech_api_key() -> str | None:
    import os

    return os.environ.get(ENV_ABUSECH_KEY) or None
