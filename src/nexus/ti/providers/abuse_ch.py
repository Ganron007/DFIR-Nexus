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
    hits = [h for h in hits if isinstance(h, dict)]
    # search_ioc is a substring search: "github.com" returns 11 URLs hosted on GitHub and no IOC
    # that is github.com, and every one of them used to make the domain MALICIOUS (D200). Only an
    # IOC that IS the value is a verdict; the rest are context.
    exact = [h for h in hits if _same_ioc(str(h.get("ioc") or ""), value)]
    first = exact[0] if exact else {}
    if exact:
        summary = f"ThreatFox: {first.get('threat_type', 'unknown')} / {first.get('malware', 'n/a')}"
    elif hits:
        summary = (f"ThreatFox: no IOC is this value; {len(hits)} IOC(s) contain it "
                   f"(e.g. {str(hits[0].get('ioc_type') or 'ioc')} {str(hits[0].get('ioc') or '')})")
    else:
        summary = "ThreatFox: no hits"
    return _abuse_result(
        "threatfox",
        tf_type,
        value,
        raw,
        malicious=True if exact else None,
        confidence=0.75 if exact else 0.0,
        summary=summary,
        tags=[str(first.get("malware"))] if first.get("malware") else [],
    )


def _same_ioc(ioc: str, value: str) -> bool:
    """True when a ThreatFox IOC is the queried value: equal, or the address of an ``ip:port`` IOC."""
    ioc, value = ioc.strip().lower(), value.strip().lower()
    if not ioc or not value:
        return False
    return ioc == value or (ioc.rsplit(":", 1)[0] == value and ioc.count(":") == 1)


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


def _yaraify_rules(raw: dict[str, Any]) -> list[dict[str, Any]]:
    """YARA matches in a documented ``lookup_hash`` reply.

    ``data`` is an object: ``data.tasks[]`` holds one entry per submission, its YARA matches on the
    file in ``static_results[]`` and on unpacked files in ``unpack_results[].unpacked_yara_matches[]``.
    A reply whose ``query_status`` is not ``ok`` names no matches (the hash is not known).
    """
    if str(raw.get("query_status") or "") != "ok":
        return []
    data = raw.get("data")
    if not isinstance(data, dict):
        return []
    matches: list[dict[str, Any]] = []
    for task in data.get("tasks") or []:
        if not isinstance(task, dict):
            continue
        matches.extend(m for m in task.get("static_results") or [] if isinstance(m, dict))
        for unpacked in task.get("unpack_results") or []:
            if isinstance(unpacked, dict):
                matches.extend(
                    m for m in unpacked.get("unpacked_yara_matches") or [] if isinstance(m, dict))
    return matches


async def query_yaraify(value: str, *, mock: bool, api_key: str | None) -> TIResult:
    if mock:
        raw = mock_data.mock_yaraify(value)
    else:
        # https://yaraify.abuse.ch/api/ (checked 2026-10-14): query "lookup_hash" with the hash
        # in "search_term". The old body ("lookup", "hash") matched no documented query.
        raw = await _post_json(
            ABUSE_CH_YARAIFY_URL,
            {"query": "lookup_hash", "search_term": value},
            api_key,
        )
    rules = _yaraify_rules(raw)
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
