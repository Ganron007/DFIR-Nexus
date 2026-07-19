"""Optional TI providers — OTX, Shodan, VirusTotal, AbuseIPDB, CrowdStrike (explicit use only)."""

from __future__ import annotations

import logging
import os
from typing import Any
from urllib.parse import quote

import httpx

from nexus.ti import mock_data
from nexus.ti.constants import (
    CROWDSTRIKE_API_BASE,
    ENV_ABUSEIPDB_API_KEY,
    ENV_CROWDSTRIKE_CLIENT_ID,
    ENV_CROWDSTRIKE_CLIENT_SECRET,
    ENV_OTX_API_KEY,
    ENV_SHODAN_API_KEY,
    ENV_VIRUSTOTAL_API_KEY,
    OTX_API_BASE,
)
from nexus.ti.schemas import IOCType, TIResult

log = logging.getLogger(__name__)


def _result(
    provider: str,
    ioc_type: str,
    value: str,
    *,
    summary: str,
    raw: dict[str, Any],
    malicious: bool | None = None,
    confidence: float = 0.5,
    error: str | None = None,
) -> TIResult:
    return TIResult(
        provider=provider,
        ioc_type=ioc_type,
        value=value,
        status="error" if error else "ok",
        malicious=malicious,
        confidence=confidence,
        summary=summary,
        raw=raw,
        error=error,
    )


def _otx_indicator_path(ioc_type: IOCType, value: str) -> tuple[str, str]:
    if ioc_type == IOCType.IP:
        return "IPv4", value
    if ioc_type == IOCType.URL:
        return "url", value
    if ioc_type == IOCType.HASH:
        return "file", value
    if ioc_type == IOCType.DOMAIN:
        return "domain", value
    return "domain", value


async def query_otx(value: str, *, mock: bool, ioc_type: str = "domain") -> TIResult:
    it = IOCType(ioc_type)
    key = os.environ.get(ENV_OTX_API_KEY)
    if mock:
        raw = mock_data.mock_otx(value)
    elif not key:
        return _result(
            "otx",
            it.value,
            value,
            summary="OTX not configured",
            raw={},
            error=f"Set {ENV_OTX_API_KEY} (free AlienVault OTX key)",
        )
    else:
        section, indicator = _otx_indicator_path(it, value)
        url = f"{OTX_API_BASE}/indicators/{section}/{quote(indicator, safe='')}/general"
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(url, headers={"X-OTX-API-KEY": key})
            resp.raise_for_status()
            raw = resp.json()
    pulse = int(raw.get("pulse_info", {}).get("count", 0) or 0)
    return _result(
        "otx",
        it.value,
        value,
        summary=f"OTX: {pulse} pulse(s)",
        raw=raw,
        malicious=pulse > 0 if pulse else None,
        confidence=0.7 if pulse else 0.2,
    )


async def query_shodan(ip: str, *, mock: bool) -> TIResult:
    key = os.environ.get(ENV_SHODAN_API_KEY)
    if mock:
        raw = mock_data.mock_shodan(ip)
    elif not key:
        return _result(
            "shodan",
            "ip",
            ip,
            summary="Shodan not configured",
            raw={},
            error=f"Set {ENV_SHODAN_API_KEY} (free tier available)",
        )
    else:
        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                resp = await client.get(
                    f"https://api.shodan.io/shodan/host/{ip}",
                    params={"key": key},
                )
                resp.raise_for_status()
                raw = resp.json()
            except httpx.HTTPStatusError as exc:
                raise httpx.HTTPStatusError(
                    message=f"Shodan returned HTTP {exc.response.status_code}",
                    request=exc.request,
                    response=exc.response,
                ) from None
            except httpx.HTTPError as exc:
                raise httpx.HTTPError("Shodan request failed") from None
    ports = raw.get("ports", [])
    return _result(
        "shodan",
        "ip",
        ip,
        summary=f"Shodan: {len(ports)} open port(s)",
        raw=raw,
        confidence=0.55,
    )


async def query_virustotal(value: str, *, mock: bool, ioc_type: str = "domain") -> TIResult:
    it = IOCType(ioc_type)
    key = os.environ.get(ENV_VIRUSTOTAL_API_KEY)
    if mock:
        raw = mock_data.mock_virustotal(value)
    elif not key:
        return _result(
            "virustotal",
            it.value,
            value,
            summary="VirusTotal not configured",
            raw={},
            error=f"Set {ENV_VIRUSTOTAL_API_KEY} (commercial/free-tier API)",
        )
    else:
        path = {"hash": "files", "ip": "ip_addresses", "domain": "domains", "url": "urls"}.get(
            it.value, "domains"
        )
        url = f"https://www.virustotal.com/api/v3/{path}/{quote(value, safe='')}"
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(url, headers={"x-apikey": key})
            resp.raise_for_status()
            raw = resp.json()
    stats = (raw.get("data", {}).get("attributes", {}) or {}).get("last_analysis_stats", {})
    malicious = int(stats.get("malicious", 0) or 0)
    return _result(
        "virustotal",
        it.value,
        value,
        summary=f"VirusTotal: {malicious} malicious detection(s)",
        raw=raw,
        malicious=malicious > 0,
        confidence=min(0.95, 0.5 + malicious * 0.05),
    )


async def query_abuseipdb(ip: str, *, mock: bool) -> TIResult:
    key = os.environ.get(ENV_ABUSEIPDB_API_KEY)
    if mock:
        raw = mock_data.mock_abuseipdb(ip)
    elif not key:
        return _result(
            "abuseipdb",
            "ip",
            ip,
            summary="AbuseIPDB not configured",
            raw={},
            error=f"Set {ENV_ABUSEIPDB_API_KEY} (commercial/free-tier API)",
        )
    else:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": key, "Accept": "application/json"},
            )
            resp.raise_for_status()
            raw = resp.json()
    data = raw.get("data", {})
    score = int(data.get("abuseConfidenceScore", 0) or 0)
    return _result(
        "abuseipdb",
        "ip",
        ip,
        summary=f"AbuseIPDB: abuse score {score}%",
        raw=raw,
        malicious=score >= 50,
        confidence=score / 100.0,
    )


async def _crowdstrike_token(client_id: str, client_secret: str) -> str:
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(
            f"{CROWDSTRIKE_API_BASE}/oauth2/token",
            data={"client_id": client_id, "client_secret": client_secret},
        )
        resp.raise_for_status()
        token = resp.json().get("access_token")
        if not token:
            raise ValueError("CrowdStrike OAuth response missing access_token")
        return str(token)


async def _crowdstrike_intel_lookup(token: str, value: str) -> dict[str, Any]:
    headers = {"Authorization": f"Bearer {token}"}
    safe = value.replace("'", "\\'")
    async with httpx.AsyncClient(timeout=30.0) as client:
        query = await client.get(
            f"{CROWDSTRIKE_API_BASE}/intel/queries/indicators/v1",
            params={"filter": f"indicator:'{safe}'", "limit": 5},
            headers=headers,
        )
        query.raise_for_status()
        ids = query.json().get("resources") or []
        if not ids:
            return {"resources": [], "ids": []}
        detail = await client.post(
            f"{CROWDSTRIKE_API_BASE}/intel/combined/indicators/v1",
            params={"ids": ids[:5]},
            headers=headers,
        )
        detail.raise_for_status()
        body: dict[str, Any] = detail.json()
        body["ids"] = ids
        return body


async def query_crowdstrike(value: str, *, mock: bool, ioc_type: str = "domain") -> TIResult:
    cid = os.environ.get(ENV_CROWDSTRIKE_CLIENT_ID)
    secret = os.environ.get(ENV_CROWDSTRIKE_CLIENT_SECRET)
    if mock:
        raw = mock_data.mock_crowdstrike(value)
        return _result(
            "crowdstrike",
            ioc_type,
            value,
            summary="CrowdStrike (mock): high confidence",
            raw=raw,
            malicious=True,
            confidence=0.9,
        )
    if not (cid and secret):
        return _result(
            "crowdstrike",
            ioc_type,
            value,
            summary="CrowdStrike not configured",
            raw={},
            error=f"Set {ENV_CROWDSTRIKE_CLIENT_ID} and {ENV_CROWDSTRIKE_CLIENT_SECRET}",
        )
    try:
        token = await _crowdstrike_token(cid, secret)
        raw = await _crowdstrike_intel_lookup(token, value)
        resources = raw.get("resources") or []
        mal = bool(resources)
        labels = [
            str(r.get("label", r.get("type", "")))
            for r in resources
            if isinstance(r, dict)
        ]
        summary = f"CrowdStrike: {len(resources)} intel indicator(s)"
        if labels:
            summary += f" ({labels[0]})"
        return _result(
            "crowdstrike",
            ioc_type,
            value,
            summary=summary,
            raw=raw,
            malicious=mal if resources else None,
            confidence=0.85 if mal else 0.2,
        )
    except httpx.HTTPStatusError as exc:
        log.warning("CrowdStrike API HTTP error: %s", exc)
        return _result(
            "crowdstrike",
            ioc_type,
            value,
            summary="CrowdStrike API error",
            raw={"status_code": exc.response.status_code},
            error=str(exc),
        )
    except Exception as exc:
        log.exception("CrowdStrike lookup failed")
        return _result(
            "crowdstrike",
            ioc_type,
            value,
            summary="CrowdStrike lookup failed",
            raw={},
            error=str(exc),
        )
