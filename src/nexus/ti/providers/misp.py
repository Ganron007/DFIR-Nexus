"""MISP REST attribute search (self-hosted, open-source TI)."""

from __future__ import annotations

import logging
import os

import httpx

from nexus.ti import mock_data
from nexus.ti.constants import ENV_MISP_API_KEY, ENV_MISP_URL
from nexus.ti.schemas import TIResult

log = logging.getLogger(__name__)


def misp_config() -> tuple[str | None, str | None]:
    return os.environ.get(ENV_MISP_URL), os.environ.get(ENV_MISP_API_KEY)


async def query_misp(value: str, *, mock: bool, ioc_type: str = "domain") -> TIResult:
    url, api_key = misp_config()
    if mock:
        raw = mock_data.mock_misp(value)
    elif not (url and api_key):
        return TIResult(
            provider="misp",
            ioc_type=ioc_type,
            value=value,
            status="error",
            summary="MISP not configured",
            error=f"Set {ENV_MISP_URL} and {ENV_MISP_API_KEY}",
        )
    else:
        endpoint = f"{url.rstrip('/')}/attributes/restSearch"
        payload = {
            "returnFormat": "json",
            "value": value,
            "enforceWarninglist": False,
            "limit": 25,
        }
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                endpoint,
                json=payload,
                headers={
                    "Authorization": api_key,
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
            )
            resp.raise_for_status()
            raw = resp.json()

    attrs = (raw.get("response") or {}).get("Attribute") or []
    mal = any(a.get("to_ids") for a in attrs)
    event_ids = sorted({str(a.get("event_id")) for a in attrs if a.get("event_id")})
    summary = f"MISP: {len(attrs)} attribute(s)" if attrs else "MISP: no attributes"
    if event_ids:
        summary += f" (events: {', '.join(event_ids[:5])})"
    return TIResult(
        provider="misp",
        ioc_type=ioc_type,
        value=value,
        status="ok" if attrs else "no_result",
        malicious=mal if attrs else None,
        confidence=0.85 if mal else 0.5 if attrs else 0.0,
        summary=summary,
        raw=raw if isinstance(raw, dict) else {"raw": raw},
        tags=[str(a.get("type", "")) for a in attrs if a.get("type")],
        references=[f"{url.rstrip('/')}/events/view/{eid}" for eid in event_ids[:3]] if url else [],
    )
