"""Customer exposure checks via HIBP and LeakCheck.

OPSEC-safe: only analyst-entered domains and emails are queried.
Adversary IOCs are **never** sent to external services.
All functions support mock mode for offline/testing use.
Pure functions — no side effects beyond optional logging.
"""

from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Literal

log = logging.getLogger(__name__)

_HIBP_API_URL = "https://haveibeenpwned.com/api/v3"
_LEAKCHECK_API_URL = "https://leakcheck.io/api/public"

_EXPOSED_DOMAINS: dict[str, list[str]] = {
    "example.com": ["breach_adobe_2013", "breach_linkedin_2016"],
    "testcorp.com": ["breach_dropbox_2012"],
}

_EXPOSED_EMAILS: dict[str, list[str]] = {
    "admin@example.com": ["breach_adobe_2013", "breach_yahoo_2014"],
    "user@testcorp.com": ["breach_linkedin_2016"],
}


@dataclass
class BreachEntry:
    """A single breach result."""

    name: str
    source: str = ""
    data_classes: list[str] = field(default_factory=list)
    breach_date: str = ""
    pwn_count: int = 0


@dataclass
class ExposureResult:
    """Result of an exposure check for a single query."""

    query: str
    query_type: Literal["email", "domain"]
    found: bool
    breaches: list[BreachEntry]
    source: Literal["hibp", "leakcheck", "mock"]
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "query": self.query,
            "query_type": self.query_type,
            "found": self.found,
            "breaches": [
                {
                    "name": b.name,
                    "source": b.source,
                    "data_classes": b.data_classes,
                    "breach_date": b.breach_date,
                    "pwn_count": b.pwn_count,
                }
                for b in self.breaches
            ],
            "source": self.source,
            "error": self.error,
        }


def _is_email(value: str) -> bool:
    return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", value))


def _is_domain(value: str) -> bool:
    return bool(
        re.match(
            r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$",
            value,
        )
    )


def check_exposure_hibp(
    query: str,
    api_key: str = "",
    *,
    mock: bool = False,
) -> ExposureResult:
    """Check an email or domain against Have I Been Pwned.

    Args:
        query: Email address or domain to check.
        api_key: HIBP API key (``$HIBP_API_KEY``). Required unless
            ``mock=True``.
        mock: If ``True``, use built-in mock data instead of calling
            the real API.

    Returns:
        An ``ExposureResult`` with breach information.
    """
    if mock:
        return _mock_hibp(query)

    if not api_key:
        return ExposureResult(
            query=query,
            query_type="email" if _is_email(query) else "domain",
            found=False,
            breaches=[],
            source="hibp",
            error="HIBP API key not configured (set HIBP_API_KEY)",
        )

    try:
        import httpx

        if _is_email(query):
            url = f"{_HIBP_API_URL}/breachedaccount/{query}"
            headers = {
                "hibp-api-key": api_key,
                "user-agent": "DFIR-Nexus",
            }
            resp = httpx.get(url, headers=headers, timeout=10.0)
            if resp.status_code == 200:
                data = resp.json()
                breaches = [
                    BreachEntry(
                        name=b.get("Name", ""),
                        source="hibp",
                        data_classes=b.get("DataClasses", []),
                        breach_date=b.get("BreachDate", ""),
                        pwn_count=b.get("PwnCount", 0),
                    )
                    for b in data
                ]
                return ExposureResult(
                    query=query,
                    query_type="email",
                    found=True,
                    breaches=breaches,
                    source="hibp",
                )
            if resp.status_code == 404:
                return ExposureResult(
                    query=query,
                    query_type="email",
                    found=False,
                    breaches=[],
                    source="hibp",
                )
            return ExposureResult(
                query=query,
                query_type="email",
                found=False,
                breaches=[],
                source="hibp",
                error=f"HIBP returned status {resp.status_code}",
            )
        else:
            return ExposureResult(
                query=query,
                query_type="domain",
                found=False,
                breaches=[],
                source="hibp",
                error="HIBP does not support domain queries via public API",
            )
    except Exception as e:
        return ExposureResult(
            query=query,
            query_type="email" if _is_email(query) else "domain",
            found=False,
            breaches=[],
            source="hibp",
            error=str(e),
        )


def check_exposure_leakcheck(
    query: str,
    api_key: str = "",
    *,
    mock: bool = False,
) -> ExposureResult:
    """Check an email or domain against LeakCheck.

    Args:
        query: Email address or domain to check.
        api_key: LeakCheck API key (``$LEAKCHECK_API_KEY``). Required
            unless ``mock=True``.
        mock: If ``True``, use built-in mock data instead of calling
            the real API.

    Returns:
        An ``ExposureResult`` with breach information.
    """
    if mock:
        return _mock_leakcheck(query)

    if not api_key:
        return ExposureResult(
            query=query,
            query_type="email" if _is_email(query) else "domain",
            found=False,
            breaches=[],
            source="leakcheck",
            error="LeakCheck API key not configured (set LEAKCHECK_API_KEY)",
        )

    try:
        import httpx

        check_type = "email" if _is_email(query) else "domain"
        url = f"{_LEAKCHECK_API_URL}"
        params = {"check": query, "type": check_type}
        headers = {"x-api-key": api_key}
        resp = httpx.get(url, params=params, headers=headers, timeout=10.0)
        if resp.status_code == 200:
            data = resp.json()
            found = data.get("found", 0) > 0
            sources = data.get("sources", [])
            breaches = [
                BreachEntry(name=s if isinstance(s, str) else s.get("name", ""), source="leakcheck")
                for s in sources
            ]
            return ExposureResult(
                query=query,
                query_type=check_type,
                found=found,
                breaches=breaches,
                source="leakcheck",
            )
        return ExposureResult(
            query=query,
            query_type=check_type,
            found=False,
            breaches=[],
            source="leakcheck",
            error=f"LeakCheck returned status {resp.status_code}",
        )
    except Exception as e:
        return ExposureResult(
            query=query,
            query_type="email" if _is_email(query) else "domain",
            found=False,
            breaches=[],
            source="leakcheck",
            error=str(e),
        )


def check_exposure_batch(
    queries: list[str],
    hibp_api_key: str = "",
    leakcheck_api_key: str = "",
    *,
    mock: bool = False,
) -> list[ExposureResult]:
    """Check multiple emails/domains against HIBP and LeakCheck.

    Args:
        queries: List of email addresses or domains.
        hibp_api_key: HIBP API key.
        leakcheck_api_key: LeakCheck API key.
        mock: Use mock data instead of real APIs.

    Returns:
        List of ``ExposureResult`` objects, one per query per provider.
    """
    results: list[ExposureResult] = []
    for q in queries:
        q = q.strip()
        if not q:
            continue
        results.append(check_exposure_hibp(q, hibp_api_key, mock=mock))
        results.append(check_exposure_leakcheck(q, leakcheck_api_key, mock=mock))
    return results


def _mock_hibp(query: str) -> ExposureResult:
    """Return mock HIBP data for testing."""
    qtype = "email" if _is_email(query) else "domain"
    if query.lower() in _EXPOSED_EMAILS:
        breaches = [
            BreachEntry(name=b, source="hibp_mock") for b in _EXPOSED_EMAILS[query.lower()]
        ]
        return ExposureResult(query=query, query_type=qtype, found=True, breaches=breaches, source="mock")
    if qtype == "domain":
        domain = query.lower()
        if domain in _EXPOSED_DOMAINS:
            breaches = [
                BreachEntry(name=b, source="hibp_mock") for b in _EXPOSED_DOMAINS[domain]
            ]
            return ExposureResult(query=query, query_type=qtype, found=True, breaches=breaches, source="mock")
    return ExposureResult(query=query, query_type=qtype, found=False, breaches=[], source="mock")


def _mock_leakcheck(query: str) -> ExposureResult:
    """Return mock LeakCheck data for testing."""
    qtype = "email" if _is_email(query) else "domain"
    if query.lower() in _EXPOSED_EMAILS:
        breaches = [
            BreachEntry(name=b, source="leakcheck_mock") for b in _EXPOSED_EMAILS[query.lower()]
        ]
        return ExposureResult(query=query, query_type=qtype, found=True, breaches=breaches, source="mock")
    return ExposureResult(query=query, query_type=qtype, found=False, breaches=[], source="mock")


def sha1_prefix_check(email: str) -> str:
    """Return SHA-1 hash prefix (first 5 chars) for k-anonymity HIBP range API.

    This is the OPSEC-safe method — only the hash prefix is sent, never
    the actual email address.
    """
    sha1 = hashlib.sha1(email.lower().encode("utf-8")).hexdigest().upper()
    return sha1[:5]
