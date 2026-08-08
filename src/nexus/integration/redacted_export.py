"""Redacted case export with reversible tokenization.

Replaces sensitive data (IPs, hostnames, usernames, domains) in findings
and descriptions with deterministic tokens. Produces a shareable ZIP
containing tokenized entities plus a mapping file for reversal.
Uses the same anonymization pattern as ``nexus.analysis.anonymize``.
Pure function — no side effects beyond returning bytes.
"""

from __future__ import annotations

import json
import re
import zipfile
from io import BytesIO
from typing import Any
from uuid import uuid4

_TOKEN_PREFIX = "REDACTED"

_CATEGORIES = {
    "IP": "IP",
    "EMAIL": "EMAIL",
    "HOST": "HOST",
    "USER": "USER",
    "DOMAIN": "DOMAIN",
}

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
)
_USER_RE = re.compile(
    r"(?<![\\/:.\w])([A-Za-z][A-Za-z0-9.-]{1,14})\\([A-Za-z0-9._$-]{2,20})(?![\\/\w])"
)
_TOKEN_RE = re.compile(rf"{_TOKEN_PREFIX}_(?:IP|EMAIL|HOST|USER|DOMAIN)_\d+", re.I)

_INTERNAL_PREFIXES = (
    "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    "169.254.",
)

_KNOWN_BENIGN_DOMAINS = frozenset({
    "microsoft.com", "google.com", "amazon.com", "windows.com",
    "windowsupdate.com", "office.com", "office365.com", "live.com",
    "outlook.com", "github.com", "apple.com", "mozilla.org",
    "cloudflare.com", "akamai.com", "akamaiedge.net",
})


def _is_internal_ip(ip: str) -> bool:
    """Check if an IPv4 address is RFC-1918 or link-local."""
    return any(ip.startswith(prefix) for prefix in _INTERNAL_PREFIXES)


def _is_benign_domain(domain: str) -> bool:
    """Check if a domain is a known benign service."""
    lower = domain.lower()
    return any(lower.endswith(bd) for bd in _KNOWN_BENIGN_DOMAINS)


class _RedactionMap:
    """Maintains reversible token ↔ real value mappings."""

    def __init__(self) -> None:
        self._to_token: dict[str, str] = {}
        self._to_real: dict[str, str] = {}
        self._counters: dict[str, int] = {}

    def assign(self, category: str, real: str) -> str:
        """Assign a deterministic token for a real value."""
        key = f"{category}:{real.lower()}"
        if key in self._to_token:
            return self._to_token[key]
        self._counters[category] = self._counters.get(category, 0) + 1
        token = f"{_TOKEN_PREFIX}_{category}_{self._counters[category]}"
        self._to_token[key] = token
        self._to_real[token.upper()] = real
        return token

    def restore(self, text: str) -> str:
        """Restore original values in tokenized text."""
        return _TOKEN_RE.sub(
            lambda m: self._to_real.get(m.group(0).upper(), m.group(0)),
            text,
        )

    def to_mapping(self) -> dict[str, str]:
        """Export the token → real mapping for reversal."""
        return dict(self._to_real)


def _redact_text(text: str, rmap: _RedactionMap) -> str:
    """Apply redaction tokens to a text string."""
    if not text:
        return text

    result = text

    result = _USER_RE.sub(
        lambda m: rmap.assign("USER", f"{m.group(1)}\\{m.group(2)}"),
        result,
    )

    result = _EMAIL_RE.sub(
        lambda m: rmap.assign("EMAIL", m.group(0)),
        result,
    )

    result = _IP_RE.sub(
        lambda m: rmap.assign("IP", m.group(0)) if _is_internal_ip(m.group(0)) else m.group(0),
        result,
    )

    def _domain_repl(m: re.Match[str]) -> str:
        d = m.group(0)
        if _is_benign_domain(d):
            return d
        if _IP_RE.match(d):
            return d
        return rmap.assign("DOMAIN", d)

    result = _DOMAIN_RE.sub(_domain_repl, result)

    return result


def _redact_value(value: Any, rmap: _RedactionMap) -> Any:
    """Recursively redact strings in nested structures."""
    if isinstance(value, str):
        return _redact_text(value, rmap)
    if isinstance(value, list):
        return [_redact_value(v, rmap) for v in value]
    if isinstance(value, dict):
        return {k: _redact_value(v, rmap) for k, v in value.items()}
    return value


def _redact_findings(
    findings: list[dict[str, Any]], rmap: _RedactionMap
) -> list[dict[str, Any]]:
    """Redact sensitive fields in a list of findings."""
    redacted: list[dict[str, Any]] = []
    sensitive_fields = {
        "title", "description", "observation", "interpretation",
        "host", "affected_account", "source_ip", "dest_ip",
    }
    for finding in findings:
        new_finding: dict[str, Any] = {}
        for key, value in finding.items():
            if key in sensitive_fields and isinstance(value, str) or isinstance(value, str):
                new_finding[key] = _redact_text(value, rmap)
            else:
                new_finding[key] = _redact_value(value, rmap)
        redacted.append(new_finding)
    return redacted


def export_redacted_zip(
    findings: list[dict[str, Any]],
    description: str = "",
    *,
    case_id: str = "",
) -> bytes:
    """Export a redacted, shareable ZIP with tokenized entities.

    Produces a ZIP containing:
    - ``redacted_findings.json``: Findings with sensitive data replaced by tokens.
    - ``redacted_description.txt``: Case description with sensitive data replaced.
    - ``token_mapping.json``: Token → real value mapping (for authorized reversal).

    Args:
        findings: List of finding dicts to redact.
        description: Case description text to redact.
        case_id: Optional case identifier for the bundle metadata.

    Returns:
        ZIP file content as bytes.
    """
    rmap = _RedactionMap()

    redacted_findings = _redact_findings(findings, rmap)
    redacted_description = _redact_text(description, rmap)

    bundle = {
        "format": "dfir-nexus-redacted-v1",
        "case_id": case_id or str(uuid4()),
        "findings": redacted_findings,
        "description": redacted_description,
        "entity_count": len(rmap.to_mapping()),
    }

    mapping = rmap.to_mapping()

    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "redacted_findings.json",
            json.dumps(bundle, indent=2, default=str),
        )
        zf.writestr("redacted_description.txt", redacted_description)
        zf.writestr(
            "token_mapping.json",
            json.dumps(mapping, indent=2, sort_keys=True),
        )
    return buf.getvalue()


def restore_redacted_text(text: str, mapping: dict[str, str]) -> str:
    """Restore original values in redacted text using a token mapping.

    Args:
        text: Redacted text containing ``REDACTED_*`` tokens.
        mapping: Token → real value mapping from ``token_mapping.json``.

    Returns:
        Text with tokens replaced by original values.
    """
    return _TOKEN_RE.sub(
        lambda m: mapping.get(m.group(0).upper(), m.group(0)),
        text,
    )
