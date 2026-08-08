"""IOC blocklist export for firewall/EDR import.

Takes findings and IOCs and generates blocklists in TXT (one per line),
CSV, and STIX format. Pure function — no side effects, no I/O.
"""

from __future__ import annotations

import csv
import json
import re
import uuid
from datetime import UTC, datetime
from io import StringIO
from typing import Any


def _extract_iocs_from_findings(findings: list[dict[str, Any]]) -> list[str]:
    """Extract IOC strings from finding dicts."""
    iocs: list[str] = []
    for finding in findings:
        for ioc_entry in finding.get("iocs", []):
            if isinstance(ioc_entry, str):
                iocs.append(ioc_entry)
            elif isinstance(ioc_entry, dict):
                val = ioc_entry.get("value") or ioc_entry.get("ioc", "")
                if val:
                    iocs.append(val)
        text = f"{finding.get('title', '')} {finding.get('description', '')}"
        for token in text.split():
            token = token.strip(".,;:()[]{}\"'")
            if _is_plausible_ioc(token):
                iocs.append(token)
    return iocs


def _is_plausible_ioc(token: str) -> bool:
    """Heuristic check for IOC-like strings."""
    if len(token) < 3:
        return False
    if re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", token):
        return True
    if re.match(r"^[a-fA-F0-9]{32,64}$", token) and len(token) in (32, 40, 64):
        return True
    if re.match(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$",
        token,
    ):
        return True
    return bool(re.match(r"^https?://", token, re.I))


def _normalize_ioc(ioc: str) -> str:
    """Normalize an IOC string for deduplication."""
    return ioc.strip().lower()


def _deduplicate_iocs(iocs: list[str]) -> list[str]:
    """Deduplicate IOCs while preserving order."""
    seen: set[str] = set()
    result: list[str] = []
    for ioc in iocs:
        norm = _normalize_ioc(ioc)
        if norm and norm not in seen:
            seen.add(norm)
            result.append(ioc.strip())
    return sorted(result)


def _format_txt(iocs: list[str]) -> str:
    return "\n".join(iocs) + ("\n" if iocs else "")


def _format_csv(iocs: list[str]) -> str:
    buf = StringIO()
    writer = csv.writer(buf)
    writer.writerow(["ioc"])
    for ioc in iocs:
        writer.writerow([ioc])
    return buf.getvalue()


def _format_stix(iocs: list[str]) -> str:
    """Generate a STIX 2.1 bundle with Indicator SDOs for each IOC."""
    now = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    objects: list[dict[str, Any]] = []

    objects.append({
        "type": "identity",
        "spec_version": "2.1",
        "id": f"identity--{uuid.uuid4()}",
        "created": now,
        "modified": now,
        "name": "DFIR-Nexus Blocklist Export",
        "identity_class": "tool",
    })

    for ioc in iocs:
        pattern = _ioc_to_stix_pattern(ioc)
        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid4()}",
            "created": now,
            "modified": now,
            "name": f"Blocklist: {ioc}",
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": now,
            "indicator_types": ["malicious-activity"],
        })

    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }
    return json.dumps(bundle, indent=2)


def _ioc_to_stix_pattern(ioc: str) -> str:
    """Convert IOC string to a STIX pattern expression."""
    ioc = ioc.strip()
    if re.match(r"^[a-fA-F0-9]{64}$", ioc):
        return f"[file:hashes.'SHA-256' = '{ioc.lower()}']"
    if re.match(r"^[a-fA-F0-9]{40}$", ioc):
        return f"[file:hashes.'SHA-1' = '{ioc.lower()}']"
    if re.match(r"^[a-fA-F0-9]{32}$", ioc):
        return f"[file:hashes.'MD5' = '{ioc.lower()}']"
    if re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", ioc):
        return f"[ipv4-addr:value = '{ioc}']"
    if re.match(r"^https?://", ioc, re.I):
        escaped = ioc.replace("'", "\\'")
        return f"[url:value = '{escaped}']"
    if re.match(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$",
        ioc,
    ):
        return f"[domain-name:value = '{ioc}']"
    return f"[artifact:payload_bin = '{ioc}']"


def export_blocklist(
    iocs: list[str],
    *,
    format: str = "txt",
    findings: list[dict[str, Any]] | None = None,
) -> str:
    """Export IOCs as a blocklist in the specified format.

    Args:
        iocs: Explicit list of IOC strings (IPs, domains, hashes, URLs).
        format: Output format — ``"txt"`` (one per line), ``"csv"``,
            or ``"stix"`` (STIX 2.1 bundle JSON string).
        findings: Optional list of finding dicts. Additional IOCs are
            extracted from finding ``iocs`` fields and description text.

    Returns:
        Blocklist content as a string.
    """
    all_iocs = list(iocs)
    if findings:
        all_iocs.extend(_extract_iocs_from_findings(findings))
    unique = _deduplicate_iocs(all_iocs)

    fmt = format.lower().strip()
    if fmt == "csv":
        return _format_csv(unique)
    if fmt == "stix":
        return _format_stix(unique)
    return _format_txt(unique)
