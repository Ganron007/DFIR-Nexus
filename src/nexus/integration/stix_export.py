"""STIX 2.1 bundle export for case findings and IOCs.

Converts case findings and IOCs into a STIX 2.1 bundle containing
Indicator, Attack-Pattern, and Relationship SDOs/SROs.
Pure function — no side effects, no I/O.
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime
from typing import Any


def _stix_id(stix_type: str, seed: str | None = None) -> str:
    """Generate a STIX 2.1 compliant ID."""
    uid = str(uuid.uuid5(uuid.NAMESPACE_URL, seed)) if seed else str(uuid.uuid4())
    return f"{stix_type}--{uid}"


def _now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _severity_to_stix_label(severity: str) -> str:
    """Map DFIR-Nexus severity to STIX kill-chain phase label."""
    mapping = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "informational": "informational",
    }
    return mapping.get(severity.lower(), "unknown")


def _technique_to_attack_pattern(technique_id: str, name: str = "") -> dict[str, Any]:
    """Create a STIX 2.1 Attack-Pattern SDO from a MITRE ATT&CK technique ID."""
    ap_id = _stix_id("attack-pattern", f"technique:{technique_id}")
    now = _now_iso()
    external_refs = [
        {
            "source_name": "mitre-attack",
            "external_id": technique_id,
            "url": f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/",
        }
    ]
    return {
        "type": "attack-pattern",
        "spec_version": "2.1",
        "id": ap_id,
        "created": now,
        "modified": now,
        "name": name or technique_id,
        "external_references": external_refs,
    }


def _ioc_to_indicator(ioc: str, description: str = "") -> dict[str, Any]:
    """Create a STIX 2.1 Indicator SDO from an IOC string."""
    ind_id = _stix_id("indicator", f"ioc:{ioc}")
    now = _now_iso()
    pattern = _detect_pattern(ioc)
    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": ind_id,
        "created": now,
        "modified": now,
        "name": description or f"IOC: {ioc}",
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": now,
        "indicator_types": ["malicious-activity"],
    }


def _detect_pattern(ioc: str) -> str:
    """Detect IOC type and return a STIX pattern expression."""
    ipv4_re = re.compile(
        r"^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$"
    )
    domain_re = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,}$"
    )
    md5_re = re.compile(r"^[a-fA-F0-9]{32}$")
    sha1_re = re.compile(r"^[a-fA-F0-9]{40}$")
    sha256_re = re.compile(r"^[a-fA-F0-9]{64}$")
    email_re = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    url_re = re.compile(r"^https?://", re.I)
    cidr_re = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}$")

    ioc = ioc.strip()

    if sha256_re.match(ioc):
        return f"[file:hashes.'SHA-256' = '{ioc.lower()}']"
    if sha1_re.match(ioc):
        return f"[file:hashes.'SHA-1' = '{ioc.lower()}']"
    if md5_re.match(ioc):
        return f"[file:hashes.'MD5' = '{ioc.lower()}']"
    if ipv4_re.match(ioc):
        return f"[ipv4-addr:value = '{ioc}']"
    if cidr_re.match(ioc):
        return f"[ipv4-addr:value = '{ioc}']"
    if email_re.match(ioc):
        return f"[email-addr:value = '{ioc}']"
    if url_re.match(ioc):
        escaped = ioc.replace("'", "\\'")
        return f"[url:value = '{escaped}']"
    if domain_re.match(ioc):
        return f"[domain-name:value = '{ioc}']"
    return f"[artifact:payload_bin = '{ioc}']"


def _relationship(
    source_id: str, target_id: str, rel_type: str = "indicates"
) -> dict[str, Any]:
    """Create a STIX 2.1 Relationship SRO."""
    rel_id = _stix_id("relationship", f"{source_id}:{target_id}:{rel_type}")
    now = _now_iso()
    return {
        "type": "relationship",
        "spec_version": "2.1",
        "id": rel_id,
        "created": now,
        "modified": now,
        "relationship_type": rel_type,
        "source_ref": source_id,
        "target_ref": target_id,
    }


def _finding_to_observation(finding: dict[str, Any]) -> list[dict[str, Any]]:
    """Convert a finding dict to STIX Indicator + Relationship objects."""
    objects: list[dict[str, Any]] = []
    finding_id = _stix_id("indicator", f"finding:{finding.get('id', finding.get('title', ''))}")
    now = _now_iso()

    indicator = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": finding_id,
        "created": now,
        "modified": now,
        "name": finding.get("title", "Case Finding"),
        "description": finding.get("description", ""),
        "pattern": f"[artifact:payload_bin = '{finding.get('id', 'unknown')}']",
        "pattern_type": "stix",
        "valid_from": now,
        "indicator_types": ["malicious-activity"],
        "labels": [_severity_to_stix_label(finding.get("severity", "informational"))],
    }
    objects.append(indicator)

    for tid in finding.get("technique_ids", finding.get("mitre_ids", [])):
        ap = _technique_to_attack_pattern(tid)
        objects.append(ap)
        objects.append(_relationship(finding_id, ap["id"], "indicates"))

    return objects


def export_stix(findings: list[dict[str, Any]], iocs: list[str]) -> dict[str, Any]:
    """Convert case findings and IOCs to a STIX 2.1 bundle.

    Args:
        findings: List of finding dicts. Each may contain keys:
            ``id``, ``title``, ``description``, ``severity``,
            ``technique_ids`` or ``mitre_ids``.
        iocs: List of IOC strings (IPs, domains, hashes, URLs, emails).

    Returns:
        A dict representing a STIX 2.1 bundle (``{"type": "bundle", ...}``).
    """
    bundle_id = _stix_id("bundle", str(uuid.uuid4()))
    objects: list[dict[str, Any]] = []

    identity_id = _stix_id("identity", "dfir-nexus")
    now = _now_iso()
    objects.append({
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id,
        "created": now,
        "modified": now,
        "name": "DFIR-Nexus",
        "identity_class": "tool",
    })

    indicator_ids: list[str] = []
    for ioc in iocs:
        if not ioc or not ioc.strip():
            continue
        ind = _ioc_to_indicator(ioc)
        objects.append(ind)
        indicator_ids.append(ind["id"])

    for finding in findings:
        finding_objects = _finding_to_observation(finding)
        objects.extend(finding_objects)
        finding_indicator_id = finding_objects[0]["id"] if finding_objects else None

        for ioc_ind_id in indicator_ids:
            if finding_indicator_id:
                objects.append(_relationship(ioc_ind_id, finding_indicator_id, "indicates"))

    ap_ids = {o["id"] for o in objects if o.get("type") == "attack-pattern"}
    for ap_id in ap_ids:
        objects.append(_relationship(ap_id, identity_id, "delivers"))

    return {
        "type": "bundle",
        "id": bundle_id,
        "objects": objects,
    }
