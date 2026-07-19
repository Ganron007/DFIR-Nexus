"""CTI ingestion module.

Pparses threat intelligence feeds into a unified CTIItem schema:
- CISA Known Exploited Vulnerabilities (KEV) catalog (JSON format)
- MITRE ATT&CK STIX bundles (if available locally)
- Vendor blog RSS feeds (parsed as generic threat intel)

All functions are pure: they accept raw data and return lists of CTIItem.
Mock mode provides deterministic offline test data.
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any

log = logging.getLogger(__name__)


class CTIItemType(StrEnum):
    """Type of CTI item."""

    VULNERABILITY = "vulnerability"
    TECHNIQUE = "technique"
    CAMPAIGN = "campaign"
    INDICATOR = "indicator"
    ADVISORY = "advisory"
    UNKNOWN = "unknown"


class CTISource(StrEnum):
    """Origin of the CTI data."""

    CISA_KEV = "cisa_kev"
    MITRE_ATTACK = "mitre_attack"
    VENDOR_BLOG = "vendor_blog"
    UNKNOWN = "unknown"


@dataclass
class CTIItem:
    """A normalized threat intelligence item.

    Unified schema for data from CISA KEV, MITRE ATT&CK, and vendor blogs.
    """

    id: str
    title: str
    description: str
    item_type: CTIItemType
    source: CTISource
    # MITRE ATT&CK technique IDs (e.g., "T1190")
    technique_ids: list[str] = field(default_factory=list)
    # MITRE ATT&CK tactic IDs (e.g., "TA0001")
    tactic_ids: list[str] = field(default_factory=list)
    # Indicators of compromise (hashes, IPs, domains)
    iocs: list[str] = field(default_factory=list)
    # CVE identifiers
    cve_ids: list[str] = field(default_factory=list)
    # Vendor / product affected
    affected_products: list[str] = field(default_factory=list)
    # Timestamp of the intelligence
    timestamp: str = ""
    # URL back to the original source
    reference_url: str = ""
    # Severity / priority (vendor-specific, normalized to low/medium/high/critical)
    severity: str = "medium"
    # Raw source data preserved for audit
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to JSON-compatible dict."""
        d = asdict(self)
        d["item_type"] = self.item_type.value
        d["source"] = self.source.value
        return d

    @staticmethod
    def new_id() -> str:
        """Generate a unique CTI item ID."""
        return f"CTI-{uuid.uuid4().hex[:12].upper()}"


def parse_cisa_kev(json_data: str | dict[str, Any]) -> list[CTIItem]:
    """Parse CISA Known Exploited Vulnerabilities catalog.

    Accepts either a raw JSON string or a pre-parsed dict.
    The CISA KEV JSON schema has a ``vulnerabilities`` array, each entry
    containing ``cveID``, ``vendorProject``, ``product``, ``vulnerabilityName``,
    ``shortDescription``, ``dateAdded``, ``dueDate``, etc.

    Args:
        json_data: Raw JSON string or parsed dict of the CISA KEV feed.

    Returns:
        List of CTIItem objects (one per vulnerability).
    """
    data = _ensure_dict(json_data)
    vulns = data.get("vulnerabilities", [])
    if not isinstance(vulns, list):
        return []

    items: list[CTIItem] = []
    for vuln in vulns:
        if not isinstance(vuln, dict):
            continue

        cve_id = str(vuln.get("cveID", "")).strip()
        vendor = str(vuln.get("vendorProject", "")).strip()
        product = str(vuln.get("product", "")).strip()
        name = str(vuln.get("vulnerabilityName", "")).strip()
        description = str(vuln.get("shortDescription", "")).strip()
        date_added = str(vuln.get("dateAdded", "")).strip()
        known_ransomware = str(vuln.get("knownRansomwareCampaignUse", "")).strip()
        notes = str(vuln.get("notes", "")).strip()

        title = f"{cve_id}: {name}" if name else cve_id
        affected = [f"{vendor} {product}".strip()] if vendor or product else []

        severity = "high"
        if known_ransomware.lower() in ("known", "yes", "true"):
            severity = "critical"

        ref_url = ""
        if cve_id:
            ref_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

        items.append(
            CTIItem(
                id=CTIItem.new_id(),
                title=title,
                description=description or notes,
                item_type=CTIItemType.VULNERABILITY,
                source=CTISource.CISA_KEV,
                cve_ids=[cve_id] if cve_id else [],
                affected_products=affected,
                timestamp=date_added,
                reference_url=ref_url,
                severity=severity,
                raw=dict(vuln),
            )
        )

    return items


def parse_mitre_stix(json_data: str | dict[str, Any]) -> list[CTIItem]:
    """Parse MITRE ATT&CK STIX 2.0 bundle.

    Expects a STIX bundle with ``type: "bundle"`` and an ``objects`` array.
    Extracts attack-pattern (techniques), campaign, and intrusion-set objects.

    Args:
        json_data: Raw JSON string or parsed STIX bundle dict.

    Returns:
        List of CTIItem objects (one per relevant STIX object).
    """
    data = _ensure_dict(json_data)

    # STIX bundle: objects is a list
    objects = data.get("objects", [])
    if not isinstance(objects, list):
        return []

    # Build a lookup of identity/name refs for descriptions
    name_lookup: dict[str, str] = {}
    for obj in objects:
        if not isinstance(obj, dict):
            continue
        if obj.get("type") in ("identity", "marking-definition"):
            oid = obj.get("id", "")
            name_lookup[oid] = obj.get("name", "")

    items: list[CTIItem] = []
    for obj in objects:
        if not isinstance(obj, dict):
            continue

        obj_type = obj.get("type", "")

        # Skip revoked objects
        if obj.get("revoked", False):
            continue

        if obj_type == "attack-pattern":
            items.append(_stix_attack_pattern(obj))
        elif obj_type == "campaign":
            items.append(_stix_campaign(obj))
        elif obj_type == "intrusion-set":
            items.append(_stix_intrusion_set(obj))

    return items


def parse_vendor_rss(feed_json: str | dict[str, Any]) -> list[CTIItem]:
    """Parse a vendor blog RSS feed in JSON format.

    Accepts RSS-to-JSON or Atom-style JSON with an ``items`` or ``entries``
    array. Each item becomes a CTIItem of type ADVISORY.

    Args:
        feed_json: Raw JSON string or parsed dict of the RSS feed.

    Returns:
        List of CTIItem objects.
    """
    data = _ensure_dict(feed_json)
    items_raw = data.get("items", data.get("entries", []))
    if not isinstance(items_raw, list):
        return []

    items: list[CTIItem] = []
    for entry in items_raw:
        if not isinstance(entry, dict):
            continue

        title = str(entry.get("title", "Untitled")).strip()
        description = str(
            entry.get("description", entry.get("summary", entry.get("content", "")))
        ).strip()
        link = str(entry.get("link", entry.get("url", ""))).strip()
        pub_date = str(
            entry.get("pubDate", entry.get("published", entry.get("updated", "")))
        ).strip()

        # Extract IOCs heuristically from the description text
        iocs = _extract_iocs_from_text(description)

        items.append(
            CTIItem(
                id=CTIItem.new_id(),
                title=title,
                description=description,
                item_type=CTIItemType.ADVISORY,
                source=CTISource.VENDOR_BLOG,
                iocs=iocs,
                timestamp=pub_date,
                reference_url=link,
                severity="medium",
                raw=dict(entry),
            )
        )

    return items


def get_mock_cisa_kev() -> dict[str, Any]:
    """Return a deterministic CISA KEV payload for offline testing.

    Returns:
        Dict matching the CISA KEV JSON schema with two sample entries.
    """
    return {
        "title": "CISA Catalog of Known Exploited Vulnerabilities",
        "catalogVersion": "2025.01.01",
        "dateReleased": "2025-01-01T00:00:00.0000Z",
        "count": 2,
        "vulnerabilities": [
            {
                "cveID": "CVE-2021-44228",
                "vendorProject": "Apache",
                "product": "Log4j",
                "vulnerabilityName": "Apache Log4j Remote Code Execution",
                "dateAdded": "2021-12-10",
                "shortDescription": "Apache Log4j2 contains a vulnerability "
                "that allows remote code execution.",
                "requiredAction": "Apply updates per vendor instructions.",
                "dueDate": "2021-12-24",
                "knownRansomwareCampaignUse": "Known",
                "notes": "",
            },
            {
                "cveID": "CVE-2023-44487",
                "vendorProject": "HTTP/2",
                "product": "Protocol",
                "vulnerabilityName": "HTTP/2 Rapid Reset Attack",
                "dateAdded": "2023-10-10",
                "shortDescription": "The HTTP/2 protocol allows a denial of "
                "service via request cancellation.",
                "requiredAction": "Apply updates per vendor instructions.",
                "dueDate": "2023-10-31",
                "knownRansomwareCampaignUse": "Known",
                "notes": "",
            },
        ],
    }


def get_mock_mitre_stix() -> dict[str, Any]:
    """Return a minimal MITRE ATT&CK STIX bundle for offline testing.

    Returns:
        Dict with ``type: "bundle"`` and a small ``objects`` array.
    """
    return {
        "type": "bundle",
        "id": "bundle--mock-mitre-attack",
        "objects": [
            {
                "type": "attack-pattern",
                "id": "attack-pattern--mock-001",
                "name": "Exploit Public-Facing Application",
                "description": "Adversaries may attempt to exploit a weakness "
                "in an Internet-facing host.",
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "T1190",
                        "url": "https://attack.mitre.org/techniques/T1190",
                    }
                ],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}
                ],
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--mock-002",
                "name": "Phishing",
                "description": "Adversaries may send phishing messages to gain "
                "access to victim systems.",
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "T1566",
                        "url": "https://attack.mitre.org/techniques/T1566",
                    }
                ],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}
                ],
            },
            {
                "type": "campaign",
                "id": "campaign--mock-001",
                "name": "APT29 Campaign 2024",
                "description": "Mock campaign for testing purposes.",
            },
        ],
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _ensure_dict(data: str | dict[str, Any]) -> dict[str, Any]:
    """Coerce JSON string to dict, pass through dicts unchanged."""
    if isinstance(data, str):
        try:
            return json.loads(data)
        except json.JSONDecodeError:
            log.warning("Failed to parse JSON string, returning empty dict")
            return {}
    return data


def _stix_attack_pattern(obj: dict[str, Any]) -> CTIItem:
    """Convert a STIX attack-pattern to a CTIItem."""
    name = obj.get("name", "Unknown Technique")
    description = obj.get("description", "")

    technique_ids: list[str] = []
    tactic_ids: list[str] = []
    ref_url = ""

    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            ext_id = ref.get("external_id", "")
            if ext_id.startswith("T"):
                technique_ids.append(ext_id)
            ref_url = ref.get("url", ref_url)

    for phase in obj.get("kill_chain_phases", []):
        if phase.get("kill_chain_name") == "mitre-attack":
            tactic_name = phase.get("phase_name", "")
            tactic_id = _TACTIC_NAME_MAP.get(tactic_name, "")
            if tactic_id:
                tactic_ids.append(tactic_id)

    return CTIItem(
        id=CTIItem.new_id(),
        title=name,
        description=description,
        item_type=CTIItemType.TECHNIQUE,
        source=CTISource.MITRE_ATTACK,
        technique_ids=sorted(set(technique_ids)),
        tactic_ids=sorted(set(tactic_ids)),
        reference_url=ref_url,
        severity="medium",
        raw=dict(obj),
    )


def _stix_campaign(obj: dict[str, Any]) -> CTIItem:
    """Convert a STIX campaign to a CTIItem."""
    return CTIItem(
        id=CTIItem.new_id(),
        title=obj.get("name", "Unknown Campaign"),
        description=obj.get("description", ""),
        item_type=CTIItemType.CAMPAIGN,
        source=CTISource.MITRE_ATTACK,
        severity="high",
        raw=dict(obj),
    )


def _stix_intrusion_set(obj: dict[str, Any]) -> CTIItem:
    """Convert a STIX intrusion-set to a CTIItem."""
    aliases = obj.get("aliases", [])
    title = obj.get("name", "Unknown Intrusion Set")
    if aliases:
        title = f"{title} (aliases: {', '.join(aliases[:5])})"

    return CTIItem(
        id=CTIItem.new_id(),
        title=title,
        description=obj.get("description", ""),
        item_type=CTIItemType.CAMPAIGN,
        source=CTISource.MITRE_ATTACK,
        severity="high",
        raw=dict(obj),
    )


def _extract_iocs_from_text(text: str) -> list[str]:
    """Heuristically extract IOCs (IPs, domains, hashes) from free text."""
    import re

    iocs: list[str] = []

    # IPv4 addresses
    ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    for match in ip_re.findall(text):
        octets = match.split(".")
        if all(0 <= int(o) <= 255 for o in octets):
            iocs.append(match)

    # SHA-256 hashes (64 hex chars)
    hash_re = re.compile(r"\b[a-fA-F0-9]{64}\b")
    iocs.extend(hash_re.findall(text))

    # MD5 hashes (32 hex chars)
    md5_re = re.compile(r"\b[a-fA-F0-9]{32}\b")
    iocs.extend(md5_re.findall(text))

    return sorted(set(iocs))


# MITRE ATT&CK kill-chain phase name → tactic ID mapping
_TACTIC_NAME_MAP: dict[str, str] = {
    "reconnaissance": "TA0043",
    "resource-development": "TA0042",
    "initial-access": "TA0001",
    "execution": "TA0002",
    "persistence": "TA0003",
    "privilege-escalation": "TA0004",
    "defense-evasion": "TA0005",
    "credential-access": "TA0006",
    "discovery": "TA0007",
    "lateral-movement": "TA0008",
    "collection": "TA0009",
    "command-and-control": "TA0011",
    "exfiltration": "TA0010",
    "impact": "TA0040",
}
