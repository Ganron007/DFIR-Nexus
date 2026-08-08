"""CISA Known Exploited Vulnerabilities (KEV) integration.

Cross-references CVEs in findings/artifacts against the CISA KEV catalog
to identify actively exploited vulnerabilities. The KEV catalog is
downloadable as JSON from https://www.cisa.gov/known-exploited-vulnerabilities-catalog.

Pure/deterministic lookup — no network calls (uses local cache).
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

_KEV_CATALOG_PATH = Path.home() / ".nexus" / "data" / "kev_catalog.json"

_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


@dataclass
class KEVEntry:
    """A CISA Known Exploited Vulnerability entry."""
    cve_id: str
    vendor_project: str
    product: str
    vulnerability_name: str
    date_added: str
    short_description: str
    required_action: str
    due_date: str
    known_ransomware_campaign_use: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "vendor_project": self.vendor_project,
            "product": self.product,
            "vulnerability_name": self.vulnerability_name,
            "date_added": self.date_added,
            "short_description": self.short_description,
            "required_action": self.required_action,
            "due_date": self.due_date,
            "known_ransomware_campaign_use": self.known_ransomware_campaign_use,
        }


class KEVCatalog:
    """Local cache of the CISA KEV catalog."""

    def __init__(self) -> None:
        self._entries: dict[str, KEVEntry] = {}
        self._loaded = False

    def load(self, path: Path | None = None) -> int:
        """Load the KEV catalog from disk. Returns count of entries."""
        catalog_path = path or _KEV_CATALOG_PATH
        if not catalog_path.exists():
            log.debug("KEV catalog not found at %s", catalog_path)
            return 0
        try:
            data = json.loads(catalog_path.read_text(encoding="utf-8"))
            vulns = data.get("vulnerabilities", [])
            for v in vulns:
                cve = v.get("cveID", "")
                if cve:
                    self._entries[cve] = KEVEntry(
                        cve_id=cve,
                        vendor_project=v.get("vendorProject", ""),
                        product=v.get("product", ""),
                        vulnerability_name=v.get("vulnerabilityName", ""),
                        date_added=v.get("dateAdded", ""),
                        short_description=v.get("shortDescription", ""),
                        required_action=v.get("requiredAction", ""),
                        due_date=v.get("dueDate", ""),
                        known_ransomware_campaign_use=v.get("knownRansomwareCampaignUse", ""),
                    )
            self._loaded = True
            log.info("Loaded %d KEV entries from %s", len(self._entries), catalog_path)
            return len(self._entries)
        except (json.JSONDecodeError, OSError) as e:
            log.warning("Failed to load KEV catalog: %s", e)
            return 0

    @property
    def count(self) -> int:
        return len(self._entries)

    def lookup(self, cve_id: str) -> KEVEntry | None:
        """Look up a CVE in the KEV catalog."""
        if not self._loaded:
            self.load()
        return self._entries.get(cve_id.upper())

    def check_artifacts(self, artifacts: list[Any]) -> list[dict[str, Any]]:
        """Check a list of artifacts for known exploited vulnerabilities.

        Scans description, raw, and tags for CVE patterns.
        """
        import re
        cve_re = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
        hits: list[dict[str, Any]] = []

        for artifact in artifacts:
            text = ""
            if hasattr(artifact, "description"):
                text += artifact.description or ""
            if hasattr(artifact, "raw") and isinstance(artifact.raw, dict):
                text += " " + json.dumps(artifact.raw)

            cves = cve_re.findall(text)
            for cve in cves:
                entry = self.lookup(cve.upper())
                if entry:
                    hits.append({
                        "artifact_id": getattr(artifact, "id", None),
                        "cve_id": entry.cve_id,
                        "kev_entry": entry.to_dict(),
                        "confidence": "high",
                    })

        return hits

    @staticmethod
    def download_catalog(output_path: Path | None = None) -> bool:
        """Download the latest KEV catalog. Returns True on success."""
        import httpx
        dest = output_path or _KEV_CATALOG_PATH
        dest.parent.mkdir(parents=True, exist_ok=True)
        try:
            resp = httpx.get(_KEV_URL, follow_redirects=True, timeout=30)
            resp.raise_for_status()
            dest.write_bytes(resp.content)
            log.info("Downloaded KEV catalog to %s (%d bytes)", dest, len(resp.content))
            return True
        except Exception as e:
            log.warning("Failed to download KEV catalog: %s", e)
            return False


_default_catalog = KEVCatalog()


def get_kev_catalog() -> KEVCatalog:
    return _default_catalog


def check_kev(cve_id: str) -> dict[str, Any] | None:
    """Quick lookup for a single CVE."""
    entry = _default_catalog.lookup(cve_id)
    if entry:
        return entry.to_dict()
    return None
