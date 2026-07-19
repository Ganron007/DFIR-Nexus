"""ThreatFox CSV importer.

Parses ThreatFox (abuse.ch) CSV exports. Each row has columns like
`first_seen_utc`, `ioc_value`, `ioc_type`, `threat_type`, `malware`,
`confidence_level`, etc.
"""

from __future__ import annotations

import csv
import logging
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

from nexus.ingest.base import Importer
from nexus.ingest.schemas import (
    Artifact,
    ArtifactSource,
    ArtifactType,
    Severity,
)

log = logging.getLogger(__name__)


class ThreatFoxImporter(Importer):
    """Parser for ThreatFox (abuse.ch) CSV exports."""

    @classmethod
    def source_class(cls) -> ArtifactSource:
        return ArtifactSource.THREATFOX

    @classmethod
    def can_handle(cls, path: Path) -> bool:
        """Heuristic: CSV with ThreatFox-specific columns."""
        if not path.is_file():
            return False
        if path.suffix.lower() != ".csv":
            return False
        try:
            with path.open("r", encoding="utf-8", errors="replace") as f:
                head = f.read(4096)
        except OSError:
            return False
        return (
            "ioc_value" in head
            and "threat_type" in head
            and ("malware" in head or "confidence_level" in head)
        )

    def parse(self, path: Path) -> Iterator[Artifact]:
        """Yield one Artifact per ThreatFox row."""
        with path.open("r", encoding="utf-8", errors="replace", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                yield self._row_to_artifact(row)

    def _row_to_artifact(self, row: dict[str, str]) -> Artifact:
        """Map a ThreatFox row to an Artifact."""
        ioc_value = row.get("ioc_value", "")
        ioc_type = row.get("ioc_type", "").lower()
        threat_type = row.get("threat_type", "")
        malware = row.get("malware", "")
        confidence = int(row.get("confidence_level", 0) or 0)
        first_seen = row.get("first_seen_utc", "")

        # Type mapping (ThreatFox uses "ip:port", "domain", "url", "sha256", etc.)
        artifact_type = ArtifactType.IOC
        file_hash_md5 = file_hash_sha1 = file_hash_sha256 = None
        source_ip = dest_ip = None
        if "sha256" in ioc_type:
            artifact_type = ArtifactType.MALWARE
            file_hash_sha256 = ioc_value
        elif "sha1" in ioc_type:
            artifact_type = ArtifactType.MALWARE
            file_hash_sha1 = ioc_value
        elif "md5" in ioc_type:
            artifact_type = ArtifactType.MALWARE
            file_hash_md5 = ioc_value
        elif ioc_type == "domain":
            artifact_type = ArtifactType.DNS
        elif ioc_type == "url":
            artifact_type = ArtifactType.HTTP
        elif ioc_type.startswith("ip"):
            artifact_type = ArtifactType.NETWORK
            source_ip = ioc_value.split(":")[0] if ":" in ioc_value else ioc_value
            dest_ip = source_ip

        # Severity
        severity = Severity.INFORMATIONAL
        if confidence >= 50:
            severity = Severity.MEDIUM
        if confidence >= 75:
            severity = Severity.HIGH
        if confidence >= 90:
            severity = Severity.CRITICAL

        ts = self.normalize_timestamp(first_seen) or datetime.now(UTC)

        return Artifact(
            id=Artifact.new_id(),
            artifact_type=artifact_type,
            source=ArtifactSource.THREATFOX,
            timestamp=ts,
            severity=severity,
            file_hash_md5=file_hash_md5,
            file_hash_sha1=file_hash_sha1,
            file_hash_sha256=file_hash_sha256,
            source_ip=source_ip,
            dest_ip=dest_ip,
            description=f"ThreatFox {ioc_type}={ioc_value} malware={malware} threat={threat_type}",
            raw=dict(row.items()),
            iocs=[ioc_value] if ioc_value else [],
            tags=[
                "threatfox",
                f"type.{ioc_type}" if ioc_type else "threatfox",
                f"malware.{malware.lower().replace(' ', '_')}" if malware else "threatfox",
            ],
        )
