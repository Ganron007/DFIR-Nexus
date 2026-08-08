"""AbuseIPDB JSON importer.

Parses AbuseIPDB API responses (IP reports). The standard response has
a `data` object with `ipAddress`, `abuseConfidenceScore`, `countryCode`,
`usageType`, `totalReports`, etc.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from nexus.ingest.base import Importer, ImporterError
from nexus.ingest.schemas import (
    Artifact,
    ArtifactSource,
    ArtifactType,
    Severity,
)

log = logging.getLogger(__name__)


class AbuseIPDBImporter(Importer):
    """Parser for AbuseIPDB JSON exports."""

    @classmethod
    def source_class(cls) -> ArtifactSource:
        return ArtifactSource.ABUSEIPDB

    @classmethod
    def can_handle(cls, path: Path) -> bool:
        """Heuristic: JSON with AbuseIPDB signature (abuseConfidenceScore)."""
        if not path.is_file():
            return False
        name = path.name.lower()
        if not (name.endswith(".json") or name.endswith(".jsonl")):
            return False
        try:
            with path.open("r", encoding="utf-8", errors="replace") as f:
                head = f.read(8192)
        except OSError:
            return False
        return (
            "abuseipdb" in head.lower()
            or "abuseConfidenceScore" in head
            or ("ipAddress" in head and "totalReports" in head)
        )

    def parse(self, path: Path) -> Iterator[Artifact]:
        """Yield one Artifact per AbuseIPDB record."""
        try:
            with path.open("r", encoding="utf-8", errors="replace") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            raise ImporterError(f"Invalid JSON in {path.name}: {e}") from e
        records = self._extract_records(data)
        for record in records:
            yield self._record_to_artifact(record)

    @staticmethod
    def _extract_records(data: Any) -> list[dict[str, Any]]:
        """Pull records from various AbuseIPDB export shapes."""
        if isinstance(data, list):
            return [r for r in data if isinstance(r, dict)]
        if isinstance(data, dict):
            if "data" in data and isinstance(data["data"], list):
                return [r for r in data["data"] if isinstance(r, dict)]
            if "data" in data and isinstance(data["data"], dict):
                return [data["data"]]
            if "ipAddress" in data and "abuseConfidenceScore" in data:
                return [data]
        return []

    def _record_to_artifact(self, record: dict[str, Any]) -> Artifact:
        """Map an AbuseIPDB record to an Artifact."""
        ip = str(record.get("ipAddress", ""))
        score = int(record.get("abuseConfidenceScore", 0) or 0)
        total_reports = int(record.get("totalReports", 0) or 0)
        country = str(record.get("countryCode", ""))
        usage_type = str(record.get("usageType", ""))
        isp = str(record.get("isp", ""))
        last_reported = record.get("lastReportedAt")

        # Severity
        severity = Severity.INFORMATIONAL
        if score >= 25:
            severity = Severity.LOW
        if score >= 50:
            severity = Severity.MEDIUM
        if score >= 75:
            severity = Severity.HIGH
        if score >= 90:
            severity = Severity.CRITICAL

        ts = self.normalize_timestamp(last_reported) or datetime.now(UTC)

        return Artifact(
            id=Artifact.new_id(),
            artifact_type=ArtifactType.NETWORK,
            source=ArtifactSource.ABUSEIPDB,
            timestamp=ts,
            severity=severity,
            source_ip=ip,
            dest_ip=ip,
            description=f"AbuseIPDB {ip} score={score}% reports={total_reports} country={country} usage={usage_type} isp={isp}",
            raw=record,
            iocs=[ip] if ip else [],
            tags=["abuseipdb", f"score.{score}", f"country.{country.lower()}"],
        )
