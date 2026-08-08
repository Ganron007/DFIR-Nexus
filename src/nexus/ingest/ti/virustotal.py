"""VirusTotal JSON importer.

Parses VirusTotal v3 API responses (file, URL, IP, domain, hash reports).
Each record is the `data.attributes` of a VT object.
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


class VirusTotalImporter(Importer):
    """Parser for VirusTotal v3 API JSON exports."""

    @classmethod
    def source_class(cls) -> ArtifactSource:
        return ArtifactSource.VIRUSTOTAL

    @classmethod
    def can_handle(cls, path: Path) -> bool:
        """Heuristic: JSON with VT shape (data.attributes, last_analysis_stats, etc.)."""
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
            "virustotal" in head.lower()
            or ("last_analysis_stats" in head and "data" in head)
            or ("popular_threat_classification" in head)
        )

    def parse(self, path: Path) -> Iterator[Artifact]:
        """Yield one Artifact per VT report."""
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
        """Pull reports from various VT export shapes."""
        if isinstance(data, list):
            return [r for r in data if isinstance(r, dict)]
        if isinstance(data, dict):
            # VT v3: {"data": {"id": ..., "attributes": {...}}, ...}
            if "data" in data and isinstance(data["data"], dict):
                return [data["data"]]
            # Plain attributes
            if "last_analysis_stats" in data or "popular_threat_classification" in data:
                return [data]
            # Batch
            for key in ("data", "results", "items"):
                if key in data and isinstance(data[key], list):
                    return [r for r in data[key] if isinstance(r, dict)]
        return []

    def _record_to_artifact(self, record: dict[str, Any]) -> Artifact:
        """Map a VT record to an Artifact."""
        attrs = record.get("attributes", record)

        # Indicator value: id or any of the indicators
        indicator = str(record.get("id", ""))
        # last_analysis_stats gives us the verdict
        stats = attrs.get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)
        undetected = int(stats.get("undetected", 0) or 0)
        total = malicious + suspicious + undetected

        # Severity based on detection ratio
        severity = Severity.INFORMATIONAL
        if malicious > 0:
            severity = Severity.MEDIUM
        if malicious >= 5:
            severity = Severity.HIGH
        if malicious >= 15:
            severity = Severity.CRITICAL

        # Type from indicator prefix (VT v3 IDs)
        artifact_type = ArtifactType.IOC
        file_hash_md5: str | None = None
        file_hash_sha1: str | None = None
        file_hash_sha256: str | None = None
        if indicator.startswith("f") and len(indicator) == 64:
            artifact_type = ArtifactType.MALWARE
            file_hash_sha256 = indicator
        elif indicator.startswith("u"):
            artifact_type = ArtifactType.HTTP
        elif len(indicator) == 32:
            file_hash_md5 = indicator
        elif len(indicator) == 40:
            file_hash_sha1 = indicator
        elif len(indicator) == 64:
            file_hash_sha256 = indicator

        # Pull name/type from popular_threat_classification
        description = attrs.get("meaningful_name") or attrs.get("popular_threat_classification", {}).get("suggested_threat_label") or indicator

        # Timestamps
        ts = self.normalize_timestamp(attrs.get("last_analysis_date") or attrs.get("creation_date") or attrs.get("first_submission_date"))
        if ts is None:
            ts = datetime.now(UTC)

        return Artifact(
            id=Artifact.new_id(),
            artifact_type=artifact_type,
            source=ArtifactSource.VIRUSTOTAL,
            timestamp=ts,
            severity=severity,
            file_hash_md5=file_hash_md5,
            file_hash_sha1=file_hash_sha1,
            file_hash_sha256=file_hash_sha256,
            description=f"VT {description} ({malicious}/{total} malicious)",
            raw=record,
            iocs=[indicator] if indicator else [],
            tags=["virustotal", f"malicious.{malicious}", f"verdict.{'malicious' if malicious > 0 else 'clean'}"],
        )
