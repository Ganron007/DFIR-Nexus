"""Azure activity log importer.

Parses Azure activity log JSON exports. The standard shape is a list of
records (or a single record) with fields like `eventTimestamp`, `operationName`,
`caller`, `resourceId`, `level`, etc.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from nexus.ingest.base import Importer
from nexus.ingest.schemas import (
    Artifact,
    ArtifactSource,
    ArtifactType,
    Severity,
)

log = logging.getLogger(__name__)


class AzureImporter(Importer):
    """Parser for Azure activity log JSON exports."""

    @classmethod
    def source_class(cls) -> ArtifactSource:
        return ArtifactSource.AZURE

    @classmethod
    def can_handle(cls, path: Path) -> bool:
        """Heuristic: JSON with Azure activity log signature."""
        if not path.exists():
            return False
        target = path if path.is_file() else next(iter(path.rglob("*.json")), None) if path.is_dir() else None
        if target is None:
            return False
        try:
            with target.open("r", encoding="utf-8", errors="replace") as f:
                head = f.read(8192)
        except OSError:
            return False
        return (
            "operationName" in head
            and ("caller" in head or "eventTimestamp" in head)
        ) or "azure" in head.lower() and "activity" in head.lower()

    def parse(self, path: Path) -> Iterator[Artifact]:
        """Yield one Artifact per Azure activity record."""
        files = [path] if path.is_file() else sorted(path.rglob("*.json"))
        for file in files:
            try:
                with file.open("r", encoding="utf-8", errors="replace") as f:
                    data = json.load(f)
            except (OSError, json.JSONDecodeError):
                continue
            records = self._extract_records(data)
            for record in records:
                if isinstance(record, dict):
                    yield self._record_to_artifact(record, file)

    @staticmethod
    def _extract_records(data: Any) -> list[dict[str, Any]]:
        """Pull records from various Azure export shapes."""
        if isinstance(data, list):
            return [r for r in data if isinstance(r, dict)]
        if isinstance(data, dict):
            for key in ("value", "records", "Records", "events"):
                if key in data and isinstance(data[key], list):
                    return [r for r in data[key] if isinstance(r, dict)]
            if "operationName" in data:
                return [data]
        return []

    def _record_to_artifact(self, record: dict[str, Any], file: Path) -> Artifact:
        """Map an Azure activity log record to an Artifact."""
        ts = self.normalize_timestamp(record.get("eventTimestamp") or record.get("time"))
        if ts is None:
            ts = datetime.now(UTC)

        operation = str(record.get("operationName", {}).get("value", "")) if isinstance(record.get("operationName"), dict) else str(record.get("operationName", ""))
        caller = str(record.get("caller", ""))
        level = str(record.get("level", "Informational"))
        resource_id = str(record.get("resourceId", ""))
        status = str(record.get("status", {}).get("value", "")) if isinstance(record.get("status"), dict) else str(record.get("status", ""))

        # Severity
        severity = Severity.INFORMATIONAL
        if "Error" in level or "Critical" in level:
            severity = Severity.HIGH
        if "Failed" in status or "Error" in status:
            severity = max(severity, Severity.MEDIUM, key=lambda s: ["informational", "low", "medium", "high", "critical"].index(s.value))

        # Extract user from caller
        user = None
        if "@" in caller or caller:
            user = caller

        # Resource type from resourceId
        resource_type = ""
        if "/providers/" in resource_id:
            resource_type = resource_id.split("/providers/")[1].split("/")[0] if "/providers/" in resource_id else ""

        return Artifact(
            id=Artifact.new_id(),
            artifact_type=ArtifactType.NETWORK,
            source=ArtifactSource.AZURE,
            timestamp=ts,
            severity=severity,
            user=user,
            description=f"Azure {operation} ({status or 'Succeeded'})",
            raw=record,
            tags=[
                "azure",
                f"op.{operation.lower()}" if operation else "azure",
                f"resource.{resource_type.lower()}" if resource_type else "azure",
            ],
        )
