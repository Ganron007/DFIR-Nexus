"""Generic CSV importer.

Fallback for CSV files that no specific importer recognizes. Uses the
same field-name heuristics as the JSONL importer.
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


class CSVImporter(Importer):
    """Fallback parser for arbitrary CSV files."""

    @classmethod
    def source_class(cls) -> ArtifactSource:
        return ArtifactSource.GENERIC_CSV

    @classmethod
    def can_handle(cls, path: Path) -> bool:
        """Accept any .csv file as a fallback."""
        if not path.is_file():
            return False
        return path.suffix.lower() == ".csv"

    def parse(self, path: Path) -> Iterator[Artifact]:
        """Yield Artifact objects from a generic CSV file."""
        with path.open("r", encoding="utf-8", errors="replace", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                yield self._row_to_artifact(row)

    def _row_to_artifact(self, row: dict[str, str]) -> Artifact:
        """Map a CSV row to an Artifact."""
        # Timestamp
        ts = None
        for key in ("@timestamp", "timestamp", "Timestamp", "time", "Time", "datetime", "Date", "_time", "TimeCreated"):
            if key in row and row[key]:
                ts = self.normalize_timestamp(row[key])
                if ts:
                    break
        if ts is None:
            ts = datetime.now(UTC)

        # Host / user
        host = None
        for key in ("host", "Host", "hostname", "Computer"):
            if key in row and row[key]:
                host = row[key]
                break
        user = None
        for key in ("user", "User", "username", "SubjectUserName"):
            if key in row and row[key]:
                user = row[key]
                break
        src_ip = row.get("src_ip") or row.get("source_ip")
        dest_ip = row.get("dest_ip") or row.get("destination_ip")

        # Severity
        severity = Severity.INFORMATIONAL
        for key in ("severity", "Severity", "level", "Level"):
            if key in row and row[key]:
                severity = Severity.normalize(row[key])
                break

        # Description
        description = row.get("message") or row.get("Message") or row.get("Description") or row.get("msg") or row.get("Details") or ""
        if not description:
            description = f"CSV record: {', '.join(list(row.keys())[:5])}"

        return Artifact(
            id=Artifact.new_id(),
            artifact_type=ArtifactType.UNKNOWN,
            source=ArtifactSource.GENERIC_CSV,
            timestamp=ts,
            severity=severity,
            host=host,
            user=user,
            source_ip=src_ip,
            dest_ip=dest_ip,
            description=str(description)[:500],
            raw=dict(row.items()),
            tags=["generic", "csv"],
        )
