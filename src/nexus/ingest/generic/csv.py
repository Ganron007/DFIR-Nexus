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
        ts_synthesized = ts is None
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
            # Render the row's VALUES, not its column names.
            #
            # This fallback used to join `row.keys()`, so every row of a CSV with
            # no message/Description column produced the identical string - the
            # header. The values survived in `raw` but `render_ingest_row` only
            # renders `description`/`details`, so the row was indexed and
            # unsearchable: an examiner feeding in a manual $LogFile export could
            # query for the path they had just parsed and get zero hits.
            #
            # `key=value` keeps the column context, and empty values are skipped
            # so a sparse row still reads.
            pairs = [f"{k}={row[k]}" for k in row if row[k] not in (None, "")]
            description = "CSV record: " + "; ".join(pairs)

        return Artifact(
            id=Artifact.new_id(),
            artifact_type=ArtifactType.UNKNOWN,
            source=ArtifactSource.GENERIC_CSV,
            timestamp=ts,
            ts_synthesized=ts_synthesized,
            severity=severity,
            host=host,
            user=user,
            source_ip=src_ip,
            dest_ip=dest_ip,
            description=str(description)[:500],
            raw=dict(row.items()),
            tags=["generic", "csv"],
        )
