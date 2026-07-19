"""Plaso psort CSV importer (super-timeline export)."""

from __future__ import annotations

import csv
import logging
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import ClassVar

from nexus.ingest.base import Importer
from nexus.ingest.schemas import (
    Artifact,
    ArtifactSource,
    ArtifactType,
    Severity,
)

log = logging.getLogger(__name__)


class PlasoImporter(Importer):
    """Parser for Plaso `psort.py` CSV output."""

    LEVEL_HINTS: ClassVar[dict[str, Severity]] = {
        "critical": Severity.CRITICAL,
        "error": Severity.HIGH,
        "warning": Severity.MEDIUM,
        "info": Severity.INFORMATIONAL,
    }

    @classmethod
    def source_class(cls) -> ArtifactSource:
        return ArtifactSource.PLASO

    @classmethod
    def can_handle(cls, path: Path) -> bool:
        if not path.is_file() or path.suffix.lower() != ".csv":
            return False
        try:
            with path.open("r", encoding="utf-8", errors="replace") as f:
                head = f.read(4096)
        except OSError:
            return False
        has_plaso_columns = "source_long" in head or "parser" in head or "display_name" in head
        return bool(
            has_plaso_columns
            and ("datetime" in head or "timestamp_desc" in head)
        )

    def parse(self, path: Path) -> Iterator[Artifact]:
        with path.open("r", encoding="utf-8", errors="replace", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                artifact = self._row_to_artifact(row)
                if artifact is not None:
                    yield artifact

    def _row_to_artifact(self, row: dict[str, str]) -> Artifact | None:
        ts_str = row.get("datetime") or row.get("timestamp") or row.get("time", "")
        ts = self.normalize_timestamp(ts_str) or datetime.now(UTC)

        message = row.get("message") or row.get("display_name") or row.get("source_long", "")
        if not message.strip():
            return None

        source_long = row.get("source_long") or row.get("source", "")
        parser = row.get("parser", "")
        host = row.get("hostname") or row.get("host") or row.get("computer", "")
        user = row.get("username") or row.get("user", "")

        severity = Severity.INFORMATIONAL
        desc_lower = (row.get("timestamp_desc") or "").lower()
        for hint, sev in self.LEVEL_HINTS.items():
            if hint in desc_lower:
                severity = sev
                break

        return Artifact(
            id=Artifact.new_id(),
            timestamp=ts,
            source=ArtifactSource.PLASO,
            artifact_type=ArtifactType.UNKNOWN,
            severity=severity,
            description=f"{source_long}: {message}"[:500],
            host=host or None,
            user=user or None,
            raw=dict(row),
            tags=[parser] if parser else [],
        )
