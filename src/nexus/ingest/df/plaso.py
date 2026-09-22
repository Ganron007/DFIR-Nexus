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
        head_lower = head.lower()
        # psort "detailed" export
        has_plaso_columns = "source_long" in head_lower or "parser" in head_lower or "display_name" in head_lower
        if has_plaso_columns and ("datetime" in head_lower or "timestamp_desc" in head_lower):
            return True
        # psort l2tcsv export (date,time,timezone,MACB,source,sourcetype,...)
        first_line = head.splitlines()[0].lower() if head.splitlines() else ""
        l2tcsv = (
            "date" in first_line
            and "time" in first_line
            and ("macb" in first_line or "sourcetype" in first_line or "timestamp_desc" in first_line)
        )
        return bool(l2tcsv)

    def parse(self, path: Path) -> Iterator[Artifact]:
        with path.open("r", encoding="utf-8", errors="replace", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                artifact = self._row_to_artifact(row)
                if artifact is not None:
                    yield artifact

    def _row_to_artifact(self, row: dict[str, str]) -> Artifact | None:
        # l2tcsv carries date + time as separate columns
        ts_str = row.get("datetime") or row.get("timestamp") or row.get("time", "")
        if not row.get("datetime") and row.get("date") and row.get("time"):
            ts_str = f"{row.get('date', '').strip()} {row.get('time', '').strip()}"
        ts = self.normalize_timestamp(ts_str)
        if ts is None:
            ts = self._parse_l2t(ts_str)
        ts_synthesized = ts is None
        if ts is None:
            ts = datetime.now(UTC)

        # l2tcsv: short/desc; detailed: message/display_name/source_long
        message = (
            row.get("message")
            or row.get("display_name")
            or row.get("short")
            or row.get("desc")
            or row.get("source_long", "")
        )
        if not message.strip():
            return None

        source_long = row.get("source_long") or row.get("source", "")
        parser = row.get("parser") or row.get("sourcetype") or row.get("format", "")
        host = row.get("hostname") or row.get("host") or row.get("computer", "")
        user = row.get("username") or row.get("user", "")

        severity = Severity.INFORMATIONAL
        desc_lower = (row.get("timestamp_desc") or row.get("type") or "").lower()
        for hint, sev in self.LEVEL_HINTS.items():
            if hint in desc_lower:
                severity = sev
                break

        return Artifact(
            id=Artifact.new_id(),
            timestamp=ts,
            ts_synthesized=ts_synthesized,
            source=ArtifactSource.PLASO,
            artifact_type=ArtifactType.UNKNOWN,
            severity=severity,
            description=f"{source_long}: {message}"[:500],
            host=host or None,
            user=user or None,
            raw=dict(row),
            tags=[parser] if parser else [],
        )

    @staticmethod
    def _parse_l2t(value: str) -> datetime | None:
        """l2tcsv timestamps: 09/27/2020 + 14:43:18 (US date format)."""
        v = (value or "").strip()
        if not v:
            return None
        for fmt in ("%m/%d/%Y %H:%M:%S", "%Y-%m-%d %H:%M:%S", "%m/%d/%Y %H:%M"):
            try:
                return datetime.strptime(v, fmt).replace(tzinfo=UTC)
            except ValueError:
                continue
        return None
