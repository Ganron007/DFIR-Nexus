"""Splunk CSV/JSON exporter.

Parses Splunk search results exported as CSV or JSON. The Splunk export
typically has columns like `_time`, `host`, `source`, `sourcetype`, plus
the user's selected fields.
"""

from __future__ import annotations

import csv
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


class SplunkImporter(Importer):
    """Parser for Splunk search-export CSV/JSON files."""

    @classmethod
    def source_class(cls) -> ArtifactSource:
        return ArtifactSource.SPLUNK

    @classmethod
    def can_handle(cls, path: Path) -> bool:
        """Heuristic: CSV/JSON with a `_time` column or field."""
        if not path.is_file():
            return False
        name = path.name.lower()
        if not (name.endswith(".csv") or name.endswith(".json") or name.endswith(".jsonl")):
            return False
        try:
            with path.open("r", encoding="utf-8", errors="replace") as f:
                head = f.read(4096)
        except OSError:
            return False
        return bool("_time" in head or "sourcetype" in head)

    def parse(self, path: Path) -> Iterator[Artifact]:
        """Yield Artifact objects from a Splunk export."""
        if path.suffix.lower() == ".csv":
            yield from self._parse_csv(path)
        else:
            yield from self._parse_jsonl(path)

    def _parse_csv(self, path: Path) -> Iterator[Artifact]:
        """Parse a Splunk CSV export."""
        with path.open("r", encoding="utf-8", errors="replace", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                yield self._row_to_artifact(row)

    def _parse_jsonl(self, path: Path) -> Iterator[Artifact]:
        """Parse a Splunk JSONL export."""
        for _n, record in self.read_jsonl(path):
            yield self._row_to_artifact(record)

    def _row_to_artifact(self, row: dict[str, Any]) -> Artifact:
        """Map a Splunk row to an Artifact."""
        # Splunk's _time is epoch seconds (or with fractions)
        ts = self.normalize_timestamp(row.get("_time"))
        if ts is None:
            ts = datetime.now(UTC)

        # Splunk severity: 1=informational, 5=critical
        severity = Severity.INFORMATIONAL
        if "severity" in row:
            raw_sev = row["severity"]
            try:
                sev_int = int(raw_sev)
                if 1 <= sev_int <= 5:
                    splunk_map = {1: "informational", 2: "low", 3: "medium", 4: "high", 5: "critical"}
                    severity = Severity.normalize(splunk_map[sev_int])
                else:
                    severity = Severity.normalize(raw_sev)
            except (ValueError, TypeError):
                severity = Severity.normalize(raw_sev)

        # Sourcetype hint
        sourcetype = str(row.get("sourcetype", "")).lower()
        artifact_type = self._sourcetype_to_artifact(sourcetype)

        # Build description
        description = ""
        for key in ("msg", "message", "event_message", "EventDescription"):
            if key in row and row[key]:
                description = str(row[key])
                break

        return Artifact(
            id=Artifact.new_id(),
            artifact_type=artifact_type,
            source=ArtifactSource.SPLUNK,
            timestamp=ts,
            severity=severity,
            host=str(row.get("host")) if row.get("host") else None,
            user=str(row.get("user")) if row.get("user") else None,
            source_ip=str(row.get("src_ip")) if row.get("src_ip") else None,
            dest_ip=str(row.get("dest_ip")) if row.get("dest_ip") else None,
            process_name=str(row.get("process_name")) if row.get("process_name") else None,
            process_id=self._safe_int(row.get("process_id")),
            command_line=str(row.get("command_line")) if row.get("command_line") else None,
            file_path=str(row.get("file_path")) if row.get("file_path") else None,
            description=description or f"Splunk {sourcetype or 'event'}",
            raw={k: str(v) for k, v in row.items()},
            tags=[f"splunk.{sourcetype}"] if sourcetype else ["splunk"],
        )

    @staticmethod
    def _sourcetype_to_artifact(sourcetype: str) -> ArtifactType:
        """Map a Splunk sourcetype to an ArtifactType."""
        if not sourcetype:
            return ArtifactType.UNKNOWN
        if "wineventlog" in sourcetype or "windows" in sourcetype:
            # Windows event logs - leave to evtx importer for richer mapping
            return ArtifactType.UNKNOWN
        if "suricata" in sourcetype:
            return ArtifactType.NETWORK
        if "zeek" in sourcetype:
            return ArtifactType.NETWORK
        if "syslog" in sourcetype:
            return ArtifactType.UNKNOWN
        if "ps" in sourcetype or "powershell" in sourcetype:
            return ArtifactType.POWERSHELL
        if "dns" in sourcetype:
            return ArtifactType.DNS
        if "http" in sourcetype or "access" in sourcetype:
            return ArtifactType.HTTP
        return ArtifactType.UNKNOWN

    @staticmethod
    def _safe_int(value: Any) -> int | None:
        if value is None or value == "":
            return None
        try:
            return int(value)
        except (ValueError, TypeError):
            return None
