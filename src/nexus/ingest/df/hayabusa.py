"""Hayabusa CSV importer.

Parses Hayabusa's CSV output (`hayabusa csv`). The CSV has a header row
and contains columns like `Timestamp`, `Computer`, `EventID`, `Channel`,
`Level`, `RuleTitle`, `Details`, `MITRE ATT&CK`, `EventID Description`.
"""

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


class HayabusaImporter(Importer):
    """Parser for Hayabusa's CSV output."""

    # Hayabusa uses these level values: critical, high, medium, low, info
    LEVEL_MAP: ClassVar[dict[str, Severity]] = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "informational": Severity.INFORMATIONAL,
        "info": Severity.INFORMATIONAL,
    }

    @classmethod
    def source_class(cls) -> ArtifactSource:
        return ArtifactSource.HAYABUSA

    @classmethod
    def can_handle(cls, path: Path) -> bool:
        """Heuristic: CSV with Hayabusa-specific columns."""
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
            "RuleTitle" in head
            and "EventID" in head
            and ("Computer" in head or "Channel" in head)
        )

    def parse(self, path: Path) -> Iterator[Artifact]:
        """Yield Artifact objects from a Hayabusa CSV."""
        with path.open("r", encoding="utf-8", errors="replace", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                artifact = self._row_to_artifact(row)
                if artifact is not None:
                    yield artifact

    def _row_to_artifact(self, row: dict[str, str]) -> Artifact | None:
        """Map a Hayabusa CSV row to an Artifact."""
        # Timestamp: ISO 8601 or "2024-01-01 12:34:56.789 +09:00"
        ts_str = row.get("Timestamp", "")
        ts = self.normalize_timestamp(ts_str)
        if ts is None:
            ts = datetime.now(UTC)

        # Severity from Level
        level = row.get("Level", "").strip().lower()
        severity = self.LEVEL_MAP.get(level, Severity.INFORMATIONAL)

        # Build MITRE technique IDs
        mitre_field = row.get("MITRE ATT&CK", "") or row.get("MITRE Tactic", "")
        techniques = []
        if mitre_field:
            # Hayabusa format: "T1003, T1059.001 - Command and Scripting Interpreter"
            for part in mitre_field.split(","):
                part = part.strip()
                for token in part.split():
                    token = token.strip(" .,;-")
                    if token.upper().startswith("T") and any(c.isdigit() for c in token):
                        techniques.append(token.upper())

        # Map event type
        event_id = row.get("EventID", "")
        artifact_type = self._event_id_to_type(event_id, row.get("Channel", ""))

        # Description
        rule_title = row.get("RuleTitle", "")
        details = row.get("Details", "")
        description = rule_title or details
        if rule_title and details and rule_title != details:
            description = f"{rule_title} - {details[:200]}"

        return Artifact(
            id=Artifact.new_id(),
            artifact_type=artifact_type,
            source=ArtifactSource.HAYABUSA,
            timestamp=ts,
            severity=severity,
            host=row.get("Computer") or None,
            user=row.get("User") or None,
            action=event_id or None,
            description=description[:1000] if description else f"Hayabusa EventID {event_id}",
            raw=dict(row.items()),
            technique_ids=techniques,
            tags=["hayabusa", f"eventid.{event_id}"] if event_id else ["hayabusa"],
        )

    @staticmethod
    def _event_id_to_type(event_id: str, channel: str) -> ArtifactType:
        """Map a Windows Event ID to an ArtifactType."""
        try:
            eid = int(event_id)
        except (ValueError, TypeError):
            return ArtifactType.UNKNOWN

        # RDP events (evaluated first because 4624/4778 overlap with AUTH)
        if eid in (1149, 4624, 4778):
            return ArtifactType.RDP
        # Authentication events
        if eid in (4624, 4625, 4634, 4647, 4648, 4672, 4720, 4722, 4723, 4724, 4725, 4726, 4728, 4729, 4730, 4731, 4732, 4733, 4734, 4735, 4736, 4737, 4738, 4740, 4756, 4757, 4768, 4769, 4770, 4771, 4776, 4778, 4779):
            return ArtifactType.AUTH
        # Process events
        if eid in (4688, 4689, 4692, 4696, 4697, 4698, 4700, 4701, 4702, 5156, 5158):
            return ArtifactType.PROCESS
        # File events
        if eid in (4663, 4664, 4670, 5145):
            return ArtifactType.FILE
        # Registry events
        if eid in (4657, 4656):
            return ArtifactType.REGISTRY
        # PowerShell events
        if eid in (4103, 4104):
            return ArtifactType.POWERSHELL
        # Service events
        if eid in (7034, 7035, 7036, 7040, 7045):
            return ArtifactType.PROCESS
        return ArtifactType.UNKNOWN
