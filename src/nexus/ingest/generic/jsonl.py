"""Generic JSONL importer.

Fallback for JSONL files that no specific importer recognizes. Each
record is wrapped in an Artifact with the raw data preserved.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, ClassVar

from nexus.ingest.base import Importer
from nexus.ingest.schemas import (
    Artifact,
    ArtifactSource,
    ArtifactType,
    Severity,
)

log = logging.getLogger(__name__)


class JSONLImporter(Importer):
    """Fallback parser for arbitrary JSONL files."""

    # Common field names to use for the primary key
    TIMESTAMP_FIELDS: ClassVar[tuple[str, ...]] = (
        "@timestamp", "timestamp", "Timestamp", "time", "Time", "datetime",
        "Date", "date", "EventTime", "TimeCreated", "created", "Created",
    )
    HOST_FIELDS: ClassVar[tuple[str, ...]] = (
        "host", "Host", "hostname", "Hostname", "computer", "Computer",
        "src_host", "agent", "device", "host_name", "host.name",
    )
    USER_FIELDS: ClassVar[tuple[str, ...]] = (
        "user", "User", "username", "Username", "user_name", "user.name",
        "SubjectUserName", "account", "Account", "TargetUserName",
    )
    SRC_IP_FIELDS: ClassVar[tuple[str, ...]] = (
        "src_ip", "source_ip", "sourceIp", "source.ip", "client_ip",
        "clientIp", "id.orig_h", "SourceAddress",
    )
    DEST_IP_FIELDS: ClassVar[tuple[str, ...]] = (
        "dest_ip", "destination_ip", "destIp", "destination.ip",
        "server_ip", "serverIp", "id.resp_h", "DestinationAddress",
    )

    @classmethod
    def source_class(cls) -> ArtifactSource:
        return ArtifactSource.GENERIC_JSONL

    @classmethod
    def can_handle(cls, path: Path) -> bool:
        """Accept any .jsonl/.ndjson file as a fallback."""
        if not path.is_file():
            return False
        name = path.name.lower()
        return name.endswith(".jsonl") or name.endswith(".ndjson")

    def parse(self, path: Path) -> Iterator[Artifact]:
        """Yield Artifact objects from a generic JSONL file."""
        for _n, record in self.read_jsonl(path):
            if not isinstance(record, dict):
                continue
            yield self._record_to_artifact(record)

    def _record_to_artifact(self, record: dict[str, Any]) -> Artifact:
        """Map a generic record to an Artifact with best-effort field mapping."""
        ts = None
        for field in self.TIMESTAMP_FIELDS:
            if field in record:
                ts = self.normalize_timestamp(record[field])
                if ts:
                    break
        if ts is None:
            ts = datetime.now(UTC)

        host = self._first_field(record, self.HOST_FIELDS)
        user = self._first_field(record, self.USER_FIELDS)
        src_ip = self._first_field(record, self.SRC_IP_FIELDS)
        dest_ip = self._first_field(record, self.DEST_IP_FIELDS)

        # Severity
        severity = Severity.INFORMATIONAL
        for key in ("severity", "Severity", "level", "Level", "alert.severity"):
            if key in record:
                severity = Severity.normalize(record[key])
                break

        # Description: prefer message/event fields
        description = ""
        for key in ("message", "Message", "event_message", "Description",
                    "msg", "details", "Details", "event", "name"):
            if key in record and record[key]:
                val = record[key]
                description = str(val)[:500]
                break

        return Artifact(
            id=Artifact.new_id(),
            artifact_type=ArtifactType.UNKNOWN,
            source=ArtifactSource.GENERIC_JSONL,
            timestamp=ts,
            severity=severity,
            host=host,
            user=user,
            source_ip=src_ip,
            dest_ip=dest_ip,
            description=description or "Generic JSONL record",
            raw=record,
            tags=["generic", "jsonl"],
        )

    @staticmethod
    def _first_field(record: dict[str, Any], field_names: tuple[str, ...]) -> str | None:
        """Return the first non-empty value for any of the given field names."""
        for name in field_names:
            if name in record and record[name] not in (None, "", "-"):
                val = record[name]
                if isinstance(val, dict):
                    # Look for nested .name or .id
                    for sub in ("name", "id", "ip", "host", "hostname"):
                        if sub in val and val[sub]:
                            return str(val[sub])
                return str(val)
        return None
