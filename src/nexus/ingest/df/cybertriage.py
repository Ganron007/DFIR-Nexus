"""Cyber Triage scored timeline importer.

Parses JSONL, JSON-array, and CSV exports from Cyber Triage. Each row
represents a host artifact with a ``Score`` field that maps to our severity
enum:

- ``Notable_Normal`` / ``Bad``  -> HIGH / CRITICAL
- ``LikelyNotable_Normal`` / ``Suspicious`` -> MEDIUM
- ``Normal`` / ``Good`` -> LOW / INFORMATIONAL
"""

from __future__ import annotations

import csv
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

_SCORE_SEVERITY_MAP: dict[str, Severity] = {
    "bad": Severity.CRITICAL,
    "notable_normal": Severity.HIGH,
    "notable": Severity.HIGH,
    "suspicious": Severity.MEDIUM,
    "likelynotable_normal": Severity.MEDIUM,
    "likelynotable": Severity.MEDIUM,
    "normal": Severity.LOW,
    "good": Severity.INFORMATIONAL,
}

_TYPE_KEYWORD_MAP: dict[str, ArtifactType] = {
    "process": ArtifactType.PROCESS,
    "file": ArtifactType.FILE,
    "registry": ArtifactType.REGISTRY,
    "network": ArtifactType.NETWORK,
    "dns": ArtifactType.DNS,
    "http": ArtifactType.HTTP,
    "auth": ArtifactType.AUTH,
    "logon": ArtifactType.AUTH,
    "browser": ArtifactType.UNKNOWN,
    "scheduled": ArtifactType.UNKNOWN,
    "service": ArtifactType.UNKNOWN,
    "prefetch": ArtifactType.UNKNOWN,
}


class CyberTriageImporter(Importer):
    """Parser for Cyber Triage scored timeline exports."""

    @classmethod
    def source_class(cls) -> ArtifactSource:
        return ArtifactSource.CYBERTRIAGE

    @classmethod
    def can_handle(cls, path: Path) -> bool:
        """Heuristic: filename contains 'cybertriage' or 'cyber_triage'."""
        if not path.is_file():
            return False
        name = path.name.lower()
        return "cybertriage" in name or "cyber_triage" in name

    def parse(self, path: Path) -> Iterator[Artifact]:
        """Yield Artifact objects from a Cyber Triage export."""
        suffix = path.suffix.lower()
        try:
            if suffix == ".csv":
                yield from self._parse_csv(path)
            else:
                yield from self._parse_json(path)
        except Exception:
            log.debug("Failed to parse Cyber Triage file %s", path, exc_info=True)

    def _parse_csv(self, path: Path) -> Iterator[Artifact]:
        """Parse a Cyber Triage CSV export."""
        with path.open("r", encoding="utf-8", errors="replace", newline="") as f:
            reader = csv.DictReader(f)
            for row_num, row in enumerate(reader, start=2):
                try:
                    yield self._row_to_artifact(row)
                except Exception:
                    log.debug(
                        "Skipping malformed Cyber Triage CSV row at %s:%d",
                        path,
                        row_num,
                        exc_info=True,
                    )

    def _parse_json(self, path: Path) -> Iterator[Artifact]:
        """Parse a Cyber Triage JSON/JSONL export."""
        suffix = path.suffix.lower()
        if suffix in (".jsonl", ".ndjson"):
            for _line_num, record in self.read_jsonl(path):
                try:
                    yield self._row_to_artifact(record)
                except Exception:
                    log.debug(
                        "Skipping malformed Cyber Triage record at %s:%d",
                        path,
                        _line_num,
                        exc_info=True,
                    )
        else:
            try:
                with path.open("r", encoding="utf-8", errors="replace") as f:
                    data = json.load(f)
            except (OSError, json.JSONDecodeError):
                log.debug("Cannot load JSON from %s", path, exc_info=True)
                return
            records = data if isinstance(data, list) else [data]
            for record in records:
                if isinstance(record, dict):
                    try:
                        yield self._row_to_artifact(record)
                    except Exception:
                        log.debug(
                            "Skipping malformed Cyber Triage JSON record",
                            exc_info=True,
                        )

    def _row_to_artifact(self, row: dict[str, Any]) -> Artifact:
        """Map a Cyber Triage row to an Artifact."""
        ts = self._extract_timestamp(row)
        severity = self._extract_severity(row)
        artifact_type = self._extract_type(row)
        host_name, user_name = self._extract_host_user(row)
        source_ip, dest_ip = self._extract_ips(row)
        description = self._extract_description(row)

        return Artifact(
            id=Artifact.new_id(),
            artifact_type=artifact_type,
            source=ArtifactSource.CYBERTRIAGE,
            timestamp=ts,
            severity=severity,
            host=host_name,
            user=user_name,
            source_ip=source_ip,
            dest_ip=dest_ip,
            process_name=row.get("ProcessName") or row.get("process_name"),
            process_id=self._safe_int(row.get("PID") or row.get("process_id")),
            command_line=row.get("CommandLine") or row.get("command_line"),
            file_path=row.get("FullPath") or row.get("Path") or row.get("file_path"),
            file_hash_md5=row.get("MD5") or row.get("md5"),
            file_hash_sha256=row.get("SHA256") or row.get("sha256"),
            description=description,
            raw=row,
            tags=self._build_tags(row),
        )

    def _extract_timestamp(self, row: dict[str, Any]) -> datetime:
        for key in ("Timestamp", "timestamp", "EventTime", "event_time", "time", "@timestamp"):
            ts = self.normalize_timestamp(row.get(key))
            if ts:
                return ts
        return datetime.now(UTC)

    def _extract_severity(self, row: dict[str, Any]) -> Severity:
        score = row.get("Score") or row.get("score") or row.get("Category") or row.get("category")
        if score is not None:
            norm = str(score).strip().lower().replace(" ", "").replace("-", "").replace("_", "")
            if norm in _SCORE_SEVERITY_MAP:
                return _SCORE_SEVERITY_MAP[norm]
            # Try partial match
            for key, sev in _SCORE_SEVERITY_MAP.items():
                if key in norm:
                    return sev
        return Severity.INFORMATIONAL

    def _extract_type(self, row: dict[str, Any]) -> ArtifactType:
        type_hint = str(
            row.get("Type")
            or row.get("type")
            or row.get("DataSource")
            or row.get("data_source")
            or row.get("ItemType")
            or row.get("item_type")
            or ""
        ).lower()
        for key, atype in _TYPE_KEYWORD_MAP.items():
            if key in type_hint:
                return atype
        return ArtifactType.UNKNOWN

    def _extract_host_user(
        self, row: dict[str, Any]
    ) -> tuple[str | None, str | None]:
        host = row.get("HostName") or row.get("host") or row.get("hostname")
        user = row.get("UserName") or row.get("user") or row.get("username")
        return (
            str(host) if host else None,
            str(user) if user else None,
        )

    def _extract_ips(
        self, row: dict[str, Any]
    ) -> tuple[str | None, str | None]:
        src = row.get("SourceIP") or row.get("src_ip") or row.get("source_ip")
        dst = row.get("DestIP") or row.get("dest_ip") or row.get("destination_ip")
        return (
            str(src) if src else None,
            str(dst) if dst else None,
        )

    def _extract_description(self, row: dict[str, Any]) -> str:
        parts: list[str] = []
        for key in ("Description", "description", "Details", "details", "Summary"):
            val = row.get(key)
            if val:
                parts.append(str(val))
                break
        # Append the type as context
        type_hint = row.get("Type") or row.get("type") or row.get("DataSource")
        if type_hint and not parts:
            parts.append(f"Cyber Triage {type_hint}")
        return " - ".join(parts) or "Cyber Triage artifact"

    def _build_tags(self, row: dict[str, Any]) -> list[str]:
        tags = ["cybertriage"]
        score = row.get("Score") or row.get("score")
        if score:
            tags.append(f"score:{score}")
        type_hint = row.get("Type") or row.get("type") or row.get("DataSource")
        if type_hint:
            tags.append(f"type:{type_hint}")
        return tags

    @staticmethod
    def _safe_int(value: Any) -> int | None:
        if value is None or value == "":
            return None
        try:
            return int(value)
        except (ValueError, TypeError):
            return None
