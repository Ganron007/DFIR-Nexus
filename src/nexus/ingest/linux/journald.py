"""journald -o json importer.

Parses systemd journal entries exported via ``journalctl -o json`` or
``journalctl -o json-pretty``. Each entry contains fields like
``PRIORITY``, ``SYSLOG_IDENTIFIER``, ``__REALTIME_TIMESTAMP``,
``_PID``, ``_UID``, ``MESSAGE``, ``_HOSTNAME``, and ``_COMM``.
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


class JournaldImporter(Importer):
    """Parser for systemd journalctl -o json exports."""

    @classmethod
    def source_class(cls) -> ArtifactSource:
        return ArtifactSource.SYSLOG

    @classmethod
    def can_handle(cls, path: Path) -> bool:
        """Heuristic: filename contains 'journal', or JSON with PRIORITY +
        __REALTIME_TIMESTAMP keys."""
        if not path.is_file():
            return False
        name = path.name.lower()
        if "journal" in name:
            return True
        if not (name.endswith(".json") or name.endswith(".jsonl")):
            return False
        try:
            with path.open("r", encoding="utf-8", errors="replace") as f:
                head = f.read(8192)
        except OSError:
            return False
        return '"PRIORITY"' in head and '"__REALTIME_TIMESTAMP"' in head

    def parse(self, path: Path) -> Iterator[Artifact]:
        """Yield one Artifact per journal entry."""
        try:
            if path.suffix.lower() == ".jsonl":
                yield from self._parse_jsonl(path)
            else:
                yield from self._parse_json(path)
        except Exception:
            log.warning("Failed to parse journald file %s", path, exc_info=True)

    def _parse_json(self, path: Path) -> Iterator[Artifact]:
        """Parse a JSON file (single object or array)."""
        with path.open("r", encoding="utf-8", errors="replace") as f:
            data = json.load(f)
        entries = self._extract_entries(data)
        for entry in entries:
            artifact = self._entry_to_artifact(entry)
            if artifact is not None:
                yield artifact

    def _parse_jsonl(self, path: Path) -> Iterator[Artifact]:
        """Parse a JSONL file."""
        for _n, entry in self.read_jsonl(path):
            artifact = self._entry_to_artifact(entry)
            if artifact is not None:
                yield artifact

    @staticmethod
    def _extract_entries(data: Any) -> list[dict[str, Any]]:
        """Normalize various journald export shapes."""
        if isinstance(data, list):
            return [e for e in data if isinstance(e, dict)]
        if isinstance(data, dict):
            if "PRIORITY" in data and "__REALTIME_TIMESTAMP" in data:
                return [data]
            for key in ("entries", "data"):
                if key in data and isinstance(data[key], list):
                    return [e for e in data[key] if isinstance(e, dict)]
        return []

    @staticmethod
    def _priority_to_severity(priority: str | int | None) -> Severity:
        """Map journald PRIORITY (0-7) to Severity.

        Syslog priorities:
        0=Emergency, 1=Alert, 2=Critical, 3=Error,
        4=Warning, 5=Notice, 6=Informational, 7=Debug
        """
        if priority is None:
            return Severity.INFORMATIONAL
        try:
            p = int(priority)
        except (ValueError, TypeError):
            return Severity.INFORMATIONAL
        if p <= 0:
            return Severity.CRITICAL
        if p <= 2:
            return Severity.CRITICAL
        if p == 3:
            return Severity.HIGH
        if p == 4:
            return Severity.MEDIUM
        if p == 5:
            return Severity.LOW
        return Severity.INFORMATIONAL

    def _entry_to_artifact(self, entry: dict[str, Any]) -> Artifact | None:
        """Convert a single journal entry to an Artifact."""
        try:
            priority = entry.get("PRIORITY")
            severity = self._priority_to_severity(priority)

            # Timestamp: __REALTIME_TIMESTAMP is microseconds since epoch
            raw_ts = entry.get("__REALTIME_TIMESTAMP")
            ts = None
            if raw_ts is not None:
                try:
                    ts_val = int(raw_ts)
                    if ts_val > 1e15:  # microseconds
                        ts_val = ts_val / 1_000_000
                    ts = datetime.fromtimestamp(ts_val, tz=UTC)
                except (ValueError, OverflowError, OSError):
                    pass
            if ts is None:
                ts = self.normalize_timestamp(
                    entry.get("_SOURCE_REALTIME_TIMESTAMP") or entry.get("__MONOTONIC_TIMESTAMP")
                )
            if ts is None:
                ts = datetime.now(UTC)

            hostname = str(entry.get("_HOSTNAME", "")) or None
            identifier = str(entry.get("SYSLOG_IDENTIFIER", "")) or ""
            comm = str(entry.get("_COMM", "")) or ""
            message = str(entry.get("MESSAGE", "")) or ""
            pid = None
            raw_pid = entry.get("_PID") or entry.get("SYSLOG_PID")
            if raw_pid is not None:
                try:
                    pid = int(raw_pid)
                except (ValueError, TypeError):
                    pass
            uid = entry.get("_UID")
            unit = str(entry.get("_SYSTEMD_UNIT", "")) or ""

            proc_name = comm or identifier or None

            tags = ["journald", "systemd"]
            if unit:
                tags.append(f"unit.{unit}")
            if identifier:
                tags.append(f"id.{identifier}")

            description = message or f"journald: {identifier or comm or 'entry'}"

            return Artifact(
                id=Artifact.new_id(),
                artifact_type=ArtifactType.UNKNOWN,
                source=ArtifactSource.SYSLOG,
                timestamp=ts,
                severity=severity,
                host=hostname,
                process_name=proc_name,
                process_id=pid,
                description=description,
                raw={k: str(v) for k, v in entry.items()},
                tags=tags,
            )
        except Exception:
            log.debug("Skipping malformed journald entry: %s", entry, exc_info=True)
            return None
