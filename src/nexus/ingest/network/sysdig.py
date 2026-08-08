"""Sysdig/Falco alert importer.

Parses Sysdig Secure or Falco JSON alert exports. Falco rules emit
events with fields like ``rule``, ``priority``, ``output``, ``output_fields``,
and ``time``. Priority maps to Falco's severity levels: Emergency, Alert,
Critical, Error, Warning, Notice, Informational, Debug.
"""

from __future__ import annotations

import contextlib
import json
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


class SysdigImporter(Importer):
    """Parser for Sysdig/Falco JSON alert files."""

    PRIORITY_MAP: ClassVar[dict[str, Severity]] = {
        "emergency": Severity.CRITICAL,
        "alert": Severity.CRITICAL,
        "critical": Severity.CRITICAL,
        "error": Severity.HIGH,
        "warning": Severity.MEDIUM,
        "notice": Severity.LOW,
        "informational": Severity.INFORMATIONAL,
        "debug": Severity.INFORMATIONAL,
    }

    @classmethod
    def source_class(cls) -> ArtifactSource:
        return ArtifactSource.SURICATA

    @classmethod
    def can_handle(cls, path: Path) -> bool:
        """Heuristic: filename contains 'falco' or 'sysdig', or JSON with
        Falco-style fields (rule, priority, output)."""
        if not path.is_file():
            return False
        name = path.name.lower()
        if "falco" in name or "sysdig" in name:
            return True
        if not (name.endswith(".json") or name.endswith(".jsonl")):
            return False
        try:
            with path.open("r", encoding="utf-8", errors="replace") as f:
                head = f.read(4096)
        except OSError:
            return False
        return '"rule"' in head and '"priority"' in head and '"output"' in head

    def parse(self, path: Path) -> Iterator[Artifact]:
        """Yield one Artifact per Falco/Sysdig alert event."""
        try:
            if path.suffix.lower() == ".jsonl":
                yield from self._parse_jsonl(path)
            else:
                yield from self._parse_json(path)
        except Exception:
            log.warning("Failed to parse Sysdig/Falco file %s", path, exc_info=True)

    def _parse_json(self, path: Path) -> Iterator[Artifact]:
        """Parse a single JSON file (object or array)."""
        with path.open("r", encoding="utf-8", errors="replace") as f:
            data = json.load(f)
        events = self._extract_events(data)
        for event in events:
            artifact = self._event_to_artifact(event)
            if artifact is not None:
                yield artifact

    def _parse_jsonl(self, path: Path) -> Iterator[Artifact]:
        """Parse a JSONL file, one event per line."""
        for _n, event in self.read_jsonl(path):
            artifact = self._event_to_artifact(event)
            if artifact is not None:
                yield artifact

    @staticmethod
    def _extract_events(data: Any) -> list[dict[str, Any]]:
        """Normalize various Sysdig/Falco JSON shapes into a list of events."""
        if isinstance(data, list):
            return [e for e in data if isinstance(e, dict)]
        if isinstance(data, dict):
            for key in ("events", "alerts", "data", "results"):
                if key in data and isinstance(data[key], list):
                    return [e for e in data[key] if isinstance(e, dict)]
            if "rule" in data and "priority" in data:
                return [data]
        return []

    def _event_to_artifact(self, event: dict[str, Any]) -> Artifact | None:
        """Convert a single Falco/Sysdig event to an Artifact."""
        try:
            rule = str(event.get("rule", "Unknown Falco rule"))
            priority_raw = str(event.get("priority", "informational")).lower()
            severity = self.PRIORITY_MAP.get(priority_raw, Severity.INFORMATIONAL)

            output = str(event.get("output", ""))
            output_fields: dict[str, Any] = event.get("output_fields", {}) or {}

            ts = self.normalize_timestamp(
                event.get("time") or event.get("timestamp") or event.get("evt.time")
            )
            if ts is None:
                ts = datetime.now(UTC)

            host = (
                str(output_fields.get("host.name"))
                or str(output_fields.get("k8s.pod.name"))
                or str(event.get("hostname"))
                or None
            )
            proc_name = str(output_fields.get("proc.name")) or None
            proc_pid = None
            raw_pid = output_fields.get("proc.pid") or event.get("pid")
            if raw_pid is not None:
                with contextlib.suppress(ValueError, TypeError):
                    proc_pid = int(raw_pid)

            container = str(output_fields.get("container.name")) or None

            tags = ["sysdig", "falco", f"rule.{rule}"]
            if container:
                tags.append(f"container.{container}")

            technique_ids = self.extract_techniques(event.get("tags") or [])
            tactic_ids = self.extract_tactics(event.get("tags") or [])

            description = output or f"Falco rule triggered: {rule}"

            return Artifact(
                id=Artifact.new_id(),
                artifact_type=ArtifactType.ALERT,
                source=ArtifactSource.SURICATA,
                timestamp=ts,
                severity=severity,
                host=host,
                process_name=proc_name,
                process_id=proc_pid,
                description=description,
                raw=event,
                technique_ids=technique_ids,
                tactic_ids=tactic_ids,
                tags=tags,
            )
        except Exception:
            log.debug("Skipping malformed Falco event: %s", event, exc_info=True)
            return None
