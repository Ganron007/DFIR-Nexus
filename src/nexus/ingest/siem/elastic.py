"""Elastic alerts/events JSONL exporter.

Parses JSONL exports from Elastic (e.g. `GET /<index>/_search` -> bulk export,
or Kibana saved-object exports). Each line is a JSON object that usually
wraps a hit inside `_source`, but the importer also handles unwrapped records.
"""

from __future__ import annotations

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


class ElasticImporter(Importer):
    """Parser for Elastic alerts/events JSONL export."""

    @classmethod
    def source_class(cls) -> ArtifactSource:
        return ArtifactSource.ELASTIC

    @classmethod
    def can_handle(cls, path: Path) -> bool:
        """Heuristic: file is JSONL with Elastic-shaped records (host.name, _source, etc.)."""
        if not path.is_file():
            return False
        name = path.name.lower()
        if not (name.endswith(".json") or name.endswith(".jsonl") or name.endswith(".ndjson")):
            return False
        try:
            import json
            with path.open("r", encoding="utf-8", errors="replace") as f:
                for _ in range(5):
                    line = f.readline()
                    if not line:
                        break
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except Exception:  # noqa: BLE001
                        return False
                    if not isinstance(obj, dict):
                        return False
                    # Elastic hits have _index / _source; signals have signal.original_event
                    if "_index" in obj or "_source" in obj:
                        return True
                    # Some exports have hit at top level
                    if "host" in obj and ("@timestamp" in obj or "event" in obj):
                        return True
                    if "signal" in obj and isinstance(obj["signal"], dict):
                        return True
        except OSError:
            return False
        return False

    def parse(self, path: Path) -> Iterator[Artifact]:
        """Yield Artifact objects from an Elastic JSONL export."""
        for _line_num, record in self.read_jsonl(path):
            inner = self._extract_inner(record)
            if inner is None:
                continue
            yield self._record_to_artifact(record, inner)

    @staticmethod
    def _extract_inner(record: dict[str, Any]) -> dict[str, Any] | None:
        """Extract the inner event object from an Elastic hit wrapper."""
        # Direct hit: { _index, _source: {...} }
        if "_source" in record and isinstance(record["_source"], dict):
            return record["_source"]
        # Plain record
        if "@timestamp" in record or "event" in record or "host" in record:
            return record
        # Signal / detection rule result
        if "signal" in record and isinstance(record["signal"], dict):
            return record["signal"]
        if "rule" in record and isinstance(record["rule"], dict):
            return record
        return None

    def _record_to_artifact(
        self, outer: dict[str, Any], inner: dict[str, Any]
    ) -> Artifact:
        """Map an Elastic event/alert to an Artifact."""
        ts = self.normalize_timestamp(
            inner.get("@timestamp") or outer.get("@timestamp")
        )
        if ts is None:
            ts = datetime.now(UTC)

        # Determine artifact type
        event_kind = inner.get("event", {})
        category = ""
        if isinstance(event_kind, dict):
            category = str(event_kind.get("category", ""))
        if category == "authentication" or "authentication" in str(event_kind):
            artifact_type = ArtifactType.AUTH
        elif category == "process" or "process" in str(event_kind):
            artifact_type = ArtifactType.PROCESS
        elif category == "file" or "file" in str(event_kind):
            artifact_type = ArtifactType.FILE
        elif category == "network" or "network" in str(event_kind):
            artifact_type = ArtifactType.NETWORK
        elif "rule" in inner or "signal" in outer or "alert" in inner:
            artifact_type = ArtifactType.ALERT
        else:
            artifact_type = ArtifactType.UNKNOWN

        # Severity
        severity = Severity.INFORMATIONAL
        # Try signal.rule.risk_score, then signal.rule.severity, then event.severity
        rule = inner.get("rule", {})
        if isinstance(rule, dict):
            risk = rule.get("risk_score")
            if isinstance(risk, (int, float)):
                if risk >= 75:
                    severity = Severity.CRITICAL
                elif risk >= 50:
                    severity = Severity.HIGH
                elif risk >= 25:
                    severity = Severity.MEDIUM
                else:
                    severity = Severity.LOW
            sev_str = rule.get("severity")
            if sev_str:
                severity = Severity.normalize(sev_str)
        # Fall back to event.severity (may be nested in event.* dict or flat)
        if severity == Severity.INFORMATIONAL:
            event_obj = inner.get("event", {})
            if isinstance(event_obj, dict):
                ev_sev = event_obj.get("severity")
                if ev_sev is not None:
                    severity = Severity.normalize(ev_sev)
            elif "event.severity" in inner:
                severity = Severity.normalize(inner.get("event.severity"))

        # Host / user
        host_obj = inner.get("host", {})
        host_name = host_obj.get("name") if isinstance(host_obj, dict) else None
        user_obj = inner.get("user", {})
        user_name = user_obj.get("name") if isinstance(user_obj, dict) else None

        # Network
        source_obj = inner.get("source", {})
        dest_obj = inner.get("destination", {})
        source_ip = source_obj.get("ip") if isinstance(source_obj, dict) else None
        dest_ip = dest_obj.get("ip") if isinstance(dest_obj, dict) else None

        # Process
        process_obj = inner.get("process", {})
        proc_name = process_obj.get("name") if isinstance(process_obj, dict) else None
        proc_pid = process_obj.get("pid") if isinstance(process_obj, dict) else None
        parent_obj = inner.get("process", {}).get("parent", {}) if isinstance(process_obj, dict) else {}
        parent_name = parent_obj.get("name") if isinstance(parent_obj, dict) else None
        cmd_line = process_obj.get("command_line") if isinstance(process_obj, dict) else None

        # Description
        desc_parts = []
        if "rule.name" in inner:
            desc_parts.append(str(inner["rule.name"]))
        elif isinstance(rule, dict) and rule.get("name"):
            desc_parts.append(str(rule["name"]))
        if "message" in inner:
            desc_parts.append(str(inner["message"]))

        return Artifact(
            id=Artifact.new_id(),
            artifact_type=artifact_type,
            source=ArtifactSource.ELASTIC,
            timestamp=ts,
            severity=severity,
            host=host_name,
            user=user_name,
            source_ip=source_ip,
            dest_ip=dest_ip,
            process_name=proc_name,
            process_id=proc_pid if isinstance(proc_pid, int) else None,
            parent_process=parent_name,
            command_line=cmd_line,
            description=" - ".join(desc_parts) or f"Elastic {artifact_type.value}",
            raw=outer,
            tags=["elastic"],
        )
