"""Wazuh alerts.json importer.

Parses Wazuh manager ``alerts.json`` (or NDJSON) exports. Each alert has
a ``rule`` object with ``level`` (0-15), ``id``, ``description``, and
an ``agent`` object with ``id``, ``name``, ``ip``.
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


class WazuhImporter(Importer):
    """Parser for Wazuh alerts.json / NDJSON exports."""

    @classmethod
    def source_class(cls) -> ArtifactSource:
        return ArtifactSource.ELASTIC

    @classmethod
    def can_handle(cls, path: Path) -> bool:
        """Heuristic: filename contains 'wazuh', or JSON with rule.level + agent keys."""
        if not path.is_file():
            return False
        name = path.name.lower()
        if "wazuh" in name:
            return True
        if not (name.endswith(".json") or name.endswith(".jsonl")):
            return False
        try:
            with path.open("r", encoding="utf-8", errors="replace") as f:
                head = f.read(8192)
        except OSError:
            return False
        return '"rule"' in head and '"level"' in head and '"agent"' in head

    def parse(self, path: Path) -> Iterator[Artifact]:
        """Yield one Artifact per Wazuh alert."""
        try:
            if path.suffix.lower() == ".jsonl":
                yield from self._parse_jsonl(path)
            else:
                yield from self._parse_json(path)
        except Exception:
            log.warning("Failed to parse Wazuh file %s", path, exc_info=True)

    def _parse_json(self, path: Path) -> Iterator[Artifact]:
        """Parse a single JSON file.

        Falls back to line-delimited parsing when the file is NDJSON with a
        plain ``.json`` extension (Wazuh ``alerts.json`` is NDJSON).
        """
        try:
            with path.open("r", encoding="utf-8", errors="replace") as f:
                data = json.load(f)
        except json.JSONDecodeError:
            yield from self._parse_jsonl(path)
            return
        alerts = self._extract_alerts(data)
        for alert in alerts:
            artifact = self._alert_to_artifact(alert)
            if artifact is not None:
                yield artifact

    def _parse_jsonl(self, path: Path) -> Iterator[Artifact]:
        """Parse a JSONL file."""
        for _n, alert in self.read_jsonl(path):
            artifact = self._alert_to_artifact(alert)
            if artifact is not None:
                yield artifact

    @staticmethod
    def _extract_alerts(data: Any) -> list[dict[str, Any]]:
        """Normalize various Wazuh export shapes."""
        if isinstance(data, list):
            return [a for a in data if isinstance(a, dict)]
        if isinstance(data, dict):
            for key in ("data", "alerts", "results", "items"):
                if key in data and isinstance(data[key], list):
                    return [a for a in data[key] if isinstance(a, dict)]
            if "rule" in data and "agent" in data:
                return [data]
        return []

    @staticmethod
    def _wazuh_level_to_severity(level: int | None) -> Severity:
        """Map Wazuh rule level (0-15) to Severity."""
        if level is None:
            return Severity.INFORMATIONAL
        if level >= 12:
            return Severity.CRITICAL
        if level >= 8:
            return Severity.HIGH
        if level >= 4:
            return Severity.MEDIUM
        if level >= 1:
            return Severity.LOW
        return Severity.INFORMATIONAL

    def _alert_to_artifact(self, alert: dict[str, Any]) -> Artifact | None:
        """Convert a single Wazuh alert to an Artifact."""
        try:
            rule: dict[str, Any] = alert.get("rule") or {}
            agent: dict[str, Any] = alert.get("agent") or {}
            agent_ip = alert.get("agentip") or alert.get("agent_ip")

            level = rule.get("level")
            if level is not None:
                try:
                    level = int(level)
                except (ValueError, TypeError):
                    level = None
            severity = self._wazuh_level_to_severity(level)

            rule_id = str(rule.get("id", ""))
            rule_desc = str(rule.get("description", ""))
            groups = rule.get("groups", [])
            if not isinstance(groups, list):
                groups = []

            ts = self.normalize_timestamp(
                alert.get("timestamp") or alert.get("@timestamp")
            )
            if ts is None:
                ts = datetime.now(UTC)

            host = str(agent.get("name")) or None
            source_ip = str(agent_ip) or str(alert.get("data", {}).get("srcip")) if isinstance(alert.get("data"), dict) else None

            technique_ids = self.extract_techniques(rule.get("mitre", {}) or {})
            if not technique_ids:
                technique_ids = self.extract_techniques(groups)

            tags = ["wazuh", f"rule.{rule_id}"]
            for g in groups[:10]:
                if isinstance(g, str):
                    tags.append(f"group.{g}")

            data_fields: dict[str, Any] = alert.get("data") or {}
            dest_ip = str(data_fields.get("dstip")) if data_fields.get("dstip") else None
            file_path = str(data_fields.get("filename")) if data_fields.get("filename") else None

            description = rule_desc or f"Wazuh rule {rule_id} (level {level})"

            return Artifact(
                id=Artifact.new_id(),
                artifact_type=ArtifactType.ALERT,
                source=ArtifactSource.ELASTIC,
                timestamp=ts,
                severity=severity,
                host=host,
                source_ip=source_ip,
                dest_ip=dest_ip,
                file_path=file_path,
                description=description,
                raw=alert,
                technique_ids=technique_ids,
                tags=tags,
            )
        except Exception:
            log.debug("Skipping malformed Wazuh alert: %s", alert, exc_info=True)
            return None
