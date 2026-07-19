"""SO-CRATES alert importer.

Parses JSON exports from the SO-CRATES (Security Operations Cyber Risk
Alerting and Threat Evaluation System) platform. SO-CRATES normalises
Suricata alerts, YARA matches, and Sigma detections into a unified JSON
envelope with fields like ``alert_type``, ``source_tool``, ``sig_name``,
and ``socrates_version``.
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

_ALERT_TYPE_MAP: dict[str, ArtifactType] = {
    "suricata": ArtifactType.ALERT,
    "yara": ArtifactType.MALWARE,
    "sigma": ArtifactType.ALERT,
    "ids": ArtifactType.ALERT,
    "malware": ArtifactType.MALWARE,
    "network": ArtifactType.NETWORK,
    "process": ArtifactType.PROCESS,
    "file": ArtifactType.FILE,
    "auth": ArtifactType.AUTH,
}


class SocRatesImporter(Importer):
    """Parser for SO-CRATES unified detection JSON exports."""

    @classmethod
    def source_class(cls) -> ArtifactSource:
        return ArtifactSource.SURICATA

    @classmethod
    def can_handle(cls, path: Path) -> bool:
        """Heuristic: filename contains 'socrates' or JSON has 'socrates'/
        'alert_type' keys."""
        if not path.is_file():
            return False
        name = path.name.lower()
        if "socrates" in name:
            return True
        if not (name.endswith(".json") or name.endswith(".jsonl") or name.endswith(".ndjson")):
            return False
        try:
            with path.open("r", encoding="utf-8", errors="replace") as f:
                head = f.read(8192)
        except OSError:
            return False
        return '"socrates"' in head or '"alert_type"' in head

    def parse(self, path: Path) -> Iterator[Artifact]:
        """Yield one Artifact per SO-CRATES detection record."""
        for _line_num, record in self.read_jsonl(path):
            try:
                yield self._record_to_artifact(record)
            except Exception:
                log.debug(
                    "Skipping malformed SO-CRATES record at %s:%d",
                    path,
                    _line_num,
                    exc_info=True,
                )

    def _record_to_artifact(self, record: dict[str, Any]) -> Artifact:
        """Map a SO-CRATES detection record to an Artifact."""
        ts = self._extract_timestamp(record)
        severity = self._extract_severity(record)
        artifact_type = self._extract_type(record)
        source_ip, dest_ip = self._extract_ips(record)
        description = self._extract_description(record)
        technique_ids = self._extract_techniques(record)

        return Artifact(
            id=Artifact.new_id(),
            artifact_type=artifact_type,
            source=ArtifactSource.SURICATA,
            timestamp=ts,
            severity=severity,
            host=str(record.get("host") or record.get("hostname") or "") or None,
            user=str(record.get("user") or record.get("username") or "") or None,
            source_ip=source_ip,
            dest_ip=dest_ip,
            source_port=self._safe_int(record.get("src_port") or record.get("source_port")),
            dest_port=self._safe_int(record.get("dest_port") or record.get("destination_port")),
            process_name=record.get("process_name"),
            process_id=self._safe_int(record.get("process_id")),
            file_path=record.get("file_path") or record.get("filepath"),
            description=description,
            raw=record,
            technique_ids=technique_ids,
            tags=self._build_tags(record),
        )

    def _extract_timestamp(self, record: dict[str, Any]) -> datetime:
        for key in ("timestamp", "@timestamp", "time", "event_time", "alert_time"):
            ts = self.normalize_timestamp(record.get(key))
            if ts:
                return ts
        return datetime.now(UTC)

    def _extract_severity(self, record: dict[str, Any]) -> Severity:
        for key in ("severity", "priority", "level", "risk_score"):
            val = record.get(key)
            if val is not None:
                return Severity.normalize(val)
        event_obj = record.get("event", {})
        if isinstance(event_obj, dict) and event_obj.get("severity") is not None:
            return Severity.normalize(event_obj["severity"])
        return Severity.INFORMATIONAL

    def _extract_type(self, record: dict[str, Any]) -> ArtifactType:
        alert_type = str(record.get("alert_type", "")).lower()
        source_tool = str(record.get("source_tool", "")).lower()
        for key, atype in _ALERT_TYPE_MAP.items():
            if key in alert_type or key in source_tool:
                return atype
        if "sig_name" in record or "signature" in record:
            return ArtifactType.ALERT
        return ArtifactType.UNKNOWN

    def _extract_ips(
        self, record: dict[str, Any]
    ) -> tuple[str | None, str | None]:
        src_ip = record.get("src_ip") or record.get("source_ip")
        dst_ip = record.get("dest_ip") or record.get("destination_ip")
        return (
            str(src_ip) if src_ip else None,
            str(dst_ip) if dst_ip else None,
        )

    def _extract_description(self, record: dict[str, Any]) -> str:
        parts: list[str] = []
        for key in ("sig_name", "signature", "rule_name", "rule.name", "title"):
            val = record.get(key)
            if val:
                parts.append(str(val))
                break
        msg = record.get("message") or record.get("description")
        if msg and (not parts or str(msg) != parts[0]):
            parts.append(str(msg))
        return " - ".join(parts) or "SO-CRATES detection"

    def _extract_techniques(self, record: dict[str, Any]) -> list[str]:
        techniques = self.extract_techniques(record.get("tags", []))
        if not techniques:
            techniques = self.extract_techniques(record.get("threat", {}))
        return techniques

    def _build_tags(self, record: dict[str, Any]) -> list[str]:
        tags = ["socrates"]
        alert_type = record.get("alert_type")
        if alert_type:
            tags.append(f"alert_type:{alert_type}")
        source_tool = record.get("source_tool")
        if source_tool:
            tags.append(f"source_tool:{source_tool}")
        return tags

    @staticmethod
    def _safe_int(value: Any) -> int | None:
        if value is None or value == "":
            return None
        try:
            return int(value)
        except (ValueError, TypeError):
            return None
