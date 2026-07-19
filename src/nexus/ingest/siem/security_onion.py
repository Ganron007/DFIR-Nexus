"""Security Onion ECS alerts importer.

Parses JSON/NDJSON exports from Security Onion using Elastic Common Schema
(ECS) fields: event.severity_label, event.category, source.ip, etc.
Security Onion normalises Suricata, Zeek, Sigma, and YARA alerts into ECS,
so this importer focuses on the alert-specific envelope rather than raw
network or process telemetry.
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

_SEVERITY_LABEL_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "informational": Severity.INFORMATIONAL,
}

_CATEGORY_TYPE_MAP: dict[str, ArtifactType] = {
    "intrusion_detection": ArtifactType.ALERT,
    "malware": ArtifactType.MALWARE,
    "authentication": ArtifactType.AUTH,
    "process": ArtifactType.PROCESS,
    "file": ArtifactType.FILE,
    "network": ArtifactType.NETWORK,
    "dns": ArtifactType.DNS,
    "web": ArtifactType.HTTP,
    "threat": ArtifactType.THREAT_INTEL,
}


class SecurityOnionImporter(Importer):
    """Parser for Security Onion ECS-formatted alert exports."""

    @classmethod
    def source_class(cls) -> ArtifactSource:
        return ArtifactSource.SECURITY_ONION

    @classmethod
    def can_handle(cls, path: Path) -> bool:
        """Heuristic: filename contains 'security_onion'/'soc' or JSON has
        event.severity_label."""
        if not path.is_file():
            return False
        name = path.name.lower()
        if "security_onion" in name or "soc" in name:
            return True
        if not (name.endswith(".json") or name.endswith(".jsonl") or name.endswith(".ndjson")):
            return False
        try:
            with path.open("r", encoding="utf-8", errors="replace") as f:
                head = f.read(8192)
        except OSError:
            return False
        return "event.severity_label" in head or "severity_label" in head

    def parse(self, path: Path) -> Iterator[Artifact]:
        """Yield one Artifact per Security Onion ECS alert."""
        for _line_num, record in self.read_jsonl(path):
            try:
                yield self._record_to_artifact(record)
            except Exception:
                log.debug(
                    "Skipping malformed Security Onion record at %s:%d",
                    path,
                    _line_num,
                    exc_info=True,
                )

    def _record_to_artifact(self, record: dict[str, Any]) -> Artifact:
        """Map an ECS alert record to an Artifact."""
        ts = self._extract_timestamp(record)
        severity = self._extract_severity(record)
        artifact_type = self._extract_type(record)
        host_name, user_name = self._extract_host_user(record)
        source_ip, dest_ip = self._extract_ips(record)
        proc_name, proc_pid = self._extract_process(record)
        description = self._extract_description(record)

        return Artifact(
            id=Artifact.new_id(),
            artifact_type=artifact_type,
            source=ArtifactSource.SENTINEL,
            timestamp=ts,
            severity=severity,
            host=host_name,
            user=user_name,
            source_ip=source_ip,
            dest_ip=dest_ip,
            process_name=proc_name,
            process_id=proc_pid,
            description=description,
            raw=record,
            technique_ids=self.extract_techniques(record.get("threat", {})),
            tags=self._build_tags(record),
        )

    def _extract_timestamp(self, record: dict[str, Any]) -> datetime:
        ts = self.normalize_timestamp(record.get("@timestamp") or record.get("timestamp"))
        return ts if ts else datetime.now(UTC)

    def _extract_severity(self, record: dict[str, Any]) -> Severity:
        event_obj = record.get("event", {})
        if isinstance(event_obj, dict):
            label = event_obj.get("severity_label", "")
            if isinstance(label, str) and label.lower() in _SEVERITY_LABEL_MAP:
                return _SEVERITY_LABEL_MAP[label.lower()]
            sev_val = event_obj.get("severity")
            if sev_val is not None:
                return Severity.normalize(sev_val)
        return Severity.INFORMATIONAL

    def _extract_type(self, record: dict[str, Any]) -> ArtifactType:
        event_obj = record.get("event", {})
        if isinstance(event_obj, dict):
            category = str(event_obj.get("category", "")).lower()
            kind = str(event_obj.get("kind", "")).lower()
            if kind == "alert" or "alert" in category:
                return ArtifactType.ALERT
            for key, atype in _CATEGORY_TYPE_MAP.items():
                if key in category:
                    return atype
        if "rule" in record and isinstance(record["rule"], dict):
            return ArtifactType.ALERT
        return ArtifactType.UNKNOWN

    def _extract_host_user(
        self, record: dict[str, Any]
    ) -> tuple[str | None, str | None]:
        host_obj = record.get("host", {})
        host_name = host_obj.get("name") if isinstance(host_obj, dict) else None
        user_obj = record.get("user", {})
        user_name = user_obj.get("name") if isinstance(user_obj, dict) else None
        return host_name, user_name

    def _extract_ips(
        self, record: dict[str, Any]
    ) -> tuple[str | None, str | None]:
        src_obj = record.get("source", {})
        dst_obj = record.get("destination", {})
        src_ip = src_obj.get("ip") if isinstance(src_obj, dict) else None
        dst_ip = dst_obj.get("ip") if isinstance(dst_obj, dict) else None
        return src_ip, dst_ip

    def _extract_process(
        self, record: dict[str, Any]
    ) -> tuple[str | None, int | None]:
        proc_obj = record.get("process", {})
        if not isinstance(proc_obj, dict):
            return None, None
        name = proc_obj.get("name")
        pid = proc_obj.get("pid")
        return name, pid if isinstance(pid, int) else None

    def _extract_description(self, record: dict[str, Any]) -> str:
        parts: list[str] = []
        rule_obj = record.get("rule", {})
        if isinstance(rule_obj, dict) and rule_obj.get("name"):
            parts.append(str(rule_obj["name"]))
        msg = record.get("message")
        if msg and (not parts or str(msg) != parts[0]):
            parts.append(str(msg))
        return " - ".join(parts) or "Security Onion alert"

    def _build_tags(self, record: dict[str, Any]) -> list[str]:
        tags = ["security_onion"]
        event_obj = record.get("event", {})
        if isinstance(event_obj, dict):
            kind = event_obj.get("kind")
            if kind:
                tags.append(f"event.kind:{kind}")
            category = event_obj.get("category")
            if category:
                tags.append(f"event.category:{category}")
        return tags
