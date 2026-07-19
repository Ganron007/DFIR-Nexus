"""Suricata eve.json importer.

Parses the Suricata extended event log (eve.json / eve.json). Each line is a
JSON object with an `event_type` field that drives the artifact type.
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
    NetworkProtocol,
    Severity,
)

log = logging.getLogger(__name__)


class SuricataImporter(Importer):
    """Parser for Suricata's eve.json (newline-delimited JSON)."""

    @classmethod
    def source_class(cls) -> ArtifactSource:
        return ArtifactSource.SURICATA

    @classmethod
    def can_handle(cls, path: Path) -> bool:
        """Heuristic: file is named eve.json or eve.json.* or has a JSON object with `event_type`."""
        if not path.is_file():
            return False
        name = path.name.lower()
        if name == "eve.json" or name.startswith("eve.json.") or name.startswith("eve."):
            return True
        # Sniff the first non-empty line
        try:
            with path.open("r", encoding="utf-8", errors="replace") as f:
                for _ in range(5):
                    line = f.readline()
                    if not line:
                        break
                    line = line.strip()
                    if not line:
                        continue
                    import json
                    try:
                        obj = json.loads(line)
                    except Exception:  # noqa: BLE001
                        return False
                    if isinstance(obj, dict) and "event_type" in obj:
                        return "src_ip" in obj or "dest_ip" in obj or "alert" in obj
        except OSError:
            return False
        return False

    def parse(self, path: Path) -> Iterator[Artifact]:
        """Yield Artifact objects from a Suricata eve.json file."""
        for _line_num, record in self.read_jsonl(path):
            yield self._record_to_artifact(record)

    def _record_to_artifact(self, record: dict[str, Any]) -> Artifact:
        """Map a single Suricata event record to an Artifact."""
        event_type = str(record.get("event_type", "")).lower()
        ts = self.normalize_timestamp(record.get("timestamp"))
        if ts is None:
            ts = datetime.now(UTC)

        # Map event_type to ArtifactType
        type_map = {
            "flow": ArtifactType.NETWORK,
            "dns": ArtifactType.DNS,
            "http": ArtifactType.HTTP,
            "tls": ArtifactType.TLS,
            "smtp": ArtifactType.SMTP,
            "ssh": ArtifactType.SSH,
            "rdp": ArtifactType.RDP,
            "fileinfo": ArtifactType.FILE,
            "alert": ArtifactType.ALERT,
        }
        artifact_type = type_map.get(event_type, ArtifactType.UNKNOWN)

        # Protocol mapping
        proto = record.get("proto", "").upper()
        proto_map = {
            "TCP": NetworkProtocol.TCP,
            "UDP": NetworkProtocol.UDP,
            "ICMP": NetworkProtocol.ICMP,
            "ICMPV6": NetworkProtocol.ICMP,
        }
        protocol = proto_map.get(proto)

        # Severity: alerts use alert.severity (1-3), others are informational
        severity = Severity.INFORMATIONAL
        alert = record.get("alert")
        if isinstance(alert, dict):
            sev_int = alert.get("severity")
            if isinstance(sev_int, int):
                severity = Severity.normalize(sev_int)

        # Build description
        description_parts = []
        if event_type:
            description_parts.append(f"Suricata {event_type}")
        if alert and isinstance(alert, dict):
            signature = alert.get("signature", "")
            category = alert.get("category", "")
            if signature:
                description_parts.append(signature)
            if category:
                description_parts.append(f"[{category}]")

        return Artifact(
            id=Artifact.new_id(),
            artifact_type=artifact_type,
            source=ArtifactSource.SURICATA,
            timestamp=ts,
            severity=severity,
            host=record.get("host"),
            source_ip=record.get("src_ip"),
            source_port=record.get("src_port"),
            dest_ip=record.get("dest_ip"),
            dest_port=record.get("dest_port"),
            protocol=protocol,
            file_path=record.get("fileinfo", {}).get("filename") if isinstance(record.get("fileinfo"), dict) else None,
            file_hash_md5=record.get("fileinfo", {}).get("md5") if isinstance(record.get("fileinfo"), dict) else None,
            file_hash_sha1=record.get("fileinfo", {}).get("sha1") if isinstance(record.get("fileinfo"), dict) else None,
            file_hash_sha256=record.get("fileinfo", {}).get("sha256") if isinstance(record.get("fileinfo"), dict) else None,
            action=record.get("alert", {}).get("action") if isinstance(record.get("alert"), dict) else None,
            description=" - ".join(description_parts) or f"Suricata {event_type or 'event'}",
            raw=record,
            tags=[f"suricata.{event_type}"] if event_type else [],
        )
