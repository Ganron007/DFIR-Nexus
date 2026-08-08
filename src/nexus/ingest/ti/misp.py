"""MISP event JSON importer.

Parses MISP event JSON exports (the standard export from the MISP UI or
the `/events/restSearch` API endpoint). Each event contains Attributes
(observables), Tags (including MITRE galaxy tags), and Galaxies.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from nexus.ingest.base import Importer, ImporterError
from nexus.ingest.schemas import (
    Artifact,
    ArtifactSource,
    ArtifactType,
    Severity,
)

log = logging.getLogger(__name__)


class MISPImporter(Importer):
    """Parser for MISP event JSON exports."""

    @classmethod
    def source_class(cls) -> ArtifactSource:
        return ArtifactSource.MISP

    @classmethod
    def can_handle(cls, path: Path) -> bool:
        """Heuristic: JSON with MISP shape (Event, Attribute, Galaxy, Tag)."""
        if not path.is_file():
            return False
        name = path.name.lower()
        if not (name.endswith(".json") or name.endswith(".jsonl")):
            return False
        try:
            with path.open("r", encoding="utf-8", errors="replace") as f:
                head = f.read(4096)
        except OSError:
            return False
        # MISP files have "Event" key with "Attribute" inside (usually).
        # Accept any file that has "Attribute" (since MISP core field) or "MISP" string.
        return "MISP" in head or '"Attribute"' in head

    def parse(self, path: Path) -> Iterator[Artifact]:
        """Yield Artifact objects from a MISP event JSON."""
        try:
            with path.open("r", encoding="utf-8", errors="replace") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            raise ImporterError(f"Invalid JSON in {path.name}: {e}") from e
        events = self._extract_events(data)
        for event in events:
            yield from self._event_to_artifacts(event)

    @staticmethod
    def _extract_events(data: Any) -> list[dict[str, Any]]:
        """Extract MISP events from various export shapes."""
        if isinstance(data, dict):
            if "Event" in data:
                return [data["Event"]]
            if "events" in data and isinstance(data["events"], list):
                return [e for e in data["events"] if isinstance(e, dict)]
        if isinstance(data, list):
            return [e.get("Event", e) if isinstance(e, dict) else e for e in data if isinstance(e, dict)]
        return []

    def _event_to_artifacts(self, event: dict[str, Any]) -> Iterator[Artifact]:
        """Convert a MISP event into one Artifact per Attribute, plus one IOC-summary artifact."""
        event_info = event.get("info", "MISP event")
        event_id = event.get("id", "")
        event_date = event.get("date", "")
        threat_level = event.get("threat_level_id", "3")  # 1=high, 2=med, 3=low, 4=undef

        # Severity from threat level
        threat_severity = {
            "1": Severity.HIGH,
            "2": Severity.MEDIUM,
            "3": Severity.LOW,
            "4": Severity.INFORMATIONAL,
        }.get(str(threat_level), Severity.INFORMATIONAL)

        # Extract MITRE techniques from Galaxies and Tags
        techniques: list[str] = []
        galaxies = event.get("Galaxy", []) or []
        for galaxy in galaxies:
            if not isinstance(galaxy, dict):
                continue
            if "mitre" in str(galaxy.get("name", "")).lower():
                for cluster in galaxy.get("GalaxyCluster", []) or []:
                    if not isinstance(cluster, dict):
                        continue
                    cluster_value = cluster.get("value", "")
                    if cluster_value.upper().startswith("T"):
                        techniques.append(cluster_value.upper())
        tags = event.get("Tag", []) or []
        if isinstance(tags, list):
            for tag in tags:
                if isinstance(tag, dict):
                    tag_name = tag.get("name", "")
                    if "mitre" in tag_name.lower():
                        techniques.extend(self.extract_techniques([tag_name]))

        ts = self.normalize_timestamp(event_date) or datetime.now(UTC)

        attributes = event.get("Attribute", []) or []
        for attr in attributes:
            if not isinstance(attr, dict):
                continue
            yield self._attribute_to_artifact(
                attr, event_info, event_id, ts, threat_severity, techniques
            )

    def _attribute_to_artifact(
        self,
        attr: dict[str, Any],
        event_info: str,
        event_id: str,
        ts: datetime,
        severity: Severity,
        techniques: list[str],
    ) -> Artifact:
        """Map a MISP attribute to an Artifact."""
        attr_type = str(attr.get("type", "")).lower()
        attr_value = str(attr.get("value", ""))
        category = str(attr.get("category", ""))

        # Map MISP type -> ArtifactType
        type_map = {
            "ip-dst": ArtifactType.NETWORK,
            "ip-src": ArtifactType.NETWORK,
            "domain": ArtifactType.DNS,
            "hostname": ArtifactType.NETWORK,
            "url": ArtifactType.HTTP,
            "md5": ArtifactType.MALWARE,
            "sha1": ArtifactType.MALWARE,
            "sha256": ArtifactType.MALWARE,
            "filename": ArtifactType.FILE,
            "filename|md5": ArtifactType.MALWARE,
            "filename|sha256": ArtifactType.MALWARE,
            "email-src": ArtifactType.AUTH,
            "process-name": ArtifactType.PROCESS,
            "registry-key": ArtifactType.REGISTRY,
            "user-agent": ArtifactType.HTTP,
        }
        artifact_type = type_map.get(attr_type, ArtifactType.IOC)

        # Extract hashes
        file_md5 = attr_value if attr_type == "md5" else None
        file_sha1 = attr_value if attr_type == "sha1" else None
        file_sha256 = attr_value if attr_type == "sha256" else None

        # IP / domain
        source_ip = attr_value if attr_type == "ip-src" else None
        dest_ip = attr_value if attr_type == "ip-dst" else None

        iocs = [attr_value] if attr_value else []
        if attr_type in ("filename|md5", "filename|sha1", "filename|sha256"):
            parts = attr_value.split("|")
            if len(parts) == 2:
                iocs.append(parts[0])
                if attr_type == "filename|md5":
                    file_md5 = parts[1]
                elif attr_type == "filename|sha1":
                    file_sha1 = parts[1]
                elif attr_type == "filename|sha256":
                    file_sha256 = parts[1]

        return Artifact(
            id=Artifact.new_id(),
            artifact_type=artifact_type,
            source=ArtifactSource.MISP,
            timestamp=ts,
            severity=severity,
            file_path=attr_value if attr_type in ("filename",) else None,
            file_hash_md5=file_md5,
            file_hash_sha1=file_sha1,
            file_hash_sha256=file_sha256,
            source_ip=source_ip,
            dest_ip=dest_ip,
            process_name=attr_value if attr_type == "process-name" else None,
            registry_key=attr_value if attr_type == "registry-key" else None,
            description=f"MISP {event_info} [#{event_id}] - {attr_type}={attr_value}",
            raw=attr,
            technique_ids=techniques,
            iocs=iocs,
            tags=[f"misp.{category}", f"misp.{attr_type}"] if category else [f"misp.{attr_type}"],
        )
