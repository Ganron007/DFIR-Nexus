"""AlienVault OTX pulse JSON importer.

Parses OTX pulse exports (single-pulse JSON or multi-pulse bundles).
Each pulse contains indicators and references a list of MITRE attacks.
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


class OTXImporter(Importer):
    """Parser for AlienVault OTX pulse JSON."""

    @classmethod
    def source_class(cls) -> ArtifactSource:
        return ArtifactSource.OTX

    @classmethod
    def can_handle(cls, path: Path) -> bool:
        """Heuristic: JSON with OTX-shape (pulse, indicators, attack_ids)."""
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
        return (
            "otx" in head.lower()
            or "alienvault" in head.lower()
            or ("indicators" in head and "pulse" in head.lower())
        )

    def parse(self, path: Path) -> Iterator[Artifact]:
        """Yield Artifact objects from an OTX pulse JSON."""
        with path.open("r", encoding="utf-8", errors="replace") as f:
            data = json.load(f)
        pulses = self._extract_pulses(data)
        for pulse in pulses:
            yield from self._pulse_to_artifacts(pulse)

    @staticmethod
    def _extract_pulses(data: Any) -> list[dict[str, Any]]:
        """Extract OTX pulses from various export shapes."""
        if isinstance(data, list):
            return [p for p in data if isinstance(p, dict)]
        if isinstance(data, dict):
            for key in ("pulses", "results", "data"):
                if key in data and isinstance(data[key], list):
                    return [p for p in data[key] if isinstance(p, dict)]
            # Single pulse
            if "indicators" in data or "name" in data:
                return [data]
        return []

    def _pulse_to_artifacts(self, pulse: dict[str, Any]) -> Iterator[Artifact]:
        """Yield one Artifact per indicator in a pulse."""
        name = pulse.get("name", "OTX pulse")
        pulse_id = pulse.get("id", "")
        description = pulse.get("description", "")
        # Tags
        tags = pulse.get("tags", []) or []
        # MITRE attack_ids is a list of technique IDs
        attack_ids = pulse.get("attack_ids", []) or []
        techniques = []
        for aid in attack_ids:
            aid_str = str(aid).strip()
            if aid_str.upper().startswith("T"):
                techniques.append(aid_str.upper())
        # TLP severity (red > amber > green > white)
        tlp = str(pulse.get("tlp", "")).lower()
        severity_map = {
            "red": Severity.CRITICAL,
            "amber": Severity.HIGH,
            "green": Severity.MEDIUM,
            "white": Severity.INFORMATIONAL,
        }
        severity = severity_map.get(tlp, Severity.INFORMATIONAL)

        # Created timestamp
        ts = self.normalize_timestamp(pulse.get("created")) or datetime.now(UTC)

        indicators = pulse.get("indicators", []) or []
        for ind in indicators:
            if not isinstance(ind, dict):
                continue
            yield self._indicator_to_artifact(
                ind, name, pulse_id, description, ts, severity, techniques, tags
            )

    def _indicator_to_artifact(
        self,
        ind: dict[str, Any],
        name: str,
        pulse_id: str,
        description: str,
        ts: datetime,
        severity: Severity,
        techniques: list[str],
        tags: list[str],
    ) -> Artifact:
        """Map an OTX indicator to an Artifact."""
        ind_type = str(ind.get("type", "")).lower()
        ind_value = str(ind.get("indicator", ""))
        if not ind_value:
            return Artifact(
                id=Artifact.new_id(),
                artifact_type=ArtifactType.IOC,
                source=ArtifactSource.OTX,
                timestamp=ts,
                severity=severity,
                description=f"OTX {name} - empty indicator",
                raw=ind,
            )

        # Map OTX type to ArtifactType
        type_map = {
            "ipv4": ArtifactType.NETWORK,
            "ipv6": ArtifactType.NETWORK,
            "domain": ArtifactType.DNS,
            "hostname": ArtifactType.NETWORK,
            "url": ArtifactType.HTTP,
            "md5": ArtifactType.MALWARE,
            "sha1": ArtifactType.MALWARE,
            "sha256": ArtifactType.MALWARE,
            "filename": ArtifactType.FILE,
            "email": ArtifactType.AUTH,
            "cidr": ArtifactType.NETWORK,
            "process_name": ArtifactType.PROCESS,
            "registry_key": ArtifactType.REGISTRY,
            "user-agent": ArtifactType.HTTP,
        }
        artifact_type = type_map.get(ind_type, ArtifactType.IOC)

        # Field assignment
        file_md5 = ind_value if ind_type == "md5" else None
        file_sha1 = ind_value if ind_type == "sha1" else None
        file_sha256 = ind_value if ind_type == "sha256" else None
        source_ip = ind_value if ind_type == "ipv4" else None
        dest_ip = ind_value if ind_type == "ipv4" else None

        return Artifact(
            id=Artifact.new_id(),
            artifact_type=artifact_type,
            source=ArtifactSource.OTX,
            timestamp=ts,
            severity=severity,
            file_path=ind_value if ind_type == "filename" else None,
            file_hash_md5=file_md5,
            file_hash_sha1=file_sha1,
            file_hash_sha256=file_sha256,
            source_ip=source_ip,
            dest_ip=dest_ip,
            process_name=ind_value if ind_type == "process_name" else None,
            registry_key=ind_value if ind_type == "registry_key" else None,
            description=f"OTX [{name}] {ind_type}={ind_value}",
            raw=ind,
            technique_ids=techniques,
            iocs=[ind_value],
            tags=["otx"] + (tags[:5] if isinstance(tags, list) else []),
        )
