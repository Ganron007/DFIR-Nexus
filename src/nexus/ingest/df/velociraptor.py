"""Velociraptor hunt result JSON importer.

Parses JSON exports from Velociraptor artifact collection. The typical
shape is a list of records (or a `Records` array) where each record
contains columns from the VQL artifact definition.
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


class VelociraptorImporter(Importer):
    """Parser for Velociraptor JSON exports."""

    @classmethod
    def source_class(cls) -> ArtifactSource:
        return ArtifactSource.VELOCIRAPTOR

    @classmethod
    def can_handle(cls, path: Path) -> bool:
        """Heuristic: JSON with Velociraptor-shape (Records, _Source, or columns)."""
        if not path.is_file():
            return False
        name = path.name.lower()
        if not (name.endswith(".json") or name.endswith(".jsonl") or name.endswith(".ndjson")):
            return False
        try:
            with path.open("r", encoding="utf-8", errors="replace") as f:
                head = f.read(8192)
        except OSError:
            return False
        # Velociraptor signatures
        return "velociraptor" in head.lower() or "_Source" in head or "Artifact" in head and "Records" in head

    def parse(self, path: Path) -> Iterator[Artifact]:
        """Yield Artifact objects from a Velociraptor JSON export.

        Falls back to line-delimited parsing for NDJSON/JSONL hunt exports
        (one JSON record per line).
        """
        try:
            with path.open("r", encoding="utf-8", errors="replace") as f:
                data = json.load(f)
        except json.JSONDecodeError:
            for _n, record in self.read_jsonl(path):
                if isinstance(record, dict):
                    yield self._record_to_artifact(record)
            return
        records = self._extract_records(data)
        for record in records:
            yield self._record_to_artifact(record)

    @staticmethod
    def _extract_records(data: Any) -> list[dict[str, Any]]:
        """Pull the records list from various Velociraptor export shapes.

        Also captures the artifact name at the data level (e.g.,
        `{"Artifact": "Windows.Network.NetstatEnriched", "Records": [...]}`)
        and attaches it to each record for later use.
        """
        records: list[dict[str, Any]] = []
        artifact_name: str | None = None
        if isinstance(data, list):
            records = [r for r in data if isinstance(r, dict)]
        elif isinstance(data, dict):
            for key in ("Records", "records", "data", "results"):
                if key in data and isinstance(data[key], list):
                    records = [r for r in data[key] if isinstance(r, dict)]
                    break
            else:
                # Single record
                if "_Source" in data or "Artifact" in data:
                    records = [data]
            # Capture artifact name at data level (applies to every record)
            artifact_name = data.get("Artifact") or data.get("_Source")
        # Attach artifact_name to each record (if not already present)
        if artifact_name:
            for r in records:
                if isinstance(r, dict) and "Artifact" not in r and "_Source" not in r:
                    r["_ArtifactName"] = artifact_name
        return records

    def _record_to_artifact(self, record: dict[str, Any]) -> Artifact:
        """Map a Velociraptor record to an Artifact."""
        # Timestamp: try common fields
        ts = None
        for key in ("@timestamp", "Timestamp", "timestamp", "TimeCreated", "EventTime", "CreatedAt"):
            if key in record:
                ts = self.normalize_timestamp(record[key])
                if ts:
                    break
        if ts is None:
            ts = datetime.now(UTC)

        # Host / user
        host = record.get("Host") or record.get("hostname") or record.get("Computer")
        user = record.get("User") or record.get("user") or record.get("SubjectUserName")

        # Try to detect artifact type from data shape
        artifact_type = ArtifactType.UNKNOWN
        if any(k in record for k in ("EventID", "Channel", "ProviderName")):
            artifact_type = ArtifactType.UNKNOWN  # could be WindowsEvent; leave to Hayabusa
        elif "ProcessName" in record or "Image" in record or "CommandLine" in record:
            artifact_type = ArtifactType.PROCESS
        elif "SourceIp" in record or "DestinationIp" in record or "SourcePort" in record:
            artifact_type = ArtifactType.NETWORK
        elif "TargetFilename" in record or "FileName" in record:
            artifact_type = ArtifactType.FILE
        elif "TargetObject" in record:
            artifact_type = ArtifactType.REGISTRY

        # MITRE tags
        techniques = []
        mitre_field = record.get("MITRE") or record.get("MitreAttack") or record.get("Tags") or []
        if isinstance(mitre_field, list):
            for tag in mitre_field:
                if isinstance(tag, str):
                    techniques.extend(self.extract_techniques([tag]))
        elif isinstance(mitre_field, str):
            techniques.extend(self.extract_techniques([mitre_field]))

        # Description
        desc = record.get("Description") or record.get("Message") or record.get("Details") or ""
        artifact_name = record.get("Artifact") or record.get("_Source") or record.get("_ArtifactName")
        if artifact_name and desc:
            desc = f"[{artifact_name}] {desc}"
        elif artifact_name and not desc:
            desc = str(artifact_name)

        return Artifact(
            id=Artifact.new_id(),
            artifact_type=artifact_type,
            source=ArtifactSource.VELOCIRAPTOR,
            timestamp=ts,
            severity=Severity.INFORMATIONAL,
            host=host,
            user=user,
            process_name=record.get("ProcessName") or record.get("Image"),
            command_line=record.get("CommandLine"),
            file_path=record.get("TargetFilename") or record.get("FileName"),
            registry_key=record.get("TargetObject"),
            source_ip=record.get("SourceIp"),
            dest_ip=record.get("DestinationIp"),
            description=str(desc)[:1000] if desc else "Velociraptor record",
            raw=record,
            technique_ids=techniques,
            tags=["velociraptor", f"artifact.{artifact_name}"] if artifact_name else ["velociraptor"],
        )
