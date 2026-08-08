"""DFIR-IRIS case import.

Parses DFIR-IRIS (Incident Response Investigation System) JSON exports
containing ``cases``, ``assets``, ``iocs``, and ``timeline`` fields.
Each case can contain multiple assets and IOCs which are mapped to
individual Artifacts.
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


class IRISImporter(Importer):
    """Parser for DFIR-IRIS case JSON exports."""

    SEVERITY_MAP: ClassVar[dict[int, Severity]] = {
        1: Severity.LOW,
        2: Severity.MEDIUM,
        3: Severity.HIGH,
        4: Severity.CRITICAL,
    }

    IOC_TYPE_MAP: ClassVar[dict[str, ArtifactType]] = {
        "ip": ArtifactType.NETWORK,
        "ipv4": ArtifactType.NETWORK,
        "ipv6": ArtifactType.NETWORK,
        "domain": ArtifactType.DNS,
        "url": ArtifactType.HTTP,
        "uri": ArtifactType.HTTP,
        "hash": ArtifactType.MALWARE,
        "md5": ArtifactType.MALWARE,
        "sha1": ArtifactType.MALWARE,
        "sha256": ArtifactType.MALWARE,
        "email": ArtifactType.AUTH,
        "filename": ArtifactType.FILE,
        "filepath": ArtifactType.FILE,
        "registry": ArtifactType.REGISTRY,
        "process": ArtifactType.PROCESS,
    }

    @classmethod
    def source_class(cls) -> ArtifactSource:
        return ArtifactSource.THEHIVE

    @classmethod
    def can_handle(cls, path: Path) -> bool:
        """Heuristic: filename contains 'iris', or JSON with 'cases' + 'iocs' keys."""
        if not path.is_file():
            return False
        name = path.name.lower()
        if "iris" in name:
            return True
        if not (name.endswith(".json") or name.endswith(".jsonl")):
            return False
        try:
            with path.open("r", encoding="utf-8", errors="replace") as f:
                head = f.read(8192)
        except OSError:
            return False
        return '"cases"' in head and '"iocs"' in head

    def parse(self, path: Path) -> Iterator[Artifact]:
        """Yield one Artifact per IRIS case, asset, IOC, and timeline event."""
        try:
            with path.open("r", encoding="utf-8", errors="replace") as f:
                data = json.load(f)
            cases = self._extract_cases(data)
            for case in cases:
                yield from self._case_to_artifacts(case)
        except Exception:
            log.warning("Failed to parse IRIS file %s", path, exc_info=True)

    @staticmethod
    def _extract_cases(data: Any) -> list[dict[str, Any]]:
        """Pull cases from various IRIS export shapes."""
        if isinstance(data, list):
            return [c for c in data if isinstance(c, dict)]
        if isinstance(data, dict):
            for key in ("cases", "data", "results"):
                if key in data and isinstance(data[key], list):
                    return [c for c in data[key] if isinstance(c, dict)]
            if "case_name" in data or "case_id" in data:
                return [data]
            # Wrapped export: {"case": {...}, "iocs"/"assets"/"timeline": [...]}
            if "case" in data and isinstance(data["case"], dict):
                case = dict(data["case"])
                for key in ("iocs", "assets", "timeline"):
                    if key in data and isinstance(data[key], list):
                        case.setdefault(key, data[key])
                return [case]
        return []

    def _case_to_artifacts(self, case: dict[str, Any]) -> Iterator[Artifact]:
        """Convert a DFIR-IRIS case into multiple Artifacts."""
        case_name = str(case.get("case_name") or case.get("name") or "IRIS Case")
        case_id = case.get("case_id") or case.get("id", "")
        severity_int = int(case.get("severity_id") or case.get("severity") or 1)
        severity = self.SEVERITY_MAP.get(severity_int, Severity.LOW)
        ts = self.normalize_timestamp(
            case.get("open_date") or case.get("created_at") or case.get("opened_at")
        )
        if ts is None:
            ts = datetime.now(UTC)

        # Case summary artifact
        yield Artifact(
            id=Artifact.new_id(),
            artifact_type=ArtifactType.ALERT,
            source=ArtifactSource.THEHIVE,
            timestamp=ts,
            severity=severity,
            description=f"DFIR-IRIS case: {case_name}",
            raw=case,
            tags=["iris", f"case.{case_id}"],
        )

        # Assets
        assets = case.get("assets", []) or []
        for asset in assets:
            if isinstance(asset, dict):
                yield self._asset_to_artifact(asset, case_name, case_id, ts, severity)

        # IOCs
        iocs = case.get("iocs", []) or []
        for ioc in iocs:
            if isinstance(ioc, dict):
                yield self._ioc_to_artifact(ioc, case_name, case_id, ts)

        # Timeline entries
        timeline = case.get("timeline", []) or []
        for entry in timeline:
            if isinstance(entry, dict):
                artifact = self._timeline_to_artifact(entry, case_name, case_id)
                if artifact is not None:
                    yield artifact

    def _asset_to_artifact(
        self,
        asset: dict[str, Any],
        case_name: str,
        case_id: Any,
        ts: datetime,
        severity: Severity,
    ) -> Artifact:
        """Map an IRIS asset to an Artifact."""
        asset_name = str(asset.get("name") or asset.get("asset_name") or "")
        asset_type = str(asset.get("type") or asset.get("asset_type") or "")
        ip = str(asset.get("ip") or asset.get("asset_ip") or "") or None
        domain = str(asset.get("domain") or asset.get("asset_domain") or "") or None

        artifact_type = ArtifactType.UNKNOWN
        if ip:
            artifact_type = ArtifactType.NETWORK
        elif domain:
            artifact_type = ArtifactType.DNS
        elif "file" in asset_type.lower():
            artifact_type = ArtifactType.FILE

        tags = ["iris", "asset", f"type.{asset_type.lower()}" if asset_type else "asset", f"case.{case_id}"]

        return Artifact(
            id=Artifact.new_id(),
            artifact_type=artifact_type,
            source=ArtifactSource.THEHIVE,
            timestamp=self.normalize_timestamp(asset.get("date_added") or asset.get("created_at")) or ts,
            severity=severity,
            host=asset_name or None,
            source_ip=ip,
            dest_ip=ip,
            description=f"IRIS asset [{case_name}]: {asset_name} ({asset_type})",
            raw=asset,
            tags=tags,
        )

    def _ioc_to_artifact(
        self,
        ioc: dict[str, Any],
        case_name: str,
        case_id: Any,
        ts: datetime,
    ) -> Artifact:
        """Map an IRIS IOC to an Artifact."""
        ioc_value = str(ioc.get("ioc_value") or ioc.get("value") or "")
        ioc_type = str(ioc.get("ioc_type") or ioc.get("type") or "")
        ioc_desc = str(ioc.get("description") or "")
        tlp = str(ioc.get("tlp_id") or ioc.get("tlp") or "")

        artifact_type = self.IOC_TYPE_MAP.get(ioc_type.lower(), ArtifactType.IOC)

        file_md5 = file_sha1 = file_sha256 = None
        if ioc_type.lower() == "md5":
            file_md5 = ioc_value
        elif ioc_type.lower() == "sha1":
            file_sha1 = ioc_value
        elif ioc_type.lower() == "sha256":
            file_sha256 = ioc_value

        tags = ["iris", "ioc", f"type.{ioc_type.lower()}" if ioc_type else "ioc", f"case.{case_id}"]
        if tlp:
            tags.append(f"tlp.{tlp.lower()}")

        return Artifact(
            id=Artifact.new_id(),
            artifact_type=artifact_type,
            source=ArtifactSource.THEHIVE,
            timestamp=self.normalize_timestamp(ioc.get("date_added") or ioc.get("created_at")) or ts,
            severity=Severity.HIGH,
            source_ip=ioc_value if artifact_type == ArtifactType.NETWORK else None,
            dest_ip=ioc_value if artifact_type == ArtifactType.NETWORK else None,
            file_hash_md5=file_md5,
            file_hash_sha1=file_sha1,
            file_hash_sha256=file_sha256,
            description=ioc_desc or f"IRIS IOC [{case_name}]: {ioc_type}={ioc_value}",
            raw=ioc,
            iocs=[ioc_value] if ioc_value else [],
            tags=tags,
        )

    def _timeline_to_artifact(
        self,
        entry: dict[str, Any],
        case_name: str,
        case_id: Any,
    ) -> Artifact | None:
        """Map an IRIS timeline entry to an Artifact."""
        try:
            ts = self.normalize_timestamp(
                entry.get("event_date") or entry.get("timestamp")
            )
            if ts is None:
                ts = datetime.now(UTC)

            event_title = str(entry.get("event_title") or entry.get("title") or "")
            event_cat = str(entry.get("category") or entry.get("event_category") or "")
            severity_raw = entry.get("severity_id") or entry.get("severity")
            severity = Severity.INFORMATIONAL
            if severity_raw is not None:
                with contextlib.suppress(ValueError, TypeError):
                    severity = self.SEVERITY_MAP.get(int(severity_raw), Severity.INFORMATIONAL)

            tags = ["iris", "timeline", f"case.{case_id}"]
            if event_cat:
                tags.append(f"cat.{event_cat.lower()}")

            return Artifact(
                id=Artifact.new_id(),
                artifact_type=ArtifactType.ALERT,
                source=ArtifactSource.THEHIVE,
                timestamp=ts,
                severity=severity,
                description=f"IRIS timeline [{case_name}]: {event_title}",
                raw=entry,
                tags=tags,
            )
        except Exception:
            log.debug("Skipping malformed IRIS timeline entry: %s", entry, exc_info=True)
            return None
