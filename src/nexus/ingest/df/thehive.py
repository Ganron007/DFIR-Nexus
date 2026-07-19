"""TheHive case JSON importer.

Parses TheHive (incident response case management) JSON exports. Each
case has `title`, `description`, `severity`, `tlp`, `startDate`,
`observables` (list of IoCs), and `tasks`.
"""

from __future__ import annotations

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


class TheHiveImporter(Importer):
    """Parser for TheHive case JSON exports."""

    SEVERITY_MAP: ClassVar[dict[int, Severity]] = {
        1: Severity.LOW,
        2: Severity.MEDIUM,
        3: Severity.HIGH,
        4: Severity.CRITICAL,
    }

    @classmethod
    def source_class(cls) -> ArtifactSource:
        return ArtifactSource.THEHIVE

    @classmethod
    def can_handle(cls, path: Path) -> bool:
        """Heuristic: JSON with TheHive shape (case title, observables, tasks)."""
        if not path.is_file():
            return False
        name = path.name.lower()
        if not (name.endswith(".json") or name.endswith(".jsonl")):
            return False
        try:
            with path.open("r", encoding="utf-8", errors="replace") as f:
                head = f.read(8192)
        except OSError:
            return False
        return (
            "thehive" in head.lower()
            or ("title" in head and "tlp" in head and "observables" in head)
            or ("caseId" in head and "observables" in head)
        )

    def parse(self, path: Path) -> Iterator[Artifact]:
        """Yield one Artifact per TheHive case/observable/task."""
        with path.open("r", encoding="utf-8", errors="replace") as f:
            data = json.load(f)
        cases = self._extract_cases(data)
        for case in cases:
            yield from self._case_to_artifacts(case)

    @staticmethod
    def _extract_cases(data: Any) -> list[dict[str, Any]]:
        """Pull cases from various TheHive export shapes."""
        if isinstance(data, list):
            return [c for c in data if isinstance(c, dict)]
        if isinstance(data, dict):
            for key in ("cases", "data", "results", "items"):
                if key in data and isinstance(data[key], list):
                    return [c for c in data[key] if isinstance(c, dict)]
            if "title" in data and "tlp" in data:
                return [data]
        return []

    def _case_to_artifacts(self, case: dict[str, Any]) -> Iterator[Artifact]:
        """Convert a TheHive case into one summary Artifact plus one per observable."""
        title = case.get("title", "TheHive case")
        severity_int = int(case.get("severity", 1) or 1)
        severity = self.SEVERITY_MAP.get(severity_int, Severity.LOW)
        tlp = str(case.get("tlp", ""))
        case_id = case.get("id") or case.get("caseId", "")
        ts = self.normalize_timestamp(case.get("startDate") or case.get("createdAt")) or datetime.now(UTC)

        # Yield a summary artifact for the case itself
        yield Artifact(
            id=Artifact.new_id(),
            artifact_type=ArtifactType.ALERT,
            source=ArtifactSource.THEHIVE,
            timestamp=ts,
            severity=severity,
            description=f"TheHive case: {title} (TLP:{tlp}, severity:{severity_int})",
            raw=case,
            tags=["thehive", f"tlp.{tlp.lower()}" if tlp else "thehive", f"case.{case_id}"],
        )

        # Yield one Artifact per observable
        observables = case.get("observables", []) or []
        for obs in observables:
            if isinstance(obs, dict):
                yield self._observable_to_artifact(obs, title, case_id, ts, tlp)

    def _observable_to_artifact(
        self,
        obs: dict[str, Any],
        case_title: str,
        case_id: str,
        ts: datetime,
        tlp: str,
    ) -> Artifact:
        """Map a TheHive observable to an Artifact."""
        data_type = str(obs.get("dataType", ""))
        data_value = str(obs.get("data", ""))
        ioc = bool(obs.get("ioc", False))

        # Type mapping
        type_map = {
            "ip": ArtifactType.NETWORK,
            "ipv4": ArtifactType.NETWORK,
            "ipv6": ArtifactType.NETWORK,
            "domain": ArtifactType.DNS,
            "fqdn": ArtifactType.NETWORK,
            "url": ArtifactType.HTTP,
            "uri": ArtifactType.HTTP,
            "email": ArtifactType.AUTH,
            "hash": ArtifactType.MALWARE,
            "md5": ArtifactType.MALWARE,
            "sha1": ArtifactType.MALWARE,
            "sha256": ArtifactType.MALWARE,
            "filename": ArtifactType.FILE,
            "filepath": ArtifactType.FILE,
            "process": ArtifactType.PROCESS,
            "registry": ArtifactType.REGISTRY,
            "user-agent": ArtifactType.HTTP,
        }
        artifact_type = type_map.get(data_type.lower(), ArtifactType.IOC)

        # Hashes
        file_md5 = file_sha1 = file_sha256 = None
        if data_type.lower() == "md5":
            file_md5 = data_value
        elif data_type.lower() == "sha1":
            file_sha1 = data_value
        elif data_type.lower() == "sha256":
            file_sha256 = data_value
        elif data_type.lower() == "hash" and len(data_value) in (32, 40, 64):
            if len(data_value) == 32:
                file_md5 = data_value
            elif len(data_value) == 40:
                file_sha1 = data_value
            else:
                file_sha256 = data_value

        # Severity: IoC = high
        severity = Severity.HIGH if ioc else Severity.INFORMATIONAL

        return Artifact(
            id=Artifact.new_id(),
            artifact_type=artifact_type,
            source=ArtifactSource.THEHIVE,
            timestamp=ts,
            severity=severity,
            file_hash_md5=file_md5,
            file_hash_sha1=file_sha1,
            file_hash_sha256=file_sha256,
            source_ip=data_value if artifact_type == ArtifactType.NETWORK else None,
            dest_ip=data_value if artifact_type == ArtifactType.NETWORK else None,
            description=f"TheHive [{case_title}] {data_type}={data_value} (ioc={ioc})",
            raw=obs,
            iocs=[data_value] if data_value else [],
            tags=[
                "thehive",
                f"type.{data_type.lower()}" if data_type else "thehive",
                f"tlp.{tlp.lower()}" if tlp else "thehive",
                "ioc.true" if ioc else "ioc.false",
                f"case.{case_id}",
            ],
        )
