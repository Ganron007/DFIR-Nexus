"""CAPEv2 / CrowdStrike sandbox report importer.

Parses malware sandbox reports from:
- CAPEv2 (``report.json``): Contains ``info``, ``behavior``,
  ``network``, ``strings``, ``target``, ``dropped`` sections.
- CrowdStrike Falcon X sandbox: JSON exports with ``sandbox`` or
  ``malware`` fields and verdict information.
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


class SandboxImporter(Importer):
    """Parser for CAPEv2 and CrowdStrike sandbox JSON reports."""

    CAPE_SEVERITY_MAP: ClassVar[dict[str, Severity]] = {
        "malicious": Severity.CRITICAL,
        "suspicious": Severity.HIGH,
        "interesting": Severity.MEDIUM,
        "info": Severity.INFORMATIONAL,
    }

    @classmethod
    def source_class(cls) -> ArtifactSource:
        return ArtifactSource.CROWDSTRIKE

    @classmethod
    def can_handle(cls, path: Path) -> bool:
        """Heuristic: filename contains 'cape', 'sandbox', or 'report.json',
        or JSON with CAPEv2-style 'info' + 'behavior' keys."""
        if not path.is_file():
            return False
        name = path.name.lower()
        if "cape" in name or "sandbox" in name or name == "report.json":
            return True
        if not (name.endswith(".json") or name.endswith(".jsonl")):
            return False
        try:
            with path.open("r", encoding="utf-8", errors="replace") as f:
                head = f.read(8192)
        except OSError:
            return False
        return (
            ('"info"' in head and '"behavior"' in head)
            or ('"verdict"' in head and '"sandbox"' in head)
        )

    def parse(self, path: Path) -> Iterator[Artifact]:
        """Yield Artifacts from a sandbox report."""
        try:
            with path.open("r", encoding="utf-8", errors="replace") as f:
                data = json.load(f)
            if self._is_cape(data):
                yield from self._parse_cape(data, path)
            else:
                yield from self._parse_crowdstrike(data, path)
        except Exception:
            log.warning("Failed to parse sandbox report %s", path, exc_info=True)

    # ── CAPEv2 ──────────────────────────────────────────────────────────

    @staticmethod
    def _is_cape(data: dict[str, Any]) -> bool:
        """Detect CAPEv2 report shape."""
        return "info" in data and "behavior" in data

    def _parse_cape(self, data: dict[str, Any], path: Path) -> Iterator[Artifact]:
        """Parse a CAPEv2 report.json."""
        info: dict[str, Any] = data.get("info") or {}
        behavior: dict[str, Any] = data.get("behavior") or {}
        network: dict[str, Any] = data.get("network") or {}
        target: dict[str, Any] = data.get("target") or {}
        dropped: list[dict[str, Any]] = data.get("dropped") or []

        ts = self.normalize_timestamp(info.get("started") or info.get("ended"))
        if ts is None:
            ts = datetime.now(UTC)

        score = info.get("score") or info.get("severity")
        severity = self.CAPE_SEVERITY_MAP.get(str(score).lower(), Severity.INFORMATIONAL)

        category = str(info.get("category", ""))
        machine = info.get("machine") or {}

        # Summary artifact
        yield Artifact(
            id=Artifact.new_id(),
            artifact_type=ArtifactType.MALWARE,
            source=ArtifactSource.CROWDSTRIKE,
            timestamp=ts,
            severity=severity,
            host=str(machine.get("name") or machine.get("label")) or None,
            description=f"CAPEv2 sandbox: {category} score={score}",
            raw=info,
            tags=["cape", "sandbox", f"category.{category}" if category else "sandbox"],
        )

        # Process tree / API calls
        procs = behavior.get("processtree", []) or []
        for proc in procs:
            if isinstance(proc, dict):
                yield from self._cape_process_to_artifacts(proc, ts, severity)

        # Network indicators
        for dns in network.get("dns", []) or []:
            if isinstance(dns, dict):
                name = dns.get("request", "")
                if name:
                    yield Artifact(
                        id=Artifact.new_id(),
                        artifact_type=ArtifactType.DNS,
                        source=ArtifactSource.CROWDSTRIKE,
                        timestamp=ts,
                        severity=Severity.MEDIUM,
                        description=f"CAPEv2 DNS lookup: {name}",
                        raw=dns,
                        iocs=[name],
                        tags=["cape", "sandbox", "dns"],
                    )

        for host in network.get("hosts", []) or []:
            if isinstance(host, dict):
                ip = host.get("ip", "")
                if ip:
                    yield Artifact(
                        id=Artifact.new_id(),
                        artifact_type=ArtifactType.NETWORK,
                        source=ArtifactSource.CROWDSTRIKE,
                        timestamp=ts,
                        severity=Severity.MEDIUM,
                        dest_ip=ip,
                        dest_port=host.get("port"),
                        description=f"CAPEv2 network connection: {ip}:{host.get('port')}",
                        raw=host,
                        iocs=[ip],
                        tags=["cape", "sandbox", "network"],
                    )

        # Dropped files
        for drop in dropped:
            if isinstance(drop, dict):
                yield self._cape_dropped_to_artifact(drop, ts)

    def _cape_process_to_artifacts(
        self,
        proc: dict[str, Any],
        ts: datetime,
        severity: Severity,
    ) -> Iterator[Artifact]:
        """Convert a CAPE process tree node to Artifacts."""
        proc_name = str(proc.get("name", ""))
        proc_pid = None
        raw_pid = proc.get("pid")
        if raw_pid is not None:
            try:
                proc_pid = int(raw_pid)
            except (ValueError, TypeError):
                pass

        if proc_name:
            yield Artifact(
                id=Artifact.new_id(),
                artifact_type=ArtifactType.PROCESS,
                source=ArtifactSource.CROWDSTRIKE,
                timestamp=ts,
                severity=severity,
                process_name=proc_name,
                process_id=proc_pid,
                description=f"CAPEv2 process: {proc_name} (pid {proc_pid})",
                raw=proc,
                tags=["cape", "sandbox", "process"],
            )

        for child in proc.get("children", []) or []:
            if isinstance(child, dict):
                yield from self._cape_process_to_artifacts(child, ts, severity)

    @staticmethod
    def _cape_dropped_to_artifact(drop: dict[str, Any], ts: datetime) -> Artifact:
        """Convert a CAPE dropped file entry to an Artifact."""
        name = str(drop.get("name", ""))
        sha256 = str(drop.get("sha256", "")) or None
        md5 = str(drop.get("md5", "")) or None
        filepath = str(drop.get("guest_paths", [None])[0] if drop.get("guest_paths") else "") or None
        type_tag = str(drop.get("type", ""))

        return Artifact(
            id=Artifact.new_id(),
            artifact_type=ArtifactType.FILE,
            source=ArtifactSource.CROWDSTRIKE,
            timestamp=ts,
            severity=Severity.HIGH,
            file_path=filepath,
            file_hash_md5=md5,
            file_hash_sha256=sha256,
            description=f"CAPEv2 dropped file: {name}",
            raw=drop,
            iocs=[v for v in [sha256, md5] if v],
            tags=["cape", "sandbox", "dropped", f"type.{type_tag}" if type_tag else "file"],
        )

    # ── CrowdStrike ─────────────────────────────────────────────────────

    def _parse_crowdstrike(self, data: dict[str, Any], path: Path) -> Iterator[Artifact]:
        """Parse a CrowdStrike Falcon X sandbox report."""
        sandbox = data.get("sandbox") or data.get("verdict") or data
        if not isinstance(sandbox, dict):
            sandbox = data

        ts = self.normalize_timestamp(
            sandbox.get("created_timestamp") or sandbox.get("timestamp")
        )
        if ts is None:
            ts = datetime.now(UTC)

        verdict = str(sandbox.get("verdict") or sandbox.get("severity") or "").lower()
        if verdict in ("malicious", "high"):
            severity = Severity.CRITICAL
        elif verdict in ("suspicious", "medium"):
            severity = Severity.HIGH
        elif verdict in ("clean", "no specific threat"):
            severity = Severity.INFORMATIONAL
        else:
            severity = Severity.MEDIUM

        # Summary
        sha256 = str(sandbox.get("sha256") or sandbox.get("file_sha256", "")) or None
        filename = str(sandbox.get("filename") or sandbox.get("file_name", "")) or None
        filetype = str(sandbox.get("file_type") or sandbox.get("type", "")) or None

        yield Artifact(
            id=Artifact.new_id(),
            artifact_type=ArtifactType.MALWARE,
            source=ArtifactSource.CROWDSTRIKE,
            timestamp=ts,
            severity=severity,
            file_path=filename,
            file_hash_sha256=sha256,
            description=f"CrowdStrike sandbox: {filename or sha256 or 'unknown'} verdict={verdict}",
            raw=data,
            iocs=[v for v in [sha256] if v],
            tags=["crowdstrike", "sandbox", f"verdict.{verdict}" if verdict else "sandbox"],
        )

        # Extract indicators from sandbox results
        indicators = sandbox.get("indicators") or sandbox.get("signatures") or []
        for ind in indicators:
            if isinstance(ind, dict):
                ind_name = str(ind.get("name") or ind.get("description", ""))
                ind_severity = str(ind.get("severity", "")).lower()
                sev = Severity.MEDIUM
                if ind_severity in ("critical", "high"):
                    sev = Severity.HIGH
                elif ind_severity in ("low", "informational", "info"):
                    sev = Severity.LOW

                technique_ids = self.extract_techniques(ind.get("tags") or ind.get("mitre") or [])

                yield Artifact(
                    id=Artifact.new_id(),
                    artifact_type=ArtifactType.MALWARE,
                    source=ArtifactSource.CROWDSTRIKE,
                    timestamp=ts,
                    severity=sev,
                    description=f"CrowdStrike indicator: {ind_name}",
                    raw=ind,
                    technique_ids=technique_ids,
                    tags=["crowdstrike", "sandbox", "indicator"],
                )
