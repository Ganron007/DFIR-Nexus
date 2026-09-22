"""KAPE BasicCollection output importer.

KAPE (Kroll Artifact Parser and Extractor) outputs a folder structure
with copies of forensic artifacts. The most common output is
`C/Windows/System32/winevt/Logs/*.evtx` plus registry hives, prefetch,
$MFT, etc.

This importer is a directory walker that delegates to other importers
based on file type. It does NOT parse KAPE's own metadata files
(BasicInformation.txt, etc.) — those are skimmed for the host name only.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

from nexus.ingest.base import Importer
from nexus.ingest.schemas import (
    Artifact,
    ArtifactSource,
    ArtifactType,
    Severity,
)

log = logging.getLogger(__name__)


class KAPEImporter(Importer):
    """Parser for KAPE BasicCollection output directories.

    Reads the collection logs (``*CopyLog.csv`` / ``*SkipLog.csv``) when
    present, else walks the tree, and records one 'KAPE collection' artifact
    per file (path, size, mtime, host).

    Raw host artifacts inside a KAPE tree (.evtx, hives, .lnk, $MFT, prefetch)
    are **N-lane material** — process them with EvtxECmd / RECmd / LECmd /
    MFTECmd and ingest their output; this importer only describes their
    collection. KAPE *module* CSV/JSON outputs are the parsed layer.
    """

    # File extensions we know how to handle and what to record
    KNOWN_EXTS: dict[str, str] = {
        ".evtx": "event_log",
        ".pf": "prefetch",
        ".lnk": "shortcut",
        ".reg": "registry_export",
        ".csv": "csv_artifact",
        ".json": "json_artifact",
        ".xml": "xml_artifact",
        ".log": "log_artifact",
        ".txt": "text_artifact",
    }

    # Files we recognize as Windows forensic artifacts by name
    KNOWN_NAMES: dict[str, str] = {
        "$MFT": "mft",
        "$MFTMirr": "mft_mirror",
        "$LogFile": "ntfs_logfile",
        "$UsnJrnl:$J": "usnjrnl",
        "SYSTEM": "registry_hive_system",
        "SOFTWARE": "registry_hive_software",
        "SAM": "registry_hive_sam",
        "SECURITY": "registry_hive_security",
        "NTUSER.DAT": "registry_hive_ntuser",
        "UsrClass.dat": "registry_hive_usrclass",
    }

    @classmethod
    def source_class(cls) -> ArtifactSource:
        return ArtifactSource.KAPE

    @classmethod
    def can_handle(cls, path: Path) -> bool:
        """Heuristic: KAPE markers, collection logs, or an .evtx tree."""
        if not path.is_dir():
            return False
        # Look for KAPE's signature file
        for marker in ("BasicInformation.txt", "KAPE_output.txt", "kape_output"):
            if (path / marker).exists():
                return True
        # KAPE collection logs written at the output root (TriageImage volumes)
        if any(path.glob("*CopyLog.csv")) or any(path.glob("*SkipLog.csv")):
            return True
        # Fallback: any directory containing .evtx files
        return any(path.rglob("*.evtx"))

    def parse(self, path: Path) -> Iterator[Artifact]:
        """Parse KAPE collection logs when present, else walk the output tree.

        Collection logs (``*CopyLog.csv`` / ``*SkipLog.csv``) are authoritative:
        one row per collected file with source path, size, SHA1 and source
        timestamps — parsing them avoids re-walking the (huge) copied tree.
        """
        host_name = self._extract_host(path)
        copy_logs = sorted(path.glob("*CopyLog.csv"))
        skip_logs = sorted(path.glob("*SkipLog.csv"))
        if copy_logs or skip_logs:
            for log_file in copy_logs:
                yield from self._parse_copy_log(log_file, host_name)
            for skip_log in skip_logs:
                yield from self._parse_skip_log(skip_log, host_name)
            return
        for file in sorted(path.rglob("*")):
            if not file.is_file():
                continue
            yield self._file_to_artifact(file, host_name)

    def _file_to_artifact(self, file: Path, host_name: str | None) -> Artifact:
        """Map a KAPE-collected file to an Artifact describing it."""
        name = file.name.upper()
        ext = file.suffix.lower()
        ts, ts_synthesized = self._safe_mtime(file)
        artifact_type = ArtifactType.FILE
        tags = ["kape"]
        description = ""

        # Check known names first
        if name in self.KNOWN_NAMES:
            kind = self.KNOWN_NAMES[name]
            description = f"KAPE collected {kind}: {file.name}"
            tags.append(f"kape.{kind}")
            if "registry_hive" in kind:
                artifact_type = ArtifactType.REGISTRY
        elif ext in self.KNOWN_EXTS:
            kind = self.KNOWN_EXTS[ext]
            description = f"KAPE collected {kind}: {file.name}"
            tags.append(f"kape.{kind}")
            if ext == ".evtx":
                artifact_type = ArtifactType.UNKNOWN  # raw EVTX: N-lane (EvtxECmd) — descriptor only
            elif ext == ".pf":
                artifact_type = ArtifactType.PROCESS
            elif ext == ".lnk":
                artifact_type = ArtifactType.FILE
        else:
            description = f"KAPE file: {file.name}"
            tags.append("kape.unknown")

        return Artifact(
            id=Artifact.new_id(),
            artifact_type=artifact_type,
            source=ArtifactSource.KAPE,
            timestamp=ts,
            ts_synthesized=ts_synthesized,
            severity=Severity.INFORMATIONAL,
            host=host_name,
            file_path=str(file),
            description=description,
            raw={"path": str(file), "size": file.stat().st_size, "mtime": ts.isoformat()},
            tags=tags,
        )

    @staticmethod
    def _extract_host(path: Path) -> str | None:
        """Try to extract the host name from KAPE's BasicInformation.txt."""
        for marker in ("BasicInformation.txt", "KAPE_output.txt"):
            f = path / marker
            if f.exists():
                try:
                    text = f.read_text(encoding="utf-8", errors="replace")
                    for line in text.splitlines():
                        # Look for "MachineName: <host>" or "Computer: <host>"
                        for label in ("MachineName", "Computer", "Hostname", "Host"):
                            if label in line and ":" in line:
                                value = line.split(":", 1)[1].strip()
                                if value and value != "-":
                                    return value
                except OSError:
                    pass
        return None

    _TS_FORMATS = ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%m/%d/%Y %H:%M:%S")

    @classmethod
    def _parse_ts(cls, value: str | None) -> datetime | None:
        v = (value or "").strip()
        if not v:
            return None
        # .NET/KAPE timestamps can carry 7 fractional digits (100 ns).
        m = re.match(r"^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})(?:\.(\d+))?$", v)
        if m:
            frac = (m.group(3) or "000000")[:6].ljust(6, "0")
            try:
                return datetime.strptime(
                    f"{m.group(1)} {m.group(2)}.{frac}", "%Y-%m-%d %H:%M:%S.%f"
                ).replace(tzinfo=UTC)
            except ValueError:
                pass
        for fmt in cls._TS_FORMATS:
            try:
                return datetime.strptime(v, fmt).replace(tzinfo=UTC)
            except ValueError:
                continue
        return None

    def _classify(self, name: str, ext: str) -> tuple[ArtifactType, str, list[str]]:
        """(artifact_type, kind, tags) for a file name/extension."""
        tags = ["kape"]
        if name in self.KNOWN_NAMES:
            kind = self.KNOWN_NAMES[name]
            tags.append(f"kape.{kind}")
            at = ArtifactType.REGISTRY if "registry_hive" in kind else ArtifactType.FILE
            return at, kind, tags
        if ext in self.KNOWN_EXTS:
            kind = self.KNOWN_EXTS[ext]
            tags.append(f"kape.{kind}")
            if ext == ".evtx":
                return ArtifactType.UNKNOWN, kind, tags
            if ext == ".pf":
                return ArtifactType.PROCESS, kind, tags
            return ArtifactType.FILE, kind, tags
        tags.append("kape.unknown")
        return ArtifactType.FILE, "file", tags

    def _parse_copy_log(self, log_file: Path, host_name: str | None) -> Iterator[Artifact]:
        """One artifact per CopyLog row (source path, size, SHA1, timestamps)."""
        import csv

        with log_file.open("r", encoding="utf-8-sig", errors="replace", newline="") as f:
            for row in csv.DictReader(f):
                src = (row.get("SourceFile") or "").strip()
                if not src:
                    continue
                ts = self._parse_ts(row.get("CopiedTimestamp"))
                ts_synthesized = ts is None
                if ts is None:
                    ts = datetime.now(UTC)
                norm = src.replace("\\", "/")
                name = norm.rsplit("/", 1)[-1]
                artifact_type, kind, tags = self._classify(name.upper(), Path(norm).suffix.lower())
                sha1 = (row.get("SourceFileSha1") or "").strip()
                size = (row.get("FileSize") or "").strip()
                yield Artifact(
                    id=Artifact.new_id(),
                    artifact_type=artifact_type,
                    source=ArtifactSource.KAPE,
                    timestamp=ts,
                    ts_synthesized=ts_synthesized,
                    severity=Severity.INFORMATIONAL,
                    host=host_name,
                    file_path=src,
                    file_hash_sha1=sha1,
                    description=f"KAPE collected {kind}: {name} ({size} B)",
                    raw={
                        "source": "kape_copy_log",
                        "destination": (row.get("DestinationFile") or "").strip(),
                        "size": size,
                        "sha1": sha1,
                        "created_utc": (row.get("CreatedOnUtc") or "").strip(),
                        "modified_utc": (row.get("ModifiedOnUtc") or "").strip(),
                        "accessed_utc": (row.get("LastAccessedOnUtc") or "").strip(),
                        "deferred": (row.get("DeferredCopy") or "").strip(),
                        "copy_duration": (row.get("CopyDuration") or "").strip(),
                        "log": log_file.name,
                    },
                    tags=tags,
                )

    def _parse_skip_log(self, log_file: Path, host_name: str | None) -> Iterator[Artifact]:
        """One artifact per SkipLog row (skipped path + reason)."""
        import csv

        with log_file.open("r", encoding="utf-8-sig", errors="replace", newline="") as f:
            for row in csv.DictReader(f):
                src = (row.get("SourceFile") or "").strip()
                if not src:
                    continue
                reason = (row.get("Reason") or "").strip()
                norm = src.replace("\\", "/")
                name = norm.rsplit("/", 1)[-1]
                yield Artifact(
                    id=Artifact.new_id(),
                    artifact_type=ArtifactType.FILE,
                    source=ArtifactSource.KAPE,
                    timestamp=datetime.now(UTC),
                    ts_synthesized=True,
                    severity=Severity.INFORMATIONAL,
                    host=host_name,
                    file_path=src,
                    file_hash_sha1=(row.get("SourceFileSha1") or "").strip(),
                    description=f"KAPE skipped: {name} — {reason}" if reason else f"KAPE skipped: {name}",
                    raw={"source": "kape_skip_log", "reason": reason, "log": log_file.name},
                    tags=["kape", "kape.skipped"],
                )

    @staticmethod
    def _safe_mtime(path: Path) -> tuple[datetime, bool]:
        """(mtime, synthesized) — mtime is evidence-derived but NOT the
        artifact's event time, so it is flagged (EH-7)."""
        try:
            return datetime.fromtimestamp(path.stat().st_mtime, tz=UTC), True
        except OSError:
            return datetime.now(UTC), True
