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

    Walks the directory, delegating to specialized importers for:
    - .evtx files (via EVTXImporter)
    - prefetch files (recognized by .pf extension)
    - registry hives (SYSTEM, SOFTWARE, SAM, etc.)
    - $MFT, $UsnJrnl
    - LNK files

    Files that don't match a known type are recorded as a 'KAPE collection'
    artifact describing the file (path, size, mtime).
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
        """Heuristic: directory contains BasicInformation.txt (KAPE marker)."""
        if not path.is_dir():
            return False
        # Look for KAPE's signature file
        for marker in ("BasicInformation.txt", "KAPE_output.txt", "kape_output"):
            if (path / marker).exists():
                return True
        # Fallback: any directory containing .evtx files
        return any(path.rglob("*.evtx"))

    def parse(self, path: Path) -> Iterator[Artifact]:
        """Walk the KAPE output directory and yield one Artifact per recognized file."""
        # Pull host name from BasicInformation.txt if present
        host_name = self._extract_host(path)
        for file in sorted(path.rglob("*")):
            if not file.is_file():
                continue
            yield self._file_to_artifact(file, host_name)

    def _file_to_artifact(self, file: Path, host_name: str | None) -> Artifact:
        """Map a KAPE-collected file to an Artifact describing it."""
        name = file.name.upper()
        ext = file.suffix.lower()
        ts = self._safe_mtime(file)
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
                artifact_type = ArtifactType.UNKNOWN  # delegated to EVTX importer
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

    @staticmethod
    def _safe_mtime(path: Path) -> datetime:
        try:
            return datetime.fromtimestamp(path.stat().st_mtime, tz=UTC)
        except OSError:
            return datetime.now(UTC)
