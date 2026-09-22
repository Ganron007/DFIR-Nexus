"""AmCache importer (AmcacheParser / KAPE CSV export).

Raw ``Amcache.hve`` is a **host artifact processed in the N-lane** by
AmcacheParser; the ingest lane consumes that CSV output (FullPath, Name,
SHA1, FileSize, FileVersionString, ...).
"""

from __future__ import annotations

import csv
import logging
import re
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


class AmCacheImporter(Importer):
    """Parser for AmcacheParser CSV exports (raw hives are N-lane)."""

    @classmethod
    def source_class(cls) -> ArtifactSource:
        return ArtifactSource.AMCACHE

    @classmethod
    def can_handle(cls, path: Path) -> bool:
        """AmcacheParser CSV with the expected columns (raw hives are N-lane)."""
        if not path.is_file() or not path.name.lower().endswith(".csv"):
            return False
        try:
            with path.open("r", encoding="utf-8-sig", errors="replace") as f:
                head = f.read(4096)
        except OSError:
            return False
        # Common AmCache CSV columns
        return ("FullPath" in head or "Path" in head) and (
            "SHA1" in head or "FileId" in head or "Name" in head
        )

    def parse(self, path: Path) -> Iterator[Artifact]:
        """Yield Artifact objects from an AmCache CSV export."""
        if path.name.lower().endswith(".csv"):
            yield from self._parse_csv(path)

    def _parse_csv(self, path: Path) -> Iterator[Artifact]:
        """Parse a pre-exported AmCache.csv (KAPE / AmcacheParser)."""
        try:
            with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    # Convert all values to str
                    record = {k: (str(v) if v is not None else "") for k, v in row.items()}
                    yield self._record_to_artifact(record, str(path))
        except OSError as e:
            log.warning("Could not read %s: %s", path, e)

    def _record_to_artifact(self, record: dict[str, Any], source_path: str) -> Artifact:
        """Map an AmCache record to an Artifact."""
        # Pull common fields with case-insensitive matching
        def get(*keys: str) -> str:
            for k in keys:
                for rk, rv in record.items():
                    if rk.lower() == k.lower() and rv:
                        return str(rv)
            return ""

        full_path = get("FullPath", "Path", "PathName", "FilePath")
        name = get("Name", "FileName", "Filename")
        sha1 = get("SHA1", "Sha1")
        sha256 = get("SHA256", "Sha256")
        md5 = get("MD5", "Md5")
        publisher = get("Publisher", "CompanyName", "SignedBy")
        version = get("FileVersion", "FileVersionString", "ProductVersion")
        # Timestamps
        ts_str = get("FileKeyLastWriteTimestamp", "LastWriteTime", "KeyTimestamp", "Created")
        ts = self.normalize_timestamp(ts_str) if ts_str else None
        ts_synthesized = ts is None
        if ts is None:
            try:
                ts = datetime.fromtimestamp(Path(source_path).stat().st_mtime, tz=UTC)
            except OSError:
                ts = datetime.now(UTC)

        # Severity
        severity = Severity.INFORMATIONAL
        # Suspicious paths
        path_lower = full_path.lower() if full_path else ""
        for pattern in [
            r"\\temp\\", r"\\appdata\\", r"\\downloads\\", r"\\programdata\\",
            r"\\users\\public\\", r"\\recycle", r"\\perflogs",
        ]:
            if re.search(pattern, path_lower):
                severity = Severity.HIGH
                break

        desc = f"AmCache: {name or full_path or 'unknown'}"
        if publisher:
            desc += f" ({publisher})"
        if version:
            desc += f" v{version}"

        return Artifact(
            id=Artifact.new_id(),
            artifact_type=ArtifactType.MALWARE,
            source=ArtifactSource.AMCACHE,
            timestamp=ts,
            ts_synthesized=ts_synthesized,
            severity=severity,
            file_path=full_path or None,
            process_name=name or None,
            file_hash_md5=md5 or None,
            file_hash_sha1=sha1 or None,
            file_hash_sha256=sha256 or None,
            description=desc,
            raw=record,
            tags=["amcache"],
            iocs=[h for h in (sha1, sha256, md5) if h],
        )
