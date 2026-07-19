"""AmCache parser.

Parses Windows AmCache.hve (Application Compatibility Cache) which records
every program executed on a Windows host. Critical for malware analysis —
shows the full path, SHA1 hash, file size, timestamps, and publisher info.

Two modes:
1. **Binary mode** (requires `python-registry`):
   - Parses raw Amcache.hve file
   - Most comprehensive (full binary path, file ID, etc.)

2. **CSV mode** (always works):
   - Parses pre-exported AmCache.csv from KAPE/AmcacheParser
   - Common columns: FullPath, Name, SHA1, FileSize, FileVersionString, etc.
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
    """Parser for Windows AmCache (Amcache.hve or pre-exported CSV)."""

    @classmethod
    def source_class(cls) -> ArtifactSource:
        return ArtifactSource.AMCACHE

    @classmethod
    def can_handle(cls, path: Path) -> bool:
        """Heuristic: Amcache.hve binary or AmCache.csv with expected columns."""
        if not path.is_file():
            return False
        name_lower = path.name.lower()
        if name_lower in {"amcache.hve", "amcache"}:
            return True
        if name_lower.endswith(".csv"):
            try:
                with path.open("r", encoding="utf-8-sig", errors="replace") as f:
                    head = f.read(4096)
            except OSError:
                return False
            # Common AmCache CSV columns
            return ("FullPath" in head or "Path" in head) and (
                "SHA1" in head or "FileId" in head or "Name" in head
            )
        return False

    def parse(self, path: Path) -> Iterator[Artifact]:
        """Yield Artifact objects from an AmCache file."""
        name_lower = path.name.lower()
        if name_lower.endswith(".csv"):
            yield from self._parse_csv(path)
            return
        if name_lower in {"amcache.hve", "amcache"}:
            yield from self._parse_binary(path)

    def _parse_binary(self, path: Path) -> Iterator[Artifact]:
        """Parse Amcache.hve (requires python-registry)."""
        try:
            from Registry import Registry
        except ImportError:
            log.error("Cannot parse Amcache.hve: install python-registry")
            return
        try:
            reg = Registry(str(path))
        except Exception as e:  # noqa: BLE001
            log.warning("Failed to open %s: %s", path, e)
            return
        # Amcache.hve has Root\File table with FullPath, SHA1, etc.
        # python-registry uses subkeys() / values() pattern
        try:
            root = reg.root()
            file_key = None
            for subkey in root.subkeys():
                if subkey.name().lower() == "file":
                    file_key = subkey
                    break
            if file_key is None:
                # Try the root directly
                file_key = root
            for entry_key in file_key.subkeys():
                values = {v.name(): v.value() for v in entry_key.values()}
                yield self._record_to_artifact(values, str(path))
        except Exception as e:  # noqa: BLE001
            log.warning("Failed to walk Amcache hive: %s", e)

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
            source=ArtifactSource.UNKNOWN,
            timestamp=ts,
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
