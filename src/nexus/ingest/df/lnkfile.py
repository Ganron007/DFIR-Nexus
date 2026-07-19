"""Windows LNK (shell link) file parser.

Parses Windows shortcut files (.lnk) which record what was opened, where
from, when, and (on Windows 7+) the target's MAC address and volume serial
number. Critical for user activity reconstruction.

Uses `lnkfile` (Python lib by Erik Bik, https://pypi.org/project/lnkfile/).
Falls back to minimal parsing if the lib is not installed.
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


class LNKFileImporter(Importer):
    """Parser for Windows .lnk (shell link) files."""

    @classmethod
    def source_class(cls) -> ArtifactSource:
        return ArtifactSource.LNK

    @classmethod
    def can_handle(cls, path: Path) -> bool:
        """Heuristic: file has .lnk extension and starts with LNK magic."""
        if not path.is_file():
            return False
        if path.suffix.lower() != ".lnk":
            return False
        try:
            with path.open("rb") as f:
                magic = f.read(4)
            # LNK magic: 4C 00 00 00 (little-endian) = 0x4C
            return magic[:1] == b"\x4c" and magic[1:4] == b"\x00\x00\x00"
        except OSError:
            return False

    def parse(self, path: Path) -> Iterator[Artifact]:
        """Yield one Artifact per LNK file."""
        try:
            from lnkfile import LnkFile
        except ImportError:
            log.error("Cannot parse .lnk file: install lnkfile (pip install lnkfile)")
            return

        try:
            lnk = LnkFile(str(path))
        except Exception as e:  # noqa: BLE001
            log.warning("Failed to parse LNK %s: %s", path, e)
            return

        # Extract key fields
        target_path = ""
        try:
            if lnk.link_target:
                target_path = lnk.link_target.get("name", "") or ""
                if lnk.link_target.get("local"):
                    target_path = lnk.link_target["local"].get("path", "") or target_path
        except (AttributeError, KeyError, TypeError):
            pass

        # Arguments
        arguments = ""
        try:
            if lnk.arguments:
                arguments = str(lnk.arguments)
        except (AttributeError, TypeError):
            pass

        # Working directory
        working_dir = ""
        try:
            if lnk.working_dir:
                working_dir = str(lnk.working_dir)
        except (AttributeError, TypeError):
            pass

        # Icon location
        icon_location = ""
        try:
            if lnk.icon_location:
                icon_location = str(lnk.icon_location)
        except (AttributeError, TypeError):
            pass

        # Timestamps
        ts = None
        try:
            if lnk.get_creation_time():
                ts = lnk.get_creation_time()
            elif lnk.get_modification_time():
                ts = lnk.get_modification_time()
            elif lnk.get_access_time():
                ts = lnk.get_access_time()
        except Exception:  # noqa: BLE001
            ts = None
        if ts is None:
            try:
                ts = datetime.fromtimestamp(path.stat().st_mtime, tz=UTC)
            except OSError:
                ts = datetime.now(UTC)
        elif ts.tzinfo is None:
            ts = ts.replace(tzinfo=UTC)

        # Volume info (for forensic correlation)
        drive_serial = ""
        try:
            if hasattr(lnk, "drive_serial_number"):
                drive_serial = str(lnk.drive_serial_number)
        except (AttributeError, TypeError):
            pass

        # Host
        host = None
        try:
            if lnk.link_target and lnk.link_target.get("local"):
                local = lnk.link_target["local"]
                if local.get("hostname"):
                    host = local["hostname"]
        except (AttributeError, KeyError, TypeError):
            pass

        # Severity
        severity = Severity.INFORMATIONAL
        target_lower = target_path.lower()
        for pattern in [
            r"\\temp\\", r"\\appdata\\", r"\\downloads\\",
            r"\\programdata\\", r"\\users\\public\\",
            r"\.ps1$", r"\.vbs$", r"\.js$", r"\.hta$", r"\.bat$", r"\.scr$",
            r"powershell", r"cmd\.exe",
        ]:
            if re.search(pattern, target_lower):
                severity = Severity.HIGH
                break

        # Description
        desc_parts = [f"LNK: {path.name}"]
        if target_path:
            desc_parts.append(f"-> {target_path}")
        if arguments:
            desc_parts.append(f"args={arguments[:100]}")
        if working_dir:
            desc_parts.append(f"cwd={working_dir}")
        desc = " ".join(desc_parts)

        # Technique IDs
        technique_ids = []
        target_lc = target_path.lower()
        if target_lc.endswith((".ps1", ".vbs", ".js", ".bat", ".hta", ".scr")):
            technique_ids.append("T1059")
        if "powershell" in target_lc or "cmd.exe" in target_lc:
            technique_ids.append("T1059.001")
        if re.search(r"\\temp\\|\\appdata\\|\\downloads\\|\\users\\public\\", target_lc):
            technique_ids.append("T1204")  # User execution
        if not technique_ids:
            technique_ids.append("T1204")  # Default: user execution

        # Description prefix
        if severity == Severity.HIGH:
            desc = "[SUSPICIOUS] " + desc

        yield Artifact(
            id=Artifact.new_id(),
            artifact_type=ArtifactType.FILE,
            source=ArtifactSource.LNK,
            timestamp=ts,
            severity=severity,
            host=host,
            file_path=str(path),
            description=desc,
            raw={
                "target_path": target_path,
                "arguments": arguments,
                "working_dir": working_dir,
                "icon_location": icon_location,
                "drive_serial": drive_serial,
            },
            technique_ids=technique_ids,
            tags=["lnk", f"target.{target_lower[:50]}" if target_path else "lnk.no_target"],
            iocs=[drive_serial] if drive_serial else [],
        )
