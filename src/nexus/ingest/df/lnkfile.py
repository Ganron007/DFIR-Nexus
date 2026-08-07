"""Windows LNK (shell link) file parser.

Parses Windows shortcut files (.lnk) which record what was opened, where
from, when, and (on Windows 7+) the target's MAC address and volume serial
number. Critical for user activity reconstruction.

Uses `lnkfile` if installed, falling back to `pylnk3`
(https://pypi.org/project/pylnk3/). Logs a clear error when neither is
available.
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

    @staticmethod
    def _empty_fields() -> dict:
        return {
            "target_path": "",
            "arguments": "",
            "working_dir": "",
            "icon_location": "",
            "drive_serial": "",
            "host": None,
            "timestamp": None,
        }

    def _extract_fields(self, path: Path) -> dict | None:
        """Extract normalized LNK fields via lnkfile or pylnk3.

        Returns None (and logs) when no parser library is installed or the
        file cannot be parsed.
        """
        try:
            from lnkfile import LnkFile
        except ImportError:
            LnkFile = None  # noqa: N806
        if LnkFile is not None:
            try:
                lnk = LnkFile(str(path))
            except Exception as e:  # noqa: BLE001
                log.warning("Failed to parse LNK %s: %s", path, e)
                return None
            fields = self._empty_fields()
            try:
                if lnk.link_target:
                    fields["target_path"] = lnk.link_target.get("name", "") or ""
                    if lnk.link_target.get("local"):
                        local = lnk.link_target["local"]
                        fields["target_path"] = local.get("path", "") or fields["target_path"]
                        if local.get("hostname"):
                            fields["host"] = local["hostname"]
            except (AttributeError, KeyError, TypeError):
                pass
            try:
                if lnk.arguments:
                    fields["arguments"] = str(lnk.arguments)
                if lnk.working_dir:
                    fields["working_dir"] = str(lnk.working_dir)
                if lnk.icon_location:
                    fields["icon_location"] = str(lnk.icon_location)
            except (AttributeError, TypeError):
                pass
            try:
                ts = lnk.get_creation_time() or lnk.get_modification_time() \
                    or lnk.get_access_time()
                if ts:
                    fields["timestamp"] = ts
            except Exception:  # noqa: BLE001
                pass
            try:
                if hasattr(lnk, "drive_serial_number"):
                    fields["drive_serial"] = str(lnk.drive_serial_number)
            except (AttributeError, TypeError):
                pass
            return fields

        try:
            import pylnk3
        except ImportError:
            log.error(
                "Cannot parse .lnk file: install pylnk3 (pip install pylnk3)"
            )
            return None
        try:
            lnk = pylnk3.parse(str(path))
        except Exception as e:  # noqa: BLE001
            log.warning("Failed to parse LNK %s: %s", path, e)
            return None
        fields = self._empty_fields()
        fields["target_path"] = str(getattr(lnk, "path", "") or "")
        try:
            fields["arguments"] = str(getattr(lnk, "arguments", "") or "")
            fields["working_dir"] = str(getattr(lnk, "work_dir", "") or "")
            fields["icon_location"] = str(getattr(lnk, "icon", "") or "")
        except (AttributeError, TypeError):
            pass
        for attr in ("creation_time", "modification_time", "access_time"):
            ts = getattr(lnk, attr, None)
            if isinstance(ts, datetime):
                fields["timestamp"] = ts
                break
        try:
            link_info = getattr(lnk, "_link_info", None)
            serial = getattr(link_info, "drive_serial", None)
            if serial:
                fields["drive_serial"] = str(serial)
        except (AttributeError, TypeError):
            pass
        return fields

    def parse(self, path: Path) -> Iterator[Artifact]:
        """Yield one Artifact per LNK file."""
        fields = self._extract_fields(path)
        if fields is None:
            return

        target_path = fields["target_path"]
        arguments = fields["arguments"]
        working_dir = fields["working_dir"]
        icon_location = fields["icon_location"]
        drive_serial = fields["drive_serial"]
        host = fields["host"]
        ts = fields["timestamp"]
        if ts is None:
            try:
                ts = datetime.fromtimestamp(path.stat().st_mtime, tz=UTC)
            except OSError:
                ts = datetime.now(UTC)
        elif ts.tzinfo is None:
            ts = ts.replace(tzinfo=UTC)

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
