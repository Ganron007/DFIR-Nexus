"""Windows registry **text export** importer (`reg export` / `reg query`).

Raw binary hives (SYSTEM / SOFTWARE / SAM / SECURITY / NTUSER.DAT /
UsrClass.dat / Amcache.hve) are **host artifacts processed in the N-lane** by
the forensic tools — RECmd with the Kroll batch — and it is that typed CSV
output the ingest lane consumes. This importer never parses raw hives.

Only the text formats the lane tools do not cover are handled here:

1. ``reg export`` text (``.reg``, UTF-16 or UTF-8 with the
   ``Windows Registry Editor Version 5.00`` header)
2. ``reg query`` / ``reg export`` captures saved as ``.txt`` / ``.export``

Extracted keys of forensic interest:
- Run / RunOnce / RunServices autorun (T1547.001)
- Winlogon Shell/Userinit/Notify (T1547.004)
- Image File Execution Options Debugger (T1546.012)
- AppInit_DLLs (T1546.010)
- SAM local account names (T1087.001) when a SAM export is provided
"""

from __future__ import annotations

import logging
import re
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


class WindowsRegistryImporter(Importer):
    """Parser for `reg export` / `reg query` text output (not raw hives).

    Output: one Artifact per value of forensic interest under the keys above.
    """

    INTERESTING_KEYS: ClassVar[dict[str, dict[str, Any]]] = {
        r"\Software\Microsoft\Windows\CurrentVersion\Run": {
            "technique": "T1547.001",
            "name": "Run key (autorun)",
            "description": "Programs that run at user logon",
        },
        r"\Software\Microsoft\Windows\CurrentVersion\RunOnce": {
            "technique": "T1547.001",
            "name": "RunOnce key",
            "description": "Programs that run once at user logon",
        },
        r"\Software\Microsoft\Windows\CurrentVersion\RunServices": {
            "technique": "T1547.001",
            "name": "RunServices key",
            "description": "Programs that run as services at user logon",
        },
        r"\Software\Microsoft\Windows NT\CurrentVersion\Windows": {
            "technique": "T1547.004",
            "name": "Winlogon keys",
            "description": "Shell, Userinit, AppInit_DLLs (logon-time execution)",
        },
        r"\Software\Microsoft\Windows NT\CurrentVersion\Winlogon": {
            "technique": "T1547.004",
            "name": "Winlogon subkey",
            "description": "Notify, Shell, Userinit values",
        },
        r"\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options": {
            "technique": "T1546.012",
            "name": "Image File Execution Options",
            "description": "Debugger hijacking — IFEO Debugger replaces process startup",
        },
        r"\Software\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs": {
            "technique": "T1546.010",
            "name": "AppInit_DLLs",
            "description": "DLLs loaded into every user-mode process",
        },
    }

    SAM_NAMES_SUFFIX: ClassVar[str] = r"\sam\domains\account\users\names"

    @classmethod
    def source_class(cls) -> ArtifactSource:
        return ArtifactSource.WINDOWS_REGISTRY

    @classmethod
    def can_handle(cls, path: Path) -> bool:
        """Text exports only — raw hives are the N-lane's (RECmd) job."""
        if not path.is_file():
            return False
        name_lower = path.name.lower()
        if name_lower.endswith(".reg"):
            return True
        if name_lower.endswith((".txt", ".export")):
            try:
                with path.open("r", encoding="utf-8", errors="replace") as f:
                    head = f.read(4096)
            except OSError:
                return False
            return (
                "Windows Registry Editor" in head
                or "HKEY_" in head
                or re.search(r"CurrentControlSet\\Services\\", head) is not None
            )
        return False

    def parse(self, path: Path) -> Iterator[Artifact]:
        """Yield Artifact objects from a registry text export."""
        yield from self._parse_text(path)

    # ----- Text mode (reg export / reg query output) -----

    TEXT_KEY_RE = re.compile(
        r"^\[([^\]]+)\]\s*$"  # [HKEY_LOCAL_MACHINE\Software\...]
    )
    TEXT_VALUE_RE = re.compile(
        r'^"([^"=]+)"\s*=\s*(.*)$'  # "ValueName"="data"
    )
    TEXT_DEFAULT_RE = re.compile(
        r"^@=([^=].*)$"  # @="default value"
    )

    def _parse_text(self, path: Path) -> Iterator[Artifact]:
        r"""Parse a `reg export` or `reg query` text file.

        Format:
            Windows Registry Editor Version 5.00

            [HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run]
            "ValueName"="data"
            @="default value"
        """
        try:
            raw = path.read_bytes()
        except OSError as e:
            log.warning("Failed to read %s: %s", path, e)
            return
        if raw.startswith(b"\xff\xfe") or raw.startswith(b"\xfe\xff"):
            text = raw.decode("utf-16", errors="replace")
        elif raw.startswith(b"\xef\xbb\xbf"):
            text = raw.decode("utf-8-sig", errors="replace")
        else:
            text = raw.decode("utf-8", errors="replace")

        current_key: str | None = None
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            # Skip header / comment lines
            if line.startswith("Windows Registry Editor") or line.startswith("//"):
                continue
            # Key header?
            m = self.TEXT_KEY_RE.match(line)
            if m:
                current_key = m.group(1).strip()
                sam_name = self._sam_name_from_key(current_key)
                if sam_name:
                    yield self._sam_user_artifact(sam_name, path, current_key)
                continue
            # If we're inside an interesting key, parse values
            if current_key:
                info = self._match_interesting_key(current_key)
                if info is None:
                    continue
                m = self.TEXT_VALUE_RE.match(line)
                if m:
                    name = m.group(1).strip()
                    raw_data = m.group(2).strip()
                    value = self._strip_reg_quotes(raw_data)
                    yield self._make_registry_artifact(
                        current_key, name, value, info, str(path)
                    )
                    continue
                m = self.TEXT_DEFAULT_RE.match(line)
                if m:
                    value = self._strip_reg_quotes(m.group(1).strip())
                    yield self._make_registry_artifact(
                        current_key, "(Default)", value, info, str(path)
                    )

    @classmethod
    def _sam_name_from_key(cls, key: str) -> str | None:
        """Extract the account name from a SAM ...\\Users\\Names\\<user> key."""
        lower = key.lower()
        idx = lower.find(cls.SAM_NAMES_SUFFIX)
        if idx < 0:
            return None
        rest = key[idx + len(cls.SAM_NAMES_SUFFIX):].strip("\\")
        if not rest or "\\" in rest:
            return None
        return rest

    @staticmethod
    def _strip_reg_quotes(value: str) -> str:
        """Strip surrounding quotes from reg export values."""
        value = value.strip()
        if len(value) >= 2 and value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
        # Unescape \"
        value = value.replace('\\"', '"').replace("\\\\", "\\")
        return value

    def _match_interesting_key(self, key: str) -> dict[str, Any] | None:
        """Return the info dict if the key matches a known interesting pattern, else None."""
        lower = key.lower().replace("hkey_local_machine\\", "").replace("hkey_current_user\\", "")
        # Normalize HKCU/HKLM prefixes
        lower = re.sub(r"^hkey_[a-z_]+\\?", "", lower)
        lower = lower.replace("hkey_local_machine", "").replace("hkey_current_user", "").lstrip("\\")
        for pattern, info in self.INTERESTING_KEYS.items():
            normalized_pattern = pattern.lower().lstrip("\\")
            if normalized_pattern in lower:
                return info
        return None

    def _make_registry_artifact(
        self,
        key: str,
        value_name: str,
        value: str,
        info: dict[str, Any],
        source_path: str,
    ) -> Artifact:
        """Build an Artifact for a registry value."""
        # Severity: any registry persistence with a non-empty executable value is HIGH
        severity = Severity.INFORMATIONAL
        if value and (
            ".exe" in value.lower()
            or ".dll" in value.lower()
            or ".scr" in value.lower()
            or ".bat" in value.lower()
            or ".ps1" in value.lower()
        ):
            severity = Severity.HIGH

        return Artifact(
            id=Artifact.new_id(),
            artifact_type=ArtifactType.REGISTRY,
            source=ArtifactSource.WINDOWS_REGISTRY,
            ts_synthesized=True,
            timestamp=datetime.fromtimestamp(
                Path(source_path).stat().st_mtime if Path(source_path).exists() else 0,
                tz=UTC,
            ),
            severity=severity,
            host=Path(source_path).stem,
            registry_key=key,
            registry_value=value_name,
            description=f"{info['name']}: {value_name}={value}",
            raw={
                "key": key,
                "value_name": value_name,
                "value": value,
                "info": info,
            },
            technique_ids=[info["technique"]],
            tags=["registry", f"key.{info['technique']}"],
        )

    def _sam_user_artifact(self, name: str, hive: Path, key_path: str) -> Artifact:
        """SAM local account entry (DOMAINS\\Account\\Users\\Names\\<user>)."""
        return Artifact(
            id=Artifact.new_id(),
            artifact_type=ArtifactType.REGISTRY,
            source=ArtifactSource.WINDOWS_REGISTRY,
            ts_synthesized=True,
            timestamp=datetime.fromtimestamp(
                Path(hive).stat().st_mtime if Path(hive).exists() else 0, tz=UTC
            ),
            severity=Severity.INFORMATIONAL,
            host=Path(hive).stem,
            registry_key=key_path,
            registry_value=name,
            description=f"SAM local account: {name}",
            raw={"key": key_path, "user": name, "source": str(hive)},
            technique_ids=["T1087.001"],
            tags=["registry", "sam", "user"],
        )
