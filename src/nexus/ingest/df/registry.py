"""Windows Registry hive importer.

Parses Windows registry hive files (SYSTEM, SOFTWARE, SAM, etc.) to extract
forensic indicators. Two modes:

1. **Binary mode** (requires `python-registry` or `regipy`):
   - Parses raw .hve / .dat files
   - Most comprehensive

2. **Text mode** (always works):
   - Parses `reg export` / `reg query` text output
   - Format: lines like `HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\...`

The text mode lets you feed in any reg-export output from a live Windows
machine or a KAPE collection, which is what most DFIR analysts actually have.
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
    """Parser for Windows registry hive files or reg export text.

    Output: one Artifact per key/value pair of forensic interest. Keys tracked:
    - Run/RunOnce autorun (T1547.001)
    - Image File Execution Options (Debugger) (T1546.012)
    - Winlogon shell/userinit (T1547.004)
    - AppInit_DLLs (T1546.010)
    - Services keys (when imported via the registry context)
    - SAM user accounts (T1003.002 if domain cache)
    """

    # Registry keys of forensic interest (case-insensitive)
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

    # Interesting SAM user attributes
    SAM_INTERESTING: ClassVar[set[str]] = {"F", "V"}  # F=full name, V=comment

    @classmethod
    def source_class(cls) -> ArtifactSource:
        return ArtifactSource.WINDOWS_REGISTRY

    @classmethod
    def can_handle(cls, path: Path) -> bool:
        """Heuristic: text-based reg export or binary .hve/.dat file."""
        if not path.is_file():
            return False
        name_lower = path.name.lower()
        # Binary-mode: hive files
        if path.suffix.lower() in (".hve", ".dat"):
            try:
                with path.open("rb") as f:
                    magic = f.read(4)
                # regf = Windows registry hive magic bytes
                return magic == b"regf"
            except OSError:
                return False
        # Text-mode: .reg files always match (standard extension)
        if name_lower.endswith(".reg"):
            return True
        # For .txt/.export, sniff content for registry signatures
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
        # Or files named SYSTEM, SOFTWARE, SAM, NTUSER, etc. (no extension)
        if name_lower in {"system", "software", "sam", "security", "ntuser.dat", "usrclass.dat", "amcache.hve", "amcache"}:
            return True
        return False

    def parse(self, path: Path) -> Iterator[Artifact]:
        """Yield Artifact objects from a registry file."""
        name_lower = path.name.lower()
        # Try binary mode first
        if path.suffix.lower() in (".hve", ".dat") or name_lower in {"system", "software", "sam", "amcache.hve"}:
            yield from self._parse_binary(path)
            return
        # Fallback: text mode
        yield from self._parse_text(path)

    # ----- Binary mode (requires python-registry or regipy) -----

    def _parse_binary(self, path: Path) -> Iterator[Artifact]:
        """Parse a binary registry hive. Requires python-registry or regipy."""
        try:
            from Registry import Registry as PyRegistry
        except ImportError:
            try:
                from regipy.registry import (
                    Registry as RegipyRegistry,
                )
            except ImportError:
                log.error(
                    "Cannot parse binary registry hive: install python-registry or regipy "
                    "(pip install python-registry)"
                )
                return
            yield from self._parse_binary_regipy(path, RegipyRegistry)
            return
        yield from self._parse_binary_python_registry(path, PyRegistry)

    def _parse_binary_python_registry(
        self, path: Path, registry_cls: Any
    ) -> Iterator[Artifact]:
        """Parse using python-registry library."""
        try:
            reg = registry_cls(str(path))
        except Exception as e:  # noqa: BLE001
            log.warning("Failed to open hive %s: %s", path, e)
            return
        yield from self._walk_reg_python_registry(reg.root(), str(path))

    def _walk_reg_python_registry(
        self, key: Any, path: Path | str
    ) -> Iterator[Artifact]:
        """Walk a python-registry key tree and emit Artifacts for interesting keys."""
        for subkey in key.subkeys():
            sub_path = f"{key.path()}\\{subkey.name()}"
            lower = sub_path.lower()
            for pattern, info in self.INTERESTING_KEYS.items():
                if pattern.lower() in lower:
                    for value in subkey.values():
                        yield self._make_registry_artifact(
                            sub_path, value.name(), str(value.value()), info, str(path)
                        )
                    break
            yield from self._walk_reg_python_registry(subkey, path)

    def _parse_binary_regipy(
        self, path: Path, registry_cls: Any
    ) -> Iterator[Artifact]:
        """Parse using regipy library (when available)."""
        try:
            reg = registry_cls(str(path))
        except Exception as e:  # noqa: BLE001
            log.warning("Failed to open hive %s: %s", path, e)
            return
        # regipy uses .root() differently
        try:
            root = reg.root
            yield from self._walk_regipy(root, str(path))
        except Exception as e:  # noqa: BLE001
            log.warning("Failed to walk regipy hive %s: %s", path, e)

    def _walk_regipy(self, key: Any, path: Path | str) -> Iterator[Artifact]:
        """Walk a regipy key tree."""
        for subkey in key.iter_subkeys():
            sub_path = subkey.path
            lower = sub_path.lower()
            for pattern, info in self.INTERESTING_KEYS.items():
                if pattern.lower() in lower:
                    for value in subkey.iter_values():
                        yield self._make_registry_artifact(
                            sub_path, value.name, str(value.value), info, str(path)
                        )
                    break
            yield from self._walk_regipy(subkey, path)

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
    TEXT_HIVE_NAMES: ClassVar[set[str]] = {
        "HKEY_CLASSES_ROOT", "HKEY_CURRENT_USER", "HKEY_LOCAL_MACHINE",
        "HKEY_USERS", "HKEY_CURRENT_CONFIG", "HKCR", "HKCU", "HKLM", "HKU",
    }

    def _parse_text(self, path: Path) -> Iterator[Artifact]:
        r"""Parse a `reg export` or `reg query` text file.

        Format:
            Windows Registry Editor Version 5.00

            [HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run]
            "ValueName"="data"
            @="default value"
        """
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            log.warning("Failed to read %s: %s", path, e)
            return

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
                # Check if this key is interesting — values will be parsed below
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
            source=ArtifactSource.UNKNOWN,
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
