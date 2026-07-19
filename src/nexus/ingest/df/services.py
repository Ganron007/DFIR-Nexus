"""Windows Services registry parser.

Parses the `SYSTEM\\CurrentControlSet\\Services` registry subtree to extract
running and installed services. This is a critical artifact for malware
analysis because malware often installs itself as a service for persistence.

Input formats:
1. `reg query` text output of SYSTEM hive (text mode)
2. `services.txt` from KAPE / third-party tools
3. `services.csv` export

Each service becomes one Artifact with the binary path, service type,
start type, and other forensic context.
"""

from __future__ import annotations

import csv
import logging
import re
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import ClassVar

from nexus.ingest.base import Importer
from nexus.ingest.schemas import (
    Artifact,
    ArtifactSource,
    ArtifactType,
    Severity,
)

log = logging.getLogger(__name__)


class WindowsServicesImporter(Importer):
    """Parser for Windows Services (registry-based).

    Output: one Artifact per service, with binary path, start type, etc.
    """

    # Suspicious service binary patterns
    SUSPICIOUS_PATTERNS: ClassVar[list[str]] = [
        r"(?i)\.ps1\b",
        r"(?i)\.vbs\b",
        r"(?i)\.js\b",
        r"(?i)\.bat\b",
        r"(?i)\.cmd\b",
        r"(?i)powershell",
        r"(?i)cmd\.exe.*\.(txt|ps1|bat)",
        r"(?i)wscript",
        r"(?i)cscript",
        r"(?i)mshta",
        r"(?i)rundll32 .*\.dat",
        r"(?i)regsvr32 .* -s ",
        r"(?i)certutil .* -url ",
        r"(?i)\\temp\\",
        r"(?i)\\appdata\\",
        r"(?i)\\downloads\\",
        r"(?i)\\programdata\\",
        r"(?i)\\users\\public\\",
    ]

    @classmethod
    def source_class(cls) -> ArtifactSource:
        return ArtifactSource.WINDOWS_SERVICES

    @classmethod
    def can_handle(cls, path: Path) -> bool:
        """Heuristic: contains 'Services' subkey export OR has service-like structure."""
        if not path.is_file():
            return False
        name_lower = path.name.lower()
        # Explicit file names
        if name_lower in {"services.txt", "services.csv", "services.json", "services.reg"}:
            return True
        # Or a registry export with services content
        if name_lower.endswith((".txt", ".reg", ".csv")):
            try:
                head = path.read_text(encoding="utf-8", errors="replace")[:4096]
            except OSError:
                return False
            # Look for service signatures
            if re.search(r"CurrentControlSet\\Services\\", head, re.IGNORECASE):
                return True
            if "HKLM\\System\\CurrentControlSet\\Services" in head:
                return True
            # CSV header signature
            if "ServiceName" in head and "ImagePath" in head:
                return True
            if "Name,DisplayName,Status,StartType" in head:  # KAPE services.csv header
                return True
        return False

    def parse(self, path: Path) -> Iterator[Artifact]:
        """Yield Artifact objects from a Services registry dump."""
        suffix = path.suffix.lower()
        if suffix == ".csv":
            yield from self._parse_csv(path)
            return
        yield from self._parse_text(path)

    def _parse_csv(self, path: Path) -> Iterator[Artifact]:
        """Parse a CSV services export."""
        try:
            with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    yield self._row_to_artifact(row, str(path))
        except OSError as e:
            log.warning("Could not read %s: %s", path, e)

    def _parse_text(self, path: Path) -> Iterator[Artifact]:
        """Parse a `reg query` text export of services.

        Format:
            HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\ServiceName
                DisplayName    REG_SZ    Service Display Name
                ImagePath      REG_SZ    C:\\path\to\\service.exe
                Start          REG_DWORD 0x2
                Type           REG_DWORD 0x10
        """
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            log.warning("Could not read %s: %s", path, e)
            return

        # State machine: collect (key, value, data) tuples grouped by service
        current_service: str | None = None
        current_data: dict[str, str] = {}
        mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=UTC) if path.exists() else datetime.now(UTC)

        def emit() -> Artifact | None:
            if current_service and current_data:
                return self._row_to_artifact(
                    {
                        "ServiceName": current_service,
                        "ImagePath": current_data.get("ImagePath", ""),
                        "DisplayName": current_data.get("DisplayName", ""),
                        "Start": current_data.get("Start", ""),
                        "Type": current_data.get("Type", ""),
                    },
                    str(path),
                    mtime=mtime,
                )
            return None

        for line in text.splitlines():
            line = line.rstrip()
            if not line.strip():
                if (a := emit()) is not None:
                    yield a
                current_service = None
                current_data = {}
                continue
            stripped = line.strip()
            # Service key header
            if re.search(r"Services\\([^\s\\]+)\s*$", stripped, re.IGNORECASE):
                # Emit previous
                if (a := emit()) is not None:
                    yield a
                m = re.search(r"Services\\([^\s\\]+)\s*$", stripped, re.IGNORECASE)
                current_service = m.group(1) if m else None
                current_data = {}
                continue
            # Value line: indented, "    Name    REG_TYPE    data"
            m = re.match(r"^\s+(\S+)\s+REG_\w+\s+(.*)$", line)
            if m and current_service:
                name = m.group(1).strip()
                data = m.group(2).strip()
                # Strip surrounding quotes from REG_SZ
                if data.startswith('"') and data.endswith('"'):
                    data = data[1:-1]
                current_data[name] = data

        # Final emit
        if (a := emit()) is not None:
            yield a

    def _row_to_artifact(
        self,
        row: dict[str, str],
        source_path: str,
        mtime: datetime | None = None,
    ) -> Artifact:
        """Convert a parsed service record to an Artifact."""
        name = row.get("ServiceName") or row.get("Name") or "unknown"
        image_path = row.get("ImagePath") or row.get("PathName") or ""
        display_name = row.get("DisplayName", "")
        start = row.get("Start") or row.get("StartType", "")
        stype = row.get("Type", "")

        # Severity: suspicious binary paths
        severity = Severity.INFORMATIONAL
        for pattern in self.SUSPICIOUS_PATTERNS:
            if image_path and re.search(pattern, image_path):
                severity = Severity.HIGH
                break
        # No ImagePath is suspicious (no binary = hollow/svchost-style)
        if not image_path and name:
            severity = max(severity, Severity.LOW, key=lambda s: ["informational", "low", "medium", "high", "critical"].index(s.value))

        # Determine action
        action = "service_installed"
        if start == "0x0" or start == "0":
            action = "service_boot"
        elif start == "0x2" or start == "2":
            action = "service_autostart"
        elif start == "0x3" or start == "3":
            action = "service_demand"
        elif start == "0x4" or start == "4":
            action = "service_disabled"

        # Description
        desc_parts = [f"Service: {name}"]
        if display_name:
            desc_parts.append(f"({display_name})")
        if image_path:
            desc_parts.append(f"-> {image_path}")
        desc = " ".join(desc_parts)

        # Technique: T1543.003 (Windows Service)
        technique_ids = ["T1543.003"]
        if severity == Severity.HIGH:
            technique_ids.append("T1543.003")  # re-affirm

        return Artifact(
            id=Artifact.new_id(),
            artifact_type=ArtifactType.PROCESS,
            source=ArtifactSource.UNKNOWN,
            timestamp=mtime or datetime.now(UTC),
            severity=severity,
            host=Path(source_path).stem if Path(source_path).exists() else None,
            process_name=image_path.split("\\")[-1] if image_path else name,
            file_path=image_path or None,
            action=action,
            description=desc,
            raw={"row": dict(row), "source": source_path},
            technique_ids=technique_ids,
            tags=["service", f"start.{start}", f"type.{stype}"],
        )
