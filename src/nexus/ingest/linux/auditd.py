"""Linux auditd log importer.

Parses the standard auditd text log format. Each line has the shape:
    type=SYSCALL msg=audit(1705320896.123:456): arch=c000003e syscall=2 ...

Two common encodings:
- Original (key=value pairs)
- Enriched (`audit.log -m --format=enriched`) which has a leading timestamp

This importer yields one Artifact per line, with msg.timestamp pulled from
the `audit(...)` token and msg.type mapped to a coarse ArtifactType.
"""

from __future__ import annotations

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


class AuditdImporter(Importer):
    """Parser for Linux auditd log files."""

    # Mapping of audit msg type -> ArtifactType
    TYPE_MAP: ClassVar[dict[str, ArtifactType]] = {
        "SYSCALL": ArtifactType.PROCESS,
        "EXECVE": ArtifactType.PROCESS,
        "USER_AUTH": ArtifactType.AUTH,
        "USER_LOGIN": ArtifactType.AUTH,
        "USER_CMD": ArtifactType.PROCESS,
        "CWD": ArtifactType.FILE,
        "PATH": ArtifactType.FILE,
        "PROCTITLE": ArtifactType.PROCESS,
        "SOCKETCALL": ArtifactType.NETWORK,
        "SOCKADDR": ArtifactType.NETWORK,
        "AVC": ArtifactType.ALERT,
        "ANOM_PROMISCUOUS": ArtifactType.ALERT,
        "ANOM_ABEND": ArtifactType.ALERT,
        "ANOM_LINK": ArtifactType.ALERT,
        "RESP_ANOMALY": ArtifactType.ALERT,
        "CRYPTO_KEY_USER": ArtifactType.AUTH,
        "CRYPTO_SESSION": ArtifactType.AUTH,
        "DAEMON_START": ArtifactType.UNKNOWN,
        "DAEMON_END": ArtifactType.UNKNOWN,
        "LOGIN": ArtifactType.AUTH,
    }

    @classmethod
    def source_class(cls) -> ArtifactSource:
        return ArtifactSource.AUDITD

    @classmethod
    def can_handle(cls, path: Path) -> bool:
        """Heuristic: file contains 'msg=audit(' or starts with 'type='."""
        if not path.is_file():
            return False
        try:
            with path.open("r", encoding="utf-8", errors="replace") as f:
                for _ in range(5):
                    line = f.readline()
                    if not line:
                        break
                    if "msg=audit(" in line or line.startswith("type="):
                        return True
        except OSError:
            return False
        return False

    def parse(self, path: Path) -> Iterator[Artifact]:
        """Yield one Artifact per auditd record."""
        for _n, line in self.read_lines(path):
            yield self._line_to_artifact(line)

    def _line_to_artifact(self, line: str) -> Artifact:
        """Map a single auditd line to an Artifact."""
        # Extract timestamp from "msg=audit(1705320896.123:456)"
        ts = datetime.now(UTC)
        m = re.search(r"msg=audit\((\d+\.\d+):", line)
        if m:
            ts = self.normalize_timestamp(m.group(1)) or ts

        # Extract msg type
        m = re.match(r"type=(\w+)", line)
        msg_type = m.group(1) if m else ""
        artifact_type = self.TYPE_MAP.get(msg_type, ArtifactType.UNKNOWN)

        # Pull a few interesting fields
        exe = self._extract_field(line, "exe")
        uid = self._extract_field(line, "uid")
        pid = self._extract_field(line, "pid")
        auid = self._extract_field(line, "auid")
        syscall = self._extract_field(line, "syscall")
        success = self._extract_field(line, "success")
        addr = self._extract_field(line, "addr")

        # Severity: AVC/anomaly = high, syscall success = info, syscall fail = medium
        severity = Severity.INFORMATIONAL
        if "AVC" in msg_type or "ANOM" in msg_type or "RESP_ANOMALY" in msg_type:
            severity = Severity.HIGH
        elif success == "no" or success == "0":
            severity = Severity.MEDIUM

        return Artifact(
            id=Artifact.new_id(),
            artifact_type=artifact_type,
            source=ArtifactSource.AUDITD,
            timestamp=ts,
            severity=severity,
            user=auid or uid,
            process_name=exe,
            process_id=int(pid) if pid and pid.isdigit() else None,
            source_ip=addr if addr and ("." in addr or ":" in addr) else None,
            description=f"auditd {msg_type}{f': {exe}' if exe else ''}{f' (syscall {syscall})' if syscall else ''}",
            raw={"line": line, "msg_type": msg_type, "exe": exe, "uid": uid, "pid": pid, "auid": auid, "syscall": syscall},
            tags=["auditd", f"type.{msg_type.lower()}"] if msg_type else ["auditd"],
        )

    @staticmethod
    def _extract_field(line: str, key: str) -> str | None:
        """Extract the value of `key=` from a space-separated key=value list."""
        pattern = rf"{key}=\"([^\"]*)\"|{key}=(\S+)"
        m = re.search(pattern, line)
        if not m:
            return None
        return m.group(1) or m.group(2)
