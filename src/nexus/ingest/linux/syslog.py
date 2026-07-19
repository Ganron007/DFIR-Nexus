"""Linux syslog importer.

Parses both RFC 3164 (BSD syslog) and RFC 5424 (modern syslog) formats.
Common locations: /var/log/syslog, /var/log/messages, /var/log/daemon.log.
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


class SyslogImporter(Importer):
    """Parser for RFC 3164 / RFC 5424 syslog files."""

    # RFC 3164: "Jan 15 12:34:56 host process[pid]: message"
    RFC3164_RE = re.compile(
        r"^(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<proc>[\w\-/]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$"
    )
    # RFC 5424: "<165>1 2003-08-24T05:14:15.000003-07:00 host process 1234 ID47 - message"
    RFC5424_RE = re.compile(
        r"^<\d+>\d+\s+(?P<ts>\S+)\s+(?P<host>\S+)\s+(?P<proc>\S+)\s+(?P<pid>\S+)\s+(?P<mid>\S+)\s+(?P<sd>\S+)\s+(?P<msg>.*)$"
    )

    @classmethod
    def source_class(cls) -> ArtifactSource:
        return ArtifactSource.SYSLOG

    @classmethod
    def can_handle(cls, path: Path) -> bool:
        """Heuristic: file name suggests syslog, or content matches RFC 3164/5424 pattern."""
        if not path.is_file():
            return False
        name = path.name.lower()
        if name in ("syslog", "messages", "daemon.log", "kern.log", "user.log") or name.endswith(".log"):
            # Look for syslog-shaped content
            try:
                with path.open("r", encoding="utf-8", errors="replace") as f:
                    for _ in range(10):
                        line = f.readline()
                        if not line:
                            break
                        if cls.RFC3164_RE.match(line) or cls.RFC5424_RE.match(line):
                            return True
            except OSError:
                return False
        return False

    def parse(self, path: Path) -> Iterator[Artifact]:
        """Yield one Artifact per syslog line."""
        for _n, line in self.read_lines(path):
            artifact = self._line_to_artifact(line)
            if artifact is not None:
                yield artifact

    def _line_to_artifact(self, line: str) -> Artifact | None:
        """Map a single syslog line to an Artifact."""
        m = self.RFC5424_RE.match(line)
        if m:
            return self._build_artifact(
                m.group("ts"),
                m.group("host"),
                m.group("proc"),
                m.group("pid"),
                m.group("msg"),
            )
        m = self.RFC3164_RE.match(line)
        if m:
            return self._build_artifact(
                m.group("ts"),
                m.group("host"),
                m.group("proc"),
                m.group("pid"),
                m.group("msg"),
            )
        return None

    def _build_artifact(
        self,
        ts_str: str,
        host: str,
        proc: str,
        pid: str | None,
        msg: str,
    ) -> Artifact:
        """Build an Artifact from parsed syslog fields."""
        ts = self.normalize_timestamp(ts_str) or datetime.now(UTC)
        # Guess type from proc name
        proc_lower = proc.lower()
        artifact_type = ArtifactType.UNKNOWN
        if any(x in proc_lower for x in ("sshd", "login", "sudo", "su", "auth")):
            artifact_type = ArtifactType.AUTH
        elif any(x in proc_lower for x in ("kernel", "kworker", "network")):
            artifact_type = ArtifactType.NETWORK
        elif any(x in proc_lower for x in ("crond", "cron", "systemd")):
            artifact_type = ArtifactType.PROCESS
        # Severity from syslog priority or message keywords
        severity = Severity.INFORMATIONAL
        msg_lower = msg.lower()
        if "error" in msg_lower or "fail" in msg_lower or "denied" in msg_lower:
            severity = Severity.MEDIUM
        if "critical" in msg_lower or "panic" in msg_lower:
            severity = Severity.CRITICAL
        if "warning" in msg_lower or "warn" in msg_lower:
            severity = Severity.LOW

        return Artifact(
            id=Artifact.new_id(),
            artifact_type=artifact_type,
            source=ArtifactSource.SYSLOG,
            timestamp=ts,
            severity=severity,
            host=host,
            process_name=proc,
            process_id=int(pid) if pid and pid.isdigit() else None,
            description=msg[:500],
            raw={"line": f"{ts_str} {host} {proc}[{pid}]: {msg}"},
            tags=["syslog", f"proc.{proc_lower}"],
        )
