"""Linux auth.log importer.

Parses `/var/log/auth.log` (Debian/Ubuntu) and `/var/log/secure` (RHEL/CentOS).
Format is the same as syslog but the content is always auth-related.
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


class AuthLogImporter(Importer):
    """Parser for Linux auth.log / /var/log/secure."""

    # Same as RFC 3164 syslog but content is always auth-related
    LINE_RE = re.compile(
        r"^(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<proc>[\w\-/]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$"
    )

    @classmethod
    def source_class(cls) -> ArtifactSource:
        return ArtifactSource.AUTHLOG

    @classmethod
    def can_handle(cls, path: Path) -> bool:
        """Heuristic: file is auth.log or secure and contains sshd/sudo/su."""
        if not path.is_file():
            return False
        name = path.name.lower()
        if name not in ("auth.log", "secure", "auth.log.1", "secure.1"):
            return False
        try:
            with path.open("r", encoding="utf-8", errors="replace") as f:
                head = f.read(8192)
        except OSError:
            return False
        return any(
            kw in head for kw in ("sshd", "sudo", "su[", "login", "pam_unix")
        )

    def parse(self, path: Path) -> Iterator[Artifact]:
        """Yield one Artifact per auth.log line."""
        for _n, line in self.read_lines(path):
            m = self.LINE_RE.match(line)
            if not m:
                continue
            ts_str = m.group("ts")
            host = m.group("host")
            proc = m.group("proc")
            pid = m.group("pid")
            msg = m.group("msg")
            ts = self.normalize_timestamp(ts_str) or datetime.now(UTC)
            yield self._build_artifact(ts, host, proc, pid, msg)

    @staticmethod
    def _build_artifact(
        ts: datetime, host: str, proc: str, pid: str | None, msg: str
    ) -> Artifact:
        """Map a parsed auth.log line to an Artifact."""
        # Severity
        msg_lower = msg.lower()
        severity = Severity.INFORMATIONAL
        if "failed" in msg_lower or "failure" in msg_lower or "invalid" in msg_lower:
            severity = Severity.MEDIUM
        if "refused" in msg_lower or "denied" in msg_lower:
            severity = Severity.HIGH
        if "accepted" in msg_lower or "session opened" in msg_lower:
            severity = Severity.INFORMATIONAL

        # Pull out user
        user = None
        for pattern in (
            r"for\s+(?:user\s+)?(\w+)\s+from",
            r"user\s+(\w+)\s+by",
            r"(\w+)\s+from\s+(\d+\.\d+\.\d+\.\d+)",
        ):
            m = re.search(pattern, msg)
            if m:
                user = m.group(1)
                break

        # Pull out source IP
        source_ip = None
        m = re.search(r"from\s+(\d+\.\d+\.\d+\.\d+)", msg)
        if m:
            source_ip = m.group(1)

        # Action label
        action = None
        if "Accepted" in msg:
            action = "logon_success"
        elif "Failed" in msg or "failure" in msg_lower:
            action = "logon_failure"
        elif "session opened" in msg_lower:
            action = "session_open"
        elif "session closed" in msg_lower:
            action = "session_close"

        return Artifact(
            id=Artifact.new_id(),
            artifact_type=ArtifactType.AUTH,
            source=ArtifactSource.AUTHLOG,
            timestamp=ts,
            severity=severity,
            host=host,
            user=user,
            source_ip=source_ip,
            process_name=proc,
            process_id=int(pid) if pid and pid.isdigit() else None,
            action=action,
            description=msg[:500],
            raw={"line": f"{ts} {host} {proc}[{pid}]: {msg}"},
            tags=["authlog", f"proc.{proc.lower()}"],
        )
