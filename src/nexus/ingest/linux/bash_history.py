"""Bash history importer.

Parses `~/.bash_history` files. Format is one command per line, with an
optional leading Unix timestamp (from HISTTIMEFORMAT="%s ").
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


class BashHistoryImporter(Importer):
    """Parser for ~/.bash_history files."""

    @classmethod
    def source_class(cls) -> ArtifactSource:
        return ArtifactSource.BASH_HISTORY

    @classmethod
    def can_handle(cls, path: Path) -> bool:
        """Heuristic: file is named .bash_history, bash_history, or .zsh_history."""
        if not path.is_file():
            return False
        name = path.name.lower()
        return name in (".bash_history", "bash_history", ".zsh_history", "zsh_history")

    def parse(self, path: Path) -> Iterator[Artifact]:
        """Yield one Artifact per history line."""
        prev_ts: datetime | None = None
        for _n, line in self.read_lines(path):
            # zsh uses ": <epoch>:<duration>;<command>"
            ts: datetime | None = None
            cmd = line
            if line.startswith(":") and ";" in line:
                parts = line.split(";", 1)
                if len(parts) == 2:
                    m = re.match(r":\s*(\d+):", parts[0])
                    if m:
                        ts = self.normalize_timestamp(m.group(1))
                        cmd = parts[1]
            elif re.match(r"^\d{10,}\s+", line):
                # bash HISTTIMEFORMAT
                parts = line.split(maxsplit=1)
                if len(parts) == 2:
                    ts = self.normalize_timestamp(parts[0])
                    cmd = parts[1]
            if ts is None:
                ts = prev_ts or datetime.fromtimestamp(path.stat().st_mtime, tz=UTC)
            prev_ts = ts
            yield self._build_artifact(ts, cmd, path)

    def _build_artifact(self, ts: datetime, cmd: str, path: Path) -> Artifact:
        """Map a history command to an Artifact."""
        cmd_stripped = cmd.strip()
        # Severity from suspicious patterns
        severity = Severity.INFORMATIONAL
        cmd_lower = cmd_stripped.lower()
        suspicious = [
            "rm -rf", "chmod 777", "curl", "wget", "nc ", "ncat",
            "bash -i", "/dev/tcp/", "python -c", "perl -e",
            "base64 -d", "mkfifo", "iptables", "passwd", "shadow",
        ]
        if any(s in cmd_lower for s in suspicious):
            severity = Severity.MEDIUM
        if any(s in cmd_lower for s in ("base64 -d", "/dev/tcp/", "nc -e", "bash -i")):
            severity = Severity.HIGH

        # Host = parent directory name (or hostname in shell)
        host = path.parent.name if path.parent.name and path.parent.name != "/" else None

        return Artifact(
            id=Artifact.new_id(),
            artifact_type=ArtifactType.PROCESS,
            source=ArtifactSource.BASH_HISTORY,
            timestamp=ts,
            severity=severity,
            host=host,
            process_name="bash",
            command_line=cmd_stripped,
            description=cmd_stripped[:500],
            raw={"line": cmd, "file": str(path)},
            tags=["bash_history"],
        )
