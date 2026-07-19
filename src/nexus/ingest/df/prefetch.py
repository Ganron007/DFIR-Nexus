r"""Windows Prefetch file importer.

Prefetch files (`C:\Windows\Prefetch\*.pf`) record metadata about
processes that have been executed. The binary format includes the
executable name, run count, last run times, and referenced file paths.

Requires the `prefetch-parser` package (https://pypi.org/project/prefetch-parser/).
If not installed, the importer reports a clear error.
"""

from __future__ import annotations

import logging
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


class PrefetchImporter(Importer):
    """Parser for Windows Prefetch files (.pf).

    Uses `prefetch-parser` to decode the binary MAM-format. Each .pf
    file becomes one Artifact summarizing the executable + run history.
    """

    @classmethod
    def source_class(cls) -> ArtifactSource:
        return ArtifactSource.PREFETCH

    @classmethod
    def can_handle(cls, path: Path) -> bool:
        """Heuristic: file has .pf extension and starts with the Prefetch magic (MAM\x04)."""
        if not path.is_file():
            return False
        if path.suffix.lower() != ".pf":
            return False
        try:
            with path.open("rb") as f:
                magic = f.read(7)
            # MAM header: b"MAM\x04" or "MAM\x03" depending on OS
            return magic[:3] == b"MAM"
        except OSError:
            return False

    def parse(self, path: Path) -> Iterator[Artifact]:
        """Yield one Artifact per .pf file."""
        try:
            from prefetch_parser import parse_prefetch_file
        except ImportError:
            log.error(
                "prefetch-parser is not installed. Install with: pip install prefetch-parser"
            )
            return

        try:
            info = parse_prefetch_file(str(path))
            yield self._info_to_artifact(info, path)
        except Exception as e:  # noqa: BLE001
            log.debug("Failed to parse prefetch %s: %s", path, e)

    @staticmethod
    def _info_to_artifact(info: Any, path: Path) -> Artifact:
        """Map a parsed Prefetch object to an Artifact."""
        executable = str(getattr(info, "executable", path.stem))
        run_count = int(getattr(info, "run_count", 0))
        # last_run_times is a list of datetime
        last_runs = getattr(info, "last_run_times", []) or []
        # Use the most recent run
        ts = max(last_runs) if last_runs else datetime.fromtimestamp(path.stat().st_mtime, tz=UTC)
        if not isinstance(ts, datetime):
            ts = datetime.now(UTC)

        return Artifact(
            id=Artifact.new_id(),
            artifact_type=ArtifactType.PROCESS,
            source=ArtifactSource.PREFETCH,
            timestamp=ts,
            severity=Severity.INFORMATIONAL,
            process_name=executable,
            file_path=str(path),
            description=f"Prefetch: {executable} (run count: {run_count})",
            raw={
                "executable": executable,
                "run_count": run_count,
                "last_run_times": [r.isoformat() if isinstance(r, datetime) else str(r) for r in last_runs],
                "file": str(path),
            },
            tags=["prefetch", f"run.{run_count}"],
        )
