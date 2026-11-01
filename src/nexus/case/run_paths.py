"""Named execution output paths, shared by operator and executor hosts.

No orchestration imports: the SIFT executor need not install LangGraph.
"""
import re
from pathlib import Path, PurePosixPath

RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{1,95}$")


def run_extractions_dir(case_dir: Path | PurePosixPath, run_id: str):
    """Preserve the caller's local/remote path kind and refuse unsafe run IDs."""
    if not RUN_ID_RE.fullmatch(run_id):
        raise ValueError("run_id must be 2-96 alphanumeric, hyphen, or underscore characters")
    return case_dir / "runs" / run_id / "extractions"
