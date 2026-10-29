"""The one folder everything an agent or a test creates lives in: `<repo>/scratch/`, gitignored (operator, 2026-10-29).

"Everything worked within our own repo and all these test items stick to one internal gitignored folder only." pytest
had roots named outside the repository (`C:\\ptt`, eleven `C:\\ptt-*`, 2.3 GB), tests wrote to the system temp folder,
and the pinned upstream snapshots the knowledge importers read lived in `%TEMP%\\kl2b-snapshots`. Each name below is
the only definition of its folder; `tests/conftest.py` refuses a pytest root outside `scratch/`.
"""
from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCRATCH = REPO / "scratch"
#: pytest's temporary root (`--basetemp`); pytest empties it at the start of each run.
PYTEST_ROOT = SCRATCH / "pytest"
#: The temporary directory (`tempfile`, `TEMP`, `TMP`, `TMPDIR`) of a pytest run and of the processes its tests start.
#: Emptied at the start of each run, as pytest empties its root: tests that never remove their own files (a
#: `NamedTemporaryFile(delete=False)`, a case folder) leave them for one run, not for good.
PYTEST_TMP = SCRATCH / "pytest-tmp"
#: The temporary directory of a lane (`run_lane.ps1`), the script suites, the functional audit and the devtools
#: scripts. Never emptied by a test run: a lane may be using it.
TMP_ROOT = SCRATCH / "tmp"
#: The pinned upstream snapshots (clones at a recorded commit) the `devtools/knowledge` importers and checks read.
SNAPSHOTS = SCRATCH / "kl2b-snapshots"
#: The gates' logs (`devtools/runbook/gates.ps1`).
GATES = SCRATCH / "gates"
#: An agent's own working scripts and logs.
AGENT = SCRATCH / "agent"


def inside_scratch(path: str | os.PathLike[str]) -> bool:
    """True when ``path`` is ``scratch/`` or below it."""
    try:
        Path(path).resolve().relative_to(SCRATCH.resolve())
    except ValueError:
        return False
    return True


def use_repo_temp(root: Path | None = None, *, empty: bool = False) -> Path:
    """Point this process's temporary directory, and that of the processes it starts, at ``root`` (in ``scratch/``).

    With no ``root``, a temporary directory already inside ``scratch/`` is kept (a script suite pytest imports keeps
    the run's `scratch/pytest-tmp`), and any other becomes ``scratch/tmp``. ``empty`` removes what an earlier run left
    there first; only a folder inside ``scratch/`` is ever emptied.
    """
    if root is None:
        current = Path(tempfile.gettempdir())
        root = current if inside_scratch(current) else TMP_ROOT
    if not inside_scratch(root):
        raise ValueError(f"{root} is outside {SCRATCH}")
    if empty and root.exists():
        shutil.rmtree(root, ignore_errors=True)
    root.mkdir(parents=True, exist_ok=True)
    for key in ("TEMP", "TMP", "TMPDIR"):
        os.environ[key] = str(root)
    tempfile.tempdir = str(root)
    return root
