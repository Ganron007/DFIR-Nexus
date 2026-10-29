"""Every file a test writes stays in the repository's one gitignored folder, `scratch/` (operator, 2026-10-29).

pytest roots named outside the repository (`C:\\ptt`, eleven `C:\\ptt-*`, 2.3 GB) and the system temp folder held
the suite's output; the knowledge importers' pinned snapshots lived in `%TEMP%`. `devtools/scratch.py` names each
folder once and `tests/conftest.py` applies it.
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from devtools.scratch import (
    PYTEST_ROOT,
    PYTEST_TMP,
    SCRATCH,
    SNAPSHOTS,
    TMP_ROOT,
    inside_scratch,
    use_repo_temp,
)

REPO = Path(__file__).resolve().parents[1]


def test_a_tests_files_and_temporary_directory_are_inside_scratch(tmp_path):
    assert inside_scratch(tmp_path) and Path(tmp_path).resolve().is_relative_to(PYTEST_ROOT.resolve())
    assert Path(tempfile.gettempdir()).resolve() == PYTEST_TMP.resolve()
    assert all(Path(os.environ[key]).resolve() == PYTEST_TMP.resolve() for key in ("TEMP", "TMP", "TMPDIR"))
    with tempfile.TemporaryDirectory() as made:
        assert inside_scratch(made)
    assert inside_scratch(TMP_ROOT) and TMP_ROOT != PYTEST_TMP  # a lane's temp is never emptied by a test run


def test_only_a_folder_inside_scratch_is_ever_emptied(tmp_path):
    with pytest.raises(ValueError, match="outside"):
        use_repo_temp(REPO / "src", empty=True)
    assert (REPO / "src" / "nexus").is_dir()


def test_a_script_suite_imported_by_pytest_keeps_the_runs_temporary_directory():
    """`test_ingest.py` calls `use_repo_temp()` at import; under pytest it must not move the run to `scratch/tmp`."""
    assert use_repo_temp() == PYTEST_TMP
    assert Path(tempfile.gettempdir()).resolve() == PYTEST_TMP.resolve()


def test_scratch_is_gitignored_and_inside_the_repository():
    assert SCRATCH.resolve().parent == REPO.resolve()
    probe = "scratch/pytest/x.txt"
    assert subprocess.run(["git", "check-ignore", "-q", probe], cwd=REPO).returncode == 0
    assert inside_scratch(SNAPSHOTS)


def test_a_pytest_root_outside_scratch_is_refused(tmp_path):
    outside = Path(os.path.splitdrive(str(REPO))[0] + os.sep) / "ptt-refused"
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", f"--basetemp={outside}",
         "tests/test_repo_scratch.py::test_scratch_is_gitignored_and_inside_the_repository"],
        cwd=REPO, capture_output=True, text=True, timeout=300)
    assert result.returncode != 0
    assert "is outside" in (result.stdout + result.stderr)
    assert not outside.exists()
