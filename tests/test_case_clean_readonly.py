"""``nexus case clean`` must actually clean, and say so when it cannot.

Found while cleaning up after the debug-mode run: the store held nine orphan
case folders totalling 223 MB that had survived every previous ``case clean``,
each one reappearing after a command that reported "Cleaned 9 case folder(s)".

The cause is the tool lane. It stages evidence with ``shutil.copy2``, which
carries the source file's attributes across, and the corpus' ``.evtx`` files are
read-only. A read-only file cannot be unlinked on Windows, so ``rmtree`` raised
- and ``ignore_errors=True`` swallowed it. The command counted the folder as
removed, printed a success line, and exited 0.

This matters more than an untidy directory: AGENTS.md tells every session to run
this command afterwards, so the failure was both silent and repeated. A cleanup
routine that cannot fail loudly is not a cleanup routine.
"""
from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest
from typer.testing import CliRunner

from nexus.cli.case_cmd import app

runner = CliRunner()


def _case(root: Path, name: str, *, readonly: bool = False) -> Path:
    d = root / name
    (d / "runs" / "RUN-1" / "extractions").mkdir(parents=True)
    ev = d / "runs" / "RUN-1" / "extractions" / "Application.evtx"
    ev.write_bytes(b"\x00" * 64)
    (d / "findings.json").write_text("[]", encoding="utf-8")
    if readonly:
        # Windows refuses to unlink a read-only file - the real failure mode.
        os.chmod(ev, stat.S_IREAD)
    return d


def _clean(root: Path, *args: str):
    import nexus.config as cfg

    original = cfg.settings.cases_root
    object.__setattr__(cfg.settings, "cases_root", root)
    try:
        return runner.invoke(app, ["clean", "--yes", *args])
    finally:
        object.__setattr__(cfg.settings, "cases_root", original)


def test_readonly_evidence_does_not_survive_a_clean(tmp_path):
    """The regression: a read-only staged .evtx used to survive every clean."""
    d = _case(tmp_path, "CASE-READONLY", readonly=True)
    assert os.stat(d / "runs/RUN-1/extractions/Application.evtx").st_file_attributes & 1

    res = _clean(tmp_path)

    assert res.exit_code == 0, res.output
    assert not d.exists(), "read-only case folder survived the clean"
    assert "Cleaned 1 case folder(s)" in res.output


def test_clean_does_not_swallow_a_failure(tmp_path, monkeypatch):
    """If a folder genuinely cannot be removed, say so and exit non-zero."""
    _case(tmp_path, "CASE-STUCK")

    import shutil as real_shutil

    def boom(*_a, **_k):
        raise OSError("simulated: file is open in another process")

    monkeypatch.setattr(real_shutil, "rmtree", boom)
    res = _clean(tmp_path)

    assert res.exit_code == 1, res.output
    assert "FAILED" in res.output
    assert "simulated" in res.output
    # The success count must not include the folder that is still there.
    assert "Cleaned 0 of 1" in res.output


def test_a_folder_still_present_after_rmtree_counts_as_failed(tmp_path, monkeypatch):
    """Some rmtree shims return without deleting; verify, do not trust."""
    _case(tmp_path, "CASE-PHANTOM")

    import shutil as real_shutil

    monkeypatch.setattr(real_shutil, "rmtree", lambda *_a, **_k: None)
    res = _clean(tmp_path)

    assert res.exit_code == 1
    assert "still present" in res.output


def test_keep_is_honoured(tmp_path):
    keep = _case(tmp_path, "CASE-KEEP")
    drop = _case(tmp_path, "CASE-DROP")
    res = _clean(tmp_path, "--keep", "CASE-KEEP")

    assert res.exit_code == 0, res.output
    assert keep.is_dir()
    assert not drop.exists()
    assert "kept: CASE-KEEP" in res.output


def test_ordinary_case_still_cleans(tmp_path):
    d = _case(tmp_path, "CASE-PLAIN")
    res = _clean(tmp_path)
    assert res.exit_code == 0, res.output
    assert not d.exists()


def test_empty_store_is_not_an_error(tmp_path):
    res = _clean(tmp_path)
    assert res.exit_code == 0
    assert "No cases to clean" in res.output


@pytest.mark.skipif(os.name != "nt", reason="the read-only unlink failure is Windows-specific")
def test_nested_readonly_files_are_all_cleared(tmp_path):
    """Deep trees are where copy2 put the attribute everywhere."""
    d = tmp_path / "CASE-DEEP"
    deep = d / "runs" / "R1" / "extractions" / "evtx_input"
    deep.mkdir(parents=True)
    for i in range(5):
        f = deep / f"ch{i}.evtx"
        f.write_bytes(b"\x00" * 16)
        os.chmod(f, stat.S_IREAD)
    res = _clean(tmp_path)
    assert res.exit_code == 0, res.output
    assert not d.exists()
