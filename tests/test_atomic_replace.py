"""D485: one definition of replacing a file, and a case record store that never disagrees with its mirror.

On the operator's host, 12 of 3,000 back-to-back replaces of one file failed with WinError 5 while Defender's
on-access scan held the file just written (no other writer). The 35 writers that each called `os.replace` failed
on it at random: an approval's mirror write failed after its record was committed, so every later approval of
the case was refused as tampering (`test_case_locks.py::test_concurrent_stage_and_approve_keep_every_update`,
2026-10-29 gate run).
"""
from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from nexus.utils import atomic

SRC = Path(__file__).resolve().parents[1] / "src" / "nexus"


def _replace_calls(path: Path) -> list[str]:
    """`os.replace`/`os.rename`, and `x.replace(y)`/`x.rename(y)` with one positional argument: a path move.

    `str.replace` takes two arguments and `datetime.replace` keywords, so neither is counted.
    """
    found = []
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
            continue
        if node.func.attr not in ("replace", "rename"):
            continue
        receiver = node.func.value
        if (isinstance(receiver, ast.Name) and receiver.id == "os") or (len(node.args) == 1 and not node.keywords):
            found.append(f"{path.relative_to(SRC).as_posix()}:{node.lineno}")
    return found


def test_every_file_replace_goes_through_the_one_definition():
    calls = [call for path in sorted(SRC.rglob("*.py")) if path.name != "atomic.py" or path.parent.name != "utils"
             for call in _replace_calls(path)]
    assert calls == []


def test_a_brief_hold_is_ridden_out(tmp_path, monkeypatch):
    src, dst = tmp_path / "a.tmp", tmp_path / "a.json"
    src.write_text("new", encoding="utf-8")
    dst.write_text("old", encoding="utf-8")
    real, tries = atomic.os.replace, []

    def held_twice(a, b):
        tries.append(1)
        if len(tries) < 3:
            raise PermissionError(5, "Access is denied", str(b))
        return real(a, b)

    monkeypatch.setattr(atomic.os, "replace", held_twice)
    monkeypatch.setattr(atomic.time, "sleep", lambda _s: None)
    assert atomic.replace(src, dst) == dst
    assert len(tries) == 3 and dst.read_text(encoding="utf-8") == "new" and not src.exists()


def test_a_hold_that_does_not_clear_is_raised_and_other_errors_at_once(tmp_path, monkeypatch):
    tries = []

    def held(a, b):
        tries.append(1)
        raise PermissionError(5, "Access is denied", str(b))

    monkeypatch.setattr(atomic.os, "replace", held)
    monkeypatch.setattr(atomic.time, "sleep", lambda _s: None)
    with pytest.raises(PermissionError, match="a.json"):
        atomic.replace(tmp_path / "a.tmp", tmp_path / "a.json")
    assert len(tries) == len(atomic.REPLACE_WAITS) + 1

    def full(a, b):
        tries.append(1)
        raise OSError("disk full")

    tries.clear()
    monkeypatch.setattr(atomic.os, "replace", full)
    with pytest.raises(OSError, match="disk full"):
        atomic.replace(tmp_path / "a.tmp", tmp_path / "a.json")
    assert len(tries) == 1


def test_a_mirror_that_cannot_be_written_leaves_the_record_store_unchanged(tmp_path, monkeypatch):
    """The real store and mirror (`save_findings`, `load_records`): a failed mirror rolls the commit back."""
    from nexus.case import records

    case = tmp_path / "CASE-D485"
    case.mkdir()
    records.save_findings(case, [{"id": "F-1", "status": "DRAFT"}])
    before = (case / "findings.json").read_bytes()

    def never(a, b):
        raise PermissionError(5, "Access is denied", str(b))

    # A context, not monkeypatch.undo(): undo would also drop conftest's case-store redirect.
    with monkeypatch.context() as patch:
        patch.setattr(atomic.os, "replace", never)
        patch.setattr(atomic.time, "sleep", lambda _s: None)
        with pytest.raises(PermissionError):
            records.save_findings(case, [{"id": "F-1", "status": "APPROVED"}])

    assert records.load_records(case, "finding") == [{"id": "F-1", "status": "DRAFT"}]
    assert (case / "findings.json").read_bytes() == before
    records.save_findings(case, [{"id": "F-1", "status": "APPROVED"}])
    assert json.loads((case / "findings.json").read_text(encoding="utf-8")) == [{"id": "F-1", "status": "APPROVED"}]
    assert records.load_records(case, "finding") == [{"id": "F-1", "status": "APPROVED"}]


def test_a_failed_commit_puts_the_previous_mirror_back(tmp_path, monkeypatch):
    from nexus.case import records

    case = tmp_path / "CASE-D485B"
    case.mkdir()
    records.save_findings(case, [{"id": "F-1", "status": "DRAFT"}])
    before = (case / "findings.json").read_bytes()
    real_connect = records._connect

    class _FailingCommit:
        def __init__(self, conn):
            self._conn = conn

        def __getattr__(self, name):
            return getattr(self._conn, name)

        def commit(self):
            raise records.sqlite3.OperationalError("disk I/O error")

    with monkeypatch.context() as patch:
        patch.setattr(records, "_connect", lambda db: _FailingCommit(real_connect(db)))
        with pytest.raises(records.sqlite3.OperationalError):
            records.save_findings(case, [{"id": "F-1", "status": "APPROVED"}])

    assert (case / "findings.json").read_bytes() == before
    assert records.load_records(case, "finding") == [{"id": "F-1", "status": "DRAFT"}]
