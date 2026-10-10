"""The MemProcFS lane wrapper waits for forensic mode and copies its outputs once (WO-TA item 6, D68).

Reproduced on rd01-memory.img (2026-10-11): the wrapper read /forensic/ straight after the VMM
started, when the outputs did not exist yet, so the lane recorded no timeline and no FindEvil.
MemProcFS reports progress; 100 is the completion signal. The timeline is written three ways (CSV,
TXT and JSON) and the union CSV repeats the per-source CSVs, so a duplicate is skipped only when its
rows match its pair.

These tests drive the wrapper's own functions with a fake virtual file system, so they need no
memory image and no MemProcFS.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
WRAPPER = REPO / "tools" / "windows" / "extra" / "memprocfs" / "run-memprocfs.py"


@pytest.fixture(scope="module")
def wrapper():
    spec = importlib.util.spec_from_file_location("run_memprocfs", WRAPPER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeVfs:
    """Only the two calls the wrapper makes: list(path) and read(path, size, offset)."""

    def __init__(self, files: dict[str, bytes], progress: list[str] | None = None):
        self.files = files
        self.progress = list(progress or [])

    def list(self, path: str) -> dict:
        children: dict[str, dict] = {}
        for full, data in self.files.items():
            if not full.startswith(path):
                continue
            head, _, rest = full[len(path):].partition("/")
            if rest:
                children[head] = {"f_isdir": True, "size": 0, "name": head}
            else:
                children[head] = {"f_isdir": False, "size": len(data), "name": head}
        if not children and path not in ("/forensic/",):
            raise FileNotFoundError(path)
        return children

    def read(self, path: str, size: int = 0, offset: int = 0) -> bytes:
        if path == "/forensic/progress_percent.txt":
            value = self.progress.pop(0) if len(self.progress) > 1 else (self.progress[0] if self.progress else "100")
            return value.encode("ascii")
        return self.files[path][offset:offset + (size or len(self.files[path]))]


def _csv(*data_rows: str) -> bytes:
    return ("Time,Type,Action\n" + "\n".join(data_rows) + "\n").encode()


def _txt(*data_rows: str) -> bytes:
    return ("\n".join(data_rows) + "\n").encode()


def _copy(wrapper, tmp_path: Path, files: dict[str, bytes]):
    vfs = FakeVfs(files)
    out = tmp_path / "out"
    out.mkdir()
    copied, skipped = wrapper._copy_forensic(vfs, out, {})
    return out, copied, skipped


def test_a_timeline_text_form_identical_to_its_csv_is_skipped(wrapper, tmp_path):
    files = {
        "/forensic/csv/timeline_process.csv": _csv("a,1", "b,2", "c,3"),
        "/forensic/timeline/timeline_process.txt": _txt("a 1", "b 2", "c 3"),
    }

    out, copied, skipped = _copy(wrapper, tmp_path, files)

    assert any("timeline_process.txt" in s["file"] for s in skipped)
    assert not (out / "forensic" / "timeline" / "timeline_process.txt").exists()
    assert (out / "forensic" / "csv" / "timeline_process.csv").is_file()


def test_a_timeline_text_form_that_differs_is_kept(wrapper, tmp_path):
    files = {
        "/forensic/csv/timeline_net.csv": _csv("a,1", "b,2"),
        "/forensic/timeline/timeline_net.txt": _txt("a 1", "b 2", "c 3"),
    }

    out, copied, skipped = _copy(wrapper, tmp_path, files)

    assert (out / "forensic" / "timeline" / "timeline_net.txt").is_file()
    assert any(c["file"].endswith("timeline_net.txt") and "kept" in c.get("note", "") for c in copied)


def test_the_union_csv_is_skipped_when_it_is_the_sum_of_its_sources(wrapper, tmp_path):
    files = {
        "/forensic/csv/timeline_process.csv": _csv("a,1", "b,2", "c,3"),
        "/forensic/csv/timeline_net.csv": _csv("d,4", "e,5"),
        # the union: one header, then all five data rows
        "/forensic/csv/timeline_all.csv": _csv("a,1", "b,2", "c,3", "d,4", "e,5"),
    }

    out, copied, skipped = _copy(wrapper, tmp_path, files)

    assert any("timeline_all.csv" in s["file"] and "union" in s["reason"] for s in skipped)
    assert not (out / "forensic" / "csv" / "timeline_all.csv").exists()


def test_the_union_csv_that_does_not_match_is_kept(wrapper, tmp_path):
    files = {
        "/forensic/csv/timeline_process.csv": _csv("a,1", "b,2"),
        "/forensic/csv/timeline_all.csv": _csv("a,1", "b,2", "z,9"),
    }

    out, copied, skipped = _copy(wrapper, tmp_path, files)

    assert (out / "forensic" / "csv" / "timeline_all.csv").is_file()


def test_json_timeline_is_skipped_when_it_has_the_union_rows(wrapper, tmp_path):
    files = {
        "/forensic/csv/timeline_process.csv": _csv("a,1", "b,2"),
        "/forensic/csv/timeline_all.csv": _csv("a,1", "b,2"),
        "/forensic/json/timeline.json": _txt('{"a":1}', '{"b":2}'),
    }

    out, copied, skipped = _copy(wrapper, tmp_path, files)

    assert any("timeline.json" in s["file"] for s in skipped)


def test_boilerplate_scripts_and_prefetch_binaries_are_not_copied(wrapper, tmp_path):
    files = {
        "/forensic/readme.txt": b"boilerplate",
        "/forensic/json/elastic_import.ps1": b"Write-Host",
        "/forensic/prefetch/0-SVCHOST.EXE-00F6E14D.pf": b"\x00\x01",
        "/forensic/prefetch/0-SVCHOST.EXE-00F6E14D.pf.txt": b"parsed text\n",
    }

    out, copied, skipped = _copy(wrapper, tmp_path, files)

    names = {c["file"] for c in copied}
    assert "forensic/prefetch/0-SVCHOST.EXE-00F6E14D.pf.txt" in names
    assert not any(n.endswith((".ps1", ".pf", "readme.txt")) for n in names)


def test_the_wait_returns_once_progress_reads_100(wrapper, monkeypatch):
    monkeypatch.setattr(wrapper, "FORENSIC_QUIET_S", 0)
    monkeypatch.setattr(wrapper.time, "sleep", lambda _s: None)
    vfs = FakeVfs({"/forensic/csv/x.csv": _csv("a,1")}, progress=["0", "51", "100"])

    wait = wrapper._wait_for_forensic(vfs)

    assert wait["progress"] == "100"
    assert wait["settled"] is True
    assert [p for _t, p in wait["progress_history"]] == ["0", "51", "100"]


def test_the_wait_reports_unfinished_forensic_mode(wrapper, monkeypatch):
    monkeypatch.setattr(wrapper, "FORENSIC_WAIT_S", 0)
    monkeypatch.setattr(wrapper.time, "sleep", lambda _s: None)
    vfs = FakeVfs({"/forensic/csv/x.csv": _csv("a,1")}, progress=["40"])

    wait = wrapper._wait_for_forensic(vfs)

    assert wait["progress"] == "40"
    assert wait["settled"] is False
