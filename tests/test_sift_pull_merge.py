"""A SIFT pull adds what the local copy lacks and never overwrites a local file (2026-10-11).

The lane creates the run's sift/extractions folder before the pull, and the old guard refused every pull into an
existing folder: no SIFT output ever reached CASE-C5B04D31's run. scp is replaced by a stub that writes the files
the remote case would hold.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from nexus.case import sift_sync

REMOTE = {"vol/pslist.csv": "remote pslist", "vol/netscan.csv": "remote netscan"}


@pytest.fixture()
def scp(tmp_path, monkeypatch):
    key = tmp_path / "cadre-sift-key"
    key.write_text("key", encoding="utf-8")
    monkeypatch.setenv("NEXUS_SIFT_SSH_KEY", str(key))
    monkeypatch.delenv("NEXUS_SIFT_SYNC", raising=False)
    calls: list[list[str]] = []

    def fake_scp(cmd, **kwargs):
        calls.append(list(cmd))
        target = Path(cmd[-1])  # scp -r <remote> <staging>: the remote's extractions land in the staging folder
        for rel, text in REMOTE.items():
            path = target / "extractions" / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(sift_sync.subprocess, "run", fake_scp)
    return calls


def test_a_pull_into_an_empty_folder_takes_its_place(tmp_path, scp):
    run = tmp_path / "RUN-1"
    dest = run / "sift" / "extractions"
    dest.mkdir(parents=True)  # the folder the lane creates before the pull
    assert sift_sync.pull_sift_extractions("CASE-X", run, dest) == dest
    assert (dest / "vol" / "pslist.csv").read_text(encoding="utf-8") == "remote pslist"
    assert (dest / "vol" / "netscan.csv").read_text(encoding="utf-8") == "remote netscan"
    assert not (dest.parent / "extractions_tmp").exists()


def test_a_pull_adds_the_missing_files_and_keeps_the_local_ones(tmp_path, scp):
    run = tmp_path / "RUN-1"
    dest = run / "sift" / "extractions"
    (dest / "vol").mkdir(parents=True)
    (dest / "vol" / "pslist.csv").write_text("local pslist", encoding="utf-8")
    assert sift_sync.pull_sift_extractions("CASE-X", run, dest) == dest
    assert (dest / "vol" / "pslist.csv").read_text(encoding="utf-8") == "local pslist"  # never overwritten
    assert (dest / "vol" / "netscan.csv").read_text(encoding="utf-8") == "remote netscan"  # added
    assert not (dest.parent / "extractions_tmp").exists()


def _hold_open(path: Path):
    """Open ``path`` the way an on-access scanner or a search indexer does: read access, every share mode.

    Returns a closer. While such a handle is open, Windows keeps a removed folder's name in place (delete pending)
    and refuses to rename a folder with an open file inside, with WinError 5 (D340).
    """
    import ctypes
    from ctypes import wintypes

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateFileW.restype = wintypes.HANDLE
    k32.CreateFileW.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
                                wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE)
    k32.CloseHandle.argtypes = (wintypes.HANDLE,)
    generic_read, share_all, open_existing, backup_semantics = 0x80000000, 0x7, 3, 0x02000000
    handle = k32.CreateFileW(str(path), generic_read, share_all, None, open_existing, backup_semantics, None)
    assert handle and handle != ctypes.c_void_p(-1).value, ctypes.get_last_error()
    return lambda: k32.CloseHandle(handle)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows file-handle semantics")
def test_a_pull_succeeds_while_another_handle_holds_the_empty_destination_open(tmp_path, scp):
    """The destination folder the lane made may itself be open elsewhere (an indexer); the pull still lands."""
    run = tmp_path / "RUN-1"
    dest = run / "sift" / "extractions"
    dest.mkdir(parents=True)
    close = _hold_open(dest)
    try:
        assert sift_sync.pull_sift_extractions("CASE-X", run, dest) == dest
    finally:
        close()
    assert (dest / "vol" / "pslist.csv").read_text(encoding="utf-8") == "remote pslist"
    assert (dest / "vol" / "netscan.csv").read_text(encoding="utf-8") == "remote netscan"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows file-handle semantics")
def test_a_pull_succeeds_while_another_handle_holds_a_fresh_file_open(tmp_path, scp, monkeypatch):
    """D340: an on-access scan opens each file scp has just written. The old pull renamed the staged folder onto the
    destination, and Windows refused with WinError 5, as in the full suite of 2026-10-23."""
    run = tmp_path / "RUN-1"
    dest = run / "sift" / "extractions"
    dest.mkdir(parents=True)
    closers = []
    stub = sift_sync.subprocess.run

    def scp_then_scan(cmd, **kwargs):
        result = stub(cmd, **kwargs)
        closers.append(_hold_open(Path(cmd[-1]) / "extractions" / "vol" / "pslist.csv"))
        return result

    monkeypatch.setattr(sift_sync.subprocess, "run", scp_then_scan)
    try:
        assert sift_sync.pull_sift_extractions("CASE-X", run, dest) == dest
    finally:
        for close in closers:
            close()
    assert (dest / "vol" / "pslist.csv").read_text(encoding="utf-8") == "remote pslist"
    assert (dest / "vol" / "netscan.csv").read_text(encoding="utf-8") == "remote netscan"


def test_no_pull_happens_when_sync_is_off(tmp_path, scp, monkeypatch):
    monkeypatch.setenv("NEXUS_SIFT_SYNC", "0")
    assert sift_sync.pull_sift_extractions("CASE-X", tmp_path, tmp_path / "e") is None
    assert scp == []
