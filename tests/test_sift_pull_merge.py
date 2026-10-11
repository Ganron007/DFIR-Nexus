"""A SIFT pull adds what the local copy lacks and never overwrites a local file (2026-10-11).

The lane creates the run's sift/extractions folder before the pull, and the old guard refused every pull into an
existing folder: no SIFT output ever reached CASE-C5B04D31's run. scp is replaced by a stub that writes the files
the remote case would hold.
"""

from __future__ import annotations

import subprocess
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


def test_no_pull_happens_when_sync_is_off(tmp_path, scp, monkeypatch):
    monkeypatch.setenv("NEXUS_SIFT_SYNC", "0")
    assert sift_sync.pull_sift_extractions("CASE-X", tmp_path, tmp_path / "e") is None
    assert scp == []
