"""A staging starts from an empty workdir, so a retry in the same run cannot replay over its own leftovers.

Real-path cause (CASE-C5B04D31, 2026-10-11): the first attempt's replay wrote SRU03FBB.log into
extractions/srum/workdir. The retry copied the evidence files over that folder and kept the stale generation,
so the replay failed with JET_errInvalidLogSequence (-515) and srumecmd read a dirty database. A scratch
reproduction with the evidence copy alone reached Clean Shutdown, and srumecmd wrote 7 CSVs.
"""

from __future__ import annotations

import pytest

from nexus.langgraph import tool_lane
from nexus.langgraph.query_pack import is_staging_copy


@pytest.fixture()
def evidence_sru(tmp_path):
    src = tmp_path / "evidence" / "sru"
    src.mkdir(parents=True)
    for name in ("SRUDB.dat", "SRU.log", "SRU.chk", "SRU03FB4.log"):
        (src / name).write_bytes(name.encode())
    (src / "notes.txt").write_text("not an ESE file", encoding="utf-8")
    return src


def test_a_second_staging_drops_the_first_attempts_generation_files(evidence_sru, tmp_path):
    work = tmp_path / "extractions" / "srum" / "workdir"
    tool_lane._copy_ese_siblings(evidence_sru, work, ("SRU",))
    (work / "SRU03FBB.log").write_bytes(b"written by the first replay")
    tool_lane._copy_ese_siblings(evidence_sru, work, ("SRU",))
    assert sorted(p.name for p in work.iterdir()) == ["SRU.chk", "SRU.log", "SRU03FB4.log", "SRUDB.dat"]


def test_only_a_lane_workdir_is_emptied(evidence_sru, tmp_path):
    keep = tmp_path / "extractions" / "srum"  # the run's own output folder, not a workdir
    keep.mkdir(parents=True)
    (keep / "SrumECmd_AppResourceUseInfo.csv").write_text("row", encoding="utf-8")
    with pytest.raises(OSError, match="not a lane workdir"):
        tool_lane._copy_ese_siblings(evidence_sru, keep, ("SRU",))
    assert (keep / "SrumECmd_AppResourceUseInfo.csv").is_file()


def test_the_bitsparser_stem_workdir_is_emptied_too(evidence_sru, tmp_path):
    work = tmp_path / "bitsparser" / "LogFile-abc12345-workdir"
    tool_lane._copy_ese_siblings(evidence_sru, work, ("SRU",))
    (work / "SRU03FBB.log").write_bytes(b"stale")
    tool_lane._copy_ese_siblings(evidence_sru, work, ("SRU",))
    assert not (work / "SRU03FBB.log").exists()


def test_the_retry_plans_srum_over_a_fresh_copy(tmp_path, monkeypatch):
    """Two planning passes over one run folder: each replay starts from the same evidence copy."""
    root = tmp_path / "C"
    sru = root / "Windows" / "System32" / "sru"
    sru.mkdir(parents=True)
    (root / "Windows" / "System32" / "config").mkdir(parents=True)
    (sru / "SRUDB.dat").write_bytes(b"srum database")
    (sru / "SRU.log").write_bytes(b"current log")
    extractions = tmp_path / "extractions"

    files_seen_by_replay: list[list[str]] = []

    def replay(work, *, log_bases):
        if tuple(log_bases) != ("sru",):
            return
        files_seen_by_replay.append(sorted(p.name for p in work.iterdir()))
        (work / "SRU03FBB.log").write_bytes(b"generation written by the replay")  # what esentutl /r leaves

    monkeypatch.setattr(tool_lane, "_esentutl_replay", replay)
    tool_lane.plan_windows_triage(str(root), extractions)
    tool_lane.plan_windows_triage(str(root), extractions)  # the retry, in the same run folder

    assert files_seen_by_replay == [["SRU.log", "SRUDB.dat"], ["SRU.log", "SRUDB.dat"]]


def test_staging_copies_are_not_indexed_as_tool_output(tmp_path):
    run = tmp_path / "run" / "extractions"
    assert is_staging_copy(run / "srum" / "workdir" / "SRU.log", run)
    assert is_staging_copy(run / "bitsparser" / "LogFile-abc12345-workdir" / "edb.log", run)
    assert not is_staging_copy(run / "srum" / "SrumECmd_AppResourceUseInfo.csv", run)
