"""D315: EVTX parser budgets follow the input workload (2026-10-21).

S08 exposed a fixed EvtxECmd budget on a 3.29 GiB directory and an
under-sized per-MiB DeepBlueCLI budget on dense 20 MiB Security logs. These
tests exercise planning only; they do not parse or fabricate EVTX records.
"""
from __future__ import annotations

from pathlib import Path

from nexus.langgraph import tool_lane as tl

MIB = 1024 * 1024


def _sparse_file(path: Path, size: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as stream:
        stream.truncate(size)


def test_evtxecmd_timeout_uses_total_directory_bytes(tmp_path, monkeypatch):
    logs = tmp_path / "winevt" / "Logs"
    _sparse_file(logs / "Application.evtx", 2 * MIB)
    _sparse_file(logs / "Security.evtx", 20 * MIB)
    _sparse_file(logs / "System.evtx", MIB)
    monkeypatch.setattr(tl, "_windows_tool_available", lambda _tool: True)
    monkeypatch.setattr(tl, "_lane_opted_in", lambda _tool: False)

    jobs = []
    tl.schedule_evtx_parsers(jobs, [logs], tmp_path / "extractions")

    evtxecmd = next(job for job in jobs if job.tool == "evtxecmd")
    deepblue = next(job for job in jobs if job.tool == "deepbluecli")
    assert evtxecmd.timeout == 323  # 300 s base + 23 MiB at 1 s/MiB
    assert deepblue.status == "SKIP" and not deepblue.argv
    assert deepblue.reason == tl._DEFAULT_OPTIONAL_TOOL_SKIP_REASONS["deepbluecli"]


def test_evtxecmd_budget_scales_past_the_old_folder_ceiling():
    # S08's failed directory had 3,365.6 MiB across 372 files. The same
    # byte-based policy yields 3,665 s instead of the old fixed 1,800 s.
    budget = tl._evtxecmd_timeout_for_bytes(3365 * MIB)
    assert budget == 3665
    assert budget > 1800
    assert tl._evtxecmd_timeout_for_bytes(10_000 * MIB) == 7200


def test_examiner_only_deepblue_does_not_get_an_automatic_workload(tmp_path, monkeypatch):
    monkeypatch.setattr(tl, "_windows_tool_available", lambda _tool: True)
    jobs = []
    tl.schedule_evtx_parsers(jobs, [tmp_path], tmp_path / "out")
    (job,) = [job for job in jobs if job.tool == "deepbluecli"]
    assert job.status == "SKIP" and not job.argv
    assert job.reason == tl._DEFAULT_OPTIONAL_TOOL_SKIP_REASONS["deepbluecli"]
