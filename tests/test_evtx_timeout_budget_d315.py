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
    deepblue = next(
        job for job in jobs
        if job.tool == "deepbluecli" and "Security.evtx" in job.purpose
    )
    assert evtxecmd.timeout == 323  # 300 s base + 23 MiB at 1 s/MiB
    assert deepblue.timeout == 1500  # 300 s base + 20 MiB at 60 s/MiB


def test_evtxecmd_budget_scales_past_the_old_folder_ceiling():
    # S08's failed directory had 3,365.6 MiB across 372 files. The same
    # byte-based policy yields 3,665 s instead of the old fixed 1,800 s.
    budget = tl._evtxecmd_timeout_for_bytes(3365 * MIB)
    assert budget == 3665
    assert budget > 1800
    assert tl._evtxecmd_timeout_for_bytes(10_000 * MIB) == 7200


def test_deepbluecli_budget_has_headroom_for_dense_security_logs():
    assert tl._deepbluecli_timeout_for_bytes(20 * MIB) == 1500
    assert tl._deepbluecli_timeout_for_bytes(200 * MIB) == 3600
    assert tl._deepbluecli_timeout_for_bytes(None) == 3600
