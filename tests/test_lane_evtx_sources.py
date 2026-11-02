"""EVTX sources keep required parser outputs scoped; DeepBlueCLI is examiner-only.

The former per-channel automatic DeepBlue planning contract is superseded by
OD-T26. SIFT pulls still require an actually dispatched SIFT job.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from nexus.langgraph import tool_lane
from nexus.langgraph.tool_lane import ToolJob, plan_windows_triage

CHANNELS = ["Security.evtx", "System.evtx", "Microsoft-Windows-PowerShell%4Operational.evtx"]
OTHER = ["Microsoft-Windows-TaskScheduler%4Operational.evtx", "Windows PowerShell.evtx", "Setup.evtx"]


@pytest.fixture(autouse=True)
def tools_installed(monkeypatch):
    monkeypatch.setattr(tool_lane, "_windows_tool_available", lambda key: True)


def _write(folder: Path, names: list[str]) -> None:
    folder.mkdir(parents=True, exist_ok=True)
    for name in names:
        (folder / name).write_bytes(b"ElfFile\x00")


def _deepblue(jobs: list[ToolJob]) -> list[ToolJob]:
    return [j for j in jobs if j.tool == "deepbluecli"]


def test_a_folder_of_evtx_records_one_examiner_only_deepblue_skip(tmp_path):
    _write(tmp_path / "S01" / "evtx", CHANNELS + OTHER)
    jobs = plan_windows_triage(str(tmp_path / "S01"), tmp_path / "x")
    (job,) = _deepblue(jobs)
    assert job.status == "SKIP" and not job.argv
    assert job.reason == tool_lane._DEFAULT_OPTIONAL_TOOL_SKIP_REASONS["deepbluecli"]
    assert {"hayabusa", "evtxecmd"} <= {j.tool for j in jobs if j.status == "PENDING"}


def test_a_windows_image_retains_the_same_examiner_only_policy(tmp_path):
    root = tmp_path / "C"
    _write(root / "Windows" / "System32" / "winevt" / "Logs", CHANNELS + OTHER)
    (job,) = _deepblue(plan_windows_triage(str(root), tmp_path / "x"))
    assert job.status == "SKIP" and not job.argv
    assert job.reason == tool_lane._DEFAULT_OPTIONAL_TOOL_SKIP_REASONS["deepbluecli"]


def test_two_evtx_folders_keep_required_parser_outputs_apart(tmp_path):
    _write(tmp_path / "pack" / "host-a", ["Security.evtx"])
    _write(tmp_path / "pack" / "host-b", ["Security.evtx"])
    jobs = plan_windows_triage(str(tmp_path / "pack"), tmp_path / "x")
    (deepblue,) = _deepblue(jobs)
    assert deepblue.status == "SKIP" and not deepblue.argv
    for family, option in (("hayabusa", "-o"), ("evtxecmd", "--csv")):
        selected = [job for job in jobs if job.tool == family and job.status == "PENDING"]
        assert len(selected) == 2
        outputs = {Path(job.argv[job.argv.index(option) + 1]) for job in selected}
        assert len(outputs) == 2
        assert all(path.is_relative_to(tmp_path / "x" / family) for path in outputs)


def test_evtxecmd_parses_every_input_and_counts_nested_logs(tmp_path):
    logs = tmp_path / "Logs"
    _write(logs, ["Security.evtx"])
    _write(logs / "nested", ["System.evtx"])
    jobs = []

    tool_lane.schedule_evtx_parsers(jobs, [logs], tmp_path / "out")

    evtxecmd = next(j for j in jobs if j.tool == "evtxecmd")
    assert evtxecmd.argv[-2:] == ["--dedupe", "false"]
    assert "(2 logs)" in evtxecmd.purpose


def test_the_sift_pull_needs_a_job_that_went_to_sift():
    windows = ToolJob(host="windows", tool="hayabusa", argv=["hayabusa"], purpose="", status="OK")
    assert not tool_lane._sift_jobs_ran([windows])
    for status in ("SKIP", "BLOCKED", "PENDING"):
        sift = ToolJob(host="sift", tool="vol", argv=[], purpose="", status=status)
        assert not tool_lane._sift_jobs_ran([windows, sift]), status
    for status in ("OK", "FAIL"):
        sift = ToolJob(host="sift", tool="vol", argv=["vol"], purpose="", status=status)
        assert tool_lane._sift_jobs_ran([windows, sift]), status
