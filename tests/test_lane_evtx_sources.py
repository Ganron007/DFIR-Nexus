"""DeepBlueCLI reads every EVTX source, and the SIFT pull runs only for a run that sent jobs to SIFT (2026-10-18).

Sample S01 (361 EVTX of one Windows 10 host, no image around them) got Hayabusa and EvtxECmd and no DeepBlueCLI:
its job sat in the planner that only runs on a Windows image. The same run then reached over SSH for a SIFT case
folder that did not exist, though it had sent nothing to SIFT. File names are channels as Windows writes them (as
in S01's folder); planning reads names only.
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
    return [j for j in jobs if j.tool == "deepbluecli" and j.status == "PENDING"]


def test_a_folder_of_evtx_gets_deepbluecli_for_each_channel_it_handles(tmp_path):
    _write(tmp_path / "S01" / "evtx", CHANNELS + OTHER)
    jobs = plan_windows_triage(str(tmp_path / "S01"), tmp_path / "x")
    assert sorted(Path(j.argv[1]).name for j in _deepblue(jobs)) == sorted(CHANNELS)
    assert {Path(j.argv[2]).parent for j in _deepblue(jobs)} == {tmp_path / "x" / "deepbluecli"}
    # Beside the other EVTX parsers, as before.
    assert {"hayabusa", "evtxecmd"} <= {j.tool for j in jobs if j.status == "PENDING"}


def test_a_windows_image_gets_each_channel_once(tmp_path):
    root = tmp_path / "C"
    _write(root / "Windows" / "System32" / "winevt" / "Logs", CHANNELS + OTHER)
    jobs = plan_windows_triage(str(root), tmp_path / "x")
    assert sorted(Path(j.argv[1]).name for j in _deepblue(jobs)) == sorted(CHANNELS)


def test_two_evtx_folders_keep_their_outputs_apart(tmp_path):
    _write(tmp_path / "pack" / "host-a", ["Security.evtx"])
    _write(tmp_path / "pack" / "host-b", ["Security.evtx"])
    jobs = _deepblue(plan_windows_triage(str(tmp_path / "pack"), tmp_path / "x"))
    assert len(jobs) == 2
    outputs = {j.argv[2] for j in jobs}
    assert len(outputs) == 2 and all(Path(o).is_relative_to(tmp_path / "x" / "deepbluecli") for o in outputs)


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
