"""D288: LogFileParser gets one budget, scaled by the $LogFile's size, on every path (2026-10-18).

Sample S08's lane killed LogFileParser after 600 s on three of fifteen hosts: the drive-tree plan gave it a fixed
600 s while a registered $LogFile got a budget scaled by its size. The test plans S08's own expanded host tree (its
$LogFile is 57 MB) where the sample's case is present.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from nexus.langgraph import tool_lane as tl

REPO = Path(__file__).resolve().parents[1]
HOSTS = sorted((REPO / "cases" / "CASE-230BD8C3" / "evidence" / "_expanded").glob("sam-adragoon-l-*/sam-adragoon-l"))


@pytest.mark.skipif(not HOSTS, reason="sample S08's expanded collections are not on this host")
def test_the_drive_tree_and_the_single_file_plans_give_one_scaled_budget(tmp_path):
    root = HOSTS[0] / "C"
    logfile = root / "$LogFile"
    assert logfile.stat().st_size > 50 * 1024 * 1024
    tree = [j for j in tl.plan_windows_triage(str(root), tmp_path / "tree") if j.tool == "logfileparser"]
    single = [j for j in tl._plan_single_artifact(logfile, tmp_path / "one") if j.tool == "logfileparser"]
    assert tree and single
    expected = tl.timeout_for_bytes(logfile.stat().st_size, base=900, per_mb=60, cap=7200)
    assert tree[0].timeout == single[0].timeout == expected > 600


def test_logfileparser_budget_scales_past_the_old_one_hour_ceiling(tmp_path, monkeypatch):
    root = tmp_path / "host" / "C"
    (root / "Windows" / "System32").mkdir(parents=True)
    logfile = root / "$LogFile"
    with logfile.open("wb") as stream:
        stream.write(b"RSTR")
        stream.truncate(57_360_384)

    monkeypatch.setattr(tl, "_windows_tool_available", lambda _key: True)
    host_jobs = tl.plan_windows_triage(str(root), tmp_path / "host-plan")
    single_jobs = tl._plan_single_artifact(logfile, tmp_path / "single-plan")
    host_parser = [job for job in host_jobs if job.tool == "logfileparser"]
    single_parser = [job for job in single_jobs if job.tool == "logfileparser"]

    assert host_parser and single_parser
    assert host_parser[0].timeout == single_parser[0].timeout == 4140
    assert tl.timeout_for_bytes(200 * 1024 * 1024, base=900, per_mb=60, cap=7200) == 7200
