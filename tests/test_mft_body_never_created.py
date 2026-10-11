"""The Windows lane never creates the MFT bodyfile (operator decision 2026-10-11).

The bodyfile is the input of the SIFT/Plaso super timeline, and the Windows lane has no use for it: the parsed MFT
table is the MFT evidence. It used to run on an opt-in, and CASE-C5B04D31's runs wrote a 199 MB file that no index
read. No setting makes the lane create it now.
"""

from __future__ import annotations

from pathlib import Path

import pytest


def _volume(tmp_path: Path) -> Path:
    root = tmp_path / "C"
    (root / "Windows" / "System32").mkdir(parents=True)
    (root / "$MFT").write_bytes(b"FILE" + b"\x00" * 1020)
    return root


@pytest.fixture()
def lane_env(monkeypatch):
    monkeypatch.delenv("NEXUS_TOOL_LANE_QUICK", raising=False)
    monkeypatch.delenv("NEXUS_LANE_OPT_IN", raising=False)
    return monkeypatch


def test_the_plan_parses_mft_to_csv_and_never_plans_a_bodyfile(tmp_path, lane_env):
    from nexus.langgraph.tool_lane import plan_windows_triage

    extractions = tmp_path / "extractions"
    extractions.mkdir()
    jobs = plan_windows_triage(str(_volume(tmp_path)), extractions)
    mft_jobs = [j for j in jobs if j.tool == "mftecmd" and j.status == "PENDING"]
    assert len(mft_jobs) == 1
    argv = list(mft_jobs[0].argv)
    assert "--csv" in argv and "--csvf" in argv and "mft.csv" in argv
    assert "--body" not in argv
    body_row = next(j for j in jobs if j.tool == "mftecmd-body")
    assert body_row.status == "SKIP"
    assert "never creates the MFT bodyfile" in body_row.reason
    assert not (extractions / "mftecmd-body").exists()


def test_no_opt_in_setting_makes_the_lane_create_the_bodyfile(tmp_path, lane_env):
    from nexus.langgraph.tool_lane import plan_windows_triage

    lane_env.setenv("NEXUS_LANE_OPT_IN", "mftecmd-body")
    extractions = tmp_path / "extractions"
    extractions.mkdir()
    jobs = plan_windows_triage(str(_volume(tmp_path)), extractions)
    assert not [j for j in jobs if j.tool == "mftecmd" and "--body" in list(j.argv)]
    body_row = next(j for j in jobs if j.tool == "mftecmd-body")
    assert body_row.status == "SKIP"
    assert not (extractions / "mftecmd-body").exists()
