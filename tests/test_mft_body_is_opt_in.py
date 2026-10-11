"""The parsed MFT table is the default MFT product; the bodyfile is opt-in (operator, 2026-10-11).

The bodyfile is the SIFT/Plaso timeline input (mactime, super timeline). Before this change the
planner added it beside the CSV job, so every Windows lane run wrote a 199 MB bodyfile that no
index read (CASE-C5B04D31). It now runs only with NEXUS_LANE_OPT_IN=mftecmd-body.
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


def test_the_default_plan_parses_mft_to_csv_and_no_bodyfile(tmp_path, lane_env):
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
    assert "NEXUS_LANE_OPT_IN=mftecmd-body" in body_row.reason
    assert not (extractions / "mftecmd-body").exists()


def test_the_bodyfile_runs_only_on_examiner_opt_in(tmp_path, lane_env):
    from nexus.langgraph.tool_lane import plan_windows_triage

    lane_env.setenv("NEXUS_LANE_OPT_IN", "mftecmd-body")
    extractions = tmp_path / "extractions"
    extractions.mkdir()
    jobs = plan_windows_triage(str(_volume(tmp_path)), extractions)
    body_jobs = [j for j in jobs if j.tool == "mftecmd" and "--body" in list(j.argv)]
    assert len(body_jobs) == 1 and body_jobs[0].status == "PENDING"
    assert not [j for j in jobs if j.tool == "mftecmd-body"]
    assert (extractions / "mftecmd-body").is_dir()
