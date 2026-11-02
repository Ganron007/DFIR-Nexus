"""Examiner-only tools cannot acquire automatic eligibility or stale run results."""
from nexus.langgraph import tool_lane
from nexus.tools import windows


def test_existing_planner_skip_is_replaced_by_examiner_only_policy():
    job = tool_lane.ToolJob(
        host="windows", tool="deepbluecli", argv=["deepbluecli"], purpose="prior plan",
        status="SKIP", reason="no EVTX for a channel DeepBlueCLI handles",
        audit_id="prior-audit", output_saved_to="prior-output", output_files=["prior-output"],
        result={"success": True}, lineage={"version": "prior"},
    )
    assert tool_lane._apply_default_optional_tool_skips([job]) == 1
    assert job.status == "SKIP" and "examiner-only" in job.reason
    assert job.reason == tool_lane._DEFAULT_OPTIONAL_TOOL_SKIP_REASONS["deepbluecli"]
    assert not job.argv and not job.audit_id and not job.output_saved_to and not job.output_files
    assert not job.result and not job.lineage
    assert tool_lane._apply_default_optional_tool_skips([job]) == 0


def test_automatic_evtx_planning_does_not_probe_examiner_tool_eligibility(tmp_path, monkeypatch):
    def available(name):
        assert name != "deepbluecli", "examiner-only support does not need automatic binary/channel eligibility"
        return True

    monkeypatch.setattr(tool_lane, "_windows_tool_available", available)
    monkeypatch.setattr(tool_lane, "_lane_opted_in", lambda _name: False)
    jobs = []
    # A planner-path control only: no EVTX record is authored or parsed.
    tool_lane.schedule_evtx_parsers(jobs, [tmp_path], tmp_path / "extractions")
    (job,) = [job for job in jobs if job.tool == "deepbluecli"]
    assert job.status == "SKIP" and not job.argv
    assert job.reason == tool_lane._DEFAULT_OPTIONAL_TOOL_SKIP_REASONS["deepbluecli"]
    assert {"hayabusa", "evtxecmd"} <= {job.tool for job in jobs if job.status == "PENDING"}


def test_manual_deepblue_registration_remains_available():
    assert windows._WIN_CATALOG["deepbluecli"]["name"] == "run-deepblue.ps1"
    assert windows._WIN_CATALOG["deepbluecli"]["category"] == "analysis"
