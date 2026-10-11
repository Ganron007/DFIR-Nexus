"""A retry carries the run's OK rows (2026-10-11): what it keeps, what it runs, and what a targeted retry leaves alone.

The retry on CASE-C5B04D31 re-ran eight OK jobs, because their rows recorded no registered sha, and it dropped the
mftecmd body row when the plan stopped naming that job. These tests pin the rules with the lane's own functions.
"""

from __future__ import annotations

import json

from nexus.langgraph import tool_lane
from nexus.langgraph.tool_lane import ToolJob

DRIVE_SHA = "a5e4afda7533"  # the registered H:\ tree of the CASE-C5B04D31 evidence


def _case(tmp_path, *, registered=True):
    case_dir = tmp_path / "CASE-CARRY-0001"
    extractions = case_dir / "runs" / "RUN-1" / "extractions"
    extractions.mkdir(parents=True)
    if registered:
        (case_dir / "evidence.json").write_text(
            json.dumps({"evidence": [{"path": "H:\\", "sha256": DRIVE_SHA}]}), encoding="utf-8")
    return case_dir, extractions


def _write_ledger(extractions, rows):
    (extractions / "_tool_lane_ledger.json").write_text(json.dumps(rows), encoding="utf-8")


def _ok_row(job, sha="", **extra):
    row = {"host": job.host, "tool": job.tool, "purpose": job.purpose, "status": "OK",
           "evidence_sha": sha, "lineage": {"version": "2026.5.0.0"}, "audit_id": "A1"}
    row.update(extra)
    return row


def _sbecmd(extractions):
    return ToolJob(
        host="windows", tool="sbecmd",
        argv=["sbecmd", "-d", str(extractions / "sbecmd" / "stage-wacsvc")],
        purpose="Shellbags UsrClass.dat (wacsvc)",
        source="H:\\C\\Users\\wacsvc\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat",
    )


def test_a_retry_reuses_an_ok_row_whose_sha_was_never_recorded(tmp_path):
    case_dir, extractions = _case(tmp_path)
    _write_ledger(extractions, [_ok_row(_sbecmd(extractions), sha="")])  # the row the 2026-10-11 retries left
    retry_job = _sbecmd(extractions)
    assert tool_lane.apply_prior_ok([retry_job], case_dir, extractions=extractions, carry=True) == 1
    assert retry_job.status == "OK" and retry_job.reason.startswith("reused prior OK")


def test_a_normal_pass_still_needs_a_recorded_sha(tmp_path):
    case_dir, extractions = _case(tmp_path)
    _write_ledger(extractions, [_ok_row(_sbecmd(extractions), sha="")])
    again = _sbecmd(extractions)
    assert tool_lane.apply_prior_ok([again], case_dir, extractions=extractions) == 0
    assert again.status == "PENDING"


def test_a_retry_never_reuses_a_row_made_from_other_bytes(tmp_path):
    case_dir, extractions = _case(tmp_path)
    _write_ledger(extractions, [_ok_row(_sbecmd(extractions), sha="0000deadbeef")])
    again = _sbecmd(extractions)
    assert tool_lane.apply_prior_ok([again], case_dir, extractions=extractions, carry=True) == 0
    assert again.status == "PENDING"


def test_the_plan_no_longer_names_an_ok_job_but_its_row_is_kept(tmp_path):
    case_dir, extractions = _case(tmp_path)
    body = ToolJob(host="windows", tool="mftecmd",
                   argv=["mftecmd", "--body", str(extractions / "mftecmd-body")],
                   purpose="MFT bodyfile for mactime (FOR508)")
    _write_ledger(extractions, [_ok_row(body, sha=DRIVE_SHA)])
    carried = tool_lane._settle_prior_rows([], case_dir, extractions, carry_ok=True, only_tools=None)
    assert [row["purpose"] for row in carried] == ["MFT bodyfile for mactime (FOR508)"]


def test_a_superseded_failure_is_not_carried(tmp_path):
    case_dir, extractions = _case(tmp_path)
    old = ToolJob(host="windows", tool="hayabusa", argv=["hayabusa"], purpose="Hayabusa (old plan)")
    _write_ledger(extractions, [dict(_ok_row(old), status="FAIL")])
    assert tool_lane._settle_prior_rows([], case_dir, extractions, carry_ok=True, only_tools=None) == []


def test_a_targeted_retry_runs_only_the_named_tool(tmp_path):
    case_dir, extractions = _case(tmp_path)
    sbecmd = _sbecmd(extractions)
    vol = ToolJob(host="sift", tool="vol", argv=["vol", "-f", "/m.img"], purpose="vol pslist")
    _write_ledger(extractions, [])
    jobs = [sbecmd, vol]
    tool_lane._settle_prior_rows(jobs, case_dir, extractions, carry_ok=True, only_tools=frozenset({"vol"}))
    assert [job.tool for job in jobs] == ["sbecmd", "vol"]
    assert jobs[0].status == "SKIP" and "targeted" in jobs[0].reason
    assert jobs[1].status == "PENDING"


def test_a_targeted_retry_keeps_the_run_row_of_another_tool(tmp_path):
    case_dir, extractions = _case(tmp_path)
    srum = ToolJob(host="windows", tool="srumecmd", argv=["srumecmd"], purpose="SRUM database")
    _write_ledger(extractions, [dict(_ok_row(srum), status="FAIL", reason="Timestamp in next log")])
    jobs = [ToolJob(host="windows", tool="srumecmd", argv=["srumecmd"], purpose="SRUM database")]
    carried = tool_lane._settle_prior_rows(jobs, case_dir, extractions, carry_ok=True,
                                           only_tools=frozenset({"sidr"}))
    assert jobs == []  # not run again
    assert carried and carried[0]["status"] == "FAIL"  # the run's own record stands


def test_the_settle_step_does_nothing_outside_a_retry(tmp_path):
    case_dir, extractions = _case(tmp_path)
    job = _sbecmd(extractions)
    _write_ledger(extractions, [_ok_row(job, sha="")])
    jobs = [job]
    assert tool_lane._settle_prior_rows(jobs, case_dir, extractions, carry_ok=False, only_tools=None) == []
    assert jobs == [job] and job.status == "PENDING"


def test_an_examiner_skip_holds_on_a_later_pass(tmp_path):
    from nexus.langgraph import lane_gate

    case_dir, extractions = _case(tmp_path)
    job = _sbecmd(extractions)
    path = lane_gate.gate_path(case_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "schema": 1, "unprocessed": [],
        "examiner_skips": [{"tool": "sbecmd", "purpose": "Shellbags UsrClass.dat (wacsvc)"}],
    }), encoding="utf-8")
    tool_lane._hold_examiner_skips([job], case_dir)
    assert job.status == "SKIP" and "examiner skip" in job.reason
