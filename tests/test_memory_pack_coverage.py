"""WO-V6: zero rows from a process-list plugin is a coverage gap, not a negative.

On the G7 image every list-walk plugin returned nothing while ``psscan`` saw
134 processes, and the A9 row read that as "no malfind hits on this image".
``malfind`` iterates the process list, so an empty list gives zero rows by
construction — the conclusion was unsupported either way (the walk failed, or
its output was lost to the 10 KB slice, WO-V5).

The D12 lane re-run added a second chapter: the first version read the job's
output file *locally*, which is empty for every SIFT job (the capture lives on
the SIFT host), so the check silently did nothing for the exact case it was
written for. ``_sift_job`` below is that shape: no local file, rows only in the
execution result.
"""
from __future__ import annotations

import json
from pathlib import Path

from nexus.analysis.negative_space import read_events
from nexus.langgraph.tool_lane import (
    ToolJob,
    reconcile_process_list_coverage,
)

EMPTY_OUTPUT_REASON = "vol exited cleanly but produced no output file"
TRUNCATED_REASON = (
    "captured output hit the byte cap, so the saved output is incomplete"
)


def _case(tmp_path: Path) -> Path:
    case = tmp_path / "CASE-MEM"
    (case / "audit").mkdir(parents=True)
    (case / "CASE.yaml").write_text("id: CASE-MEM\n", encoding="utf-8")
    return case


def _vol_job(tmp_path: Path, plugin: str, rows: int) -> ToolJob:
    """A Windows-side job with a real local output file."""
    out = tmp_path / f"{plugin.replace('.', '_')}.jsonl"
    if rows:
        out.write_text(
            "\n".join(json.dumps({"PID": i, "ImageFileName": f"p{i}.exe"}) for i in range(rows))
            + "\n",
            encoding="utf-8",
        )
    else:
        out.write_text("", encoding="utf-8")
    return ToolJob(
        host="windows",
        tool="vol",
        argv=["vol", "-f", "mem.raw", "-r", "jsonl", plugin],
        purpose=f"Volatility3 {plugin}",
        status="OK",
        output_saved_to=str(out),
    )


def _sift_job(plugin: str, rows: int, status: str = "OK") -> ToolJob:
    """A SIFT-shaped job: no local output file, rows only in the result body."""
    body = "\n".join(
        json.dumps({"PID": i, "ImageFileName": f"p{i}.exe"}) for i in range(rows)
    )
    return ToolJob(
        host="sift",
        tool="vol",
        argv=["vol", "-f", "/host/mem.raw", "-r", "jsonl", plugin],
        purpose=f"Volatility3 {plugin}",
        status=status,
        result={"data": body, "audit_id": "a-1"},
    )


def test_a_list_walk_with_no_rows_is_a_warn_and_a_coverage_gap(tmp_path):
    case = _case(tmp_path)
    jobs = [
        _vol_job(tmp_path, "windows.psscan", 134),
        _vol_job(tmp_path, "windows.dlllist", 0),
        _vol_job(tmp_path, "windows.malfind", 0),
        _vol_job(tmp_path, "windows.netscan", 148),
    ]
    ledger = [
        {"tool": "vol", "purpose": j.purpose, "status": "OK", "reason": "(no findings)"}
        for j in jobs
    ]

    warned = reconcile_process_list_coverage(jobs, case, ledger)

    names = sorted(j.purpose for j in warned)
    assert names == ["Volatility3 windows.dlllist", "Volatility3 windows.malfind"]
    for job in warned:
        assert job.status == "WARN"
        assert "psscan saw 134" in job.reason
        assert "no findings" not in job.reason
    # The scan-based plugin is untouched: it found rows.
    assert next(j for j in jobs if "netscan" in j.purpose).status == "OK"

    # The ledger row carries the warning too, not the old wording.
    for row in ledger:
        if row["purpose"] in names:
            assert row["status"] == "WARN"
            assert "coverage gap" in row["reason"]

    events = read_events(case)
    gaps = [e for e in events if e.get("kind") == "coverage_gap"]
    assert len(gaps) == 2, events
    subjects = sorted(str(e.get("subject") or "") for e in gaps)
    assert subjects == ["windows.dlllist", "windows.malfind"]


def test_a_remote_job_is_judged_from_its_result_not_a_local_file(tmp_path):
    """A SIFT job's capture is on the SIFT host, so the local read sees nothing."""
    case = _case(tmp_path)
    failed_walk = _sift_job("windows.malfind", 0, status="FAIL")
    failed_walk.reason = EMPTY_OUTPUT_REASON
    jobs = [
        _sift_job("windows.psscan", 134),
        failed_walk,
        _sift_job("windows.dlllist", 0),
        _sift_job("windows.netscan", 148),
    ]
    ledger = [{"tool": "vol", "purpose": j.purpose, "status": j.status} for j in jobs]

    warned = reconcile_process_list_coverage(jobs, case, ledger)

    assert sorted(j.purpose for j in warned) == [
        "Volatility3 windows.dlllist",
        "Volatility3 windows.malfind",
    ]
    assert all(j.status == "WARN" for j in warned)
    assert all("psscan saw 134" in j.reason for j in warned)
    assert next(j for j in jobs if "netscan" in j.purpose).status == "OK"
    events = [e for e in read_events(case) if e.get("kind") == "coverage_gap"]
    assert len(events) == 2, events


def test_a_remote_job_with_rows_is_left_alone(tmp_path):
    case = _case(tmp_path)
    jobs = [_sift_job("windows.psscan", 134), _sift_job("windows.dlllist", 900)]
    assert reconcile_process_list_coverage(jobs, case, []) == []
    assert all(j.status == "OK" for j in jobs)


def test_a_populated_pack_stays_ok(tmp_path):
    case = _case(tmp_path)
    jobs = [
        _vol_job(tmp_path, "windows.psscan", 134),
        _vol_job(tmp_path, "windows.dlllist", 900),
        _vol_job(tmp_path, "windows.malfind", 3),
    ]
    ledger = [{"tool": "vol", "purpose": j.purpose, "status": "OK"} for j in jobs]

    assert reconcile_process_list_coverage(jobs, case, ledger) == []
    assert all(job.status == "OK" for job in jobs)
    assert read_events(case) == []


def test_no_psscan_rows_means_no_claim(tmp_path):
    """Without psscan there is no population to compare against, so nothing is said."""
    case = _case(tmp_path)
    jobs = [_vol_job(tmp_path, "windows.dlllist", 0)]
    assert reconcile_process_list_coverage(jobs, case, []) == []
    assert jobs[0].status == "OK"
    assert read_events(case) == []


def test_a_failed_job_is_not_softened_to_warn(tmp_path):
    """A FAIL from a tool error stays FAIL; only the empty-output FAIL is reconciled."""
    case = _case(tmp_path)
    failed = _vol_job(tmp_path, "windows.dlllist", 0)
    failed.status = "FAIL"
    failed.reason = "exit_code=-9: killed"
    jobs = [_vol_job(tmp_path, "windows.psscan", 134), failed]
    assert reconcile_process_list_coverage(jobs, case, []) == []
    assert failed.status == "FAIL"


def test_a_truncated_capture_stays_failed(tmp_path):
    """V5's refusal must survive V6: a capped capture is not a coverage gap."""
    case = _case(tmp_path)
    truncated = _sift_job("windows.malfind", 0, status="FAIL")
    truncated.reason = TRUNCATED_REASON
    jobs = [_sift_job("windows.psscan", 134), truncated]
    assert reconcile_process_list_coverage(jobs, case, []) == []
    assert truncated.status == "FAIL"


def test_the_report_coverage_section_carries_the_gap(tmp_path):
    """WO-V6 item 1: the gap is visible in the report's coverage section."""
    from nexus.analysis.coverage_audit import report_section

    case = _case(tmp_path)
    jobs = [_sift_job("windows.psscan", 134), _sift_job("windows.dlllist", 0)]
    reconcile_process_list_coverage(jobs, case, [])

    audit = {
        "tools": {"status": "ok"},
        "sources": {"status": "ok"},
        "needles": {"status": "ok"},
        "overall": "ok",
    }
    section = "\n".join(report_section(audit, case_dir=case))
    assert "Coverage gap" in section
    assert "windows.dlllist" in section
