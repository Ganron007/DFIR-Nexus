"""A retry reuses the OK rows of jobs that run on staged copies (2026-10-11).

On CASE-C5B04D31 the retry re-ran the five sbecmd jobs, sidr and bmc-tools on both passes, and the
bitsparser job, although each had an OK row with a lineage version. These jobs run on a staged copy, so
their argv names the staging folder and not the registered evidence: no registered path matched, the
evidence sha stayed empty, and the reuse key could not match. Each re-run wrote a second output set, and
the index held 3,045 duplicate documents. A staged job now names the registered source it was copied
from, and that source keys the reuse.
"""

from __future__ import annotations

import json

from nexus.langgraph import tool_lane

DRIVE_SHA = "a5e4afda7533"  # the registered H:\ tree the CASE-C5B04D31 evidence was read from


def _staged_sbecmd(extractions, source):
    return tool_lane.ToolJob(
        host="windows", tool="sbecmd",
        argv=["sbecmd", "-d", str(extractions / "sbecmd" / "stage-wacsvc"), "--csv", str(extractions / "sbecmd")],
        purpose="Shellbags UsrClass.dat (wacsvc)", source=source,
    )


def test_a_staged_job_is_keyed_on_the_registered_tree_its_source_is_in(tmp_path):
    job = _staged_sbecmd(tmp_path, r"H:\C\Users\wacsvc\AppData\Local\Microsoft\Windows\UsrClass.dat")
    assert tool_lane._evidence_sha_for(job, [("H:\\", DRIVE_SHA)]) == DRIVE_SHA


def test_a_job_without_a_source_still_keys_on_the_registered_path_in_its_argv(tmp_path):
    job = tool_lane.ToolJob(
        host="windows", tool="srumecmd",
        argv=["srumecmd", "-f", str(tmp_path / "workdir" / "SRUDB.dat"), "-r", r"H:\C\Windows\System32\config\SOFTWARE"],
        purpose="SRUM database (staged copy, logs replayed)",
    )
    assert tool_lane._evidence_sha_for(job, [("H:\\", DRIVE_SHA)]) == DRIVE_SHA


def test_a_retry_reuses_the_ok_row_of_a_staged_job(tmp_path):
    case_dir = tmp_path / "CASE-STAGED-0001"
    extractions = case_dir / "runs" / "RUN-1" / "extractions"
    extractions.mkdir(parents=True)
    (case_dir / "evidence.json").write_text(
        json.dumps({"evidence": [{"path": "H:\\", "sha256": DRIVE_SHA}]}), encoding="utf-8")
    source = r"H:\C\Users\wacsvc\AppData\Local\Microsoft\Windows\UsrClass.dat"

    first = _staged_sbecmd(extractions, source)
    assert tool_lane.apply_prior_ok([first], case_dir, extractions=extractions) == 0  # nothing to reuse yet
    (extractions / "_tool_lane_ledger.json").write_text(json.dumps([{
        "host": "windows", "tool": "sbecmd", "purpose": first.purpose, "status": "OK",
        "evidence_sha": first.evidence_sha, "lineage": {"version": "2026.5.0.0"}, "audit_id": "A1",
    }]), encoding="utf-8")

    second = _staged_sbecmd(extractions, source)  # the retry plans the same job again
    assert tool_lane.apply_prior_ok([second], case_dir, extractions=extractions) == 1
    assert second.status == "OK" and second.reason.startswith("reused prior OK")


def test_the_planner_names_the_registered_source_of_the_srum_and_search_copies(tmp_path, monkeypatch):
    root = tmp_path / "C"
    sru = root / "Windows" / "System32" / "sru"
    sru.mkdir(parents=True)
    (root / "Windows" / "System32" / "config").mkdir(parents=True)
    (sru / "SRUDB.dat").write_bytes(b"srum database")
    search = root / "ProgramData" / "Microsoft" / "Search" / "Data" / "Applications" / "Windows"
    search.mkdir(parents=True)
    (search / "Windows.edb").write_bytes(b"ese" * 100)
    monkeypatch.setattr(tool_lane, "_esentutl_replay", lambda work, *, log_bases: None)
    monkeypatch.setattr(tool_lane, "_ese_state", lambda database: "Clean Shutdown")
    monkeypatch.setattr(tool_lane, "_windows_tool_available", lambda key: True)

    jobs = tool_lane.plan_windows_triage(str(root), tmp_path / "extractions")
    by_tool = {job.tool: job for job in jobs if job.tool in ("srumecmd", "sidr")}
    assert by_tool["srumecmd"].source == str(sru / "SRUDB.dat")
    assert by_tool["sidr"].source == str(search / "Windows.edb")
