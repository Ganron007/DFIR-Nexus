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


def _registry_job(label: str, rows: int, status: str = "OK") -> ToolJob:
    """One `windows.registry.printkey --key ...` job, as the pack schedules it.

    The plugin token is identical across the three, which is exactly why a
    plugin-keyed count collapses them (D24/V8). The `purpose` differs.
    """
    body = "\n".join(
        json.dumps({"Key": f"k{i}", "Name": f"v{i}", "Data": "x"}) for i in range(rows)
    )
    return ToolJob(
        host="sift",
        tool="vol",
        argv=[
            "vol", "-f", "/host/mem.raw", "-r", "jsonl",
            "windows.registry.printkey", "--key", rf"Software\...\{label}",
        ],
        purpose=f"Volatility3 registry.printkey {label}",
        status=status,
        result={"data": body, "audit_id": f"a-{label}"},
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


def test_a_remote_job_reports_the_capture_row_count_not_the_slice(tmp_path):
    """The ledger's number is evidence: psscan saw 134, not the slice's 40.

    The first SIFT-aware version counted rows in the 10 KB reply body, so the
    lane wrote "psscan saw 40 process(es)" for a 134-row output. The tool now
    reports the capture's line count and the check prefers it.
    """
    case = _case(tmp_path)
    slice_body = "\n".join(
        json.dumps({"PID": i, "ImageFileName": f"p{i}.exe"}) for i in range(40)
    )
    psscan = _sift_job("windows.psscan", 0)
    psscan.result = {"data": slice_body, "stdout_lines": 134, "audit_id": "a-2"}
    jobs = [psscan, _sift_job("windows.dlllist", 0)]

    warned = reconcile_process_list_coverage(jobs, case, [])

    assert len(warned) == 1
    assert "psscan saw 134" in warned[0].reason, warned[0].reason


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


def test_the_report_coverage_section_renders_without_an_audit(tmp_path):
    """A `--mode tools` run writes no coverage audit, so gaps must still render.

    On the D12 lane run the audit was absent and the coverage section was
    dropped entirely, so the gaps had no line there.
    """
    from nexus.analysis.coverage_audit import report_section

    case = _case(tmp_path)
    jobs = [_sift_job("windows.psscan", 134), _sift_job("windows.dlllist", 0)]
    reconcile_process_list_coverage(jobs, case, [])

    section = "\n".join(report_section({}, case_dir=case))
    assert "Coverage gap" in section
    assert "windows.dlllist" in section
    # With neither an audit nor gaps there is genuinely nothing to show.
    assert report_section({}, case_dir=_case(tmp_path / "other")) == []


def test_the_tool_run_summary_counts_warn():
    """7 OK / 0 FAIL / 0 SKIP out of 15 read as if 8 rows had vanished."""
    from nexus.langgraph.llm_pipeline import _format_tool_run_markdown

    ledger = (
        [{"status": "OK", "host": "sift", "tool": "vol", "purpose": "p", "audit_id": "a"}]
        * 7
        + [{"status": "WARN", "host": "sift", "tool": "vol", "purpose": "w", "audit_id": "b"}]
        * 8
    )
    md = _format_tool_run_markdown({"case_id": "CASE-X", "tool_run_ledger": ledger})
    assert "7 OK" in md
    assert "8 WARN" in md
    assert "(total 15)" in md


def test_the_plugin_list_sits_past_the_reply_slice():
    """`vol -h` lists plugins after ~21 KB, so a slice-only probe sees nothing.

    Measured on the D12 lane run: the first `windows.*` name is at byte 21,411
    of a 26,973-byte banner. The probe therefore has to ask for the whole
    capture (``full_output``); reading the 10 KB slice returned an empty set and
    the "missing plugin is SKIP" behaviour never ran.
    """
    from nexus.langgraph.tool_lane import parse_vol_plugin_names

    banner = ("usage: vol [-h] ...\n" + " " * 21000
              + "\n  windows.info\n  windows.pslist\n  windows.psscan\n")
    assert parse_vol_plugin_names(banner) >= {"windows.info", "windows.pslist",
                                             "windows.psscan"}
    # The slice the reply used to carry: the banner only, no plugin names.
    assert parse_vol_plugin_names(banner[:10240]) == set()


def test_a_plugin_the_host_lacks_becomes_a_skip():
    from nexus.langgraph.tool_lane import mark_missing_vol_plugins

    jobs = [
        _sift_job("windows.pslist", 0, status="PENDING"),
        _sift_job("windows.nosuchplugin", 0, status="PENDING"),
    ]
    mark_missing_vol_plugins(jobs, {"windows.pslist", "windows.psscan"})
    assert jobs[0].status == "PENDING"
    assert jobs[1].status == "SKIP"
    assert "not installed on this SIFT host" in jobs[1].reason

    # An empty probe result changes nothing (a failed probe is not a claim).
    jobs2 = [_sift_job("windows.nosuchplugin", 0, status="PENDING")]
    mark_missing_vol_plugins(jobs2, set())
    assert jobs2[0].status == "PENDING"


def test_the_host_list_is_fully_qualified_and_matching_is_by_prefix():
    """`vol -h` prints windows.pslist.PsList, jobs ask for windows.pslist.

    Exact membership marked every plugin absent and skipped the whole pack —
    a false "not installed" claim for plugins that had just run (D12 run 3).
    """
    from nexus.langgraph.tool_lane import mark_missing_vol_plugins

    listed = {
        "windows.pslist.PsList",
        "windows.psscan.PsScan",
        "windows.registry.printkey.PrintKey",
        "windows.malfind.Malfind",
    }
    jobs = [
        _sift_job("windows.pslist", 0, status="PENDING"),
        _sift_job("windows.psscan", 0, status="PENDING"),
        _sift_job("windows.malfind", 0, status="PENDING"),
        _sift_job("windows.nosuchplugin", 0, status="PENDING"),
    ]
    jobs[2].argv = ["vol", "-f", "m.raw", "-r", "jsonl", "windows.registry.printkey"]
    mark_missing_vol_plugins(jobs, listed)

    assert [j.status for j in jobs] == ["PENDING", "PENDING", "PENDING", "SKIP"]
    assert jobs[3].reason.endswith("is not installed on this SIFT host")


def test_a_warned_remote_job_audit_id_is_still_citable(tmp_path):
    """A WARN row ran on the host; its audit_id must exist in the case log.

    V6 reclassified zero-row list walks from OK to WARN, and the bridge wrote
    only OK rows — so the ledger advertised an audit_id the case log did not
    have and the flow e2e's citation-integrity check refused the finding.
    """
    import json

    from nexus.langgraph.tool_lane import _bridge_remote_audits

    case = _case(tmp_path)
    ledger = [
        {"host": "sift", "tool": "vol", "status": "OK", "audit_id": "a-ok",
         "purpose": "info", "output_saved_to": "/r/ok.txt"},
        {"host": "sift", "tool": "vol", "status": "WARN", "audit_id": "a-warn",
         "purpose": "dlllist", "output_saved_to": "/r/warn.txt"},
        {"host": "sift", "tool": "vol", "status": "FAIL", "audit_id": "a-fail",
         "purpose": "malfind", "output_saved_to": "/r/fail.txt"},
        {"host": "windows", "tool": "pecmd", "status": "OK", "audit_id": "a-win",
         "purpose": "prefetch", "output_saved_to": "C:/x.csv"},
    ]
    assert _bridge_remote_audits(case, ledger) == 2

    written = {
        json.loads(line)["audit_id"]
        for line in (case / "audit" / "nexus.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    }
    assert written == {"a-ok", "a-warn"}
    # Re-bridging must not duplicate a row.
    assert _bridge_remote_audits(case, ledger) == 0


def test_a_registry_read_is_a_gap_only_when_the_list_walk_is_broken(tmp_path):
    """Register D18: an empty key is legitimate; an unreadable hive is not.

    On the A9 image the three printkey jobs were empty with no "key not found"
    message while `psxview`'s pslist column was False for all 130 processes —
    the keys could not be read. Gating on a broken list walk is what separates
    that from a genuinely empty Run key on a healthy image.
    """
    # Broken list walk (dlllist empty) + empty printkey -> both are gaps.
    case = _case(tmp_path)
    printkey = _sift_job("windows.registry.printkey", 0)
    jobs = [_sift_job("windows.psscan", 134), _sift_job("windows.dlllist", 0), printkey]
    warned = reconcile_process_list_coverage(jobs, case, [])
    assert sorted(j.purpose for j in warned) == [
        "Volatility3 windows.dlllist",
        "Volatility3 windows.registry.printkey",
    ]
    assert "registry read" in printkey.reason

    # Healthy list walk + empty printkey -> the key is simply empty. No claim.
    case2 = _case(tmp_path / "healthy")
    printkey2 = _sift_job("windows.registry.printkey", 0)
    jobs2 = [_sift_job("windows.psscan", 134), _sift_job("windows.dlllist", 900), printkey2]
    assert reconcile_process_list_coverage(jobs2, case2, []) == []
    assert printkey2.status == "OK"


def test_the_coverage_gap_event_names_the_run(tmp_path):
    """Register D19: two runs on one case must be distinguishable."""
    case = _case(tmp_path)
    jobs = [_sift_job("windows.psscan", 134), _sift_job("windows.dlllist", 0)]
    reconcile_process_list_coverage(jobs, case, [], run_id="RUN-ABC")

    events = [e for e in read_events(case) if e.get("kind") == "coverage_gap"]
    assert len(events) == 1
    refs = [str(r) for r in (events[0].get("refs") or [])]
    assert "psscan:134" in refs
    assert "run:RUN-ABC" in refs


def test_the_report_lists_each_gap_once_across_runs(tmp_path):
    """Register D19: a case re-processed twice must not list every gap twice."""
    from nexus.analysis.coverage_audit import report_section

    case = _case(tmp_path)
    for run in ("RUN-1", "RUN-2"):
        jobs = [_sift_job("windows.psscan", 134), _sift_job("windows.dlllist", 0)]
        reconcile_process_list_coverage(jobs, case, [], run_id=run)

    recorded = [e for e in read_events(case) if e.get("kind") == "coverage_gap"]
    assert len(recorded) == 2, "the fixture must record the gap twice"

    section = "\n".join(report_section({}, case_dir=case))
    assert section.count("windows.dlllist") == 1, section


def test_the_lane_aligns_the_remote_active_case():
    """run_command persists into the SIFT host's ACTIVE case; the pull reads ours.

    When they disagree every SIFT output is written where the pull never looks
    and the lane still reports OK — a silent loss of the whole pack. The host's
    active case drifted to a test case on 2026-10-02, so this is a real check.
    """
    import asyncio
    import json

    from nexus.langgraph.tool_lane import _align_remote_active_case

    calls: list[dict] = []

    class _Tool:
        async def ainvoke(self, payload):
            calls.append(payload)
            return [{"type": "text", "text": json.dumps(
                {"status": "activated", "case_id": payload.get("case_id")}
            )}]

    status = asyncio.run(_align_remote_active_case(_Tool(), "CASE-X"))
    assert status == "activated"
    assert calls == [{"case_id": "CASE-X"}], calls


def test_a_failed_alignment_never_fails_the_lane():
    """Best-effort: the jobs still run; only the pull is at risk."""
    import asyncio

    from nexus.langgraph.tool_lane import _align_remote_active_case

    class _Boom:
        async def ainvoke(self, _payload):
            raise RuntimeError("no such tool")

    assert asyncio.run(_align_remote_active_case(_Boom(), "CASE-X")) == ""


def test_an_unexpected_alignment_reply_is_reported_not_assumed():
    """No "activated" means the pull is at risk, and the log must say so."""
    import asyncio
    import json

    from nexus.langgraph.tool_lane import _align_remote_active_case

    class _Tool:
        async def ainvoke(self, _payload):
            return [{"type": "text", "text": json.dumps({"status": "error"})}]

    assert asyncio.run(_align_remote_active_case(_Tool(), "CASE-X")) == "error"


def test_registry_keys_are_judged_one_by_one_not_as_one_plugin(tmp_path):
    """D24/V8: the three printkey jobs are separate jobs, not one collapsed key.

    The pack schedules `windows.registry.printkey` three times (Run, RunOnce,
    Services). A plugin-keyed count collapses them to whichever ran last, so an
    empty key could stay OK because a sibling key had rows — and a key that had
    rows could be marked WARN "returned nothing". Counts are per job now.
    """
    case = _case(tmp_path)
    run = _registry_job("Run", rows=0)
    runonce = _registry_job("RunOnce", rows=0)
    services = _registry_job("Services", rows=7)
    jobs = [
        _sift_job("windows.psscan", 134),
        _sift_job("windows.dlllist", 0),  # the list walk is broken
        run,
        runonce,
        services,
    ]

    warned = reconcile_process_list_coverage(jobs, case, [])

    assert run.status == "WARN", "an empty key must not ride on a sibling's rows"
    assert runonce.status == "WARN"
    assert services.status == "OK", "a key WITH rows must not be warned"
    assert services not in warned
    # And the warning is the registry reason, not invented fabrication.
    assert "registry read" in run.reason


def test_the_registry_verdict_mirrors_when_the_rows_move(tmp_path):
    """Swapping which key has rows gives the mirror result."""
    case = _case(tmp_path)
    run = _registry_job("Run", rows=5)
    runonce = _registry_job("RunOnce", rows=0)
    jobs = [
        _sift_job("windows.psscan", 134),
        _sift_job("windows.dlllist", 0),
        run,
        runonce,
    ]

    reconcile_process_list_coverage(jobs, case, [])

    assert run.status == "OK"
    assert runonce.status == "WARN"


def test_a_duplicate_plugin_process_list_job_is_judged_on_its_own_rows(tmp_path):
    """The same holds for any plugin scheduled twice (e.g. `handles --pid`)."""
    case = _case(tmp_path)
    first = _sift_job("windows.handles", 42)
    second = _sift_job("windows.handles", 0)
    jobs = [_sift_job("windows.psscan", 134), first, second]

    warned = reconcile_process_list_coverage(jobs, case, [])

    assert first.status == "OK", "a populated job must not inherit an empty sibling"
    assert second.status == "WARN"
    assert warned == [second]


def test_the_alignment_is_handed_case_activate_not_run_command():
    """The first version passed `run_command`, so it activated nothing.

    `_align_remote_active_case(run_command, case_id)` sends
    `run_command(case_id=…)` — a request with no `command` argument — so the
    call cannot activate a case and the helper only logs a warning. The jobs
    then persist nowhere unless something else set the host's active case, which
    is why a fresh `sift setup` + staged evidence produced 15/15 FAIL
    "produced no output file" (found 2026-10-03).

    Pinned by source, because the defect is the *argument*, not the helper's
    logic — the helper's own tests stub the tool and pass either way.
    """
    import inspect

    from nexus.langgraph import tool_lane

    src = inspect.getsource(tool_lane.run_tool_lane)
    assert 'tools.get("_sift_case_activate")' in src, (
        "the lane must hand the alignment the SIFT host's `_sift_case_activate`; passing run_command "
        "silently activates nothing"
    )
    assert 'tools.get("case_activate")' not in src, (
        "the plain name is the examiner host's tool after the Windows-wins merge; using it writes this "
        "machine's global active-case pointer"
    )
    assert "_align_remote_active_case(sift_tool" not in src, (
        "`sift_tool` is run_command — passing it here is the bug this pins"
    )


def test_the_alignment_without_the_tool_warns_and_returns_empty():
    """A host that does not expose case_activate must not crash the lane."""
    import asyncio

    from nexus.langgraph.tool_lane import _align_remote_active_case

    assert asyncio.run(_align_remote_active_case(None, "CASE-X")) == ""


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
