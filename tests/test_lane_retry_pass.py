"""`nexus lane retry` completes the run: with no FAIL row the pass still runs, and nothing that passed is re-run.

Before this, a retry with no FAIL row stopped at "nothing to retry", so a job waiting on the SIFT host (a SKIP row
that the plan turns PENDING once the host answers) never reached the pipeline. Only the pass itself is stubbed
here; the retry command, its selection and its arguments are the real ones.
"""

from __future__ import annotations

import pytest
import typer

from nexus.cli import lane_retry_cmd
from nexus.langgraph import lane_gate


@pytest.fixture()
def passes(tmp_path, monkeypatch):
    run_dir = tmp_path / "runs" / "RUN-T"
    run_dir.mkdir(parents=True)
    calls: list[tuple] = []

    async def fake_run_retry(case_dir, run_id, evidence_paths, rerun_tools=frozenset(), only_tools=frozenset()):
        calls.append((run_id, frozenset(rerun_tools), frozenset(only_tools)))
        return {"tool_run_ledger": [{"tool": "vol", "status": "OK"}]}

    ledger = [
        {"tool": "vol", "status": "SKIP", "purpose": "vol pslist"},  # waiting on the SIFT host
        {"tool": "sbecmd", "status": "OK", "purpose": "Shellbags UsrClass.dat (wacsvc)"},
    ]
    monkeypatch.setattr(lane_retry_cmd, "_resolve", lambda case: tmp_path)
    monkeypatch.setattr(lane_retry_cmd, "_load_ledger", lambda case_dir: (ledger, run_dir))
    monkeypatch.setattr(lane_retry_cmd, "_run_evidence_paths", lambda run: ["H:\\"])
    monkeypatch.setattr(lane_retry_cmd, "_run_retry", fake_run_retry)
    monkeypatch.setattr(lane_retry_cmd, "_index_retried_output", lambda case_dir: None)
    monkeypatch.setattr(lane_gate, "write_lane_gate", lambda *args, **kwargs: {"status": "clear"})
    return calls


def test_a_retry_with_no_fail_row_still_runs_the_pass(passes):
    lane_retry_cmd.retry(case="CASE-X", tool="", dry_run=False)
    assert len(passes) == 1
    _run_id, rerun, only = passes[0]
    assert rerun == frozenset() and only == frozenset()  # nothing is forced: the pass carries what passed


def test_a_dry_run_plans_nothing(passes):
    lane_retry_cmd.retry(case="CASE-X", tool="", dry_run=True)
    assert passes == []


def test_a_tool_retry_runs_only_that_tool(passes, monkeypatch, tmp_path):
    run_dir = tmp_path / "runs" / "RUN-T"
    ledger = [
        {"tool": "vol", "status": "OK", "purpose": "vol pslist"},
        {"tool": "sbecmd", "status": "OK", "purpose": "Shellbags UsrClass.dat (wacsvc)"},
    ]
    monkeypatch.setattr(lane_retry_cmd, "_load_ledger", lambda case_dir: (ledger, run_dir))
    lane_retry_cmd.retry(case="CASE-X", tool="vol", dry_run=False)
    _run_id, rerun, only = passes[0]
    assert rerun == frozenset({"vol"}) and only == frozenset({"vol"})


def test_a_tool_with_only_skip_rows_is_not_re_run_by_name(passes):
    # The contract of test_lane_retry_tool: a SKIP row is not a re-run by name. The plain retry picks the job up.
    with pytest.raises(typer.Exit):
        lane_retry_cmd.retry(case="CASE-X", tool="vol", dry_run=False)
    assert passes == []
