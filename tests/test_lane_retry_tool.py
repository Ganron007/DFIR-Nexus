"""``nexus lane retry --tool`` re-runs one tool's jobs in the same run (operator decision, 2026-10-11).

A parser fix for one tool must not need a new run. The named tool's jobs run again inside the same
run, the OK rows of every other tool are reused, and only the changed files are indexed afterwards.
No lane is started here: the planner's reuse rule and the command's selection are what is tested.
"""

from __future__ import annotations

import json

import pytest
import typer
from typer.testing import CliRunner


def _job(tool: str, purpose: str):
    from nexus.langgraph.tool_lane import ToolJob

    return ToolJob(host="windows", tool=tool, argv=[tool, "-f", "x"], purpose=purpose)


def _ok_row(tool: str, purpose: str, sha: str = "sha-1") -> dict:
    return {
        "status": "OK", "host": "windows", "tool": tool, "purpose": purpose,
        "evidence_sha": sha, "lineage": {"version": "1.0"}, "audit_id": f"audit-{tool}",
        "output_saved_to": "", "output_files": [],
    }


@pytest.fixture()
def reuse_env(tmp_path, monkeypatch):
    from nexus.langgraph import tool_lane

    monkeypatch.delenv("NEXUS_TOOL_LANE_RERUN", raising=False)
    monkeypatch.setattr(tool_lane, "_registered_evidence_hashes", lambda case_dir: {})
    monkeypatch.setattr(tool_lane, "_evidence_sha_for", lambda job, hashes: "sha-1")
    extractions = tmp_path / "extractions"
    extractions.mkdir()
    (extractions / "_tool_lane_ledger.json").write_text(json.dumps([
        _ok_row("hayabusa", "EVTX timeline"),
        _ok_row("evtxecmd", "EVTX parse"),
    ]), encoding="utf-8")
    return tool_lane, tmp_path, extractions


def test_a_named_tool_is_not_reused_and_the_other_ok_rows_are(reuse_env):
    tool_lane, case_dir, extractions = reuse_env
    jobs = [_job("hayabusa", "EVTX timeline"), _job("evtxecmd", "EVTX parse")]
    reused = tool_lane.apply_prior_ok(
        jobs, case_dir, extractions=extractions, rerun_tools=frozenset({"hayabusa"}),
    )
    assert reused == 1
    assert {j.tool: j.status for j in jobs} == {"hayabusa": "PENDING", "evtxecmd": "OK"}


def test_without_a_named_tool_every_ok_row_is_reused(reuse_env):
    tool_lane, case_dir, extractions = reuse_env
    jobs = [_job("hayabusa", "EVTX timeline"), _job("evtxecmd", "EVTX parse")]
    assert tool_lane.apply_prior_ok(jobs, case_dir, extractions=extractions) == 2
    assert {j.status for j in jobs} == {"OK"}


@pytest.fixture()
def retry_case(tmp_path, monkeypatch):
    from nexus.config import settings
    from nexus.langgraph import pipeline_runs

    monkeypatch.setattr(settings, "cases_root", tmp_path)
    case_dir = tmp_path / "CASE-RETRY-0001"
    run = pipeline_runs.create_run(case_dir, "tools", run_id="RUN-RETRY-1")
    extractions = run.extractions
    manifest = pipeline_runs.load_manifest(run.path)
    manifest["status"] = "interrupted"
    (run.path / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    rows = [
        _ok_row("hayabusa", "EVTX timeline"),
        {**_ok_row("hayabusa", "EVTX timeline (second)"), "status": "SKIP", "reason": "examiner"},
        {**_ok_row("evtxecmd", "EVTX parse"), "status": "FAIL", "reason": "boom"},
    ]
    (extractions / "_tool_lane_ledger.json").write_text(json.dumps(rows), encoding="utf-8")
    monkeypatch.setattr(
        pipeline_runs, "resolve_tools_extractions", lambda case_dir, run_id="": extractions,
    )
    return case_dir


def _retry_app():
    from nexus.cli.lane_retry_cmd import retry

    app = typer.Typer()
    app.command()(retry)
    return app


def test_the_tool_flag_lists_only_that_tools_runnable_rows(retry_case):
    result = CliRunner().invoke(
        _retry_app(), ["--case", "CASE-RETRY-0001", "--tool", "hayabusa", "--dry-run"],
    )
    assert result.exit_code == 0, result.output
    assert "1 job(s) to re-run in RUN-RETRY-1:" in result.output  # the SKIP row is not a re-run
    assert "hayabusa" in result.output
    assert "evtxecmd" not in result.output  # the FAIL row of another tool is not selected
    assert "Dry run - nothing executed." in result.output


def test_an_unknown_tool_is_refused(retry_case):
    result = CliRunner().invoke(
        _retry_app(), ["--case", "CASE-RETRY-0001", "--tool", "nosuchtool", "--dry-run"],
    )
    assert result.exit_code == 1
    assert "No rows for nosuchtool in the lane ledger" in result.output
