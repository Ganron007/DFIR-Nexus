"""A BLOCKED job is never run (operator decision 2026-10-11: sidr is blocked on a dirty Windows.edb).

Real path: a full ``run_tool_lane`` pass over a Windows root whose Windows.edb is a dirty database. The
lane used to hand BLOCKED jobs to the executor, which refused their empty command, so sidr was recorded
as a FAIL and the gate counted a failure instead of a block. Found on the fresh lane run of
CASE-C5B04D31 (run RUN-20261011T084105445874Z-tools-b4c9add7).
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest


@pytest.fixture()
def case_dir(tmp_path, monkeypatch) -> Path:
    from nexus.case.manager import CaseManager
    from nexus.case.schemas import FindingSeverity
    from nexus.config import settings

    monkeypatch.setattr(settings, "cases_root", tmp_path)
    monkeypatch.setenv("NEXUS_EXAMINER", "blocked_test")
    root = tmp_path / "CASE-BLOCKED-0001"
    root.mkdir()
    mgr = CaseManager(settings.cases_root / "cases.db")
    mgr.create_case(
        name="Blocked Job Fixture", description="blocked jobs are never run",
        severity=FindingSeverity.LOW, created_by="blocked_test",
        metadata={"synthetic": True}, case_id=root.name,
    )
    mgr.close()
    return root


def test_a_blocked_sidr_job_is_recorded_blocked_and_never_reaches_the_executor(case_dir, monkeypatch):
    from nexus.case.evidence_service import register_evidence
    from nexus.langgraph import case_index
    from nexus.langgraph.tool_lane import run_tool_lane

    # Nothing is indexed here: the fixture is not an ES case, and this test is about the job runner.
    monkeypatch.setattr(case_index, "es_available", lambda: False)

    volume = case_dir / "evidence" / "C"
    (volume / "Windows" / "System32").mkdir(parents=True)
    search = volume / "ProgramData" / "Microsoft" / "Search" / "Data" / "Applications" / "Windows"
    search.mkdir(parents=True)
    (search / "Windows.edb").write_bytes(b"ese" * 200)
    register_evidence(case_dir, str(volume), description="blocked-job fixture", examiner="blocked_test")

    run_id = "R-20261011-000000-blocked"
    run_dir = case_dir / "runs" / run_id
    run_dir.mkdir(parents=True)
    (run_dir / "manifest.json").write_text(json.dumps({
        "run_id": run_id, "mode": "tools", "case_id": case_dir.name, "status": "running",
    }), encoding="utf-8")

    calls: list[tuple[str, object]] = []

    class RecordingTool:
        def __init__(self, name: str):
            self.name = name

        async def ainvoke(self, args):
            calls.append((self.name, args))
            return json.dumps({"success": True, "output": ""})

    async def run() -> dict:
        return await run_tool_lane(
            tools={
                "run_windows_command": RecordingTool("run_windows_command"),
                "run_command": RecordingTool("run_command"),
            },
            evidence_path=str(volume),
            case_id=case_dir.name,
            run_id=run_id,
            parse_result=json.loads,
            pipeline_mode="tools",
        )

    lane = asyncio.run(run())
    ledger = lane.get("tool_run_ledger") if isinstance(lane, dict) else lane
    sidr_rows = [r for r in ledger if isinstance(r, dict) and r.get("tool") == "sidr"]

    assert sidr_rows, f"the planner did not record sidr at all: {ledger}"
    assert all(r.get("status") == "BLOCKED" for r in sidr_rows), sidr_rows
    assert "clean shutdown" in str(sidr_rows[0].get("reason") or "")
    assert not any("sidr" in json.dumps(args, default=str) for _name, args in calls), (
        "a blocked job must never reach the executor")


def test_required_query_pack_failure_is_returned_as_lane_error(case_dir, monkeypatch):
    from nexus.langgraph import snippets
    from nexus.langgraph.pipeline_runs import create_run
    from nexus.langgraph.tool_lane import run_tool_lane

    run = create_run(case_dir, "tools")

    def fail_snippets(*_args, **_kwargs):
        raise OSError("timeline output unavailable")

    monkeypatch.setattr(snippets, "write_snippets", fail_snippets)

    lane = asyncio.run(run_tool_lane(
        tools={},
        evidence_path="",
        case_id=case_dir.name,
        run_id=run.run_id,
        parse_result=json.loads,
        pipeline_mode="tools",
        strict=False,
    ))

    assert "N4 query-pack/timeline generation failed: timeline output unavailable" in lane["error"]
    assert any(
        "N4 query-pack/timeline generation failed" in step
        for step in lane["step_log"]
    )


def test_pipeline_query_pack_includes_rows_from_its_i1_import(case_dir, tmp_path, monkeypatch):
    from nexus.langgraph import snippets, tool_lane
    from nexus.langgraph.lane_gate import write_lane_gate
    from nexus.langgraph.llm_pipeline import execute_tool_lane
    from nexus.langgraph.pipeline_runs import create_run

    evidence = tmp_path / "evidence" / "bind.log"
    evidence.parent.mkdir(parents=True)
    evidence.write_text(
        "12-Jul-2016 09:49:46.413 client 10.10.10.44#61936 "
        "(isatap.pwnd.biz): query: isatap.pwnd.biz IN A + (10.10.10.5)\n",
        encoding="utf-8",
    )
    (case_dir / "CASE.yaml").write_text(
        "intake:\n  query_extra: isatap.pwnd.biz\n",
        encoding="utf-8",
    )
    run = create_run(case_dir, "tools", [str(evidence)])
    write_lane_gate(case_dir, run.run_id, [{
        "tool": "(discovery)",
        "purpose": "locate evidence",
        "status": "SKIP",
        "reason": "No recognized Windows image shape",
    }])

    async def fake_run_tool_lane(**kwargs):
        assert kwargs["defer_analysis"] is True
        return {
            "tool_run_ledger": [],
            "evidence_audit_ids": [],
            "rag_notes": [],
            "step_log": ["tool lane complete"],
        }

    monkeypatch.setattr(tool_lane, "run_tool_lane", fake_run_tool_lane)
    real_write_snippets = snippets.write_snippets
    writer_calls: list[Path] = []

    def write_after_import(case, ledger, **kwargs):
        artifact_store = case / "ingest" / "artifacts.jsonl"
        assert artifact_store.is_file()
        assert "isatap.pwnd.biz" in artifact_store.read_text(encoding="utf-8")
        writer_calls.append(Path(kwargs["run_dir"]))
        return real_write_snippets(case, ledger, **kwargs)

    monkeypatch.setattr(snippets, "write_snippets", write_after_import)
    result = asyncio.run(execute_tool_lane({
        "case_id": case_dir.name,
        "run_id": run.run_id,
        "pipeline_mode": "tools",
        "evidence_path": str(evidence),
        "evidence_paths": [str(evidence)],
        "case_context": {"query_extra": "isatap.pwnd.biz"},
    }, {}))

    pack = run.path / "analysis" / "query_pack.md"
    assert writer_calls == [run.path]
    assert pack.is_file()
    packed = pack.read_text(encoding="utf-8")
    assert "isatap.pwnd.biz" in packed
    assert "ingest/artifacts.jsonl" in packed
    assert any("generated after I1" in step for step in result["step_log"])
    assert "error" not in result


def test_pipeline_query_pack_failure_is_returned_as_lane_error(case_dir, monkeypatch):
    from nexus.langgraph import snippets, tool_lane
    from nexus.langgraph.llm_pipeline import execute_tool_lane
    from nexus.langgraph.pipeline_runs import create_run

    run = create_run(case_dir, "tools")

    async def fake_run_tool_lane(**kwargs):
        assert kwargs["defer_analysis"] is True
        return {
            "tool_run_ledger": [],
            "evidence_audit_ids": [],
            "rag_notes": [],
            "step_log": ["tool lane complete"],
        }

    def fail_snippets(*_args, **_kwargs):
        raise OSError("post-I1 query-pack output unavailable")

    monkeypatch.setattr(tool_lane, "run_tool_lane", fake_run_tool_lane)
    monkeypatch.setattr(snippets, "write_snippets", fail_snippets)
    result = asyncio.run(execute_tool_lane({
        "case_id": case_dir.name,
        "run_id": run.run_id,
        "pipeline_mode": "tools",
        "evidence_paths": [],
        "case_context": {},
    }, {}))

    assert result["error"] == (
        "N4 query-pack/timeline generation failed: post-I1 query-pack output unavailable"
    )
    assert any(
        "N4 query-pack/timeline generation failed" in step
        for step in result["step_log"]
    )
