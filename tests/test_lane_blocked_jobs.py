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
    assert "dirty-shutdown" in str(sidr_rows[0].get("reason") or "")
    assert not any("sidr" in json.dumps(args, default=str) for _name, args in calls), (
        "a blocked job must never reach the executor")
