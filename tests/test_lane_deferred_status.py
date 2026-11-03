"""Deferred importer work is pending; actual failed work still needs action."""
import asyncio
import json

import pytest

from nexus.config import settings
from nexus.langgraph.tool_lane import ToolJob, run_tool_lane


@pytest.mark.parametrize("deferred, job_status", [(True, "SKIP"), (False, "SKIP"), (True, "BLOCKED")])
def test_actual_lane_distinguishes_pending_importer_from_examiner_action(monkeypatch, deferred, job_status):
    from nexus.analysis import freshness
    from nexus.langgraph import case_index, snippets, tool_lane
    from nexus.langgraph.pipeline_runs import create_run

    case = settings.cases_root / "CASE-DEFERRED-STATUS"
    case.mkdir(parents=True)
    # Metadata-only case/ledger control: no authored forensic event or evidence.
    (case / "evidence.json").write_text(json.dumps({"evidence": [{"path": str(case)}]}), encoding="utf-8")
    run = create_run(case, "tools")
    monkeypatch.setattr(tool_lane, "plan_windows_triage", lambda *a, **k: [
        ToolJob(host="windows", tool="discovery", argv=[], purpose="status control",
                status=job_status, reason="status control"),
    ])
    monkeypatch.setattr(tool_lane, "sift_jobs_for_lane", lambda *a, **k: [])
    monkeypatch.setattr(tool_lane, "_artifact_completeness_for_paths", lambda *a, **k: [])
    monkeypatch.setattr(freshness, "capture_freshness", lambda *a, **k: {"items": [], "result": "unknown"})
    monkeypatch.setattr(case_index, "es_available", lambda: False)
    monkeypatch.setattr(snippets, "write_snippets", lambda *a, **k: {})
    from nexus.langgraph.llm_pipeline import emit_stage

    progress = case / "progress.jsonl"

    def receive(status, detail, extra):
        emit_stage({"progress_path": str(progress)}, "tool", status, detail, **extra)

    result = asyncio.run(run_tool_lane(
        tools={}, evidence_path=str(case), case_id=case.name, run_id=run.run_id,
        parse_result=json.loads, pipeline_mode="tools", strict=False, defer_analysis=deferred,
        on_event=receive,
    ))
    gate = json.loads((case / "analysis/lane_gate.json").read_text(encoding="utf-8"))
    message = " ".join(result["step_log"])
    assert gate["status"] == "blocked"
    assert gate["no_evidence_processed"] is True
    if deferred and job_status == "SKIP":
        assert gate["blocked_count"] == 0
        assert "awaiting evidence import" in message
        assert "examiner re-runs or skips" not in message
        events = [json.loads(line) for line in progress.read_text(encoding="utf-8").splitlines()]
        pending = [event for event in events if event["status"] == "PENDING"]
        assert len(pending) == 1, "Pending status must reach the actual pipeline progress publisher"
        assert "tool" not in pending[0], "A phase notification must not invent a tool job"
        assert pending[0]["detail"] == "awaiting evidence import; no evidence processed yet"
    else:
        assert "EVIDENCE GATE BLOCKED" in message
        assert "awaiting evidence import" not in message
        assert all(json.loads(line)["status"] != "PENDING"
                   for line in progress.read_text(encoding="utf-8").splitlines())
        if job_status == "BLOCKED":
            assert gate["blocked_count"] == 1
            assert "examiner re-runs or skips" in message
