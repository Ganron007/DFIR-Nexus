"""Live feed — granular tool events, re-attach, short-run-id resolution.

The feed used to die at the stage level: the tool lane's per-tool entries
(command/status/output) were dropped because ``api_pipeline_status`` resolved
the run dir with the SHORT run id while ``resolve_run`` requires the full
``RUN-…`` name; the run id also lived only in React state, so a reload lost
the live view entirely.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from starlette.requests import Request


def _make_request(query: str = "") -> Request:
    return Request({
        "type": "http",
        "method": "GET",
        "path": "/portal/api/pipeline/status",
        "headers": [],
        "query_string": query.encode(),
    })


def _case() -> Path:
    from nexus.config import settings

    case = settings.cases_root / "CASE-LIVE"
    (case / "analysis" / "pipeline_runs").mkdir(parents=True)
    run_dir = case / "runs" / "RUN-20260923T000000000000Z-coverage-abc12345"
    (run_dir / "extractions").mkdir(parents=True)
    (run_dir / "manifest.json").write_text(
        json.dumps({
            "run_id": run_dir.name, "case_id": case.name, "mode": "coverage",
            "status": "running", "created_at": "2026-09-23T00:00:00+00:00",
        }),
        encoding="utf-8",
    )
    (case / "analysis" / "pipeline_runs" / "abc12345.json").write_text(
        json.dumps({
            "run_id": "abc12345", "case_id": case.name, "mode": "coverage",
            "status": "running", "started_at": "2026-09-23T00:00:00+00:00",
            "completed_at": "", "error": "", "stages": [],
        }),
        encoding="utf-8",
    )
    (case / "analysis" / "pipeline_runs" / "abc12345.progress.jsonl").write_text(
        json.dumps({
            "ts": "2026-09-23T00:00:01+00:00", "stage": "pipeline",
            "status": "running", "detail": "mode=coverage",
        }) + "\n",
        encoding="utf-8",
    )
    (run_dir / "extractions" / "_tool_lane_progress.json").write_text(
        json.dumps({
            "done": 1,
            "total": 2,
            "current": "chainsaw",
            "running": {
                "tool": "hayabusa", "host": "windows",
                "purpose": "EVTX timeline",
                "command": "hayabusa.exe -d C:\\evidence -o out.csv",
            },
            "entries": [
                {
                    "tool": "evtxecmd", "host": "windows", "status": "OK",
                    "purpose": "parse evtx",
                    "command": "EvtxECmd.exe -f Security.evtx --csv out",
                    "duration_s": 4.2,
                    "output": ".../EvtxECmd_Output.csv",
                    "reason": "",
                },
            ],
        }),
        encoding="utf-8",
    )
    return case


def test_emit_stage_carries_tool_extras(tmp_path):
    from nexus.langgraph.llm_pipeline import emit_stage

    progress = tmp_path / "p.progress.jsonl"
    emit_stage(
        {"progress_path": str(progress)}, "tool", "OK", "4.2s",
        tool="evtxecmd", command="EvtxECmd.exe -f x", duration_s=4.2,
        ignored="drop me",
    )
    entry = json.loads(progress.read_text(encoding="utf-8").splitlines()[0])
    assert entry["stage"] == "tool" and entry["status"] == "OK"
    assert entry["tool"] == "evtxecmd"
    assert entry["command"].startswith("EvtxECmd")
    assert entry["duration_s"] == 4.2
    assert "ignored" not in entry  # allowlisted extras only


def test_latest_pipeline_run_prefers_running():
    from nexus.dashboard.app import _latest_pipeline_run_id

    case = _case()
    (case / "analysis" / "pipeline_runs" / "zzz99999.json").write_text(
        json.dumps({"run_id": "zzz99999", "status": "complete"}),
        encoding="utf-8",
    )
    # A still-running record wins even when a complete one is newer on disk.
    assert _latest_pipeline_run_id(case) == "abc12345"


def test_status_reattaches_and_feeds_tool_granularity():
    from nexus.dashboard.app import _pipeline_runs, api_pipeline_status

    _pipeline_runs.clear()
    case = _case()
    # A run started by THIS server lives in memory — that is what re-attach
    # reads while it is still working.
    record = json.loads(
        (case / "analysis" / "pipeline_runs" / "abc12345.json").read_text(encoding="utf-8")
    )
    _pipeline_runs["abc12345"] = record
    req = _make_request(f"case_id={case.name}")
    resp = asyncio.run(api_pipeline_status(req))
    data = json.loads(resp.body)

    # Re-attach without a run_id: newest running record for the case.
    assert data["run_id"] == "abc12345"
    # Live "running" block carries the exact tool + command.
    assert data["progress"]["running"]["tool"] == "hayabusa"
    assert data["progress"]["running"]["command"].startswith("hayabusa.exe")
    assert data["progress"]["done"] == 1 and data["progress"]["total"] == 2
    # Per-tool entries reach the feed with command + duration + output,
    # resolved through the short id (RUN-…-abc12345).
    tools = [s for s in data["stages"] if s.get("tool")]
    assert tools, data["stages"]
    assert tools[0]["command"].startswith("EvtxECmd")
    assert tools[0]["duration_s"] == 4.2
    assert tools[0]["output"].endswith("EvtxECmd_Output.csv")
    # Pipeline stage lines still ride along in order.
    assert any(s.get("stage") == "pipeline" for s in data["stages"])
