"""D323: the evidence gate must consume the ledger-reconciled completeness table."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

from nexus.config import settings
from nexus.langgraph.tool_lane import ToolJob, run_tool_lane


def test_lane_gate_uses_final_policy_skip_completeness(tmp_path: Path, monkeypatch):
    from nexus.analysis import freshness
    from nexus.langgraph import case_index, tool_lane

    case_id = "CASE-D323"
    case_dir = settings.cases_root / case_id
    run_id = "RUN-20261022T000000Z-tools-d323"
    run_dir = case_dir / "runs" / run_id
    extractions = run_dir / "extractions"
    extractions.mkdir(parents=True)
    (run_dir / "manifest.json").write_text(json.dumps({
        "run_id": run_id,
        "case_id": case_id,
        "mode": "tools",
        "status": "running",
        "previous_active_run_id": "",
    }), encoding="utf-8")

    volume = case_dir / "evidence" / "C"
    (volume / "Windows" / "System32").mkdir(parents=True)
    (volume / "$LogFile").write_bytes(b"RSTR" + b"\0" * 8188)
    # The lane plans on registered evidence only, and the case-pipeline guard reads the registry (D383), so the
    # fixture registers its volume as every real case does (it used to register nothing).
    (case_dir / "evidence.json").write_text(json.dumps({"evidence": [{"path": str(volume)}]}), encoding="utf-8")

    initial = [{
        "artifact": "NTFS $LogFile",
        "status": "PRESENT_NO_PARSER",
        "tools": "LogFileParser",
        "hits": "1",
        "reason": "1 hit(s)",
    }]
    reconciled = [{
        **initial[0],
        "status": "NOT_APPLICABLE",
        "reason": (
            "optional by operator policy; LogFileParser is excluded from the default lane "
            "and may be run manually by the examiner when needed"
        ),
    }]

    def completeness(_paths, _scheduled_tools, ledger=None):
        return initial if ledger is None else reconciled

    monkeypatch.setattr(tool_lane, "_artifact_completeness_for_paths", completeness)
    monkeypatch.setattr(
        tool_lane,
        "plan_windows_triage",
        lambda *_args, **_kwargs: [
            ToolJob(
                host="windows", tool="pecmd", argv=[], purpose="processed control", status="OK",
            ),
            ToolJob(
                host="windows", tool="logfileparser",
                argv=["logfileparser", f"/LogFileFile:{volume / '$LogFile'}"],
                purpose="NTFS $LogFile",
            ),
        ],
    )
    monkeypatch.setattr(
        freshness, "capture_freshness",
        lambda *_args, **_kwargs: {"items": [], "result": "unknown"},
    )
    monkeypatch.setattr(case_index, "es_available", lambda: False)
    monkeypatch.setattr(tool_lane, "sift_jobs_for_lane", lambda *_args, **_kwargs: [])

    asyncio.run(run_tool_lane(
        tools={},
        evidence_path=str(volume),
        evidence_paths=[str(volume)],
        case_id=case_id,
        run_id=run_id,
        parse_result=json.loads,
        pipeline_mode="tools",
        strict=False,
    ))

    table = json.loads((extractions / "_artifact_completeness.json").read_text(encoding="utf-8"))
    gate = json.loads((case_dir / "analysis" / "lane_gate.json").read_text(encoding="utf-8"))
    row = next(row for row in table if row["artifact"] == "NTFS $LogFile")
    assert row["status"] == "NOT_APPLICABLE"
    assert gate["run_id"] == run_id
    assert gate["status"] == "clear"
    assert not any("NTFS $LogFile" in str(item.get("purpose")) for item in gate["unprocessed"])
