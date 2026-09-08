"""Tests for Mode 3 — agentic plan/execute/seal."""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from nexus.langgraph.mode3 import execute_plan, plan_extras


def _make_case(tmp_path: Path, with_ledger: bool = True) -> Path:
    case_dir = tmp_path / "CASE-M3"
    case_dir.mkdir()
    (case_dir / "CASE.yaml").write_text("name: m3\nintake:\n  question: test?\n")
    ext = case_dir / "extractions" / "hayabusa"
    ext.mkdir(parents=True)
    (ext / "timeline.csv").write_text("time,host\n2026-08-10T15:00:00Z,WS01\n")
    if with_ledger:
        import json

        ledger = [
            {"tool": "hayabusa", "status": "OK", "audit_id": "a1"},
            {"tool": "srumecmd", "status": "SKIP", "reason": "binary not installed"},
        ]
        (case_dir / "extractions" / "_tool_lane_ledger.json").write_text(json.dumps(ledger))
    return case_dir


def test_plan_extras_proposes_unrequested(tmp_path):
    case_dir = _make_case(tmp_path, with_ledger=False)
    plan = plan_extras(case_dir, model=None)
    assert plan["case_id"] == "CASE-M3" or plan["case_id"] == case_dir.name
    keys = [i.get("key") for i in plan["items"] if i.get("type") == "extra"]
    assert "chrome_profiles" in keys  # not requested in intake -> proposed
    assert plan["rationale"]


def test_plan_reads_ledger_skips(tmp_path):
    case_dir = _make_case(tmp_path)
    plan = plan_extras(case_dir, model=None)
    skips = [i for i in plan["items"] if i.get("type") == "tool_skip"]
    assert any(s.get("tool") == "srumecmd" for s in skips)


def test_execute_plan_persists_extras(tmp_path):
    case_dir = _make_case(tmp_path)
    result = execute_plan(case_dir, ["usb_serial"], ["sdelete"])
    assert result["status"] == "executed"
    assert "usb_serial" in result["extras_persisted"]
    from nexus.langgraph.query_pack import load_case_intake

    intake = load_case_intake(case_dir)
    assert "usb_serial" in (intake.get("extras") or "")


def test_execute_plan_empty(tmp_path):
    case_dir = _make_case(tmp_path)
    result = execute_plan(case_dir, [], [])
    assert result["status"] == "executed"
    assert result["extras_persisted"] == []


def test_agent_run_log(tmp_path):
    case_dir = _make_case(tmp_path)
    plan_extras(case_dir, model=None)
    log_file = case_dir / "agent_runs.jsonl"
    assert log_file.is_file()
    lines = [ln for ln in log_file.read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert any('"action": "plan"' in ln for ln in lines)
