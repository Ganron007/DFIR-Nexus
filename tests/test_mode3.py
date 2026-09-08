"""Tests for Mode 3 — agentic plan/execute/seal."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from nexus.langgraph.mode3 import execute_plan, plan_extras, seal_case


def _make_case(tmp_path: Path, with_ledger: bool = True, with_ok: bool = True) -> Path:
    case_dir = tmp_path / "CASE-M3"
    case_dir.mkdir()
    (case_dir / "CASE.yaml").write_text("name: m3\nintake:\n  question: test?\n")
    ext = case_dir / "extractions" / "hayabusa"
    ext.mkdir(parents=True)
    (ext / "timeline.csv").write_text("time,host\n2026-08-10T15:00:00Z,WS01\n")
    if with_ledger:
        ledger = []
        if with_ok:
            ledger.append({"tool": "hayabusa", "status": "OK", "audit_id": "a1"})
        ledger.append({"tool": "srumecmd", "status": "SKIP", "reason": "binary not installed"})
        (case_dir / "extractions" / "_tool_lane_ledger.json").write_text(json.dumps(ledger))
    return case_dir


class TestPlanExtras:
    def test_proposes_unrequested(self, tmp_path):
        case_dir = _make_case(tmp_path, with_ledger=False)
        plan = plan_extras(case_dir, model=None)
        keys = [i["key"] for i in plan["items"] if i.get("type") == "extra"]
        assert "chrome_profiles" in keys
        assert plan["rationale"]

    def test_reads_ledger_skips(self, tmp_path):
        case_dir = _make_case(tmp_path)
        plan = plan_extras(case_dir, model=None)
        skips = [i for i in plan["items"] if i.get("type") == "tool_skip"]
        assert any(s.get("tool") == "srumecmd" for s in skips)

    def test_excludes_suzaku_on_windows(self, tmp_path):
        case_dir = _make_case(tmp_path)
        # Add a suzaku SKIP
        ledger = json.loads((case_dir / "extractions" / "_tool_lane_ledger.json").read_text())
        ledger.append({"tool": "suzaku", "status": "SKIP", "reason": "linux parser"})
        (case_dir / "extractions" / "_tool_lane_ledger.json").write_text(json.dumps(ledger))
        plan = plan_extras(case_dir, model=None)
        skips = [i.get("tool") for i in plan["items"] if i.get("type") == "tool_skip"]
        assert "suzaku" not in skips

    def test_lane_complete_flag(self, tmp_path):
        case_dir = _make_case(tmp_path, with_ok=True)
        plan = plan_extras(case_dir, model=None)
        assert plan["lane_complete"] is True

    def test_lane_incomplete_flag(self, tmp_path):
        case_dir = _make_case(tmp_path, with_ledger=True, with_ok=False)
        plan = plan_extras(case_dir, model=None)
        assert plan["lane_complete"] is False


class TestExecutePlan:
    def test_persists_extras(self, tmp_path):
        case_dir = _make_case(tmp_path)
        result = execute_plan(case_dir, ["usb_serial"], [])
        assert result["status"] == "executed"
        assert "usb_serial" in result["extras_persisted"]
        from nexus.langgraph.query_pack import load_case_intake

        intake = load_case_intake(case_dir)
        assert "usb_serial" in (intake.get("extras") or "")

    def test_rejects_arbitrary_extras(self, tmp_path):
        case_dir = _make_case(tmp_path)
        result = execute_plan(case_dir, ["evil_parser"], [])
        assert result["status"] == "executed"
        assert "evil_parser" not in result["extras_persisted"]

    def test_rejects_no_lane(self, tmp_path):
        case_dir = _make_case(tmp_path, with_ledger=False)
        result = execute_plan(case_dir, ["usb_serial"], [])
        assert result.get("error")
        assert "Mandatory lane" in result["error"]

    def test_empty_plan(self, tmp_path):
        case_dir = _make_case(tmp_path)
        result = execute_plan(case_dir, [], [])
        assert result["status"] == "executed"

    def test_extras_separator_consistency(self, tmp_path):
        case_dir = _make_case(tmp_path)
        # Pre-populate with semicolon-separated extras
        from nexus.langgraph.case_intake import persist_case_intake

        persist_case_intake(case_dir, {"extras": "email;drivefs"})
        execute_plan(case_dir, ["usb_serial"], [])
        from nexus.langgraph.query_pack import load_case_intake

        intake = load_case_intake(case_dir)
        extras = intake.get("extras", "")
        # All three should be present, no semicolons
        assert "email" in extras and "drivefs" in extras and "usb_serial" in extras
        assert ";" not in extras


class TestSealCase:
    def test_seal_no_report(self, tmp_path):
        case_dir = _make_case(tmp_path)
        result = seal_case(case_dir, "examiner", "pw")
        assert result.get("error")
        assert "REPORT.md" in result["error"]

    def test_seal_wrong_password(self, tmp_path):
        case_dir = _make_case(tmp_path)
        (case_dir / "reports").mkdir()
        (case_dir / "reports" / "REPORT.md").write_text("# Report\n")
        from nexus.auth import setup_password

        setup_password("examiner", "correct_password_123")
        result = seal_case(case_dir, "examiner", "wrong_password")
        assert result.get("error")
        assert "verification failed" in result["error"].lower()

    def test_seal_correct_password(self, tmp_path):
        case_dir = _make_case(tmp_path)
        (case_dir / "reports").mkdir()
        (case_dir / "reports" / "REPORT.md").write_text("# Report\ncontent")
        (case_dir / "findings.json").write_text(json.dumps([{"id": "F-001"}]))
        from nexus.auth import setup_password

        setup_password("examiner", "correct_password_123")
        result = seal_case(case_dir, "examiner", "correct_password_123")
        assert result["status"] == "SEALED"
        assert result["examiner"] == "examiner"

    def test_seal_skip_verify(self, tmp_path):
        case_dir = _make_case(tmp_path)
        (case_dir / "reports").mkdir()
        (case_dir / "reports" / "REPORT.md").write_text("# Report\ncontent")
        from nexus.auth import setup_password

        setup_password("examiner", "correct_password_123")
        result = seal_case(case_dir, "examiner", "", skip_verify=True)
        assert result["status"] == "SEALED"


class TestAgentRunLog:
    def test_log_appended(self, tmp_path):
        case_dir = _make_case(tmp_path)
        plan_extras(case_dir, model=None)
        log_file = case_dir / "agent_runs.jsonl"
        assert log_file.is_file()
        lines = [ln for ln in log_file.read_text(encoding="utf-8").splitlines() if ln.strip()]
        assert any('"action": "mode3_plan"' in ln for ln in lines)
