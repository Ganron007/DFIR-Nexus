"""D133 / D141: one analysis preflight, on every surface, for every mode.

`nexus interpret` (Mode 1) used to start with no lane-gate, busy or SIFT check; `busy_runs`
(the CLIs' only busy check) read Modes 2 and 3 alone; and a SIFT-selected case refused every
analysis run while the SIFT VM was off, although analysis never calls SIFT.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import yaml
from typer.testing import CliRunner


def _case(case_id: str, intake: dict | None = None) -> Path:
    from nexus.config import settings

    case = settings.cases_root / case_id
    (case / "analysis").mkdir(parents=True)
    (case / "audit").mkdir()
    meta = {"case_id": case_id, "status": "created"}
    if intake:
        meta["intake"] = intake
    (case / "CASE.yaml").write_text(yaml.safe_dump(meta), encoding="utf-8")
    return case


def _gate(case: Path, **gate) -> None:
    (case / "analysis" / "lane_gate.json").write_text(
        json.dumps({"schema": 1, "status": "clear", **gate}), encoding="utf-8")


def _interpret(case: Path):
    """`nexus interpret`, with run_pipeline replaced by a recorder so nothing runs."""
    from nexus.cli.main import app

    started: list[str] = []

    async def _recorder(**kwargs):
        started.append(str(kwargs.get("case_id") or ""))
        return {}

    with patch("nexus.langgraph.llm_pipeline.run_pipeline", _recorder):
        result = CliRunner().invoke(app, ["interpret", "--case", case.name])
    return result, started


def test_interpret_refuses_a_blocked_lane_gate():
    case = _case("CASE-PF-GATE")
    _gate(case, status="blocked", blocked_count=1,
          unprocessed=[{"tool": "srumecmd", "purpose": "SRUM", "reason": "ESE logs"}])
    result, started = _interpret(case)
    assert result.exit_code == 1
    assert "EVIDENCE GATE BLOCKED" in result.output
    assert started == []


def test_interpret_refuses_while_a_mode2_run_is_live():
    case = _case("CASE-PF-BUSY")
    _gate(case)
    (case / "analysis" / "mode2_runs").mkdir()
    (case / "analysis" / "mode2_runs" / "M2-LIVE.json").write_text(
        json.dumps({"run_id": "M2-LIVE", "status": "planned"}), encoding="utf-8")
    result, started = _interpret(case)
    assert result.exit_code == 1
    assert "M2-LIVE" in result.output
    assert started == []


def test_interpret_starts_on_a_free_case():
    case = _case("CASE-PF-FREE")
    _gate(case)
    result, started = _interpret(case)
    assert result.exit_code == 0, result.output
    assert started == [case.name]


def test_a_live_mode1_run_makes_the_case_busy_and_a_dead_one_does_not():
    from nexus.langgraph.pipeline_runs import create_run
    from nexus.modes.multi_role import busy_runs

    case = _case("CASE-PF-M1")
    live = create_run(case, "interpret")  # this process: alive
    assert [b["run_id"] for b in busy_runs(case)] == [live.run_id]

    finished = subprocess.run([sys.executable, "-c", "import os; print(os.getpid())"],
                              capture_output=True, text=True, check=True)
    manifest_path = live.path / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["pid"] = int(finished.stdout.strip())  # a process that has exited
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    assert busy_runs(case) == []


def test_sift_matters_only_while_the_lane_waits_on_it(monkeypatch):
    from nexus.langgraph.analysis_preflight import analysis_preflight

    monkeypatch.setenv("NEXUS_SIFT_SYNC", "0")  # the SIFT host is unreachable
    case = _case("CASE-PF-SIFT", intake={"sift_required": "true"})
    _gate(case)
    assert analysis_preflight(case) == ""
    _gate(case, status="waiting", waiting_sift=[{"tool": "plaso", "purpose": "super-timeline"}])
    assert "SIFT analysis is required" in analysis_preflight(case)
