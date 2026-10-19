"""D133 / D141: one analysis preflight, on every surface, for every mode.

`nexus interpret` (Mode 1) used to start with no lane-gate, busy or SIFT check; `busy_runs`
(the CLIs' only busy check) read Modes 2 and 3 alone; and a SIFT-selected case refused every
analysis run while the SIFT VM was off, although analysis never calls SIFT.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
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


def test_preflight_reaps_dead_mode3_cli_run(monkeypatch):
    from nexus.langgraph.analysis_preflight import analysis_preflight

    case = _case("CASE-PF-M3-DEAD")
    _gate(case)
    records = case / "analysis" / "mode3_runs"
    records.mkdir()
    path = records / "M3-DEAD.json"
    path.write_text(json.dumps({
        "run_id": "M3-DEAD",
        "status": "running",
        "process_pid": 424242,
        "budgets": {"wall_seconds": 3600},
    }), encoding="utf-8")
    monkeypatch.setattr("nexus.langgraph.pipeline_runs.process_alive",
                        lambda _pid: False)

    assert analysis_preflight(case) == ""
    saved = json.loads(path.read_text(encoding="utf-8"))
    assert saved["status"] == "interrupted"
    assert "process" in saved["error"]


def test_preflight_reaps_legacy_mode_runs_after_long_idle_period():
    """A legacy record has no owner PID; only stale record and journal mtimes can identify it."""
    from nexus.langgraph.analysis_preflight import analysis_preflight

    case = _case("CASE-PF-M3-LEGACY")
    _gate(case)
    stale_time = time.time() - 30 * 60 * 60
    paths = []
    for sub, run_id in (("mode2_runs", "M2-LEGACY"),
                        ("mode3_runs", "M3-LEGACY")):
        records = case / "analysis" / sub
        records.mkdir()
        path = records / f"{run_id}.json"
        path.write_text(json.dumps({
            "run_id": run_id,
            "status": "running",
        }), encoding="utf-8")
        journal = path.with_suffix(".jsonl")
        journal.write_text("", encoding="utf-8")
        os.utime(path, (stale_time, stale_time))
        os.utime(journal, (stale_time, stale_time))
        paths.append(path)

    assert analysis_preflight(case) == ""
    for path in paths:
        saved = json.loads(path.read_text(encoding="utf-8"))
        assert saved["status"] == "interrupted"
        assert "24 hours" in saved["error"]


def test_preflight_keeps_a_recent_legacy_mode3_run_busy():
    from nexus.langgraph.analysis_preflight import analysis_preflight

    case = _case("CASE-PF-M3-LEGACY-RECENT")
    _gate(case)
    records = case / "analysis" / "mode3_runs"
    records.mkdir()
    path = records / "M3-LEGACY-RECENT.json"
    path.write_text(json.dumps({
        "run_id": "M3-LEGACY-RECENT",
        "status": "running",
    }), encoding="utf-8")
    path.with_suffix(".jsonl").write_text("", encoding="utf-8")

    assert "M3-LEGACY-RECENT" in analysis_preflight(case)
    assert json.loads(path.read_text(encoding="utf-8"))["status"] == "running"


def test_preflight_does_not_reap_live_mode3_cli_run():
    from nexus.langgraph.analysis_preflight import analysis_preflight

    case = _case("CASE-PF-M3-LIVE")
    _gate(case)
    records = case / "analysis" / "mode3_runs"
    records.mkdir()
    (records / "M3-LIVE.json").write_text(json.dumps({
        "run_id": "M3-LIVE",
        "status": "running",
        "process_pid": os.getpid(),
        "process_thread_id": threading.get_native_id(),
        "budgets": {"wall_seconds": 3600},
    }), encoding="utf-8")

    assert "M3-LIVE" in analysis_preflight(case)


def test_preflight_reaps_dead_mode2_and_mode3_worker_threads():
    from nexus.langgraph.analysis_preflight import analysis_preflight

    case = _case("CASE-PF-DEAD-WORKERS")
    _gate(case)
    for sub, run_id in (("mode2_runs", "M2-DEAD-THREAD"),
                        ("mode3_runs", "M3-DEAD-THREAD")):
        records = case / "analysis" / sub
        records.mkdir()
        (records / f"{run_id}.json").write_text(json.dumps({
            "run_id": run_id,
            "status": "running",
            "process_pid": os.getpid(),
            "process_thread_id": 99999999,
        }), encoding="utf-8")

    assert analysis_preflight(case) == ""
    for sub, run_id in (("mode2_runs", "M2-DEAD-THREAD"),
                        ("mode3_runs", "M3-DEAD-THREAD")):
        saved = json.loads((case / "analysis" / sub / f"{run_id}.json").read_text(
            encoding="utf-8"))
        assert saved["status"] == "interrupted"
        assert "worker thread" in saved["error"]


def test_preflight_checks_worker_thread_in_another_live_process():
    from nexus.langgraph.analysis_preflight import analysis_preflight

    case = _case("CASE-PF-DEAD-REMOTE-THREAD")
    _gate(case)
    records = case / "analysis" / "mode3_runs"
    records.mkdir()
    path = records / "M3-DEAD-REMOTE-THREAD.json"
    owner = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    try:
        (records / "M3-DEAD-REMOTE-THREAD.json").write_text(json.dumps({
            "run_id": "M3-DEAD-REMOTE-THREAD",
            "status": "running",
            "process_pid": owner.pid,
            "process_thread_id": 4294967295,
        }), encoding="utf-8")
        assert analysis_preflight(case) == ""
        saved = json.loads(path.read_text(encoding="utf-8"))
        assert saved["status"] == "interrupted"
        assert "worker thread" in saved["error"]
    finally:
        owner.terminate()
        owner.wait(timeout=10)


def test_mode2_and_mode3_records_capture_the_active_owner():
    from nexus.modes.multi_agent import run_mode3
    from nexus.modes.multi_role import run_mode2

    for mode, run in (("mode2", run_mode2), ("mode3", run_mode3)):
        case = _case(f"CASE-PF-OWNER-{mode.upper()}")
        _gate(case)
        record = run(case, "test only", model=None, es_ok=False)
        saved = json.loads((case / "analysis" / f"{mode}_runs" /
                            f"{record['run_id']}.json").read_text(encoding="utf-8"))
        assert saved["status"] == "failed"
        assert saved["process_pid"] == os.getpid()
        assert saved["process_thread_id"] == threading.get_native_id()


def test_sift_matters_only_while_the_lane_waits_on_it(monkeypatch):
    from nexus.langgraph.analysis_preflight import analysis_preflight

    monkeypatch.setenv("NEXUS_SIFT_SYNC", "0")  # the SIFT host is unreachable
    case = _case("CASE-PF-SIFT", intake={"sift_required": "true"})
    _gate(case)
    assert analysis_preflight(case) == ""
    _gate(case, status="waiting", waiting_sift=[{"tool": "plaso", "purpose": "super-timeline"}])
    assert "SIFT analysis is required" in analysis_preflight(case)
