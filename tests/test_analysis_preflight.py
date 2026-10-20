"""D133 / D141: one analysis preflight, on every surface, for every mode.

`nexus interpret` (Mode 1) used to start with no lane-gate, busy or SIFT check; `busy_runs`
(the CLIs' only busy check) read Modes 2 and 3 alone; and a SIFT-selected case refused every
analysis run while the SIFT VM was off, although analysis never calls SIFT.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path
from unittest.mock import patch

import pytest
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


def _real_s07_mode3_record() -> Path | None:
    for parent in Path(__file__).resolve().parents:
        candidate = (parent / "cases" / "CASE-F8811FAB" / "analysis" / "mode3_runs"
                     / "M3-20261018T190632-ebaab5.json")
        if candidate.is_file():
            return candidate
    return None


def _copy_real_s07_record(tmp_path: Path) -> tuple[Path, Path, bytes]:
    source = _real_s07_mode3_record()
    if source is None:
        pytest.skip("private S07 Mode 3 record is not present in this checkout")
    original = source.read_bytes()
    case = _case("CASE-F8811FAB")
    _gate(case)
    destination_dir = case / "analysis" / "mode3_runs"
    destination_dir.mkdir()
    destination = destination_dir / source.name
    shutil.copyfile(source, destination)
    return case, destination, original


def test_reaper_does_not_infer_legacy_run_death_from_file_age(tmp_path: Path):
    """The verbatim S07 run stays busy regardless of its age; no case JSON is rewritten."""
    from nexus.langgraph.pipeline_runs import reap_dead_runs
    from nexus.modes.multi_role import busy_runs

    case, copied_record, original = _copy_real_s07_record(tmp_path)
    os.utime(copied_record, (time.time() - 30 * 60 * 60,) * 2)

    assert reap_dead_runs(case) == []
    assert copied_record.read_bytes() == original
    assert _real_s07_mode3_record().read_bytes() == original
    assert any(row["run_id"] == copied_record.stem for row in busy_runs(case))


def test_mode3_recovery_command_appends_event_and_preserves_real_run_record(
    tmp_path: Path,
):
    from nexus.cli.mode3_cmd import app
    from nexus.modes.multi_agent import read_run_record, run_mode3
    from nexus.modes.multi_role import busy_runs

    case, copied_record, original = _copy_real_s07_record(tmp_path)
    run_id = copied_record.stem
    runner = CliRunner()
    refused = runner.invoke(app, [
        "recover", "--case", case.name, "--run-id", run_id,
    ])
    assert refused.exit_code == 1
    assert "confirm the no-worker check" in refused.output
    assert copied_record.read_bytes() == original

    recovered = runner.invoke(app, [
        "recover", "--case", case.name, "--run-id", run_id,
        "--confirm-no-worker",
    ])
    assert recovered.exit_code == 0, recovered.output
    assert "record=preserved" in recovered.output
    assert copied_record.read_bytes() == original
    assert _real_s07_mode3_record().read_bytes() == original
    assert read_run_record(case, run_id)["status"] == "interrupted"
    assert busy_runs(case) == []
    event_path = case / "analysis" / "run_recoveries" / f"{run_id}.json"
    event = json.loads(event_path.read_text(encoding="utf-8"))
    assert event["source_record_sha256"] == hashlib.sha256(original).hexdigest()
    assert event["confirmed_no_worker"] is True

    duplicate = run_mode3(case, "ignored after recovery", run_id=run_id, model=object())
    assert duplicate["status"] == "interrupted"
    assert duplicate["recovery_event"] == event
    assert copied_record.read_bytes() == original
    assert _real_s07_mode3_record().read_bytes() == original


def test_recovery_marker_does_not_apply_to_a_changed_source_record(tmp_path: Path):
    from nexus.langgraph.pipeline_runs import read_mode_run_recovery, recover_mode_run
    from nexus.modes.multi_role import busy_runs

    case, copied_record, original = _copy_real_s07_record(tmp_path)
    run_id = copied_record.stem
    recover_mode_run(case, run_id, confirmed_no_worker=True)

    changed = copied_record.read_bytes() + b" "
    copied_record.write_bytes(changed)
    assert read_mode_run_recovery(case, run_id) is None
    assert copied_record.read_bytes() == changed
    assert any(row["run_id"] == run_id for row in busy_runs(case))
    with pytest.raises(ValueError, match="does not match the run"):
        recover_mode_run(case, run_id, confirmed_no_worker=True)
    assert _real_s07_mode3_record().read_bytes() == original


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
