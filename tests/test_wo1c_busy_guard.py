"""WO-1C item 2 — one analysis run per case, across all three modes.

D5 = C: one case, three modes. The old rule (one mode per case, enforced by
``mode_guard``) is gone; what remains is the WRITER race. Staging two runs at
once interleaves writes into findings.json, so the busy guard must see a
running run in ANY mode — Mode 1 (pipeline run + full-run record), Mode 2 and
Mode 3.

These tests run the real guard against a real case dir with real run records,
not a mock: the records are written exactly the way the run paths write them.
"""
from __future__ import annotations

import json
from pathlib import Path


def _case_key(case_dir: Path) -> str:
    from nexus.dashboard.app import _case_key as key

    return key(case_dir)


def _write_run(case_dir: Path, sub: str, run_id: str, status: str) -> None:
    d = case_dir / "analysis" / sub
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{run_id}.json").write_text(
        json.dumps({"run_id": run_id, "status": status, "mode": "x"}),
        encoding="utf-8",
    )


class _DeadThread:
    def is_alive(self) -> bool:
        return False


def test_busy_guard_sees_a_running_mode2_run(tmp_path: Path):
    from nexus.dashboard.app import _busy_run_error

    _write_run(tmp_path, "mode2_runs", "M2-abc", "running")
    err = _busy_run_error(tmp_path)
    assert err is not None, "a running Mode 2 run did not block a second run"
    assert err.status_code == 409


def test_busy_guard_sees_a_running_mode3_run(tmp_path: Path):
    from nexus.dashboard.app import _busy_run_error

    _write_run(tmp_path, "mode3_runs", "M3-abc", "running")
    err = _busy_run_error(tmp_path)
    assert err is not None, "a running Mode 3 run did not block a second run"
    assert err.status_code == 409


def test_busy_guard_sees_a_running_mode1_pipeline_run(tmp_path: Path):
    """The WO-1C defect: a Mode 1 interpret run was invisible to the guard.

    Root cause: ``_busy_run_error`` only scanned ``mode2_runs`` and
    ``mode3_runs``. A Mode 1 interpret pipeline run stages findings too, so
    two concurrent runs could interleave findings.json.
    """
    from nexus.dashboard.app import _busy_run_error

    _write_run(tmp_path, "pipeline_runs", "M1-abc", "running")
    err = _busy_run_error(tmp_path)
    assert err is not None, "a running Mode 1 run did not block a second run"
    assert err.status_code == 409


def test_busy_guard_ignores_a_running_non_m1_pipeline_run(tmp_path: Path):
    """A tools/lane pipeline run is not an analysis run — it must not block."""
    from nexus.dashboard.app import _busy_run_error

    _write_run(tmp_path, "pipeline_runs", "TOOLS-abc", "running")
    assert _busy_run_error(tmp_path) is None, "a tools run blocked analysis"


def test_busy_guard_sees_a_running_mode1_full_run(tmp_path: Path):
    """Mode 1's needle full-run record lives in analysis/mode1_full_run.json.

    It is reconciled against the live worker thread, so a record whose worker
    is dead (server restart) must NOT block — the same rule
    ``_mode1_run_record`` applies. The record marks itself interrupted in
    place, so a restart cannot wedge a case.
    """
    from nexus.dashboard import app as appmod
    from nexus.dashboard.app import _busy_run_error

    rec = tmp_path / "analysis" / "mode1_full_run.json"
    rec.parent.mkdir(parents=True, exist_ok=True)
    rec.write_text(json.dumps({"run_id": "M1-1", "status": "running"}),
                   encoding="utf-8")
    # A dead worker means a tombstone, not a live run.
    with appmod._mode1_run_lock:
        appmod._mode1_run_threads[_case_key(tmp_path)] = _DeadThread()
    try:
        assert _busy_run_error(tmp_path) is None, (
            "a Mode 1 record whose worker is dead blocked the case"
        )
    finally:
        with appmod._mode1_run_lock:
            appmod._mode1_run_threads.pop(_case_key(tmp_path), None)


def test_busy_guard_allows_a_completed_run(tmp_path: Path):
    from nexus.dashboard.app import _busy_run_error

    _write_run(tmp_path, "pipeline_runs", "M1-abc", "completed")
    _write_run(tmp_path, "mode2_runs", "M2-def", "done")
    _write_run(tmp_path, "mode3_runs", "M3-ghi", "error")
    assert _busy_run_error(tmp_path) is None, "finished runs blocked the case"


def test_busy_guard_ignores_a_corrupt_run_record(tmp_path: Path):
    """A corrupt record is skipped, not treated as running (never wedges)."""
    from nexus.dashboard.app import _busy_run_error

    d = tmp_path / "analysis" / "mode2_runs"
    d.mkdir(parents=True)
    (d / "M2-bad.json").write_text("{not json", encoding="utf-8")
    assert _busy_run_error(tmp_path) is None


def test_busy_guard_sees_a_planned_mode2_run(tmp_path: Path):
    """The 36f defect, reproduced on the real path.

    Mode 2's ``director_node`` writes ``status="planned"`` the moment the work
    orders exist and keeps it for the whole investigation — worker, verify and
    assess all run in that state. The guard only accepted ``"running"``, so an
    in-flight run was invisible and a second ``nexus mode2 run`` started on the
    same case. Measured live on CASE-WO1C-REALPATH: the guard returned ``None``
    while that run was on work order 8 of 7.
    """
    from nexus.dashboard.app import _busy_run_error

    _write_run(tmp_path, "mode2_runs", "M2-abc", "planned")
    err = _busy_run_error(tmp_path)
    assert err is not None, (
        "a Mode 2 run in 'planned' state did not block a second run — this is "
        "the duplicate-run defect"
    )
    assert err.status_code == 409


def test_busy_guard_sees_a_planned_mode3_run(tmp_path: Path):
    """Mode 3's live state is also ``planned``; same hole, same fix."""
    from nexus.dashboard.app import _busy_run_error

    _write_run(tmp_path, "mode3_runs", "M3-abc", "planned")
    err = _busy_run_error(tmp_path)
    assert err is not None, "a planned Mode 3 run did not block a second run"
    assert err.status_code == 409


def test_busy_runs_reports_the_blocking_run_id(tmp_path: Path):
    """The refusal must NAME the run, so the operator can find and stop it."""
    from nexus.modes.multi_role import busy_message, busy_runs

    _write_run(tmp_path, "mode2_runs", "M2-live", "planned")
    busy = busy_runs(tmp_path)
    assert [b["run_id"] for b in busy] == ["M2-live"], busy
    assert "M2-live" in busy_message(busy)


def test_busy_runs_own_run_is_not_a_competitor(tmp_path: Path):
    """A caller resuming its own run must not be refused by itself."""
    from nexus.modes.multi_role import busy_runs

    _write_run(tmp_path, "mode2_runs", "M2-own", "planned")
    assert busy_runs(tmp_path, own_run_id="M2-own") == []


def test_busy_runs_ignores_terminal_statuses(tmp_path: Path):
    """planned/running are live; stopped/completed/failed/paused are not."""
    from nexus.modes.multi_role import busy_runs

    for status in ("completed", "failed", "stopped", "paused"):
        _write_run(tmp_path, "mode2_runs", f"M2-{status}", status)
    assert busy_runs(tmp_path) == []


def _write_case(case_dir: Path, name: str) -> None:
    """Make ``case_dir`` a resolvable case (mirrors test_wo1c_cli_parity)."""
    (case_dir / "analysis").mkdir(parents=True, exist_ok=True)
    (case_dir / "CASE.yaml").write_text(f"case_id: {name}\n", encoding="utf-8")


def test_mode2_cli_refuses_while_a_run_is_live(tmp_path: Path, monkeypatch):
    """The CLI is a writer surface too — it must take the same guard.

    Reproduced the real defect: ``mode2_cmd.run`` called ``lane_gate_blocked``
    and ``sift_preflight_message`` but never the busy check, so a second CLI
    run started on a case the portal had already refused.
    """
    from typer.testing import CliRunner

    from nexus.cli import main as cli_main
    from nexus.modes.multi_role import busy_runs

    case_dir = tmp_path / "CASE-BUSY2"
    _write_case(case_dir, "CASE-BUSY2")
    _write_run(case_dir, "mode2_runs", "M2-live", "planned")
    monkeypatch.setattr("nexus.cli.mode2_cmd._case_dir", lambda _c: case_dir)
    monkeypatch.setattr("nexus.langgraph.lane_gate.lane_gate_blocked",
                        lambda _c: None)
    result = CliRunner().invoke(cli_main.app,
                                ["mode2", "run", "--case", "CASE-BUSY2"])
    assert result.exit_code == 1, result.output
    assert "already running" in result.output, result.output
    # And the guard agrees about which run blocks.
    assert [b["run_id"] for b in busy_runs(case_dir)] == ["M2-live"]


def test_mode3_cli_refuses_while_a_run_is_live(tmp_path: Path, monkeypatch):
    from typer.testing import CliRunner

    from nexus.cli import main as cli_main

    case_dir = tmp_path / "CASE-BUSY3"
    _write_case(case_dir, "CASE-BUSY3")
    _write_run(case_dir, "mode3_runs", "M3-live", "planned")
    monkeypatch.setattr("nexus.cli.mode3_cmd._case_dir", lambda _c: case_dir)
    monkeypatch.setattr("nexus.langgraph.lane_gate.lane_gate_blocked",
                        lambda _c: None)
    result = CliRunner().invoke(cli_main.app,
                                ["mode3", "run", "--case", "CASE-BUSY3"])
    assert result.exit_code == 1, result.output
    assert "already running" in result.output, result.output

