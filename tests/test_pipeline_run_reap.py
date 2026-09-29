"""Stale 'running' lane records are reaped at server start (defect D48).

A tools run lives as a thread inside the server process. When the server is
restarted (or dies) mid-run, the status record under
``analysis/pipeline_runs/<run_id>.json`` is left saying ``running`` forever -
the portal then presents a ghost run. Startup reaping is legal by
construction: at startup no lane thread exists yet.
"""
from __future__ import annotations

import json
from pathlib import Path

from nexus.langgraph.pipeline_runs import reap_stale_running_runs


def _write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def test_running_is_interrupted_terminal_and_garbage_are_left(tmp_path: Path):
    runs = tmp_path / "CASE-TEST1" / "analysis" / "pipeline_runs"
    _write(runs / "abc.json", {"run_id": "abc", "mode": "tools", "status": "running"})
    _write(runs / "ok.json", {"run_id": "ok", "mode": "tools", "status": "complete"})
    _write(runs / "bad.json", {"run_id": "bad", "mode": "tools", "status": "failed"})
    (runs / "broken.json").write_text("not json", encoding="utf-8")

    reaped = reap_stale_running_runs(tmp_path)

    assert reaped == ["CASE-TEST1/abc"]
    abc = json.loads((runs / "abc.json").read_text(encoding="utf-8"))
    assert abc["status"] == "interrupted"
    assert "server restart" in abc["stop_reason"]
    assert abc["finished_at"]
    assert json.loads((runs / "ok.json").read_text(encoding="utf-8"))["status"] == "complete"
    assert json.loads((runs / "bad.json").read_text(encoding="utf-8"))["status"] == "failed"


def test_second_pass_is_a_noop_and_missing_root_is_safe(tmp_path: Path):
    runs = tmp_path / "CASE-TEST2" / "analysis" / "pipeline_runs"
    _write(runs / "x.json", {"run_id": "x", "mode": "tools", "status": "running"})

    assert reap_stale_running_runs(tmp_path) == ["CASE-TEST2/x"]
    assert reap_stale_running_runs(tmp_path) == []  # already interrupted
    assert reap_stale_running_runs(tmp_path / "does-not-exist") == []
