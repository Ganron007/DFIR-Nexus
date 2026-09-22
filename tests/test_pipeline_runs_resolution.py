"""Reuse-run resolution: data-less runs must never blind the briefing/indexer."""

from __future__ import annotations

import json
from pathlib import Path


def _mk_run(case_dir: Path, run_id: str, mode: str, *, data: bool,
            previous: str = "", parent: str = "") -> Path:
    run = case_dir / "runs" / run_id
    (run / "extractions").mkdir(parents=True)
    for name in ("analysis", "reports", "ledger"):
        (run / name).mkdir()
    (run / "extractions" / "_tool_lane_ledger.json").write_text("{}", encoding="utf-8")
    if data:
        (run / "extractions" / "hayabusa-timeline.csv").write_text(
            "Timestamp,RuleTitle\n2020-11-14,x\n", encoding="utf-8"
        )
    (run / "manifest.json").write_text(json.dumps({
        "run_id": run_id, "mode": mode, "parent_run_id": parent,
        "previous_active_run_id": previous, "status": "completed",
    }), encoding="utf-8")
    return run / "extractions"


def _point(case_dir: Path, tools: str, coverage: str = "") -> None:
    pointers = {"tools": tools}
    if coverage:
        pointers["coverage"] = coverage
    (case_dir / "active_runs.json").write_text(json.dumps(pointers), encoding="utf-8")


def test_resolver_skips_dataless_active_run(tmp_path):
    from nexus.langgraph.pipeline_runs import resolve_tools_extractions

    case_dir = tmp_path / "CASE-X"
    good = _mk_run(case_dir, "RUN-good-tools-1", "tools", data=True)
    _mk_run(case_dir, "RUN-reuse-coverage-2", "coverage", data=False,
            previous="RUN-good-tools-1")
    _point(case_dir, tools="RUN-reuse-coverage-2", coverage="RUN-reuse-coverage-2")
    assert resolve_tools_extractions(case_dir) == good


def test_resolver_follows_parent_chain(tmp_path):
    from nexus.langgraph.pipeline_runs import resolve_tools_extractions

    case_dir = tmp_path / "CASE-Y"
    good = _mk_run(case_dir, "RUN-a-tools-1", "tools", data=True)
    _mk_run(case_dir, "RUN-b-coverage-2", "coverage", data=False, parent="RUN-a-tools-1")
    _mk_run(case_dir, "RUN-c-design-3", "design", data=False, parent="RUN-b-coverage-2")
    _point(case_dir, tools="RUN-c-design-3")
    assert resolve_tools_extractions(case_dir) == good


def test_resolver_newest_with_data_wins_without_chain(tmp_path):
    from nexus.langgraph.pipeline_runs import resolve_tools_extractions

    case_dir = tmp_path / "CASE-Z"
    _mk_run(case_dir, "RUN-old-tools-1", "tools", data=True)
    newer = _mk_run(case_dir, "RUN-new-tools-2", "tools", data=True)
    import os
    import time

    os.utime(case_dir / "runs" / "RUN-new-tools-2", (time.time() + 5, time.time() + 5))
    _point(case_dir, tools="RUN-missing-tools-9")  # pointer to a run that does not exist
    assert resolve_tools_extractions(case_dir) == newer


def test_resolver_falls_back_to_case_extractions(tmp_path):
    from nexus.langgraph.pipeline_runs import resolve_tools_extractions

    case_dir = tmp_path / "CASE-W"
    (case_dir / "extractions").mkdir(parents=True)
    assert resolve_tools_extractions(case_dir) == case_dir / "extractions"


def test_create_run_records_parent_for_reuse_modes(tmp_path):
    from nexus.langgraph.pipeline_runs import create_run, resolve_tools_extractions

    case_dir = tmp_path / "CASE-V"
    tools = _mk_run(case_dir, "RUN-prev-tools-1", "tools", data=True)
    _point(case_dir, tools="RUN-prev-tools-1")
    run = create_run(case_dir, "coverage")
    manifest = json.loads((run.path / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["parent_run_id"] == "RUN-prev-tools-1"
    # the new run owns no data, so resolution still lands on the tools run
    assert resolve_tools_extractions(case_dir) == tools
