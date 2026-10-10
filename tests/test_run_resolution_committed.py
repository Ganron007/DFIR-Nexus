"""R10: the committed tools run is the one evidence is resolved from.

A failed or interrupted run that is newer than the committed run, and holds
partial output, must not be chosen. The scenario is real: EvtxECmd output
copied into run folders, with manifests written the way the run records do.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import time
from pathlib import Path

import pytest

from nexus.langgraph.pipeline_runs import resolve_tools_extractions

REAL_OUTPUT = (
    Path(__file__).resolve().parents[1]
    / "Evidence-files" / "ES-Mapping" / "outputs" / "evtxecmd"
)


def _real_csv(tmp_path: Path) -> Path:
    """A verbatim EvtxECmd output file. Skips where the operator's set is absent."""
    found = sorted(REAL_OUTPUT.glob("*.csv")) if REAL_OUTPUT.is_dir() else []
    if not found:
        pytest.skip("operator's ES-Mapping EvtxECmd outputs are not present")
    dest = tmp_path / "source.csv"
    shutil.copy2(found[0], dest)
    return dest


def _run(case: Path, rid: str, status: str, when: float, csv: Path) -> None:
    run = case / "runs" / rid
    (run / "extractions" / "evtxecmd").mkdir(parents=True)
    shutil.copy2(csv, run / "extractions" / "evtxecmd" / csv.name)
    (run / "manifest.json").write_text(json.dumps({
        "run_id": rid, "mode": "tools", "status": status,
        "parent_run_id": "", "previous_active_run_id": "",
    }), encoding="utf-8")
    os.utime(run, (when, when))


@pytest.fixture
def case(tmp_path: Path) -> Path:
    root = tmp_path / "CASE-R10TEST"
    (root / "analysis").mkdir(parents=True)
    (root / "CASE.yaml").write_text("case_id: CASE-R10TEST\n", encoding="utf-8")
    return root


def test_the_pointed_completed_run_beats_a_newer_failed_run(case, tmp_path):
    csv = _real_csv(tmp_path)
    now = time.time()
    _run(case, "RUN-A-COMPLETED", "completed", now - 3600, csv)
    _run(case, "RUN-B-FAILED", "failed", now, csv)
    (case / "active_runs.json").write_text(json.dumps({"tools": "RUN-A-COMPLETED"}), encoding="utf-8")
    assert resolve_tools_extractions(case).parent.name == "RUN-A-COMPLETED"


def test_without_a_pointer_the_newest_completed_run_wins_over_newer_partial_output(case, tmp_path):
    csv = _real_csv(tmp_path)
    now = time.time()
    _run(case, "RUN-OLD-COMPLETED", "completed", now - 7200, csv)
    _run(case, "RUN-NEW-INTERRUPTED", "interrupted", now - 60, csv)
    _run(case, "RUN-NEWEST-FAILED", "failed", now, csv)
    assert resolve_tools_extractions(case).parent.name == "RUN-OLD-COMPLETED"


def test_with_no_completed_run_the_recovery_is_logged(case, tmp_path, caplog):
    csv = _real_csv(tmp_path)
    _run(case, "RUN-ONLY-FAILED", "failed", time.time(), csv)
    with caplog.at_level(logging.WARNING, logger="nexus.langgraph.pipeline_runs"):
        resolved = resolve_tools_extractions(case)
    assert resolved.parent.name == "RUN-ONLY-FAILED"
    assert any("did not complete" in rec.getMessage() for rec in caplog.records)
