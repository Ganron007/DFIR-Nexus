"""The run resolver warns once per uncommitted run, not once per lookup.

While a lane is still running its run is not committed, and the resolver falls back to
it on every lookup. Reproduced on SC1 (2026-10-10): 20 lookups logged 20 identical
warnings. The warning is kept (it says the run did not complete), logged once.
"""
from __future__ import annotations

import json
import logging

from nexus.langgraph import pipeline_runs


def _uncommitted_run_with_data(case_dir, run_name: str) -> None:
    run = case_dir / "runs" / run_name
    (run / "extractions" / "evtxecmd").mkdir(parents=True)
    (run / "extractions" / "evtxecmd" / "rows.csv").write_text("a,b\n1,2\n", encoding="utf-8")
    (run / "manifest.json").write_text(json.dumps({"status": "running"}), encoding="utf-8")


def test_repeated_lookups_warn_once_and_keep_resolving_the_same_run(tmp_path, caplog):
    case_dir = tmp_path / "CASE-RESOLVE01"
    _uncommitted_run_with_data(case_dir, "RUN-uncommitted-01")
    pipeline_runs._INCOMPLETE_RUNS_WARNED.discard(str(case_dir / "runs" / "RUN-uncommitted-01"))

    caplog.set_level(logging.WARNING, logger=pipeline_runs.__name__)
    resolved = {pipeline_runs.resolve_tools_extractions(case_dir) for _ in range(5)}

    assert resolved == {case_dir / "runs" / "RUN-uncommitted-01" / "extractions"}
    warnings = [r for r in caplog.records if "did not complete" in r.getMessage()]
    assert len(warnings) == 1, [r.getMessage() for r in warnings]
