"""The runbook's tools (TIER1-WORK-ORDERS Part 10, devtools/runbook): the gate report, the timeout matcher, the sweep diff.

The lane log lines are verbatim from sample S08's lane of 2026-10-18 (a LogFileParser job and the timeout that ended
it 600 s later, and a job of the next host).
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).parent / "fixtures"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(f"runbook_{name}", REPO / "devtools" / "runbook" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_gate_report_names_each_unprocessed_item(tmp_path):
    case = tmp_path / "CASE-S06"
    (case / "analysis").mkdir(parents=True)
    (case / "analysis" / "lane_gate.json").write_text(json.dumps({
        "status": "blocked", "processed_count": 2, "blocked_count": 1, "waiting_count": 0,
        "unprocessed": [{"tool": "import", "purpose": "import C:\\x\\Evidence-files\\_samples\\S06\\logs\\a.log",
                         "reason": "Could not detect format for a.log"}],
    }), encoding="utf-8")
    lines = _load("gate_unread").report(case)
    assert lines[0] == "CASE-S06: gate blocked, processed 2, blocked 1, waiting 0"
    assert "S06\\logs\\a.log" in lines[1] and "Could not detect format" in lines[1]
    assert _load("gate_unread").report(tmp_path / "CASE-NONE")[0].endswith("has not run)")


def test_a_timeout_is_matched_to_the_jobs_that_started_its_budget_earlier(capsys):
    _load("lane_timeouts").main(str(FIXTURES / "runbook_lane_log.txt"))
    out = capsys.readouterr().out
    assert "12:03:49 timed out after 600s" in out
    assert "sam-adragoon-l" in out and "sam-ccrocomir-l" not in out, "the next host's job started later"


def test_the_sweep_diff_lists_every_file_whose_detection_changed(tmp_path, capsys):
    before, after = tmp_path / "b.tsv", tmp_path / "a.tsv"
    before.write_text("x.csv\tscheduled_tasks\ny.log\tNone\nz.csv\tgeneric_csv", encoding="utf-8")
    after.write_text("x.csv\tgeneric_csv\ny.log\tossec\nz.csv\tgeneric_csv", encoding="utf-8")
    _load("detect_sweep").diff(before, after)
    out = capsys.readouterr().out
    assert out.startswith("2 of 3 file(s) change detection")
    assert "scheduled_tasks -> generic_csv  x.csv" in out and "None -> ossec  y.log" in out
