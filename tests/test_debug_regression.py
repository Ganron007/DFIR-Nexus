"""A8: the regression checker must fail on a regression, not on its own bugs.

The three failure modes that matter: it stays quiet when nothing broke, it
speaks up with a diff when something did, and its watchdog fires on a run that
stopped writing while still claiming to be running.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import debug_regression as checker
import pytest


def _row(**over) -> dict:
    """A clean invariant row; each test then breaks exactly one field."""
    row = {
        "case_id": "CASE-REG00001",
        "lane": {"ok": 4, "skip": 1, "fail": 0},
        "gate": {"blocked": 0},
        "index": {"docs": 1854, "capped": False},
        "runs": {"status": "settled", "model_errors": 0},
        "findings": {"staged": 26, "approved": 26},
        "l1": {"counts": {"PROVEN": 24, "UNSUPPORTED": 2}},
        "grade": {"report_class": "B"},
        "coverage": {"overall": "complete"},
        "reconciliation": {"match": 14, "mismatch": 0, "malformed_quoting": 0},
        "cross_mode": {"contradictions": 0},
    }
    row.update(over)
    return row


def _baseline(row: dict) -> dict:
    return {"head": "abc1234", "cases": {row["case_id"]: row}}


def test_no_regression_is_quiet():
    report = checker.compare(
        {"cases": {"CASE-REG00001": _row()}}, _baseline(_row())
    )
    assert report["regressed"] is False
    assert report["regressions"] == {}


def test_l1_proven_drop_is_a_regression_with_a_diff():
    worse = _row()
    worse["l1"] = {"counts": {"PROVEN": 19, "UNSUPPORTED": 7}}
    report = checker.compare({"cases": {"CASE-REG00001": worse}}, _baseline(_row()))

    assert report["regressed"] is True
    breaks = report["regressions"]["CASE-REG00001"]
    assert any("l1.counts.PROVEN: 24 -> 19" in b for b in breaks)
    assert any("fewer PROVEN claims" in b for b in breaks)


def test_reconciliation_mismatch_and_malformed_quoting_are_regressions():
    worse = _row()
    worse["reconciliation"] = {"match": 13, "mismatch": 1, "malformed_quoting": 1}
    report = checker.compare({"cases": {"CASE-REG00001": worse}}, _baseline(_row()))
    breaks = report["regressions"]["CASE-REG00001"]
    assert any("reconciliation.mismatch" in b for b in breaks)
    assert any("reconciliation.malformed_quoting" in b for b in breaks)


def test_a_higher_grade_or_more_proven_is_not_a_regression():
    better = _row()
    better["grade"] = {"report_class": "A"}
    better["l1"] = {"counts": {"PROVEN": 26}}
    better["reconciliation"] = {"match": 14, "mismatch": 0, "malformed_quoting": 0}
    report = checker.compare({"cases": {"CASE-REG00001": better}}, _baseline(_row()))
    assert report["regressed"] is False


def test_a_missing_case_is_a_regression():
    report = checker.compare({"cases": {}}, _baseline(_row()))
    assert report["regressed"] is True
    assert report["missing_cases"] == ["CASE-REG00001"]


def test_new_cases_are_reported_but_not_a_regression():
    current = {"cases": {"CASE-REG00001": _row(), "CASE-REG00002": _row(case_id="CASE-REG00002")}}
    report = checker.compare(current, _baseline(_row()))
    assert report["new_cases"] == ["CASE-REG00002"]
    assert report["regressed"] is False


def test_lane_failure_and_gate_blocking_are_regressions():
    worse = _row()
    worse["lane"] = {"ok": 3, "skip": 1, "fail": 1}
    worse["gate"] = {"blocked": 2}
    report = checker.compare({"cases": {"CASE-REG00001": worse}}, _baseline(_row()))
    breaks = report["regressions"]["CASE-REG00001"]
    assert any("lane.ok" in b for b in breaks)
    assert any("gate.blocked" in b for b in breaks)


# --------------------------------------------------------------------------
# the watchdog
# --------------------------------------------------------------------------

def _case_with_progress(root: Path, case_id: str = "CASE-WATCH001") -> Path:
    case = root / case_id
    (case / "extractions").mkdir(parents=True)
    (case / "analysis" / "mode3_runs" / "M3-1").mkdir(parents=True)
    (case / "extractions" / "_tool_lane_progress.json").write_text(
        json.dumps({"done": 3, "total": 4}), encoding="utf-8"
    )
    (case / "analysis" / "mode3_runs" / "M3-1" / "state.json").write_text(
        json.dumps({"status": "running"}), encoding="utf-8"
    )
    return case


def test_watchdog_fires_on_a_running_case_that_stopped_writing(tmp_path, monkeypatch):
    case = _case_with_progress(tmp_path)
    # status reads as running...
    monkeypatch.setattr(checker, "run_status", lambda _case: "running")
    # ...and the progress files stopped changing 45 minutes ago
    old = time.time() - 45 * 60
    for path in checker._progress_files(case):
        import os

        os.utime(path, (old, old))

    result = checker.watchdog(case.name, tmp_path, stale_minutes=20)
    assert result["stale"] is True
    assert result["status"] == "running"
    assert result["newest_progress_age_minutes"] > 40
    assert len(result["progress_files"]) == 2


def test_watchdog_stays_quiet_while_progress_moves(tmp_path, monkeypatch):
    case = _case_with_progress(tmp_path)
    monkeypatch.setattr(checker, "run_status", lambda _case: "running")
    result = checker.watchdog(case.name, tmp_path, stale_minutes=20)
    assert result["stale"] is False


def test_watchdog_ignores_a_settled_run(tmp_path, monkeypatch):
    """A finished run has stopped writing by design - that is not staleness."""
    case = _case_with_progress(tmp_path)
    monkeypatch.setattr(checker, "run_status", lambda _case: "settled")
    old = time.time() - 45 * 60
    for path in checker._progress_files(case):
        import os

        os.utime(path, (old, old))

    result = checker.watchdog(case.name, tmp_path, stale_minutes=20)
    assert result["stale"] is False


def test_watchdog_reports_an_unknown_case(tmp_path):
    result = checker.watchdog("CASE-NOPE", tmp_path)
    assert result["stale"] is False
    assert result["reason"] == "case not found"


# --------------------------------------------------------------------------
# CLI surface: exit codes are the contract
# --------------------------------------------------------------------------

def test_cli_exit_codes(tmp_path, monkeypatch):
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps(_baseline(_row())), encoding="utf-8")
    monkeypatch.setattr(checker, "collect_all", lambda root, only=None: {
        "head": "abc1234", "cases": {"CASE-REG00001": _row()},
    })
    assert checker.main(["--baseline", str(baseline), "--cases-root", str(tmp_path)]) == 0

    worse = _row()
    worse["l1"] = {"counts": {"PROVEN": 3}}
    monkeypatch.setattr(checker, "collect_all", lambda root, only=None: {
        "head": "abc1234", "cases": {"CASE-REG00001": worse},
    })
    assert checker.main(["--baseline", str(baseline), "--cases-root", str(tmp_path)]) == 1

    monkeypatch.setattr(checker, "watchdog", lambda *a, **k: {"stale": True})
    assert checker.main(["--watch", "CASE-REG00001", "--cases-root", str(tmp_path)]) == 1


def test_collect_all_never_raises_on_one_broken_case(tmp_path, monkeypatch):
    (tmp_path / "CASE-GOOD0001").mkdir()
    (tmp_path / "CASE-BAD00001").mkdir()
    monkeypatch.setattr(
        checker,
        "_git_head",
        lambda: "abc1234",
    )
    import debug_leg_check

    def _collect(case_dir: Path) -> dict:
        if case_dir.name == "CASE-BAD00001":
            raise RuntimeError("unreadable")
        return {"case_id": case_dir.name}

    monkeypatch.setattr(debug_leg_check, "collect", _collect)
    result = checker.collect_all(tmp_path)
    assert "CASE-GOOD0001" in result["cases"]
    assert "error" in result["cases"]["CASE-BAD00001"]


@pytest.mark.parametrize("path,rule", [(p, r) for p, r, _m in checker.RULES])
def test_every_rule_is_reachable(path: str, rule: str):
    """A rule with a typo in its path would compare nothing and stay quiet."""
    assert path.split(".")[0] in {
        "lane", "gate", "index", "runs", "findings", "l1", "grade",
        "coverage", "reconciliation", "cross_mode",
    }
    assert rule in {"down", "up", "worse"}