"""WO-4 (D40): Mode 2/3 runs build the signal map before the graph runs.

Without it, `analysis/signal_map.csv` only existed when a portal route happened
to call the briefing, so CLI / `/mode3/run` cases audited `needles: unknown`.
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch


def _case(tmp_path: Path, name: str) -> Path:
    case = tmp_path / name
    (case / "analysis").mkdir(parents=True)
    (case / "extractions" / "hayabusa").mkdir(parents=True)
    (case / "extractions" / "hayabusa" / "hits.csv").write_text(
        "time,eventid,detail\n2026-09-01T00:00:00Z,4688,psexec started\n",
        encoding="utf-8",
    )
    (case / "CASE.yaml").write_text(
        "name: Signal map fixture\nstatus: active\n"
        "intake:\n  question: did psexec run on ws01\n",
        encoding="utf-8",
    )
    return case


def _seat(spawn, _board, step):
    return {
        "entry_id": f"{spawn['role']}-{step}",
        "agent_id": f"{spawn['role']}-{step}",
        "role": spawn["role"],
        "family": spawn.get("family") or "",
        "superstep": step,
        "claims": [],
        "open_questions": [],
    }


def _assert_signal_map(case: Path) -> None:
    assert (case / "analysis" / "signal_map.csv").is_file()
    assert (case / "analysis" / "briefing.md").is_file()
    events = "".join(
        p.read_text(encoding="utf-8", errors="replace") for p in case.rglob("*.jsonl")
    )
    assert "briefing.ready" in events

    from nexus.analysis.coverage_audit import build_coverage_audit

    needles = build_coverage_audit(case).get("needles") or {}
    assert needles.get("status") != "unknown", needles


def test_mode3_run_builds_signal_map(tmp_path):
    from nexus.modes.multi_agent import run_mode3

    case = _case(tmp_path, "CASE-M3SIG")
    record = run_mode3(
        case, "did psexec run on ws01", families=[("hayabusa", 1)],
        seat_fn=_seat, es_ok=True,
    )
    assert record["status"] == "completed", record.get("stop_reason")
    _assert_signal_map(case)


def test_mode2_run_builds_signal_map(tmp_path):
    from nexus.modes import multi_role as m3

    case = _case(tmp_path, "CASE-M2SIG")
    with patch.object(m3, "plan_work_orders", return_value=[]):
        record = m3.run_mode2(case, "did psexec run on ws01", model=object(), es_ok=True)
    assert record["status"] in ("completed", "planned"), record.get("status")
    _assert_signal_map(case)
