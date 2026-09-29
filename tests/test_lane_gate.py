"""Evidence gate - never skip evidence processing (operator rule, 2026-09-29).

The gate turns "unprocessed artifact" into a blocking, visible, examiner-owned
decision: analysis stages refuse to start until the lane re-runs the item so it
processes, or the examiner records an audited skip (HMAC, same as approvals).
"""
from __future__ import annotations

from pathlib import Path

from nexus.langgraph.lane_gate import (
    examiner_skip,
    gate_message,
    lane_gate_blocked,
    lane_stages,
    read_lane_gate,
    write_lane_gate,
)

_FAIL_ROW = {
    "tool": "mftecmd",
    "purpose": "NTFS metadata ($I30)",
    "reason": "Command timed out after 240s",
    "status": "FAIL",
}


def test_fail_row_blocks_and_skip_clears(tmp_path: Path):
    gate = write_lane_gate(tmp_path, "RUN-1", [_FAIL_ROW], ts="2026-09-29T00:00:00Z")
    assert gate["status"] == "blocked"
    assert gate["blocked_count"] == 1
    assert lane_gate_blocked(tmp_path)

    out = examiner_skip(tmp_path, examiner="gate_bot", reason="known tool loop")
    assert out["added"] == 1
    assert out["gate"]["status"] == "clear"
    assert lane_gate_blocked(tmp_path) == {}


def test_all_ok_clears_without_a_skip(tmp_path: Path):
    write_lane_gate(tmp_path, "RUN-1", [_FAIL_ROW])
    # A re-run that processes the item simply drops it from unprocessed.
    gate = write_lane_gate(tmp_path, "RUN-2", [{**_FAIL_ROW, "status": "OK"}])
    assert gate["status"] == "clear"
    assert gate["unprocessed"] == []


def test_stale_skip_for_a_now_parsed_item_is_dropped(tmp_path: Path):
    write_lane_gate(tmp_path, "RUN-1", [_FAIL_ROW])
    examiner_skip(tmp_path, examiner="gate_bot", reason="skip once")
    gate = write_lane_gate(tmp_path, "RUN-2", [{**_FAIL_ROW, "status": "OK"}])
    assert gate["examiner_skips"] == [], "the skipped item now parses - the skip is moot"


def test_skip_survives_a_rerun_that_still_fails(tmp_path: Path):
    write_lane_gate(tmp_path, "RUN-1", [_FAIL_ROW])
    examiner_skip(tmp_path, examiner="gate_bot", reason="accepted limitation")
    gate = write_lane_gate(tmp_path, "RUN-2", [_FAIL_ROW])
    assert gate["status"] == "clear", "an examiner decision must not be undone by a re-run"
    assert len(gate["examiner_skips"]) == 1


def test_message_names_the_tool_and_the_options(tmp_path: Path):
    write_lane_gate(tmp_path, "RUN-1", [_FAIL_ROW])
    msg = gate_message(read_lane_gate(tmp_path))
    assert "mftecmd" in msg and "$I30" in msg
    assert "lane/skip" in msg and "never skip evidence" in msg.lower()


def test_stages_cover_n1_to_n8(tmp_path: Path):
    write_lane_gate(tmp_path, "RUN-1", [_FAIL_ROW])
    stages = lane_stages(tmp_path)
    assert [s["stage"] for s in stages] == [f"N{i}" for i in range(1, 9)]
    n2 = next(s for s in stages if s["stage"] == "N2")
    assert n2["status"] == "blocked"
    assert "1 unprocessed" in n2["detail"]


def test_lane_gate_error_helper_blocks_and_clears(tmp_path: Path):
    from nexus.dashboard.app import _lane_gate_error

    write_lane_gate(tmp_path, "RUN-1", [_FAIL_ROW])
    resp = _lane_gate_error(tmp_path)
    assert resp is not None and resp.status_code == 409

    examiner_skip(tmp_path, examiner="gate_bot", reason="accepted")
    assert _lane_gate_error(tmp_path) is None
