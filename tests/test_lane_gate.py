"""Evidence gate - never skip evidence processing (operator rule, 2026-09-29).

The gate turns "unprocessed artifact" into a blocking, visible, examiner-owned
decision: analysis stages refuse to start until the lane re-runs the item so it
processes, or the examiner records an audited skip (HMAC, same as approvals).
"""
from __future__ import annotations

from pathlib import Path

from nexus.langgraph.lane_gate import (
    coverage_snapshot,
    examiner_skip,
    gate_message,
    lane_gate_blocked,
    lane_stages,
    pending_family_notice,
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
    assert gate["jobs"][0]["state"] == "failed"
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


def test_a_skipped_job_blocks_when_nothing_else_processed(tmp_path: Path):
    """The K1 shape: a SIFT discovery skip and no parser run.

    SIFT may wait, but this case had no evidence root *and* nothing processed, so
    the run examined nothing. It must not read as a clean pass.
    """
    gate = write_lane_gate(tmp_path, "RUN-1", [{
        "tool": "(discovery)",
        "purpose": "SIFT evidence root",
        "host": "sift",
        "status": "SKIP",
        "reason": "No SIFT evidence root - set NEXUS_SIFT_EVIDENCE_ROOT",
    }])
    assert gate["status"] == "waiting", "SIFT-deferred, not clean"
    assert gate["processed_count"] == 0
    assert gate["waiting_count"] == 1


def test_a_pass_that_processed_nothing_is_never_clear(tmp_path: Path):
    """Even with no rows at all, a lane pass that ran nothing is not clean."""
    gate = write_lane_gate(tmp_path, "RUN-1", [])
    assert gate["status"] == "blocked"
    assert gate["no_evidence_processed"] is True
    assert gate["processed_count"] == 0


def test_an_examiner_decision_still_clears_a_waiting_item(tmp_path: Path):
    """The exemption is preserved: an audited skip is a decision, not a no-op."""
    write_lane_gate(tmp_path, "RUN-1", [{
        "tool": "(discovery)",
        "purpose": "SIFT evidence root",
        "host": "sift",
        "status": "SKIP",
        "reason": "no evidence root on this case",
    }])
    out = examiner_skip(tmp_path, examiner="gate_bot", reason="no memory image here")
    assert out["added"] == 1
    assert out["gate"]["status"] == "clear"
    assert lane_gate_blocked(tmp_path) == {}


def test_a_nothing_processed_block_can_be_settled_by_the_examiner(tmp_path: Path):
    """A pass that ran nothing and cannot be run again must not be a dead end."""
    write_lane_gate(tmp_path, "RUN-1", [{
        "tool": "pecmd",
        "purpose": "",
        "host": "windows",
        "status": "SKIP",
        "reason": "missing Prefetch",
    }])
    assert lane_gate_blocked(tmp_path), "nothing processed, so this must block"

    out = examiner_skip(tmp_path, examiner="gate_bot", reason="evidence holds no prefetch")
    assert out["added"] == 1, "the not-applicable row must be settleable"
    assert out["gate"]["status"] == "clear"
    assert lane_gate_blocked(tmp_path) == {}


def test_a_processed_job_clears_without_a_skip(tmp_path: Path):
    gate = write_lane_gate(tmp_path, "RUN-1", [
        {"tool": "evtxecmd", "purpose": "Security.evtx", "status": "OK"},
    ])
    assert gate["status"] == "clear"
    assert gate["processed_count"] == 1
    assert gate["no_evidence_processed"] is False


_SIFT_SKIP_ROW = {
    "tool": "(discovery)",
    "purpose": "SIFT evidence root",
    "host": "sift",
    "reason": "No SIFT evidence root - set NEXUS_SIFT_EVIDENCE_ROOT",
    "status": "SKIP",
}


def test_sift_work_waits_and_is_never_reported_as_clear(tmp_path: Path):
    """SIFT is the one lane that may wait (operator rule) - but waiting is not clear.

    It is also not *blocked*: no examiner decision is needed to continue, because
    the evidence is queued for the host rather than dropped.
    """
    from nexus.langgraph.lane_gate import sift_waiting_message

    gate = write_lane_gate(tmp_path, "RUN-1", [_SIFT_SKIP_ROW])
    assert gate["status"] == "waiting", "SIFT-deferred work is not a clean pass"
    assert gate["status"] != "clear"
    assert lane_gate_blocked(tmp_path) == {}, "waiting on SIFT must not block analysis"
    assert len(gate["waiting_sift"]) == 1
    assert gate["unprocessed"] == [], "SIFT items are not 'unprocessed', they are waiting"
    assert gate["waiting_count"] == 1
    assert "SIFT evidence root" in sift_waiting_message(gate)


def test_a_lone_skip_with_nothing_processed_is_not_clear(tmp_path: Path):
    """No parser ran, so the gate must not report a clean pass.

    Reproduces the K1 wiring defect: one `(discovery)` SKIP meant the lane read
    no evidence, and the gate said `clear` - a no-op that looked like a clean case.
    """
    gate = write_lane_gate(tmp_path, "RUN-1", [{
        "tool": "(discovery)",
        "purpose": "locate evidence",
        "host": "windows",
        "status": "SKIP",
        "reason": "No recognized evidence shape",
    }])
    assert gate["status"] == "blocked", "a pass that processed nothing is not clean"
    assert gate["no_evidence_processed"] is True
    assert gate["processed_count"] == 0
    assert lane_gate_blocked(tmp_path)


def test_a_tool_that_does_not_apply_does_not_block(tmp_path: Path):
    """A not-applicable tool is not skipped evidence, so it must not block.

    Suzaku 2.x is cloud-log only, so it correctly skips on local EVTX while the
    EVTX parsers process the evidence. Blocking there would refuse analysis for a
    run that did its job.
    """
    gate = write_lane_gate(tmp_path, "RUN-1", [
        {"tool": "evtxecmd", "purpose": "Parse all EVTX", "host": "windows", "status": "OK"},
        {"tool": "hayabusa", "purpose": "EVTX timeline", "host": "windows", "status": "OK"},
        {"tool": "suzaku", "purpose": "", "host": "windows", "status": "SKIP",
         "reason": "Suzaku 2.x is cloud-log only (no local EVTX timeline)"},
    ])
    assert gate["status"] == "clear"
    assert gate["unprocessed"] == [], "a not-applicable tool is not unprocessed evidence"
    assert gate["processed_count"] == 2
    # It stays visible rather than disappearing.
    assert [j["tool"] for j in gate["jobs"]].count("suzaku") == 1
    assert gate["jobs"][2]["state"] == "skipped"


def test_processed_evidence_plus_waiting_sift_is_waiting_not_clear(tmp_path: Path):
    """Work landed, but SIFT is still outstanding - say so rather than 'clear'."""
    gate = write_lane_gate(tmp_path, "RUN-1", [
        {"tool": "evtxecmd", "purpose": "Parse all EVTX", "host": "windows", "status": "OK"},
        _SIFT_SKIP_ROW,
    ])
    assert gate["status"] == "waiting"
    assert gate["processed_count"] == 1
    assert gate["waiting_count"] == 1


def test_examiner_can_settle_a_waiting_sift_item(tmp_path: Path):
    """'This evidence has no memory image' is the examiner's call to make."""
    write_lane_gate(tmp_path, "RUN-1", [_SIFT_SKIP_ROW])
    out = examiner_skip(tmp_path, examiner="gate_bot", reason="no memory image here")
    assert out["added"] == 1
    assert out["gate"]["status"] == "clear"
    assert lane_gate_blocked(tmp_path) == {}


def test_waiting_sift_families_are_named_as_pending_to_a_model(tmp_path: Path):
    """A model must no more claim a waiting family absent than a failed one."""
    write_lane_gate(tmp_path, "RUN-1", [_SIFT_SKIP_ROW])
    snap = coverage_snapshot(tmp_path)
    assert snap["status"] == "waiting"
    assert snap["waiting_sift"] == ["SIFT evidence root"]
    assert "SIFT evidence root" in pending_family_notice(tmp_path)
    assert "absent" in pending_family_notice(tmp_path).lower()


def test_stages_report_the_waiting_state(tmp_path: Path):
    write_lane_gate(tmp_path, "RUN-1", [_SIFT_SKIP_ROW])
    n2 = next(s for s in lane_stages(tmp_path) if s["stage"] == "N2")
    assert n2["status"] == "waiting"
    assert "SIFT" in n2["detail"]


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


def test_processed_family_is_announced_to_a_running_mode(tmp_path: Path):
    run_dir = tmp_path / "analysis" / "mode2_runs"
    run_dir.mkdir(parents=True)
    (run_dir / "M2-test.json").write_text(
        '{"run_id": "M2-test", "status": "running"}',
        encoding="utf-8",
    )
    write_lane_gate(tmp_path, "RUN-1", [{
        "tool": "evtxecmd",
        "purpose": "Security.evtx",
        "family": "evtxecmd",
        "status": "OK",
    }])
    notice = (run_dir / "M2-test.steering.jsonl").read_text(encoding="utf-8")
    assert "evtxecmd" in notice
    assert pending_family_notice(tmp_path) == ""


def test_failed_job_is_named_as_pending(tmp_path: Path):
    write_lane_gate(tmp_path, "RUN-1", [_FAIL_ROW])
    notice = pending_family_notice(tmp_path)
    assert "NTFS metadata" in notice
    assert "absent" in notice
