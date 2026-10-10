"""Hayabusa with zero detections is a zero-entry result, not a missing output (tool lane).

Reproduced on the 2026-10-10 design-flow run: hayabusa parsed 64 events, 0 matched a rule, and it
wrote a 0-byte evtx-timeline.csv. The lane read the empty file as "no output" and failed the job.
Its own summary says "Events with hits / Total events: 0 / 64": that is the tool's testimony that
the logs held events and none matched. The decision turns on the hit count, and only on it.
"""
from __future__ import annotations

from nexus.langgraph.tool_lane import ToolJob, _empty_output_status

ESC = chr(27)


def _summary(hits: int, events: int) -> str:
    # The summary line as hayabusa prints it: colour codes around every value.
    return (
        f"{ESC}[38;2;255;255;0mEvents with hits{ESC}[0m / "
        f"{ESC}[38;2;0;255;255mTotal events{ESC}[0m: "
        f"{ESC}[38;2;255;255;0m{hits}{ESC}[0m / "
        f"{ESC}[38;2;0;255;0m{events}{ESC}[0m (0.00%)\n"
    )


def _job(tmp_path) -> ToolJob:
    csv_file = tmp_path / "evtx-timeline.csv"
    csv_file.write_bytes(b"")
    return ToolJob(
        host="windows", tool="hayabusa",
        argv=["hayabusa", "dfir-timeline", "-d", "pack", "-o", str(csv_file), "-w", "-C", "-Q"],
        purpose="EVTX timeline pack (2 logs)",
    )


def test_zero_hits_over_parsed_events_is_a_zero_entry_result(tmp_path):
    status, reason = _empty_output_status(_job(tmp_path), {"stdout": _summary(0, 64)})
    assert status == "SKIP"
    assert "zero entries" in reason


def test_hits_with_an_empty_timeline_is_still_a_failed_output(tmp_path):
    status, reason = _empty_output_status(_job(tmp_path), {"stdout": _summary(3, 64)})
    assert status == "FAIL"
    assert "no output file" in reason
