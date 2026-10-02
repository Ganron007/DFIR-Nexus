"""WO-V5: a SIFT capture is persisted whole, not as the reply slice.

The defect (pre-existing since 2026-08-13): ``_execute`` returned the 10 KB
response slice and ``run_command`` persisted *that*, so every SIFT tool that
writes to stdout — ``vol -r jsonl``, ``fls``, ``mmls``, ``strings`` — was cut
in the case file while the audit recorded the full length.

These run a real subprocess: the capturing reader and the two different cuts
(transport reply vs capture) are what is under test, not a stub.
"""
from __future__ import annotations

import sys

import pytest

from nexus.config import settings
from nexus.langgraph.tool_lane import persist_truncation_reason
from nexus.tools.sift import _execute


def _py(code: str) -> list[str]:
    return [sys.executable, "-c", code]


def test_a_long_capture_is_kept_whole_even_when_the_reply_is_sliced(monkeypatch):
    monkeypatch.setattr(settings, "max_output_bytes", 5_000_000)
    monkeypatch.setattr(settings, "response_byte_budget", 10_240)

    lines = 500
    result = _execute(_py(
        f"print('\\n'.join('row-%d-' % i + 'y' * 40 for i in range({lines})))"
    ))

    assert result["exit_code"] == 0
    full = result["stdout_full"]
    assert len(full.splitlines()) == lines, "the capture lost rows"
    assert "more bytes truncated" not in full
    assert len(full) > 10_240, "the fixture must exceed the reply budget to test the slice"
    # The reply is sliced, and says so — that is the transport budget.
    assert result["truncated"] is True
    assert "more bytes truncated" in result["stdout"]
    assert len(result["stdout"]) <= 10_240 + 80
    # The capture is not the slice, and its length is the capture's.
    assert len(full) > len(result["stdout"])
    assert result["stdout_full_length"] == len(full)
    assert result["persist_truncated"] is False, "the capture was not capped"


def test_hitting_the_capture_cap_is_flagged_not_silent(monkeypatch):
    monkeypatch.setattr(settings, "max_output_bytes", 2_048)
    monkeypatch.setattr(settings, "response_byte_budget", 10_240)

    result = _execute(_py("print('x' * 50000)"))

    assert result["persist_truncated"] is True
    assert result["stdout_full_length"] <= 2_048
    # A capped capture is not a success, and the lane has a reason to say why.
    reason = persist_truncation_reason(result)
    assert reason and "byte cap" in reason


def test_a_whole_capture_carries_no_truncation_reason(monkeypatch):
    monkeypatch.setattr(settings, "max_output_bytes", 5_000_000)
    monkeypatch.setattr(settings, "response_byte_budget", 10_240)

    result = _execute(_py("print('one short row')"))
    assert result["persist_truncated"] is False
    assert result["truncated"] is False
    assert persist_truncation_reason(result) == ""


def test_a_jsonl_capture_larger_than_the_reply_budget_keeps_every_row(monkeypatch):
    """``vol -r jsonl`` shape: one JSON object per line, over the reply budget."""
    import json

    monkeypatch.setattr(settings, "max_output_bytes", 5_000_000)
    monkeypatch.setattr(settings, "response_byte_budget", 10_240)

    rows = 500
    code = (
        "import json\n"
        f"for i in range({rows}):\n"
        "    print(json.dumps({'PID': i, 'ImageFileName': 'p%d.exe' % i}))\n"
    )
    result = _execute(_py(code))
    captured = [line for line in result["stdout_full"].splitlines() if line.strip()]
    assert len(captured) == rows
    parsed = [json.loads(line) for line in captured]
    assert parsed[0]["PID"] == 0 and parsed[-1]["PID"] == rows - 1
    # The reply carries far fewer, which is the point: the slice is not the file.
    assert len(result["stdout"].splitlines()) < rows


def test_execute_reports_the_command_that_ran(monkeypatch):
    monkeypatch.setattr(settings, "max_output_bytes", 5_000_000)
    result = _execute(_py("print('ok')"))
    assert result["command"].strip()
    assert result["stdout_full"].strip() == "ok"


@pytest.mark.parametrize("status", [{}, {"persist_truncated": False}])
def test_no_reason_for_a_complete_result(status):
    assert persist_truncation_reason(status) == ""
