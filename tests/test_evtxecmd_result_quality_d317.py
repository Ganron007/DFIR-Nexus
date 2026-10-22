"""D317: reconcile real EvtxECmd output instead of treating partial CSV as complete.

The sample-dependent check reads an unmodified captured stdout file from the
operator's live S08 run. It has no committed or hand-written evidence fixture.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

import pytest

from nexus.langgraph.tool_lane import ToolJob, _evtxecmd_incomplete_reason


def test_live_evtxecmd_output_with_duplicates_and_record_errors_fails_closed():
    raw_path = os.environ.get("NEXUS_D317_EVTX_STDOUT", "")
    raw_count = os.environ.get("NEXUS_D317_EVTX_EXPECTED_INPUTS", "")
    if not raw_path or not raw_count:
        pytest.skip(
            "set NEXUS_D317_EVTX_STDOUT and NEXUS_D317_EVTX_EXPECTED_INPUTS "
            "to use a captured real EvtxECmd result"
        )
    stdout = Path(raw_path)
    if not stdout.is_file():
        pytest.skip("the captured real EvtxECmd stdout file is not present")
    try:
        expected_inputs = int(raw_count)
    except ValueError:
        pytest.skip("NEXUS_D317_EVTX_EXPECTED_INPUTS must be an integer")
    if expected_inputs <= 0:
        pytest.skip("NEXUS_D317_EVTX_EXPECTED_INPUTS must be positive")

    job = ToolJob(
        host="windows",
        tool="evtxecmd",
        argv=["evtxecmd", "-d", "<redacted>", "--csv", "<redacted>", "--dedupe", "false"],
        purpose=f"Parse all EVTX from evidence ({expected_inputs} logs)",
    )
    captured = stdout.read_text(encoding="utf-8", errors="replace")
    error_counts = [
        int(value.replace(",", ""))
        for value in re.findall(r"(?im)^.*\berror count:\s*(\d[\d,]*)\s*$", captured)
    ]
    reason = _evtxecmd_incomplete_reason(
        job, {"stdout": captured, "output_saved_to": str(stdout)}
    )

    assert f" of {expected_inputs} planned EVTX inputs" in reason
    assert "record errors" in reason
    assert f"({sum(error_counts)} record error(s))" in reason
