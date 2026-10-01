"""Examiner confirmation that a pre-processed file covers the raw artifact."""
from nexus.langgraph.lane_gate import confirm_preprocessed_pair, read_lane_gate, write_lane_gate


def test_confirmed_pair_clears_the_matching_raw_job(tmp_path):
    case = tmp_path / "CASE-P"
    (case / "analysis").mkdir(parents=True)
    write_lane_gate(
        case,
        "run-1",
        [{
            "tool": "$LogFile",
            "purpose": "$LogFile",
            "status": "FAIL",
            "reason": "raw logfile still queued",
        }],
    )
    gate = confirm_preprocessed_pair(
        case,
        raw_name="$LogFile",
        output_name="LogFile.csv",
        output_sha256="ab" * 32,
        examiner="examiner",
    )
    assert gate["status"] == "clear"
    assert gate["pairs"][0]["output"] == "LogFile.csv"
    assert "pre-processed output supplied" in gate["pairs"][0]["reason"]
    assert read_lane_gate(case)["status"] == "clear"
