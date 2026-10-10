"""WO-TA item 9: the gate reads the completeness table.

The lane has written ``_artifact_completeness.json`` for a while, but nothing
consumed it - so a volume full of artifacts no tool parses still produced a
``clear`` gate. That is D43's shape one artifact at a time: the gate audited the
jobs that ran, not the evidence that exists.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from nexus.langgraph.lane_gate import write_lane_gate


def _gate(tmp_path: Path, rows: list[dict], ledger: list[dict] | None = None) -> dict:
    case = tmp_path / "CASE-GATE9"
    case.mkdir(parents=True, exist_ok=True)
    return write_lane_gate(
        case,
        "run-1",
        ledger or [{"tool": "evtxecmd", "status": "OK", "purpose": "parse"}],
        completeness=rows,
    )


def test_unparsed_artifacts_block_the_gate(tmp_path: Path):
    gate = _gate(tmp_path, [
        {"artifact": "weird.dat", "status": "PRESENT_NO_PARSER", "tool": "none"},
        {"artifact": "ok.evtx", "status": "OK", "tool": "evtxecmd"},
    ])
    assert gate["status"] == "blocked"
    assert gate["blocked_count"] == 1
    assert gate["unprocessed"][0]["purpose"] == "weird.dat [PRESENT_NO_PARSER]"
    assert gate["unprocessed"][0]["kind"] == "completeness"


def test_staged_but_unprocessed_blocks_the_gate(tmp_path: Path):
    gate = _gate(tmp_path, [
        {"artifact": "a.log", "status": "STAGED", "tool": "logfileparser"},
    ])
    assert gate["status"] == "blocked"
    assert "STAGED" in gate["unprocessed"][0]["purpose"]


def test_a_fully_parsed_volume_stays_clear(tmp_path: Path):
    """The point of the check: OK and ABSENT rows are not unprocessed evidence."""
    gate = _gate(tmp_path, [
        {"artifact": "a.evtx", "status": "OK", "tool": "evtxecmd"},
        {"artifact": "b.bin", "status": "ABSENT", "tool": "none"},
        {"artifact": "c.evtx", "status": "PARSED", "tool": "evtxecmd"},
    ])
    assert gate["status"] != "blocked"
    assert gate["blocked_count"] == 0


def test_a_failed_parser_row_blocks(tmp_path: Path):
    gate = _gate(tmp_path, [
        {"artifact": "d.evtx", "status": "FAIL", "tool": "evtxecmd"},
    ])
    assert gate["status"] == "blocked"
    assert "FAIL" in gate["unprocessed"][0]["purpose"]


def test_no_completeness_table_changes_nothing(tmp_path: Path):
    """A lane that never wrote the table must behave exactly as before."""
    gate = _gate(tmp_path, [], ledger=[{"tool": "evtxecmd", "status": "OK"}])
    assert gate["status"] != "blocked"


def test_the_gate_is_persisted_with_the_rows(tmp_path: Path):
    gate = _gate(tmp_path, [
        {"artifact": "weird.dat", "status": "PRESENT_NO_PARSER", "tool": "none"},
    ])
    written = tmp_path / "CASE-GATE9" / "analysis" / "lane_gate.json"
    assert written.is_file()
    import json

    persisted = json.loads(written.read_text(encoding="utf-8"))
    assert persisted["status"] == "blocked"
    assert gate["blocked_count"] == persisted["blocked_count"]
