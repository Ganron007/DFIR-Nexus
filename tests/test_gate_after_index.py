"""The gate is re-derived from what the index holds (WO-TA item 9).

Reproduced on SC1 (2026-10-10): the lane copied PowerShell transcripts, SetupAPI and WER into
their own families, and indexed them, but the completeness table still named those artifacts
STAGED or PRESENT_NO_PARSER, so the gate could not clear. Once the family has documents the
artifact is parsed. An artifact whose family holds nothing stays unprocessed.
"""
from __future__ import annotations

import json
from pathlib import Path

from nexus.langgraph.lane_gate import read_lane_gate, reconcile_after_index


def _case_with_completeness(tmp_path: Path, rows: list[dict]) -> Path:
    case = tmp_path / "CASE-GATE0001"
    run = case / "runs" / "RUN-20261011T000000Z-tools-gate"
    extractions = run / "extractions"
    extractions.mkdir(parents=True)
    # A run with no parsed data is skipped by the resolver, so the fixture carries one table.
    (extractions / "evtxecmd").mkdir()
    (extractions / "evtxecmd" / "rows.csv").write_text("a,b\n1,2\n", encoding="utf-8")
    (case / "active_runs.json").write_text(json.dumps({"tools": run.name}), encoding="utf-8")
    (run / "manifest.json").write_text(json.dumps({"status": "completed"}), encoding="utf-8")
    (extractions / "_tool_lane_ledger.json").write_text("[]", encoding="utf-8")
    (extractions / "_artifact_completeness.json").write_text(json.dumps(rows), encoding="utf-8")
    (case / "evidence.json").write_text("[]", encoding="utf-8")
    return case


def _row(artifact: str, status: str) -> dict:
    return {"artifact": artifact, "status": status, "tools": "-", "hits": 5, "reason": ""}


def test_a_staged_artifact_whose_family_is_indexed_becomes_parsed(tmp_path):
    case = _case_with_completeness(tmp_path, [_row("PowerShell Transcript Logs", "STAGED")])

    result = reconcile_after_index(case, {"pstranscript/x.txt": {"docs": 5, "deduped": 0}})

    assert result["changed"] == 1
    rows = json.loads((case / "runs" / "RUN-20261011T000000Z-tools-gate" / "extractions"
                       / "_artifact_completeness.json").read_text(encoding="utf-8"))
    assert rows[0]["status"] == "PARSED"
    assert "pstranscript" in rows[0]["reason"]


def test_a_staged_artifact_with_no_documents_stays_unprocessed(tmp_path):
    case = _case_with_completeness(tmp_path, [_row("SetupAPI Device Log", "STAGED")])

    result = reconcile_after_index(case, {"pstranscript/x.txt": {"docs": 5, "deduped": 0}})

    assert result["changed"] == 0
    rows = json.loads((case / "runs" / "RUN-20261011T000000Z-tools-gate" / "extractions"
                       / "_artifact_completeness.json").read_text(encoding="utf-8"))
    assert rows[0]["status"] == "STAGED"
    assert any("SetupAPI" in str(u.get("purpose")) for u in read_lane_gate(case).get("unprocessed") or [])


def test_an_artifact_no_tool_parses_still_blocks_the_gate(tmp_path):
    case = _case_with_completeness(tmp_path, [
        _row("PowerShell Transcript Logs", "STAGED"),
        _row("Thumbcache", "PRESENT_NO_PARSER"),
    ])

    reconcile_after_index(case, {"pstranscript/x.txt": {"docs": 5, "deduped": 0}})

    gate = read_lane_gate(case)
    assert gate.get("status") == "blocked"
    rows = json.loads((case / "runs" / "RUN-20261011T000000Z-tools-gate" / "extractions"
                       / "_artifact_completeness.json").read_text(encoding="utf-8"))
    assert [r["status"] for r in rows] == ["PARSED", "PRESENT_NO_PARSER"]


def test_no_completeness_file_is_a_no_op(tmp_path):
    case = tmp_path / "CASE-GATE0002"
    (case / "runs").mkdir(parents=True)

    assert reconcile_after_index(case, {}) == {"changed": 0}
