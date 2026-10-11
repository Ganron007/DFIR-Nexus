"""A finding or timeline event lands in the case its tool call names, not the global active case (2026-10-11).

Reproduced on CASE-C5B04D31: Mode 1's staging called the record_finding MCP tool, which had no case parameter,
so seven DRAFT findings were written to CASE-D6B93BF1, the active case. The tools now take a case_id, and the
pipeline names its run's case. A call that names no case still stages into the active case, as before.
"""
from __future__ import annotations

import ast
import json
import os
import sqlite3
from pathlib import Path

import pytest

ACTIVE = "CASE-A1B2C3D4"
TARGET = "CASE-E5F6A7B8"
AID = "evtxecmd-examiner-20261011-001"

FINDING = dict(
    title="PST file staged",
    observation="Outlook PST copied to a staging folder",
    interpretation="possible collection before exfiltration",
    confidence="LOW",
    confidence_justification="one row, no corroboration yet",
    artifacts=[{"audit_id": AID}],
)


def _case(root: Path, case_id: str) -> Path:
    case = root / case_id
    (case / "audit").mkdir(parents=True)
    (case / "CASE.yaml").write_text(f"case_id: {case_id}\n", encoding="utf-8")
    (case / "audit" / "tool.jsonl").write_text(
        json.dumps({"audit_id": AID, "source": "mcp", "tool": "test"}) + "\n", encoding="utf-8")
    return case


@pytest.fixture()
def cases():
    from nexus.config import settings

    root = settings.cases_root  # redirected to a temporary root by tests/conftest.py
    active = _case(root, ACTIVE)
    target = _case(root, TARGET)
    Path(os.environ["NEXUS_ACTIVE_CASE_FILE"]).write_text(str(active), encoding="utf-8")
    return root, active, target


def _tools(tmp_path: Path):
    from mcp.server.fastmcp import FastMCP

    from nexus.audit import AuditWriter
    from nexus.tools import forensic

    server = FastMCP("case-routing-test")
    forensic.register_tools(server, AuditWriter("t", audit_dir=tmp_path / "audit"))
    return server._tool_manager._tools


def _stored_case_ids(root: Path) -> list[str]:
    db = root / "cases.db"
    if not db.is_file():
        return []
    with sqlite3.connect(db) as conn:
        return [row[0] for row in conn.execute("select case_id from findings")]


def test_a_finding_names_its_case_and_leaves_the_active_case_alone(cases, tmp_path):
    root, _active, _target = cases
    record = _tools(tmp_path)["record_finding"].fn

    result = record(case_id=TARGET, **FINDING)

    assert result.get("status") == "STAGED", result
    assert _stored_case_ids(root) == [TARGET]


def test_an_unnamed_finding_still_stages_into_the_active_case(cases, tmp_path):
    root, _active, _target = cases
    record = _tools(tmp_path)["record_finding"].fn

    result = record(**FINDING)

    assert result.get("status") == "STAGED", result
    assert _stored_case_ids(root) == [ACTIVE]


def test_an_unknown_case_is_refused_and_nothing_is_staged(cases, tmp_path):
    root, _active, _target = cases
    record = _tools(tmp_path)["record_finding"].fn

    result = record(case_id="CASE-DEADBEEF", **FINDING)

    assert "error" in result, result
    assert _stored_case_ids(root) == []


def test_a_timeline_event_names_its_case(cases, tmp_path):
    _root, active, target = cases
    record = _tools(tmp_path)["record_timeline_event"].fn

    result = record(timestamp="2026-10-11T04:00:00+00:00", description="PST copied", case_id=TARGET)

    assert result.get("status") == "STAGED", result
    assert "PST copied" in (target / "timeline.json").read_text(encoding="utf-8")
    assert not (active / "timeline.json").exists()


def test_the_pipeline_names_its_run_case_on_both_staging_calls():
    """Wiring pin: stage_findings sends its run's case on the finding call and on the timeline call."""
    src = Path("src/nexus/langgraph/llm_pipeline.py").read_text(encoding="utf-8")
    fn = next(n for n in ast.walk(ast.parse(src))
              if isinstance(n, ast.AsyncFunctionDef) and n.name == "stage_findings")
    body = ast.get_source_segment(src, fn) or ""

    assert 'payload["case_id"] = stage_case_id' in body
    assert '"case_id": stage_case_id' in body
