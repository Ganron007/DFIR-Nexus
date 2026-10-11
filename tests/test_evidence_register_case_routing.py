"""evidence_register records the evidence in the case its call names, and a pipeline run names its own (2026-10-11).

Reproduced on CASE-C5B04D31: the pipeline's register step sent only a path, and the evidence_register tool had no
case parameter, so the registration went to the active case (CASE-D6B93BF1) instead of the run's case. The tool
now takes a case_id, and the pipeline sends its run's case. An unnamed call still registers into the active case.
"""
from __future__ import annotations

import ast
import os
import sqlite3
from pathlib import Path

ACTIVE = "CASE-A1B2C3D4"
TARGET = "CASE-E5F6A7B8"


def _case(root: Path, case_id: str) -> None:
    case = root / case_id
    (case / "audit").mkdir(parents=True)
    (case / "CASE.yaml").write_text(f"case_id: {case_id}\n", encoding="utf-8")


def _setup(tmp_path: Path) -> tuple[Path, Path]:
    from nexus.case.compat import get_sqlite_manager
    from nexus.config import settings

    root = settings.cases_root  # redirected to a temporary root by tests/conftest.py
    registry = get_sqlite_manager()
    for case_id in (ACTIVE, TARGET):
        _case(root, case_id)
        registry.create_case(name=f"routing {case_id}", case_id=case_id)
    Path(os.environ["NEXUS_ACTIVE_CASE_FILE"]).write_text(str(root / ACTIVE), encoding="utf-8")
    evidence = tmp_path / "evidence" / "sample.evtx"
    evidence.parent.mkdir()
    evidence.write_bytes(b"sample evidence bytes for the routing test\n" * 8)
    return root, evidence


def _tool(tmp_path: Path):
    from mcp.server.fastmcp import FastMCP

    from nexus.audit import AuditWriter
    from nexus.tools import case as case_tools

    server = FastMCP("evidence-routing-test")
    case_tools.register_tools(server, AuditWriter("t", audit_dir=tmp_path / "audit"))
    return server._tool_manager._tools["evidence_register"].fn


def _registered_case_ids(root: Path, evidence: Path) -> list[str]:
    db = root / "cases.db"
    if not db.is_file():
        return []
    target_path = os.path.normcase(str(evidence.resolve()))
    with sqlite3.connect(db) as conn:
        rows = conn.execute("select case_id, file_path from evidence").fetchall()
    return [case for case, path in rows if os.path.normcase(str(path or "")) == target_path]


def test_a_registration_names_its_case(tmp_path):
    root, evidence = _setup(tmp_path)
    register = _tool(tmp_path)

    result = register(path=str(evidence), description="routing test", case_id=TARGET)

    assert "error" not in result, result
    assert _registered_case_ids(root, evidence) == [TARGET]


def test_an_unnamed_registration_still_uses_the_active_case(tmp_path):
    root, evidence = _setup(tmp_path)
    register = _tool(tmp_path)

    result = register(path=str(evidence), description="routing test")

    assert "error" not in result, result
    assert _registered_case_ids(root, evidence) == [ACTIVE]


def test_an_unknown_case_is_refused_and_nothing_is_registered(tmp_path):
    root, evidence = _setup(tmp_path)
    register = _tool(tmp_path)

    result = register(path=str(evidence), description="routing test", case_id="CASE-DEADBEEF")

    assert "error" in result, result
    assert _registered_case_ids(root, evidence) == []


def test_the_pipeline_names_its_run_case_on_the_register_call():
    """Wiring pin: register_evidence sends its run's case with the evidence_register call."""
    src = Path("src/nexus/langgraph/llm_pipeline.py").read_text(encoding="utf-8")
    fn = next(n for n in ast.walk(ast.parse(src))
              if isinstance(n, ast.AsyncFunctionDef) and n.name == "register_evidence")
    body = ast.get_source_segment(src, fn) or ""

    assert '"case_id": case_id' in body
