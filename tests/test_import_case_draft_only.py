"""D139 (third-eye R01): an imported bundle never brings approval with it.

The MCP tool merged imported findings verbatim into the active case, so a record carrying
`status: APPROVED` became an approved finding nobody approved. It now names its case, and
every imported record is staged again as a DRAFT through the normal validator.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from _audit_rows import cite_rows


@pytest.fixture()
def tool_and_case(tmp_path):
    from mcp.server.fastmcp import FastMCP

    from nexus.audit import AuditWriter
    from nexus.config import settings
    from nexus.tools import case as case_tools

    case = settings.cases_root / "CASE-IMPORT01"
    (case / "audit").mkdir(parents=True)
    (case / "analysis").mkdir()
    (case / "CASE.yaml").write_text(
        yaml.safe_dump({"case_id": case.name, "status": "open"}), encoding="utf-8")
    server = FastMCP("import-test")
    case_tools.register_tools(server, AuditWriter("t", audit_dir=tmp_path / "audit"))
    return server._tool_manager._tools["import_case"].fn, case


def _stored(case: Path, name: str) -> list[dict]:
    from nexus.case_manager import CaseManager

    cm = CaseManager()
    return cm._load_findings(case) if name == "findings" else cm._load_timeline(case)


def test_import_needs_a_case(tool_and_case):
    tool, case = tool_and_case
    out = tool(bundle_json=json.dumps({"findings": [{"id": "F-x", "status": "APPROVED"}]}))
    assert "case_id is required" in out["error"]
    assert _stored(case, "findings") == []


def test_an_approved_record_is_imported_as_a_draft(tool_and_case):
    tool, case = tool_and_case
    aid = cite_rows(case, [{"loc": "evtx.csv:7", "detail": "4688 powershell -enc", "host": "ws01"}])
    bundle = {
        "findings": [{
            "id": "F-OTHER-001", "status": "APPROVED", "approved_by": "someone",
            "approved_at": "2026-01-01T00:00:00Z",
            "title": "Encoded PowerShell on ws01", "observation": "4688 with -enc",
            "interpretation": "a staged payload ran", "confidence": "MEDIUM",
            "confidence_justification": "one process-creation row",
            "audit_ids": [aid], "artifacts": [{"audit_id": aid}],
        }],
        "timeline": [{"id": "T-OTHER-1", "status": "APPROVED",
                      "timestamp": "2023-07-10T10:00:00Z", "description": "payload ran"}],
    }
    out = tool(bundle_json=json.dumps(bundle), case_id=case.name)
    assert out["findings_imported"] == 1, out
    findings = _stored(case, "findings")
    assert len(findings) == 1
    stored = findings[0]
    assert stored["status"] == "DRAFT"
    assert stored["id"] != "F-OTHER-001"
    assert not stored.get("approved_by")
    assert stored["source"] == "import"
    assert stored["provenance"]["origin"] == "import"
    assert stored["provenance"]["imported_id"] == "F-OTHER-001"
    assert stored["provenance"]["imported_status"] == "APPROVED"
    events = _stored(case, "timeline")
    assert [e["status"] for e in events] == ["DRAFT"]


def test_a_record_the_validator_refuses_is_reported_not_stored(tool_and_case):
    tool, case = tool_and_case
    bundle = {"findings": [{"id": "F-NOAUDIT", "status": "APPROVED", "title": "no evidence",
                            "observation": "x", "interpretation": "y"}]}
    out = tool(bundle_json=json.dumps(bundle), case_id=case.name)
    assert out["findings_imported"] == 0
    assert out["findings_rejected"][0]["id"] == "F-NOAUDIT"
    assert _stored(case, "findings") == []
