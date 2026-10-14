"""D70: a finding's entity survives every hop from the model's reply to the DRAFT.

The parser used to rebuild each candidate field by field, so an entity the model wrote was
dropped before it reached the record. These tests walk one Mode 1 candidate through the
parser and the record-finding payload, and check the value at each hop.
"""
from __future__ import annotations

from nexus.langgraph.hunt_parser import normalize_candidate, parse_hunt_candidates
from nexus.langgraph.llm_pipeline import _finding_tool_payload

ENTITY = {"type": "event_id", "value": "1004"}


def test_normalize_keeps_a_dict_entity_and_drops_anything_else():
    kept = normalize_candidate({"title": "t", "observation": "o", "entity": ENTITY})
    assert kept["entity"] == ENTITY
    assert normalize_candidate({"title": "t", "observation": "o", "entity": "1004"})["entity"] == {}
    assert normalize_candidate({"title": "t", "observation": "o"})["entity"] == {}


def test_a_fenced_json_finding_keeps_its_entity_through_the_parser():
    reply = (
        "Here is the finding.\n"
        "```json\n"
        '{"title": "SPP event 1004 present", "observation": "rows returned",'
        ' "entity": {"type": "event_id", "value": "1004"}}\n'
        "```\n"
    )
    (candidate,) = parse_hunt_candidates([{"role": "assistant", "content": reply}])
    assert candidate["entity"] == ENTITY


def test_the_record_payload_no_longer_takes_the_models_entity():
    """WO-1C item 4 (option b, operator decision 2026-10-11): the entity is derived from the rows a
    finding cites, in stage_findings. A model's entity is not the identity, so the payload does not carry it."""
    candidate = normalize_candidate({
        "title": "SPP event 1004 present", "observation": "rows returned",
        "interpretation": "recorded", "entity": ENTITY,
    })
    payload = _finding_tool_payload(candidate)
    assert "entity" not in payload


def test_the_mcp_record_finding_tool_takes_no_entity_from_the_caller(monkeypatch, tmp_path):
    """The MCP tool does not take a caller's entity (operator decision 2026-10-12): the subject is
    derived from the rows the cited audit calls stored. A call that cites no stored row has no
    subject, so the model's entity never reaches the case."""
    from mcp.server.fastmcp import FastMCP

    from nexus import case_manager
    from nexus.audit import AuditWriter
    from nexus.tools import forensic

    captured: dict = {}

    def _record(self, finding, **_kwargs):
        captured.update(finding)
        return {"status": "DUPLICATE", "finding_id": "F-test"}

    monkeypatch.setattr(case_manager.CaseManager, "record_finding", _record)
    server = FastMCP("entity-boundary-test")
    forensic.register_tools(server, AuditWriter("t", audit_dir=tmp_path / "audit"))
    tool = server._tool_manager._tools["record_finding"].fn
    tool(title="SPP event 1004 present", observation="rows returned",
         interpretation="recorded", entity=ENTITY,
         evidence=[{"detail": "EventId 1004"}])
    assert captured.get("entity") == {}, captured.get("entity")
    assert captured.get("category") == "other", captured.get("category")
