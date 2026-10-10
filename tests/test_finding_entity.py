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


def test_the_record_payload_carries_the_entity():
    candidate = normalize_candidate({
        "title": "SPP event 1004 present", "observation": "rows returned",
        "interpretation": "recorded", "entity": ENTITY,
    })
    payload = _finding_tool_payload(candidate, trail=[])
    assert payload["entity"] == ENTITY


def test_the_mcp_record_finding_tool_passes_the_entity_to_the_case(monkeypatch, tmp_path):
    """The interpret payload reaches the case through the MCP tool: its entity must not be
    dropped at that boundary (D70)."""
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
    assert captured.get("entity") == ENTITY, captured.keys()
