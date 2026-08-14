"""Deterministic tools-mode case-context overlay."""

from nexus.langgraph.case_intake import extra_playbook_names
from nexus.langgraph.tool_context import (
    build_tool_context_markdown,
    relevant_tool_keys,
)


def test_empty_intake_warns_no_category():
    md = build_tool_context_markdown({}, [])
    assert "No examiner category" in md
    assert relevant_tool_keys({}) == []


def test_insider_usb_maps_playbooks_to_tools():
    ctx = {
        "hypothesis": "insider-threat USB staging",
        "question": "What left the host?",
    }
    keys = relevant_tool_keys(ctx)
    assert "sbecmd" in keys
    assert "srumecmd" in keys
    md = build_tool_context_markdown(
        ctx,
        [
            {"host": "rocba", "tool": "sbecmd", "status": "OK", "purpose": "shellbags"},
            {"host": "rocba", "tool": "hayabusa", "status": "OK", "purpose": "evtx"},
        ],
    )
    assert "hypothesis" in md
    assert "sbecmd" in md
    assert "This is not a finding" in md


def test_external_compromise_maps_execution_tools():
    ctx = {"hypothesis": "external compromise / malware C2"}
    keys = relevant_tool_keys(ctx)
    assert "hayabusa" in keys
    assert "amcacheparser" in keys
    assert extra_playbook_names(ctx) == ["external_compromise"]
