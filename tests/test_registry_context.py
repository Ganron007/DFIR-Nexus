"""Registry context (ATLAS/MBC) + Mode 1 renderer for the new KB lenses."""

from __future__ import annotations


def test_atlas_context_matches_ai_questions_only():
    from nexus.knowledge.registry_context import atlas_context_for

    block = atlas_context_for("prompt injection against the LLM")
    assert "AML.T0051" in block
    assert "LLM Prompt Injection" in block

    # Generic words must not drag the taxonomy in (precision gate).
    assert atlas_context_for("zzzqqq nothing here") == ""
    assert atlas_context_for("") == ""


def test_mbc_context_matches_malware_behaviors():
    from nexus.knowledge.registry_context import mbc_context_for

    keylog = mbc_context_for("keylogging")
    assert "F0002" in keylog or "Keylogging" in keylog

    taskbar = mbc_context_for("taskbar discovery")
    assert "B0043" in taskbar

    assert mbc_context_for("zzzqqq nothing here") == ""


def test_mode1_context_block_renders_registry_lenses():
    from nexus.langgraph.mode1 import _context_block

    block = _context_block({
        "itm_context": "AR3/PR026 Remote Desktop (RDP)",
        "atlas_context": "AML.T0051 LLM Prompt Injection",
        "mbc_context": "F0002 Keylogging",
    })
    assert "Insider Threat Matrix" in block
    assert "MITRE ATLAS" in block
    assert "MITRE MBC" in block
    assert "AR3/PR026" in block and "AML.T0051" in block and "F0002" in block
    assert _context_block({}) == ""
    assert _context_block(None) == ""
