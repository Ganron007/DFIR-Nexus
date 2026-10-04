"""Mode 2 initial-interpret context wiring — RAG + ES tools + playbooks.

The interpret node must build context from sources before steering takes
over: RAG methodology, its own ES queries, playbook guidance, and TI.
These tests pin the tool allowlist and the deterministic context builders.
"""
from __future__ import annotations

from nexus.langgraph.llm_pipeline import INTERPRET_TOOL_NAMES


def test_interpret_toolset_covers_all_sources():
    required = {
        # RAG methodology
        "forensic_rag_search", "forensic_rag_status",
        # own evidence queries (ES via MCP core, case-gated)
        "es_fields", "es_search", "es_aggregate", "es_sample",
        "index_mappings", "family_fields",
        # threat intel
        "ti_lookup", "ti_fanout", "ti_list_providers",
    }
    missing = required - set(INTERPRET_TOOL_NAMES)
    assert not missing, f"interpret toolset missing: {sorted(missing)}"
    assert "kb_search" not in INTERPRET_TOOL_NAMES
    assert "kb_read" not in INTERPRET_TOOL_NAMES
    assert "kb_cite" not in INTERPRET_TOOL_NAMES


def test_playbook_context_returns_guidance_for_families():
    from nexus.modes.llm_guided import _playbook_context_for_families

    text = _playbook_context_for_families({"hayabusa"})
    assert isinstance(text, str)
    # Best-effort: guidance may be empty when no playbook maps the family,
    # but it must never raise or return non-text.
    if text:
        assert "Playbook" in text or "Caveats" in text
