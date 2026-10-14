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


def test_playbooks_are_given_whole_and_the_rest_are_named():
    """D172: the guidance was cut at 200 characters an item, 1,200 a playbook and 3,000 in all,
    mid-item (KA3: whole items or "more available")."""
    from nexus.knowledge.loader import get_playbook
    from nexus.modes.llm_guided import _playbook_context_for_families

    families = {"evtxecmd", "volatility", "setupapi", "yara", "mftecmd", "hayabusa"}
    whole = _playbook_context_for_families(families)
    budgeted = _playbook_context_for_families(families, budget=3000)
    shown = [line for line in budgeted.splitlines() if line.startswith("--- Playbook:")]
    assert shown and whole.count("--- Playbook:") > len(shown)
    assert "More playbooks apply to these families (not shown):" in budgeted
    for caveat in get_playbook("memory_forensics").get("caveats") or []:
        assert f"  - {caveat}\n" in whole, "a caveat is given whole"


def test_a_family_inside_another_word_does_not_select_a_playbook():
    """D172: "wer" (Windows Error Reporting) matched "PowerShell", "web" matched "webshell"."""
    from nexus.modes.llm_guided import _playbook_match

    pb = {"name": "PowerShell Anomaly", "description": "Encoded PowerShell and webshell drops",
          "query_terms": ["encodedcommand"]}
    assert _playbook_match(pb, {"wer", "web"}) == 0
    assert _playbook_match(pb, {"encodedcommand"}) == 2
    assert _playbook_match({"name": "x", "families": ["prefetch"]}, {"prefetch"}) == 2
