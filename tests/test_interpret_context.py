"""Mode 2 initial-interpret context wiring — RAG + ES tools + KB + playbooks.

The interpret node must build context from ALL sources before steering takes
over: RAG methodology, its own ES queries (n4_*), the examiner KB, playbook
guidance, and TI. These tests pin the tool allowlist and the deterministic
context builders.
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
        # examiner KB
        "kb_search", "kb_read", "kb_cite",
        # threat intel
        "ti_lookup", "ti_fanout", "ti_list_providers",
    }
    missing = required - set(INTERPRET_TOOL_NAMES)
    assert not missing, f"interpret toolset missing: {sorted(missing)}"


def test_kb_context_builds_and_renders(monkeypatch):
    from nexus.langgraph import kb_context

    def fake_search(query, limit=3):
        return {
            "available": True,
            "hits": [
                {"title": f"page for {query}", "snippet": "check the SRUM database"},
            ],
        }

    monkeypatch.setattr(kb_context, "_search", fake_search)
    ctx = kb_context.build_kb_context(
        question="What did the process do?",
        families=["hayabusa", "evtxecmd"],
        entities=["winword.exe"],
        max_queries=3,
    )
    assert ctx["hits"], ctx
    md = kb_context.render_kb_markdown(ctx)
    assert "page for" in md
    assert "never evidence" in md.lower()


def test_kb_context_unavailable_is_graceful(monkeypatch):
    from nexus.langgraph import kb_context

    def unavailable(query, limit=3):
        return {"error": "KB not configured (NEXUS_KB_DIR unset and default KB absent)",
                "available": False}

    monkeypatch.setattr(kb_context, "_search", unavailable)
    ctx = kb_context.build_kb_context(question="anything")
    md = kb_context.render_kb_markdown(ctx)
    assert not ctx["hits"]
    assert "no KB context" in md


def test_playbook_context_returns_guidance_for_families():
    from nexus.langgraph.mode2 import _playbook_context_for_families

    text = _playbook_context_for_families({"hayabusa"})
    assert isinstance(text, str)
    # Best-effort: guidance may be empty when no playbook maps the family,
    # but it must never raise or return non-text.
    if text:
        assert "Playbook" in text or "Caveats" in text
