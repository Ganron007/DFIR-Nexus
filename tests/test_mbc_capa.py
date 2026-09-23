"""F7: capa output -> MBC behaviors + ATLAS/MBC grounding in Mode 3 prompts."""

from __future__ import annotations


def test_capa_rule_mapping():
    from nexus.knowledge.mbc import (
        mbc_behaviors_for_capa_rules,
        mbc_capa_context,
    )

    mapped = mbc_behaviors_for_capa_rules(["find taskbar"], cap=5)
    assert mapped, "expected 'find taskbar' to map onto an MBC behavior"
    ids = {row["behavior_id"] for row in mapped}
    assert "B0043" in ids, ids
    row = next(r for r in mapped if r["behavior_id"] == "B0043")
    assert row["behavior_name"] == "Taskbar Discovery"
    assert row["rule_name"] == "find taskbar"

    # Containment style (capa names often embed the family prefix).
    contained = mbc_behaviors_for_capa_rules(["windows_find_taskbar"], cap=5)
    assert any(r["behavior_id"] == "B0043" for r in contained), contained

    block = mbc_capa_context(["find taskbar"])
    assert "B0043" in block and "capa rule" in block

    assert mbc_behaviors_for_capa_rules([]) == []
    assert mbc_capa_context(["no_such_rule_zzz"]) == ""


def test_capa_rule_names_from_case(tmp_path):
    from nexus.dashboard.app import _capa_rule_names_from_case

    capa_dir = tmp_path / "extractions" / "capa"
    capa_dir.mkdir(parents=True)
    (capa_dir / "capa_output.txt").write_text(
        "find taskbar\nsome other line\n",
        encoding="utf-8",
    )
    (capa_dir / "capa_output.jsonl").write_text(
        '{"rule": "find taskbar", "meta": {}}\n{"rule": "no_such_rule_zzz"}\n',
        encoding="utf-8",
    )
    names = _capa_rule_names_from_case(tmp_path, limit=50)
    assert "find taskbar" in names
    assert "no_such_rule_zzz" in names

    assert _capa_rule_names_from_case(tmp_path / "missing") == []


def test_mode1_context_includes_capa_mbc(tmp_path):
    from nexus.dashboard.app import _mode1_ask_context

    capa_dir = tmp_path / "extractions" / "capa"
    capa_dir.mkdir(parents=True)
    (capa_dir / "capa_output.jsonl").write_text(
        '{"rule": "find taskbar"}\n', encoding="utf-8"
    )
    context = _mode1_ask_context(tmp_path, "what does the sample do?")
    assert "mbc_capa_context" in context, sorted(context)
    assert "B0043" in str(context["mbc_capa_context"])
    assert "mbc-capa" in (context.get("sources") or [])


def test_mode3_registry_block():
    from nexus.langgraph.llm_pipeline import _registry_context_block

    block = _registry_context_block({
        "case_context": {"question": "did they abuse an AI agent via prompt injection?"}
    })
    assert "AML." in block

    empty = _registry_context_block({"case_context": {}})
    assert empty == ""
