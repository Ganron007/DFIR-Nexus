"""D199: every playbook declares the evidence families it investigates, derived from its own text (2026-10-18).

21 of the 26 playbooks declared none, so Mode 1 chose them by a family word anywhere in their text and a generic
word chose loosely (Web Shell for a browser-history case). The families were written by
`devtools/knowledge/declare_playbook_families.py`; these tests run on the real playbook files.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]
PLAYBOOKS = REPO / "src" / "nexus" / "data" / "knowledge" / "discipline" / "playbooks"


def _script():
    spec = importlib.util.spec_from_file_location(
        "declare_playbook_families", REPO / "devtools" / "knowledge" / "declare_playbook_families.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _playbooks() -> dict[str, dict]:
    return {f.stem: yaml.safe_load(f.read_text(encoding="utf-8")) or {} for f in sorted(PLAYBOOKS.glob("*.yaml"))}


def test_every_playbook_declares_families_the_product_writes():
    families, _tools = _script().vocabulary()
    playbooks = _playbooks()
    assert len(playbooks) == 26
    for slug, doc in playbooks.items():
        declared = doc.get("families") or []
        assert declared, f"{slug} declares no families"
        # The five declared before D199 use the older alias spellings (evtx, prefetch); the derived ones are families.
        if "D199" in (PLAYBOOKS / f"{slug}.yaml").read_text(encoding="utf-8"):
            assert set(declared) <= families, f"{slug}: {sorted(set(declared) - families)} is no family"


def test_a_browser_history_case_no_longer_chooses_web_shell():
    from nexus.langgraph.query_pack import _family_matched_playbooks

    chosen = {str(pb.get("name")) for pb in _family_matched_playbooks({"hindsight", "sqlecmd"})}
    assert "Web Shell Investigation" not in chosen
    assert any("Browser" in name for name in chosen)


def test_the_script_reproduces_what_the_playbooks_declare():
    script = _script()
    families, tools = script.vocabulary()
    arts = script.artifacts()
    for slug, doc in _playbooks().items():
        if "D199" not in (PLAYBOOKS / f"{slug}.yaml").read_text(encoding="utf-8"):
            continue
        assert sorted(script.derive(doc, arts, families, tools, slug)) == sorted(doc["families"]), slug
