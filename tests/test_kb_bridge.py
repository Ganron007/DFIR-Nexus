"""KB-6 — offline-safe KB bridge tests."""
from __future__ import annotations

import json
from pathlib import Path


def _mkroot(tmp_path: Path) -> Path:
    root = tmp_path / "kbroot"
    (root / "kb").mkdir(parents=True)
    (root / "kb" / "kb.py").write_text("# dummy kb\n", encoding="utf-8")
    pack = root / "kb" / "exports" / "pack_demo"
    pack.mkdir(parents=True)
    (pack / "manifest.json").write_text(json.dumps({
        "selection": {"folder": "X"}, "docs": 1, "chunks": 2, "generated": "2026-09-14",
    }), encoding="utf-8")
    (pack / "documents.md").write_text(
        "<!-- d_abc123:c0001 | SANS/x.md:1-2 -->\n"
        "lsass memory dumping with procdump\n",
        encoding="utf-8",
    )
    return root


def test_bridge_lists_and_searches(tmp_path, monkeypatch):
    root = _mkroot(tmp_path)
    monkeypatch.setenv("NEXUS_KB_DIR", str(root))
    from nexus.knowledge import kb_bridge

    assert kb_bridge.kb_root() == root
    packs = kb_bridge.list_packs()
    assert packs and packs[0]["name"] == "pack_demo"
    assert packs[0]["chunks"] == 2

    hits = kb_bridge.search_pack(packs[0]["path"], "procdump")
    assert hits, "expected a match"
    assert hits[0]["citation"].startswith("d_abc123")


def test_bridge_absent_is_inert(tmp_path, monkeypatch):
    monkeypatch.delenv("NEXUS_KB_DIR", raising=False)
    from nexus.knowledge import kb_bridge

    monkeypatch.setattr(kb_bridge, "_DEFAULT_ROOT", tmp_path / "does-not-exist")
    assert kb_bridge.kb_root() is None
    assert kb_bridge.exports_dir() is None
    assert kb_bridge.list_packs() == []
    assert kb_bridge.search_pack(tmp_path, "x") == []
    assert kb_bridge.cite("d_abc123:c0001") == {}
