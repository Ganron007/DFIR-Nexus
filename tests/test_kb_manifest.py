"""F4: KB/registry manifest + RAG bundle metadata (visibility, no hiding)."""

from __future__ import annotations

import json
from pathlib import Path


def test_registry_manifest_lists_four_registries():
    from nexus.knowledge.loader import registry_manifest, synced_source_manifest

    entries = registry_manifest()
    by_name = {e["name"]: e for e in entries}
    assert {"itm", "attack", "atlas", "mbc"} <= set(by_name), sorted(by_name)
    for entry in entries:
        assert entry["kind"] == "compiled_registry"
        assert int(entry["count"]) > 0, entry["name"]
        assert entry["counts"], entry["name"]

    # The doctor-facing manifest carries both synced feeds and registries.
    all_entries = synced_source_manifest()
    kinds = {e.get("kind") for e in all_entries}
    assert "synced_source" in kinds and "compiled_registry" in kinds
    assert {"itm", "attack", "atlas", "mbc"} <= {e["name"] for e in all_entries}


def test_rag_bundle_metadata(tmp_path: Path):
    from nexus.tools.rag import _rag_bundle_metadata

    idx = tmp_path / "rag"
    (idx / "sources").mkdir(parents=True)
    (idx / "sources" / "itm.jsonl").write_text("{}\n", encoding="utf-8")
    (idx / "metadata.json").write_text(
        json.dumps({
            "model": "BAAI/bge-base-en-v1.5",
            "install_method": "download",
            "record_count": 22268,
            "source_count": 67,
            "bundle_tag": "rag-index-v2026.03.01",
            "created": "2026-03-01T11:52:15",
        }),
        encoding="utf-8",
    )
    meta = _rag_bundle_metadata(idx)
    assert meta["bundle_tag"] == "rag-index-v2026.03.01"
    assert meta["install_method"] == "download"
    assert meta["record_count"] == 22268
    assert meta["local_source_files"] == ["itm"]

    assert _rag_bundle_metadata(tmp_path / "missing") == {}
