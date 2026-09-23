"""Local RAG delta build (existing-index update, Phase F8).

Covers: JSONL generation from our compiled registries (net-new content only),
the local delta collection rebuild (upsert + prune, vendor index untouched),
delta stats, and the vendor+delta result merge.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent


def _load_builder():
    path = REPO / "scripts" / "build_rag_sources.py"
    spec = importlib.util.spec_from_file_location("build_rag_sources", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _doc(i: int, source: str = "itm") -> dict:
    return {
        "id": f"t:{i}",
        "text": f"doc {i} body",
        "source": source,
        "title": f"T{i}",
        "technique_id": "",
        "platform": "",
        "metadata": {"itm_id": f"AR1/PR00{i}"},
    }


def _write_docs(path: Path, docs: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as fh:
        for doc in docs:
            fh.write(json.dumps(doc) + "\n")


def _fake_encode(_texts):
    return [[0.1, 0.2, 0.3, 0.4] for _ in _texts]


# ---------------------------------------------------------------------------
# Source generation
# ---------------------------------------------------------------------------

def test_builder_itm_docs_match_registry():
    from nexus.knowledge.loader import get_itm_registry

    module = _load_builder()
    docs = module.build_itm()
    registry = get_itm_registry()
    sections = [s for a in registry["articles"] for s in a.get("sections") or []]
    subsections = [sub for s in sections for sub in s.get("subsections") or []]

    assert len(docs) == len(sections) + len(subsections)
    ids = [d["id"] for d in docs]
    assert len(set(ids)) == len(ids)
    assert all(d["source"] == "itm" for d in docs)
    # Canonical ids resolve in the ITM registry index (article/short-id).
    from nexus.langgraph.itm import itm_index

    lookup = {k.upper() for k in itm_index()}
    assert all(d["id"].startswith("itm:") and "/" in d["id"] for d in docs)
    assert all(d["id"].split("/", 1)[1].upper() in lookup for d in docs)
    section_full = {f"{a['id']}/{s['id']}" for a in registry["articles"]
                    for s in a.get("sections") or []}
    assert section_full <= {d["metadata"]["itm_id"] for d in docs}
    assert all("Insider Threat Matrix" in d["text"] for d in docs)
    assert all(d["metadata"].get("itm_id") for d in docs)
    assert all(0 < len(d["text"]) <= module.MAX_TEXT for d in docs)
    # No accidental duplicates against the vendor corpus is a build-time
    # property (net-new sources); here we only pin determinism.
    assert [d["id"] for d in module.build_itm()] == ids


def test_builder_attack_detections_and_atlas_and_mbc():
    from nexus.knowledge.loader import get_atlas_registry, get_attack_registry, get_mbc_registry

    module = _load_builder()

    attack = get_attack_registry()
    strategies = [
        s for t in attack["techniques"] for s in t.get("detection") or []
    ]
    det_docs = module.build_attack_detections()
    assert len(det_docs) == len(strategies)
    assert len({d["id"] for d in det_docs}) == len(det_docs)
    assert all(d["id"].startswith("attack-det:") for d in det_docs)
    assert all(d["metadata"]["mitre_techniques"].startswith("T") for d in det_docs)

    atlas = get_atlas_registry()
    atlas_docs = module.build_atlas()
    assert len(atlas_docs) == len(atlas["techniques"]) + len(atlas["mitigations"])
    sources = {d["source"] for d in atlas_docs}
    assert sources == {"mitre_atlas_techniques", "mitre_atlas_mitigations"}
    tech_ids = {t["id"] for t in atlas["techniques"]}
    assert {d["id"].removeprefix("atlas:") for d in atlas_docs
            if d["id"].startswith("atlas:")} == tech_ids

    mbc = get_mbc_registry()
    with_rules = [b for b in mbc["behaviors"] if b.get("detection_rules")]
    mbc_docs = module.build_mbc_capa()
    assert len(mbc_docs) == len(with_rules)
    assert all(d["metadata"]["rule_count"] >= 1 for d in mbc_docs)
    assert all(d["id"].startswith("mbc-capa:") for d in mbc_docs)


def test_generator_main_writes_manifest_and_loads_back(tmp_path, monkeypatch):
    module = _load_builder()
    monkeypatch.setattr(
        sys, "argv",
        ["build_rag_sources.py", "--out", str(tmp_path), "--only", "mbc_capa"],
    )
    assert module.main() == 0

    manifest = json.loads((tmp_path / "_manifest.json").read_text(encoding="utf-8"))
    assert manifest["model_expected"] == module.MODEL_EXPECTED
    entry = manifest["sources"]["mbc_capa"]
    assert entry["count"] > 0 and entry["registry_sha256_16"]

    lines = (tmp_path / "mbc_capa.jsonl").read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == entry["count"]

    from nexus.rag.sources import load_jsonl

    docs = list(load_jsonl(tmp_path / "mbc_capa.jsonl"))
    assert len(docs) == entry["count"]
    assert all(d.source == "mbc_capa" and d.id.startswith("mbc-capa:") for d in docs)
    assert all(d.metadata.get("rule_count") for d in docs)


# ---------------------------------------------------------------------------
# Delta collection rebuild
# ---------------------------------------------------------------------------

def test_rebuild_local_index_upserts_prunes_vendor_untouched(tmp_path):
    chromadb = pytest.importorskip("chromadb")

    from nexus.tools.rag import (
        DELTA_COLLECTION,
        RAG_BUILD_TAG,
        delta_stats,
        rebuild_local_index,
    )

    index_dir = tmp_path / "index"
    sources = tmp_path / "sources"
    sources.mkdir(parents=True)

    client = chromadb.PersistentClient(path=str(index_dir / "chroma"))
    vendor = client.get_or_create_collection("ir_knowledge")
    vendor.add(
        ids=["v1"], documents=["vendor doc"],
        embeddings=[[0.5, 0.5, 0.5, 0.5]], metadatas=[{"source": "vendor-src"}],
    )

    _write_docs(sources / "a.jsonl", [_doc(1), _doc(2), _doc(3)])
    result = rebuild_local_index(index_dir, data_dir=sources, encode=_fake_encode)
    assert result["status"] == "ok"
    assert result["documents"] == 3 and result["upserted"] == 3
    assert result["collection"] == DELTA_COLLECTION

    delta = client.get_collection(DELTA_COLLECTION)
    assert delta.count() == 3
    meta = delta.get(ids=["t:1"], include=["metadatas"])["metadatas"][0]
    assert meta["built_by"] == RAG_BUILD_TAG
    assert meta["itm_id"] == "AR1/PR001"
    assert meta["source"] == "itm"

    stats = delta_stats(index_dir)
    assert stats["count"] == 3
    assert stats["sources"] == {"itm": 3}

    # Rebuild after a source shrinks: stale docs are pruned, vendor untouched.
    _write_docs(sources / "a.jsonl", [_doc(1)])
    result2 = rebuild_local_index(index_dir, data_dir=sources, encode=_fake_encode)
    assert result2["documents"] == 1 and result2["pruned"] == 2
    assert client.get_collection(DELTA_COLLECTION).count() == 1
    assert vendor.count() == 1
    assert vendor.get(ids=["v1"], include=["documents"])["documents"] == ["vendor doc"]

    # prune=False keeps stale rows (idempotent rebuild).
    result3 = rebuild_local_index(index_dir, data_dir=sources, encode=_fake_encode, prune=False)
    assert result3["pruned"] == 0


def test_rebuild_local_index_empty_sources(tmp_path):
    pytest.importorskip("chromadb")
    from nexus.tools.rag import rebuild_local_index

    empty = tmp_path / "nope"
    result = rebuild_local_index(tmp_path / "index", data_dir=empty, encode=_fake_encode)
    assert result["status"] == "empty"
    assert "no local sources" in result["error"]


def test_delta_stats_absent_collection(tmp_path):
    pytest.importorskip("chromadb")
    from nexus.tools.rag import delta_stats

    index_dir = tmp_path / "index"
    (index_dir / "chroma").mkdir(parents=True, exist_ok=True)
    assert delta_stats(index_dir) == {"count": 0, "sources": {}}


def test_delta_stats_without_chroma_dir(tmp_path):
    from nexus.tools.rag import delta_stats

    assert delta_stats(tmp_path / "nothing") == {"count": 0, "sources": {}}


# ---------------------------------------------------------------------------
# Search merge (vendor + local)
# ---------------------------------------------------------------------------

def test_merge_search_rows_dedupes_and_ranks():
    from nexus.tools.rag import merge_search_rows

    rows = [
        {"id": "a", "score": 0.5, "source": "x"},
        {"id": "b", "score": 0.9, "source": "y"},
        {"id": "a", "score": 0.7, "source": "x2"},
    ]
    out = merge_search_rows(rows, 5)
    assert [r["id"] for r in out] == ["b", "a"]
    assert out[1]["score"] == 0.7 and out[1]["source"] == "x2"
    assert [r["rank"] for r in out] == [1, 2]
    assert merge_search_rows(rows, 1)[0]["id"] == "b"


def test_search_merges_vendor_and_delta(tmp_path):
    chromadb = pytest.importorskip("chromadb")

    from nexus.tools.rag import DELTA_COLLECTION, RAGIndex

    index_dir = tmp_path / "index"
    client = chromadb.PersistentClient(path=str(index_dir / "chroma"))
    vendor = client.get_or_create_collection("ir_knowledge")
    vendor.add(
        ids=["v1"], documents=["vendor doc"],
        embeddings=[[0.5, 0.5, 0.5, 0.5]], metadatas=[{"source": "vendor-src", "title": "V"}],
    )
    delta = client.get_or_create_collection(DELTA_COLLECTION)
    delta.add(
        ids=["t:1"], documents=["delta doc"],
        embeddings=[[0.5, 0.5, 0.5, 0.5]],
        metadatas=[{"source": "itm", "title": "ITM doc", "mitre_techniques": ""}],
    )

    class _Vec(list):
        def tolist(self):
            return list(self)

    class _StubModel:
        def encode(self, _text):
            return _Vec([0.1, 0.2, 0.3, 0.4])

    idx = RAGIndex(index_dir=index_dir)
    idx.model = _StubModel()
    idx.collection = vendor
    idx.delta_collection = delta
    idx.available_sources = ["vendor-src", "itm"]
    idx._loaded = True

    out = idx.search("anything", top_k=5)
    results = out["results"]
    collections = {r["collection"] for r in results}
    assert collections == {"vendor", "local"}
    assert {r["id"] for r in results} == {"v1", "t:1"}
    assert [r["rank"] for r in results] == [1, 2]

    # Source filter matches delta sources too (available_sources union).
    filtered = idx.search("anything", top_k=5, source="itm")["results"]
    assert [r["id"] for r in filtered] == ["t:1"]
