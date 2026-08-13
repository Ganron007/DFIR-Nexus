"""RAG embedding-model resolution (local HuggingFace hub cache)."""

from __future__ import annotations

from pathlib import Path

from nexus.tools.rag import (
    DEFAULT_MODEL_NAME,
    resolve_embedding_source,
    resolve_hf_snapshot,
)


def test_resolve_hf_snapshot_from_hub_layout(tmp_path: Path, monkeypatch):
    snap_id = "a5beb1e3e68b9ab74eb54cfd186867f64f240e1a"
    hub = tmp_path / "huggingface" / "hub"
    repo = hub / "models--BAAI--bge-base-en-v1.5"
    (repo / "refs").mkdir(parents=True)
    (repo / "snapshots" / snap_id).mkdir(parents=True)
    (repo / "refs" / "main").write_text(snap_id, encoding="utf-8")
    monkeypatch.setenv("HF_HOME", str(tmp_path / "huggingface"))
    got = resolve_hf_snapshot("BAAI/bge-base-en-v1.5")
    assert got == repo / "snapshots" / snap_id


def test_resolve_embedding_prefers_cached_snapshot(tmp_path: Path, monkeypatch):
    snap_id = "deadbeef"
    hub = tmp_path / "huggingface" / "hub"
    repo = hub / "models--BAAI--bge-base-en-v1.5"
    snap = repo / "snapshots" / snap_id
    snap.mkdir(parents=True)
    (repo / "refs").mkdir(parents=True)
    (repo / "refs" / "main").write_text(snap_id, encoding="utf-8")
    monkeypatch.setenv("HF_HOME", str(tmp_path / "huggingface"))
    monkeypatch.delenv("NEXUS_RAG_MODEL", raising=False)
    monkeypatch.delenv("NEXUS_RAG_EMBED_MODEL", raising=False)
    src = resolve_embedding_source()
    assert src["model_id"] == DEFAULT_MODEL_NAME
    assert src["local_files_only"] is True
    assert src["source"] == "hf_hub_cache"
    assert Path(src["load_path"]) == snap


def test_resolve_embedding_explicit_dir(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("NEXUS_RAG_MODEL", str(tmp_path))
    src = resolve_embedding_source()
    assert src["source"] == "explicit_dir"
    assert src["local_files_only"] is True
    assert Path(src["load_path"]) == tmp_path


def test_resolve_embedding_alias_env(monkeypatch):
    monkeypatch.delenv("NEXUS_RAG_MODEL", raising=False)
    monkeypatch.setenv("NEXUS_RAG_EMBED_MODEL", "BAAI/bge-base-en-v1.5")
    monkeypatch.delenv("HF_HOME", raising=False)
    src = resolve_embedding_source()
    assert src["model_id"] == "BAAI/bge-base-en-v1.5"
