"""The RAG download tool must never replace an installed index by accident.

On 2026-09-28 a download overlay replaced the live Chroma store and dropped the
``ir_knowledge_extra`` delta (1,832 docs). The tool is now non-destructive by
default, and a forced swap rebuilds the delta from ``sources/local``.
"""
from __future__ import annotations

from pathlib import Path


def _tool(tmp_path: Path):
    from mcp.server.fastmcp import FastMCP

    import nexus.tools.rag as rag_mod
    from nexus.audit import AuditWriter

    server = FastMCP("rag-guard-test")
    rag_mod.register_tools(server, AuditWriter("t", audit_dir=tmp_path / "audit"))
    return server._tool_manager._tools["forensic_rag_download"].fn


def _installed_index(tmp_path: Path) -> Path:
    idx = tmp_path / "rag"
    (idx / "chroma").mkdir(parents=True)
    (idx / "chroma" / "chroma.sqlite3").write_bytes(b"x")
    (idx / "metadata.json").write_text("{}", encoding="utf-8")
    return idx


def test_download_is_a_noop_when_an_index_exists(tmp_path, monkeypatch):
    import nexus.tools.rag as rag_mod

    idx = _installed_index(tmp_path)
    monkeypatch.setattr(rag_mod, "_get_index_dir", lambda: idx)
    monkeypatch.setattr(rag_mod, "delta_stats", lambda dest: {"count": 0})

    def _boom(*_args, **_kwargs):
        raise AssertionError("network path reached despite an installed index")

    monkeypatch.setattr(rag_mod, "_fetch_latest_release", _boom)
    monkeypatch.setattr(rag_mod, "_download_asset", _boom)

    result = _tool(tmp_path)(tag="latest")
    assert result["status"] == "skipped"
    assert "already installed" in result["reason"]
    assert (idx / "chroma" / "chroma.sqlite3").read_bytes() == b"x"


def test_forced_download_rebuilds_the_delta_after_the_swap(tmp_path, monkeypatch):
    import nexus.tools.rag as rag_mod

    idx = _installed_index(tmp_path)
    monkeypatch.setattr(rag_mod, "_get_index_dir", lambda: idx)
    monkeypatch.setattr(rag_mod, "delta_stats", lambda dest: {"count": 0})
    monkeypatch.setattr(
        rag_mod,
        "_fetch_latest_release",
        lambda: {
            "tag_name": "rag-index-test",
            "assets": [{"name": "rag-index.tar.zst", "url": "http://example.invalid/bundle"}],
        },
    )

    def _fake_download(url, dest):
        Path(dest).write_bytes(b"bundle")

    monkeypatch.setattr(rag_mod, "_download_asset", _fake_download)
    monkeypatch.setattr(rag_mod, "_verify_checksums", lambda directory: True)

    def _fake_extract(bundle, dest):
        (Path(dest) / "chroma").mkdir(parents=True, exist_ok=True)
        (Path(dest) / "chroma" / "chroma.sqlite3").write_bytes(b"vendor")

    monkeypatch.setattr(rag_mod, "_extract_bundle", _fake_extract)
    monkeypatch.setattr(rag_mod, "_verify_index", lambda directory: True)

    class _StubIndex:
        def get_stats(self):
            return {"records": 22268}

    monkeypatch.setattr(rag_mod, "_get_index", lambda: _StubIndex())

    (idx / "sources" / "local").mkdir(parents=True)
    (idx / "sources" / "local" / "itm.jsonl").write_text("{}\n", encoding="utf-8")

    calls: dict = {}

    def _fake_rebuild(index_dir, data_dir=None, collection=None, prune=True):
        calls["index_dir"] = str(index_dir)
        calls["collection"] = collection
        return {"status": "ok", "documents": 1832, "sources": {"itm": 615}}

    monkeypatch.setattr(rag_mod, "rebuild_local_index", _fake_rebuild)

    result = _tool(tmp_path)(tag="latest", force=True)
    assert result["status"] == "success"
    assert calls.get("collection") == rag_mod.DELTA_COLLECTION
    assert calls.get("index_dir") == str(idx)
    assert result["delta_rebuilt"]["documents"] == 1832
