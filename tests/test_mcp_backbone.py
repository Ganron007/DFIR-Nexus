"""WP 9.10/9.11 — MCP backbone tool tests (evidence plane + knowledge plane).

The LLM reaches a case's evidence ONLY through the case-gated MCP tools;
the KB tools are inert without the KB and case-gated tools refuse a
case_id that is not the active case.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

os.environ.setdefault("NEXUS_RAG_PRELOAD", "0")


def _make_case_dir(tools, tmp_path: Path) -> str:
    """Create + activate a case with minimal evidence through the tool surface."""
    r = tools["case_init"].fn("Backbone Test", case_id="CASE-BB1")
    cid = r["case_id"]
    tools["case_activate"].fn(cid)
    case_dir = Path(r["case_dir"])
    ext = case_dir / "extractions" / "hayabusa"
    ext.mkdir(parents=True, exist_ok=True)
    (ext / "timeline.csv").write_text(
        "time,host,event,channel\n"
        "2026-08-10T15:00:00Z,WS01,sdelete.exe,Security\n"
        "2026-08-10T15:01:00Z,WS01,rundll32.exe,Security\n",
        encoding="utf-8",
    )
    return cid


@pytest.fixture()
def backbone(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_CASES_ROOT", str(tmp_path / "cases"))
    monkeypatch.setenv("NEXUS_ACTIVE_CASE_FILE", str(tmp_path / "active_case"))
    monkeypatch.delenv("NEXUS_KB_DIR", raising=False)
    (tmp_path / "cases").mkdir(parents=True, exist_ok=True)
    from nexus.app import create_server

    server = create_server()
    tools = server._tool_manager._tools
    cid = _make_case_dir(tools, tmp_path)
    return tools, cid


def test_backbone_tools_registered(backbone):
    tools, _cid = backbone
    for name in ("n4_query", "n4_aggregate", "index_mappings",
                 "kb_search", "kb_read", "kb_cite", "kb_verify_cites",
                 "kb_topics", "kb_coverage_map", "kb_list_packs"):
        assert name in tools, f"missing backbone tool {name}"


def test_n4_query_gated_to_active_case(backbone):
    tools, cid = backbone
    r = tools["n4_query"].fn(case_id=cid, dsl="sdelete OR rundll32", limit=10)
    assert "error" not in r, r
    assert r["count"] >= 1
    assert r["hits"], "expected evidence rows"
    assert r["provenance"]["audit_id"], "FD-001 provenance required"
    assert r["provenance"]["case_id"] == cid


def test_n4_query_refuses_other_case(backbone, tmp_path):
    tools, _cid = backbone
    r = tools["n4_query"].fn(case_id="CASE-OTHER", dsl="sdelete")
    assert "error" in r
    assert "not the active case" in r["error"]


def test_n4_query_refuses_traversal(backbone):
    tools, _cid = backbone
    r = tools["n4_query"].fn(case_id="../..", dsl="x")
    assert "error" in r


def test_n4_query_validates_dsl(backbone):
    tools, _cid = backbone
    r = tools["n4_query"].fn(dsl='regex:((((a+)+)+)*b)')
    assert "error" in r, "ReDoS-guarded regex must be refused"


def test_n4_aggregate_counts(backbone):
    tools, cid = backbone
    r = tools["n4_aggregate"].fn(dsl="sdelete OR rundll32", field="host", top=5)
    assert "error" not in r, r
    assert r["rows_scanned"] >= 1
    top = {t["value"]: t["count"] for t in r["top"]}
    assert sum(top.values()) >= 1
    assert "never evidence" in r["note"]


def test_index_mappings_grounded(backbone):
    tools, cid = backbone
    r = tools["index_mappings"].fn()
    assert "error" not in r, r
    assert "hayabusa" in r["families"], r
    # 4k.6: the catalog surface is typed and complete, not the old 5 fields.
    assert {"family", "host", "user", "event_id", "file"} <= set(r["dsl_fields"])
    assert r.get("dsl_operators")
    # ES state is environment-dependent (operator ES may be up) — assert the
    # payload is self-consistent with whatever backend answered.
    assert isinstance(r["es_available"], bool)
    if r["es_available"]:
        assert "reachable" in r["note"]
    else:
        assert "CSV" in r["note"]
    assert r["provenance"]["case_id"] == cid


def test_cached_index_mappings_get_fresh_audit_provenance(backbone):
    from nexus.audit import AuditWriter
    from nexus.langgraph.backbone import backbone_call
    from nexus.tools.evidence_index import invalidate_mappings_cache

    _tools, cid = backbone
    invalidate_mappings_cache(cid)
    audit = AuditWriter("nexus")
    first = backbone_call("index_mappings", audit=audit, case_id=cid)
    second = backbone_call("index_mappings", audit=audit, case_id=cid)
    assert second["cached"] is True
    assert first["provenance"]["audit_id"]
    assert second["provenance"]["audit_id"]
    assert first["provenance"]["audit_id"] != second["provenance"]["audit_id"]


def test_kb_tools_inert_without_kb(backbone, monkeypatch):
    from nexus.knowledge import kb_bridge

    monkeypatch.setattr(kb_bridge, "_DEFAULT_ROOT", Path("Z:/definitely-not-here"))
    tools, _cid = backbone
    r = tools["kb_search"].fn(query="lsass")
    assert r.get("available") is False and "error" in r
    assert tools["kb_read"].fn(chunk_id="d_abc:c0001").get("available") is False
    assert tools["kb_list_packs"].fn().get("available") is False


@pytest.mark.skipif(
    not (Path(os.environ.get("NEXUS_KB_DIR", r"G:\doc_extract")) / "kb" / "kb.py").is_file(),
    reason="operator KB not present")
def test_kb_search_live(backbone):
    tools, _cid = backbone
    r = tools["kb_search"].fn(query="lsass", limit=2)
    assert r.get("available") is True
    assert r.get("hits"), "expected KB hits on the operator KB"


@pytest.mark.skipif(
    not (Path(os.environ.get("NEXUS_KB_DIR", r"G:\doc_extract")) / "kb" / "kb.py").is_file(),
    reason="operator KB not present")
def test_kb_verify_cites_on_installed_skill(backbone):
    tools, _cid = backbone
    r = tools["kb_verify_cites"].fn(skill="memory_process_analysis")
    assert "error" not in r, r


def test_every_allowlisted_tool_has_a_binding(backbone):
    """Structural guard: a name in MODE2_TOOL_ALLOWLIST without a binding
    raises PermissionError('no binding') — web_search/web_fetch were
    allowlisted but unbound and only surfaced when first called."""
    from nexus.langgraph.backbone import MODE2_TOOL_ALLOWLIST, backbone_call

    _tools, cid = backbone
    minimal = {
        "es_fields": {"case_id": cid},
        "es_search": {"case_id": cid, "query": {"match_all": {}}, "size": 2},
        "es_aggregate": {"case_id": cid,
                         "aggs": {"v": {"terms": {"field": "host"}}}},
        "es_sample": {"case_id": cid, "family": "hayabusa", "n": 2},
        "index_mappings": {"case_id": cid},
        "family_fields": {"family": "hayabusa"},
        "kb_search": {"query": "sdelete"},
        "kb_read": {"chunk_id": "x"},
        "kb_cite": {"chunk_id": "x"},
        "ti_lookup": {"value": "127.0.0.1"},
        "ti_fanout": {"value": "127.0.0.1"},
        "ti_list_providers": {},
        "web_status": {},
        "web_search": {"query": "test"},
        "web_fetch": {"url": "https://example.com"},
    }
    for name in MODE2_TOOL_ALLOWLIST:
        result = backbone_call(name, audit=None, **minimal.get(name, {}))
        assert isinstance(result, dict), f"{name} must return a dict"
