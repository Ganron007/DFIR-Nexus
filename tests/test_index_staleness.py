"""Tests for N3 staleness detection + auto-index hook (Phase 1.2)."""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


def _make_case_dir(tmp_path: Path) -> Path:
    case_dir = tmp_path / "CASE-STALE"
    case_dir.mkdir(parents=True)
    (case_dir / "CASE.yaml").write_text("name: stale-test\n")
    ext = case_dir / "extractions" / "hayabusa"
    ext.mkdir(parents=True)
    (ext / "timeline.csv").write_text("time,host\n2026-08-10T15:00:00Z,WS01,x\n")
    return case_dir


def _make_case(tmp_path: Path) -> Path:
    case_dir = tmp_path / "CASE-STALE"
    case_dir.mkdir(parents=True)
    (case_dir / "CASE.yaml").write_text("name: stale-test\n")
    ext = case_dir / "extractions" / "hayabusa"
    ext.mkdir(parents=True)
    (ext / "timeline.csv").write_text("time,host,event\n2026-08-10T15:00:00Z,WS01,x\n")
    return case_dir


def test_index_state_never_indexed(tmp_path):
    from nexus.langgraph.case_index import index_stale

    stale, info = index_stale(tmp_path)
    assert stale is True
    assert info["reason"] == "never indexed"


def test_index_state_fresh_then_stale(tmp_path):
    from nexus.langgraph.case_index import index_stale, write_index_state

    case_dir = _make_case_dir(tmp_path)
    write_index_state(case_dir, {"docs": 10, "index": "nexus-case-x"})
    stale, info = index_stale(case_dir)
    assert stale is False

    # Simulate: index was taken 60s ago; a new extraction lands now -> stale
    state_path = case_dir / "analysis" / "index_state.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    state["newest_extraction_mtime"] = time.time() - 60
    state_path.write_text(json.dumps(state), encoding="utf-8")
    (case_dir / "extractions" / "hayabusa" / "new.csv").write_text("a,b\n1,2\n")
    stale2, info2 = index_stale(case_dir)
    assert stale2 is True
    assert info2["reason"] == "extractions newer than index"


def test_autoindex_env_gating(tmp_path, monkeypatch):
    import nexus.langgraph.llm_pipeline as lp

    case_dir = tmp_path / "CASE-A"
    case_dir.mkdir()

    # Disabled
    monkeypatch.setenv("NEXUS_ES_AUTOINDEX", "0")
    monkeypatch.setenv("NEXUS_ES_URL", "http://localhost:9200")
    out = lp._autoindex_case(case_dir)
    assert any("disabled" in s for s in out)

    # No ES URL -> skipped (auto-index must be re-enabled first)
    monkeypatch.delenv("NEXUS_ES_AUTOINDEX", raising=False)
    monkeypatch.delenv("NEXUS_ES_URL", raising=False)
    out2 = lp._autoindex_case(case_dir)
    assert any("NEXUS_ES_URL empty" in s for s in out2)

    # ES URL set -> attempts index (unreachable ES -> error captured, not raised)
    monkeypatch.setenv("NEXUS_ES_URL", "http://127.0.0.1:1")
    out3 = lp._autoindex_case(case_dir)
    assert any("auto-index" in s for s in out3)


def test_doctor_environment_checks():
    from nexus.cli.doctor_cmd import _environment_checks

    rows = _environment_checks()
    names = {r[0] for r in rows}
    assert "elasticsearch (N3)" in names
    assert "llm config" in names
    assert "rag index" in rows[0][0] or any("rag index" in n for n in names)
    assert "embedding model" in names
    assert "sift ssh" in names
