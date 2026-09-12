"""Tests for Mode 1 Portal UI (ask/select endpoints)."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


def _make_case_dir(tmp_path: Path) -> Path:
    """Create a minimal active case for portal tests."""
    case_dir = tmp_path / "INC-test-0001"
    case_dir.mkdir(parents=True)
    (case_dir / "CASE.yaml").write_text("name: test\nstatus: open\nintake:\n  question: \"test?\"\n")
    (case_dir / "audit").mkdir()
    (case_dir / "extractions").mkdir()
    (case_dir / "findings.json").write_text("[]")
    return case_dir


def _write_hits(case_dir: Path) -> None:
    """Write a tiny CSV extraction and query pack so n4_hits has rows."""
    ext = case_dir / "extractions" / "hayabusa"
    ext.mkdir(parents=True)
    (ext / "timeline.csv").write_text(
        "time,host,event,channel\n"
        "2026-08-10T15:00:00Z,WS01,sdelete.exe,Security\n"
        "2026-08-10T15:01:00Z,WS01,sdelete.exe,Security\n"
    )
    # Write a minimal query pack so run_ad_hoc_query doesn't fail
    from nexus.langgraph.query_pack import load_case_intake
    intake = load_case_intake(case_dir)
    intake["query_extra"] = "sdelete"
    from nexus.langgraph.case_intake import persist_case_intake
    persist_case_intake(case_dir, intake)


def test_nl_to_needles_question():
    from nexus.langgraph.mode1 import _heuristic_needles
    result = _heuristic_needles("Was sdelete used to wipe files?")
    assert "sdelete" in result["needles"]


def test_ask_page_renders_with_no_case():
    from starlette.applications import Starlette
    from starlette.testclient import TestClient

    from nexus.dashboard.app import create_dashboard
    app = Starlette(routes=create_dashboard())
    client = TestClient(app)
    resp = client.get("/portal/ask")
    assert resp.status_code == 200
    assert b"Mode 1" in resp.content


@patch("nexus.dashboard.app._get_case_dir")
@patch("nexus.langgraph.mode1.nl_to_needles")
@patch("nexus.langgraph.query_pack.run_ad_hoc_query")
def test_api_ask_returns_needles_and_hits(mock_query, mock_nl, mock_get_dir, tmp_path):
    from starlette.applications import Starlette
    from starlette.testclient import TestClient

    from nexus.dashboard.app import create_dashboard

    case_dir = _make_case_dir(tmp_path)
    mock_get_dir.return_value = case_dir
    mock_nl.return_value = {"needles": ["sdelete"], "window": "", "source": "llm"}
    mock_query.return_value = {
        "hits": [
            {"family": "hayabusa", "file": "a.csv", "line": "1", "text": "sdelete hit", "terms": "sdelete"}
        ],
        "count": 1,
        "backend": "csv",
    }

    app = Starlette(routes=create_dashboard())
    client = TestClient(app)
    resp = client.post("/portal/api/mode1/ask", json={"question": "sdelete?"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["needles"] == ["sdelete"]
    assert data["count"] == 1


@patch("nexus.dashboard.app._get_case_dir")
def test_api_select_requires_title(mock_get_dir, tmp_path):
    from starlette.applications import Starlette
    from starlette.testclient import TestClient

    from nexus.dashboard.app import create_dashboard

    case_dir = _make_case_dir(tmp_path)
    mock_get_dir.return_value = case_dir

    app = Starlette(routes=create_dashboard())
    client = TestClient(app)
    resp = client.post("/portal/api/mode1/select", json={"hits": [1], "title": ""})
    assert resp.status_code == 400
    data = resp.json()
    assert "error" in data


@patch("nexus.dashboard.app._get_case_dir")
@patch("nexus.langgraph.query_pack.n4_hits")
@patch("nexus.langgraph.mode1.save_draft_finding")
def test_api_select_promotes_hits(mock_save, mock_n4, mock_get_dir, tmp_path):
    from starlette.applications import Starlette
    from starlette.testclient import TestClient

    from nexus.dashboard.app import create_dashboard

    case_dir = _make_case_dir(tmp_path)
    mock_get_dir.return_value = case_dir
    mock_n4.return_value = (
        [
            {"family": "hayabusa", "file": "a.csv", "line": "1", "text": "hit1", "terms": "x"},
            {"family": "hayabusa", "file": "a.csv", "line": "2", "text": "hit2", "terms": "x"},
        ],
        "csv",
    )
    mock_save.return_value = {
        "status": "STAGED",
        "finding_id": "F-test-001",
    }

    app = Starlette(routes=create_dashboard())
    client = TestClient(app)
    resp = client.post("/portal/api/mode1/select", json={
        "hits": [1, 2],
        "title": "sdelete test",
        "scribe": False,
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data.get("finding_id") == "F-test-001"
    assert data.get("status") == "DRAFT"


@patch("nexus.dashboard.app._get_case_dir")
def test_explore_page_renders(mock_get_dir, tmp_path):
    from starlette.applications import Starlette
    from starlette.testclient import TestClient

    from nexus.dashboard.app import create_dashboard

    case_dir = _make_case_dir(tmp_path)
    mock_get_dir.return_value = case_dir

    app = Starlette(routes=create_dashboard())
    client = TestClient(app)
    resp = client.get("/portal/explore")
    assert resp.status_code == 200
    assert b"Explore Evidence" in resp.content


@patch("nexus.dashboard.app._get_case_dir")
@patch("nexus.langgraph.query_pack.n4_query")
def test_api_explore_search(mock_n4q, mock_get_dir, tmp_path):
    """WP 4j.5: a single family filter is pushed into the DSL so the engine's
    `count` is the true filtered total — not the post-filtered page size."""
    from starlette.applications import Starlette
    from starlette.testclient import TestClient

    from nexus.dashboard.app import create_dashboard

    case_dir = _make_case_dir(tmp_path)
    mock_get_dir.return_value = case_dir
    mock_n4q.return_value = {
        "count": 1,
        "backend": "csv",
        "query": "sdelete family:hayabusa",
        "hits": [
            {"family": "hayabusa", "file": "a.csv", "line": "1", "text": "2026-08-10T15:00:00Z hit", "terms": "sdelete"},
        ],
    }

    app = Starlette(routes=create_dashboard())
    client = TestClient(app)
    resp = client.post("/portal/api/explore/search", json={
        "needles": "sdelete",
        "family": "hayabusa",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data.get("count") == 1
    assert len(data.get("hits", [])) == 1
    assert data["hits"][0]["family"] == "hayabusa"
    # the family filter reached the engine as a DSL field, not a page post-filter
    sent_query = mock_n4q.call_args[0][1]
    assert "family:hayabusa" in sent_query
    assert "sdelete" in sent_query


@patch("nexus.dashboard.app._get_case_dir")
@patch("nexus.langgraph.query_pack.n4_query")
def test_api_workbench_add_many(mock_n4q, mock_get_dir, tmp_path):
    """WP 4j.5c — POST /workbench/add_many bookmarks the FULL result set of
    the current Explore query (re-runs server-side), dedupes, and reports
    matched/added/skipped honestly."""
    from starlette.applications import Starlette
    from starlette.testclient import TestClient

    from nexus.dashboard.app import create_dashboard

    case_dir = _make_case_dir(tmp_path)
    mock_get_dir.return_value = case_dir
    mock_n4q.return_value = {
        "count": 3,
        "backend": "csv",
        "query": "sdelete family:hayabusa",
        "hits": [
            {"family": "hayabusa", "file": "a.csv", "line": "1", "text": "2026-08-10T15:00:00Z sdelete", "terms": "sdelete"},
            {"family": "hayabusa", "file": "a.csv", "line": "2", "text": "2026-08-10T15:01:00Z sdelete", "terms": "sdelete"},
            {"family": "hayabusa", "file": "a.csv", "line": "1", "text": "dupe row", "terms": "sdelete"},
        ],
    }

    app = Starlette(routes=create_dashboard())
    client = TestClient(app)
    resp = client.post("/portal/api/workbench/add_many", json={
        "needles": "sdelete",
        "family": "hayabusa",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["matched"] == 3
    assert data["added"] == 2          # same file+line dedupes
    assert data["skipped"] == 1
    assert data["total"] == 2
    assert data["truncated"] is False
    # same DSL construction as /explore/search — family pushed into the query
    sent_query = mock_n4q.call_args[0][1]
    assert "family:hayabusa" in sent_query

    # second call is a no-op — everything already bookmarked
    resp2 = client.post("/portal/api/workbench/add_many", json={"needles": "sdelete", "family": "hayabusa"})
    assert resp2.json()["added"] == 0
    assert resp2.json()["skipped"] == 3


@patch("nexus.dashboard.app._get_case_dir")
@patch("nexus.langgraph.mode1.save_draft_finding")
@patch("nexus.langgraph.query_pack.attach_hit_fields")
@patch("nexus.langgraph.query_pack.n4_query")
@patch("nexus.langgraph.briefing.case_briefing")
def test_api_mode1_full_run(mock_brief, mock_n4q, mock_attach, mock_save, mock_get_dir, tmp_path):
    """WP 4j.5d — POST /mode1/full-run: scan all needles → bookmark all hits
    → stage one DRAFT per needle (heuristic scribe). Approval stays manual —
    the response must stop at DRAFTs and point the examiner at Approve."""
    from starlette.applications import Starlette
    from starlette.testclient import TestClient

    from nexus.dashboard.app import create_dashboard

    case_dir = _make_case_dir(tmp_path)
    mock_get_dir.return_value = case_dir
    mock_brief.return_value = {
        "scanned_needles": 12,
        "needle_scan": [
            {"needle": "sdelete", "hits": 2, "source": "playbook"},
            {"needle": "rundll32", "hits": 1, "source": "playbook"},
            {"needle": "nohit", "hits": 1, "source": "playbook"},
        ],
    }
    mock_attach.side_effect = lambda _cd, hits: hits

    def _query(_cd, q, **_kw):
        if "sdelete" in q:
            return {"count": 2, "backend": "csv", "hits": [
                {"family": "hayabusa", "file": "a.csv", "line": "1", "text": "sdelete x", "terms": "sdelete"},
                {"family": "hayabusa", "file": "a.csv", "line": "2", "text": "sdelete y", "terms": "sdelete"},
            ]}
        if "rundll32" in q:
            return {"count": 1, "backend": "csv", "hits": [
                {"family": "evtx", "file": "b.csv", "line": "9", "text": "rundll32 z", "terms": "rundll32"},
            ]}
        return {"count": 0, "backend": "csv", "hits": []}

    mock_n4q.side_effect = _query
    mock_save.side_effect = lambda _cd, draft: {"status": "STAGED", "finding_id": "F-test-001"}

    app = Starlette(routes=create_dashboard())
    client = TestClient(app)
    resp = client.post("/portal/api/mode1/full-run", json={})
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "complete"
    assert data["needles_scanned"] == 12
    assert data["needles_hit"] == 3
    assert data["bookmarks_added"] == 3
    assert data["drafts_staged"] == 2
    assert len(data["drafts"]) == 2
    # no-hit needle is reported, not silently dropped
    assert any(s.get("needle") == "nohit" for s in data["skipped"])
    # HITL boundary — the run ends at DRAFTs and routes the examiner to Approve
    assert "Approve" in data["next"]
    # hits really landed in the workbench
    from nexus.case.workbench import load_bookmarks
    assert len(load_bookmarks(case_dir)) == 3

    # a pre-existing DRAFT with the same title is skipped, not duplicated
    import json as _json
    (case_dir / "findings.json").write_text(_json.dumps([
        {"title": "Signal: sdelete — 2 hit(s) across hayabusa", "status": "DRAFT"},
    ]))
    resp2 = client.post("/portal/api/mode1/full-run", json={})
    data2 = resp2.json()
    assert data2["drafts_staged"] == 1   # only rundll32 stages this time
    assert any("already staged" in s.get("reason", "") for s in data2["skipped"])
    # bookmarks still dedupe — nothing new added
    assert data2["bookmarks_added"] == 0


@patch("nexus.dashboard.app._get_case_dir")
@patch("nexus.langgraph.briefing.case_briefing")
def test_api_mode1_full_run_no_hits(mock_brief, mock_get_dir, tmp_path):
    """Full run on a case with zero needle hits exits cleanly — no drafts,
    no crash, honest 'nothing to promote'."""
    from starlette.applications import Starlette
    from starlette.testclient import TestClient

    from nexus.dashboard.app import create_dashboard

    case_dir = _make_case_dir(tmp_path)
    mock_get_dir.return_value = case_dir
    mock_brief.return_value = {"scanned_needles": 40, "needle_scan": []}

    app = Starlette(routes=create_dashboard())
    client = TestClient(app)
    resp = client.post("/portal/api/mode1/full-run", json={})
    assert resp.status_code == 200
    data = resp.json()
    assert data["drafts_staged"] if "drafts_staged" in data else data["drafts"] == []
    assert data["needles_hit"] == 0
    assert data["bookmarks_added"] == 0
