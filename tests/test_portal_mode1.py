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
@patch("nexus.langgraph.query_pack.n4_hits")
def test_api_explore_search(mock_n4, mock_get_dir, tmp_path):
    from starlette.applications import Starlette
    from starlette.testclient import TestClient

    from nexus.dashboard.app import create_dashboard

    case_dir = _make_case_dir(tmp_path)
    mock_get_dir.return_value = case_dir
    mock_n4.return_value = (
        [
            {"family": "hayabusa", "file": "a.csv", "line": "1", "text": "2026-08-10T15:00:00Z hit", "terms": "sdelete"},
            {"family": "prefetch", "file": "b.csv", "line": "2", "text": "2026-08-10T16:00:00Z hit", "terms": "sdelete"},
        ],
        "csv",
    )

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
