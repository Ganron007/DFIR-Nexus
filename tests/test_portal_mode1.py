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
    from nexus.modes.llm_desk import _heuristic_needles
    result = _heuristic_needles("Was sdelete used to wipe files?")
    assert "sdelete" in result["needles"]


def test_ask_page_redirects_to_spa():
    """WO-U7: the legacy server-rendered pages are retired — the SPA is the
    one portal, and legacy URLs redirect to their SPA routes."""
    from starlette.applications import Starlette
    from starlette.testclient import TestClient

    from nexus.dashboard.app import create_dashboard
    app = Starlette(routes=create_dashboard())
    client = TestClient(app)
    resp = client.get("/portal/ask", follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"] == "/portal/app/steer"


@patch("nexus.dashboard.app._get_case_dir")
@patch("nexus.modes.llm_desk.nl_to_needles")
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
@patch("nexus.modes.llm_desk.save_draft_finding")
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


def test_explore_page_redirects_to_spa():
    """WO-U7: legacy page URLs 302 to their SPA routes."""
    from starlette.applications import Starlette
    from starlette.testclient import TestClient

    from nexus.dashboard.app import create_dashboard

    app = Starlette(routes=create_dashboard())
    client = TestClient(app)
    resp = client.get("/portal/explore", follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"] == "/portal/app/explore"


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
@patch("nexus.modes.llm_desk.save_draft_finding")
@patch("nexus.langgraph.query_pack.attach_hit_fields")
def test_api_workbench_promote_confidence_override(mock_attach, mock_save, mock_get_dir, tmp_path):
    """Examiner-selected confidence + justification override the heuristic
    scribe's values before the draft is staged — the UI controls are
    authoritative, the scribe is only the fallback."""
    import json as _json

    from starlette.applications import Starlette
    from starlette.testclient import TestClient

    from nexus.dashboard.app import create_dashboard

    case_dir = _make_case_dir(tmp_path)
    mock_get_dir.return_value = case_dir
    (case_dir / "workbench.json").write_text(_json.dumps([
        {"id": "B-001", "family": "hayabusa", "file": "a.csv", "line": "1",
         "time": "", "text": "sdelete hit", "note": "", "bookmarked_at": "x"},
    ]), encoding="utf-8")
    mock_attach.side_effect = lambda _cd, hits: hits
    mock_save.return_value = {"status": "STAGED", "finding_id": "F-wb-1"}

    app = Starlette(routes=create_dashboard())
    client = TestClient(app)

    bad = client.post("/portal/api/workbench/promote", json={
        "bookmark_ids": ["B-001"], "title": "t", "confidence": "BOGUS",
    })
    assert bad.status_code == 400

    resp = client.post("/portal/api/workbench/promote", json={
        "bookmark_ids": ["B-001"],
        "title": "Examiner finding",
        "scribe": False,
        "confidence": "high",
        "confidence_justification": "Two corroborating sources confirmed by examiner",
    })
    assert resp.status_code == 200, resp.text
    assert resp.json()["finding_id"] == "F-wb-1"
    draft = mock_save.call_args.args[1]
    assert draft["confidence"] == "HIGH"
    assert draft["confidence_justification"] == "Two corroborating sources confirmed by examiner"


@patch("nexus.dashboard.app._get_case_dir")
def test_api_report_steer_records_round_and_regenerates(mock_get_dir, tmp_path):
    """4j.5i — POST /report/steer persists a round and regenerates REPORT.md."""
    import json as _json

    from starlette.applications import Starlette
    from starlette.testclient import TestClient

    from nexus.dashboard.app import create_dashboard

    case_dir = _make_case_dir(tmp_path)
    (case_dir / "findings.json").write_text(_json.dumps([{
        "id": "F-1", "title": "Signal: mshta — 2 hit(s) across hayabusa",
        "status": "APPROVED", "severity": "high",
        "evidence": [{"time": "2019-05-21T15:32:57", "source": "hayabusa/x.csv",
                      "detail": "RuleTitle: MSHTA exec", "loc": "x.csv:3"}],
    }]))
    mock_get_dir.return_value = case_dir
    app = Starlette(routes=create_dashboard())
    client = TestClient(app)

    bad = client.post("/portal/api/report/steer", json={})
    assert bad.status_code == 400

    res = client.post("/portal/api/report/steer", json={
        "instruction": "dig into the mshta chain", "llm": False,
        "finding_id": "F-1",
    })
    assert res.status_code == 200
    assert res.json()["round"] == 1
    assert res.json()["report_sha256"]
    assert res.json()["snapshot_path"] == "analysis/report_rounds/round-0001.md"
    assert (case_dir / "reports" / "REPORT.md").is_file()

    res2 = client.post("/portal/api/report/steer", json={
        "instruction": "focus on persistence next", "llm": False,
    })
    assert res2.json()["round"] == 2
    assert res2.json()["instructions_applied"] == 2

    rounds = client.get("/portal/api/report/rounds").json()["rounds"]
    assert len(rounds) == 2
    assert rounds[0]["instruction"] == "dig into the mshta chain"
    assert rounds[0]["finding_id"] == "F-1"
    assert rounds[1]["model"]  # model name or 'heuristic' recorded

    import hashlib
    for r in rounds:
        snap = case_dir / r["snapshot_path"]
        assert snap.is_file()
        assert hashlib.sha256(snap.read_bytes()).hexdigest() == r["report_sha256"]
    assert rounds[1]["previous_report_sha256"] == rounds[0]["report_sha256"]


@patch("nexus.dashboard.app._get_case_dir")
def test_api_report_generate_preserves_steering(mock_get_dir, tmp_path):
    """Ordinary /report/generate keeps the accumulated steering — including
    per-finding focus — instead of resetting the narrative loop."""
    import json as _json

    from starlette.applications import Starlette
    from starlette.testclient import TestClient

    from nexus.dashboard.app import create_dashboard

    case_dir = _make_case_dir(tmp_path)
    (case_dir / "analysis").mkdir(parents=True, exist_ok=True)
    (case_dir / "analysis" / "report_rounds.json").write_text(_json.dumps([
        {"round": 1, "instruction": "dig into mshta", "finding_id": "F-1"},
        {"round": 2, "instruction": "focus on persistence"},
    ]), encoding="utf-8")
    mock_get_dir.return_value = case_dir

    app = Starlette(routes=create_dashboard())
    client = TestClient(app)

    with patch("nexus.dashboard.app._write_case_report") as mock_write:
        mock_write.return_value = {"ok": True, "report_path": "x", "findings_count": 0}
        resp = client.post("/portal/api/report/generate", json={"llm": False})
    assert resp.status_code == 200
    steer = mock_write.call_args.kwargs["steer"]
    assert "(r1) dig into mshta [focus: F-1]" in steer
    assert "(r2) focus on persistence" in steer

@patch("nexus.dashboard.app._get_case_dir")
@patch("nexus.modes.llm_desk.save_draft_finding")
@patch("nexus.modes.llm_desk.promote_hits_to_draft")
def test_api_select_rows_identity_and_drift(mock_promote, mock_save, mock_get_dir, tmp_path):
    """EH-6: selection by stable row identity — a row that is not in the
    current result is reported (409), never substituted by index drift."""
    from starlette.applications import Starlette
    from starlette.testclient import TestClient

    from nexus.dashboard.app import create_dashboard

    case_dir = _make_case_dir(tmp_path)
    _write_hits(case_dir)
    mock_get_dir.return_value = case_dir

    def _promote(_cd, hits, title, **_kw):
        return {
            "id": "F-draft", "title": title,
            "evidence": [
                {"source": f"{h.get('family')}/{h.get('file')}",
                 "line": h.get("line"), "detail": h.get("text")}
                for h in hits
            ],
            "audit_ids": ["a-1"], "confidence": "LOW",
            "confidence_justification": "test",
        }

    mock_promote.side_effect = _promote
    mock_save.side_effect = lambda _cd, draft: {"status": "STAGED", "finding_id": "F-test-001"}

    app = Starlette(routes=create_dashboard())
    client = TestClient(app)

    drift = client.post("/portal/api/mode1/select", json={
        "rows": [{"family": "hayabusa", "file": "hayabusa/timeline.csv", "line": "999"}],
        "title": "Drift test", "scribe": False,
    })
    assert drift.status_code == 409
    assert "999" in str(drift.json().get("missing"))
    assert not mock_promote.called

    ok = client.post("/portal/api/mode1/select", json={
        "rows": [{"family": "hayabusa", "file": "hayabusa/timeline.csv", "line": "2"}],
        "title": "Exact row", "scribe": False,
    })
    assert ok.status_code == 200
    assert ok.json()["finding_id"] == "F-test-001"
    selected = mock_promote.call_args.kwargs["hits"]
    assert len(selected) == 1
    assert str(selected[0].get("line")) == "2"
