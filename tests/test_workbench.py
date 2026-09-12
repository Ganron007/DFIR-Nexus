"""Tests for the Mode 1 workbench (bookmarks -> DRAFT)."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from nexus.case.workbench import (  # noqa: E402
    add_bookmark,
    clear_bookmarks,
    load_bookmarks,
    remove_bookmark,
)


def _hit(n: int = 1, text: str = "2026-08-10T15:00:00Z sdelete.exe on WS01") -> dict:
    return {
        "family": "hayabusa",
        "file": "hayabusa/timeline.csv",
        "line": str(n),
        "text": text,
        "terms": "sdelete",
    }


def test_add_dedupe_and_ids(tmp_path):
    case_dir = tmp_path / "CASE-WB"
    case_dir.mkdir()
    r1 = add_bookmark(case_dir, _hit(1))
    assert r1["status"] == "added"
    r2 = add_bookmark(case_dir, _hit(1))
    assert r2["status"] == "exists"
    r3 = add_bookmark(case_dir, _hit(2))
    assert r3["status"] == "added"
    assert r3["total"] == 2


def test_remove_and_clear(tmp_path):
    case_dir = tmp_path / "CASE-WB"
    case_dir.mkdir()
    add_bookmark(case_dir, _hit(1))
    r = add_bookmark(case_dir, _hit(2))
    bid = r["bookmark_id"]
    assert remove_bookmark(case_dir, "B-999")["status"] == "not_found"
    assert remove_bookmark(case_dir, bid)["status"] == "removed"
    assert clear_bookmarks(case_dir)["status"] == "cleared"

    assert load_bookmarks(case_dir) == []


def test_bookmark_parses_time_from_text(tmp_path):

    case_dir = tmp_path / "CASE-T"
    case_dir.mkdir()
    add_bookmark(case_dir, _hit(1))
    bm = load_bookmarks(case_dir)[0]
    assert bm["time"] == "2026-08-10T15:00:00"


def test_add_bookmarks_bulk_dedupes(tmp_path):
    """WP 4j.5c — bulk bookmark: dedupes within the batch and against
    existing bookmarks, assigns sequential ids, single write."""
    from nexus.case.workbench import add_bookmarks

    case_dir = tmp_path / "CASE-WB"
    case_dir.mkdir()
    add_bookmark(case_dir, _hit(1))  # existing B-001

    r = add_bookmarks(case_dir, [_hit(1), _hit(2), _hit(2), _hit(3)])
    assert r["status"] == "added"
    assert r["added"] == 2            # _hit(1) exists; _hit(2) dupes in-batch
    assert r["skipped"] == 2
    assert r["total"] == 3
    ids = [b["id"] for b in load_bookmarks(case_dir)]
    assert ids == ["B-001", "B-002", "B-003"]


def test_add_bookmarks_empty_is_noop(tmp_path):
    from nexus.case.workbench import add_bookmarks

    case_dir = tmp_path / "CASE-WB"
    case_dir.mkdir()
    r = add_bookmarks(case_dir, [])
    assert r["added"] == 0 and r["total"] == 0
    assert not (case_dir / "workbench.json").exists()
