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
