"""Tests for steer-chat persistence (Phase 1.4)."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from nexus.case.chat import append_chat, clear_chat, load_chat


def test_append_and_load(tmp_path):
    case_dir = tmp_path / "CASE-CHAT"
    case_dir.mkdir()
    append_chat(case_dir, "examiner", "ask", "Was sdelete used?")
    append_chat(case_dir, "llm", "query_run", "Needles: sdelete | hits: 5", {"hits": 5})
    msgs = load_chat(case_dir)
    assert len(msgs) == 2
    assert msgs[0]["role"] == "examiner"
    assert msgs[0]["action"] == "ask"
    assert msgs[1]["role"] == "llm"
    assert msgs[1]["meta"]["hits"] == "5"


def test_clear(tmp_path):
    case_dir = tmp_path / "CASE-C"
    case_dir.mkdir()
    append_chat(case_dir, "examiner", "ask", "q")
    assert clear_chat(case_dir)["status"] == "cleared"
    from nexus.case.chat import load_chat

    assert load_chat(case_dir) == []


def test_load_empty_case(tmp_path):
    assert load_chat(tmp_path / "nope") == []
