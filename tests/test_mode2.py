"""Tests for Mode 2 — iterative LLM-guided analysis."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from nexus.langgraph.mode2 import corroboration_check, corroboration_suggestions


def _make_case(tmp_path: Path) -> Path:
    case_dir = tmp_path / "CASE-M2"
    case_dir.mkdir()
    (case_dir / "CASE.yaml").write_text("name: m2\nintake:\n  question: test?\n")
    ext = case_dir / "extractions" / "hayabusa"
    ext.mkdir(parents=True)
    (ext / "timeline.csv").write_text(
        "time,host,event\n"
        "2026-08-10T15:00:00Z,WS01,sdelete.exe run\n"
        "2026-08-10T15:01:00Z,WS01,sdelete42.tmp renamed\n"
    )
    return case_dir


class TestCorroboration:
    def test_single_family_low_is_ok(self):
        finding = {"evidence": [{"source": "prefetch/x"}], "confidence": "LOW", "audit_ids": ["a1"]}
        result = corroboration_check(finding)
        assert result["ok"] is True
        assert result["distinct_families"] == 1

    def test_single_family_high_flagged(self):
        finding = {"evidence": [{"source": "prefetch/x"}], "confidence": "HIGH", "audit_ids": ["a1"]}
        result = corroboration_check(finding)
        assert result["ok"] is False
        assert any("FD-006" in p for p in result["problems"])

    def test_multi_family_ok(self):
        finding = {
            "evidence": [{"source": "prefetch/x"}, {"source": "amcache/y"}],
            "confidence": "HIGH",
            "audit_ids": ["a1", "a2", "a3"],
        }
        result = corroboration_check(finding)
        assert result["ok"] is True

    def test_suggestions_map_family(self):
        finding = {"evidence": [{"source": "prefetch/x"}], "confidence": "LOW"}
        sugg = corroboration_suggestions(finding)
        assert "amcache" in sugg and "shimcache" in sugg


class TestIterativeLoop:
    @patch("nexus.langgraph.query_pack.n4_query")
    @patch("nexus.langgraph.mode1.nl_to_needles")
    def test_loop_runs_and_logs(self, mock_nl, mock_n4, tmp_path):
        from nexus.case.chat import load_chat
        from nexus.langgraph.mode2 import run_iterative_loop

        case_dir = _make_case(tmp_path)
        mock_nl.return_value = {"needles": ["sdelete"], "window": "", "source": "heuristic"}
        mock_n4.side_effect = [
            {"hits": [{"family": "hayabusa", "file": "t.csv", "line": "1", "text": "sdelete.exe run", "terms": "sdelete"}], "count": 1, "backend": "csv", "error": None},
            {"hits": [{"family": "hayabusa", "file": "t.csv", "line": "2", "text": "sdelete42.tmp renamed", "terms": "sdelete"}], "count": 1, "backend": "csv", "error": None},
        ]
        result = run_iterative_loop(case_dir, "Was sdelete used?", model=None, max_iterations=1)
        assert not result.get("error")
        assert len(result["iterations"]) >= 1
        assert result["total_hits"] >= 1
        chat = load_chat(case_dir)
        assert any(m["action"] == "mode2_iter0" for m in chat)
        assert any(m["action"] == "mode2_proposal" for m in chat)

    @patch("nexus.langgraph.mode1.nl_to_needles")
    def test_loop_no_needles(self, mock_nl, tmp_path):
        from nexus.langgraph.mode2 import run_iterative_loop

        case_dir = _make_case(tmp_path)
        mock_nl.return_value = {"needles": [], "window": "", "source": "heuristic"}
        result = run_iterative_loop(case_dir, "gibberish", model=None, max_iterations=1)
        assert result.get("error")
