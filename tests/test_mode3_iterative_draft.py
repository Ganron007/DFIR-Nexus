"""Tests for WP 3.6 (iterative query in Mode 3) and WP 3.7 (agent DRAFT findings)."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


def _make_case(tmp_path: Path, with_ledger: bool = True, with_ok: bool = True) -> Path:
    case_dir = tmp_path / "CASE-M3IT"
    case_dir.mkdir()
    (case_dir / "CASE.yaml").write_text(
        "name: m3it\nintake:\n  question: credential access mimikatz?\n"
    )
    ext = case_dir / "extractions" / "hayabusa"
    ext.mkdir(parents=True)
    (ext / "timeline.csv").write_text(
        "time,host,event\n2026-08-10T15:00:00Z,WS01,mimikatz.exe run\n"
    )
    if with_ledger:
        ledger = []
        if with_ok:
            ledger.append({"tool": "hayabusa", "status": "OK", "audit_id": "a1"})
        (case_dir / "extractions" / "_tool_lane_ledger.json").write_text(json.dumps(ledger))
    return case_dir


class TestIterativeQueryInMode3:
    """WP 3.6: Mode 3 execution should run an iterative query loop, not just one-shot queries."""

    def test_execute_plan_runs_iterative_loop(self, tmp_path):
        """execute_plan should run the Mode 2 iterative loop for approved queries."""
        from nexus.langgraph.mode3 import execute_plan

        case_dir = _make_case(tmp_path)
        with patch("nexus.langgraph.mode3._run_iterative_for_queries") as mock_iter:
            mock_iter.return_value = {
                "iterations": [
                    {"iteration": 0, "action": "initial_query", "hits": 5},
                    {"iteration": 1, "action": "proposed_and_ran", "hits": 3},
                ],
                "total_hits": 8,
                "capped": False,
            }
            result = execute_plan(case_dir, [], ["mimikatz"])
        assert result["status"] == "executed"
        assert "iterative" in result
        assert result["iterative"]["total_hits"] == 8
        mock_iter.assert_called_once()

    def test_iterative_loop_produces_needle_proposals(self, tmp_path):
        """The iterative loop should propose new needles based on initial hits."""
        from nexus.langgraph.mode3 import _run_iterative_for_queries

        case_dir = _make_case(tmp_path)
        with patch("nexus.langgraph.query_pack.n4_query") as mock_n4, \
             patch("nexus.langgraph.mode1.nl_to_needles") as mock_nl, \
             patch("nexus.langgraph.mode2.propose_next_needles") as mock_propose:
            mock_nl.return_value = {"needles": ["mimikatz"], "window": "", "source": "heuristic"}
            mock_n4.side_effect = [
                {"hits": [{"family": "hayabusa", "file": "t.csv", "line": "1",
                          "text": "mimikatz.exe", "terms": "mimikatz"}],
                 "count": 1, "backend": "csv", "error": None},
                {"hits": [{"family": "prefetch", "file": "p.csv", "line": "1",
                          "text": "mimikatz.exe", "terms": "mimikatz"}],
                 "count": 1, "backend": "csv", "error": None},
            ]
            mock_propose.return_value = {
                "needles": ["lsass", "credential"],
                "rationale": "expand",
                "source": "heuristic",
            }
            result = _run_iterative_for_queries(case_dir, "mimikatz", model=None, max_iterations=2)

        assert "iterations" in result
        assert len(result["iterations"]) >= 2  # initial + at least 1 proposal
        assert result["total_hits"] >= 1

    def test_iterative_loop_caps_at_max_iterations(self, tmp_path):
        """The loop should respect the max_iterations cap."""
        from nexus.langgraph.mode3 import _run_iterative_for_queries

        case_dir = _make_case(tmp_path)
        with patch("nexus.langgraph.query_pack.n4_query") as mock_n4, \
             patch("nexus.langgraph.mode1.nl_to_needles") as mock_nl, \
             patch("nexus.langgraph.mode2.propose_next_needles") as mock_propose:
            mock_nl.return_value = {"needles": ["test"], "source": "heuristic"}
            mock_n4.return_value = {
                "hits": [{"family": "hayabusa", "file": "t.csv", "line": "1",
                         "text": "hit", "terms": "test"}],
                "count": 1, "backend": "csv", "error": None,
            }
            mock_propose.return_value = {
                "needles": ["new1"], "rationale": "expand", "source": "heuristic",
            }
            result = _run_iterative_for_queries(case_dir, "test", model=None, max_iterations=3)

        assert result["capped"] is True
        assert len(result["iterations"]) <= 4  # initial + 3 iterations

    def test_iterative_loop_no_hits_stops_early(self, tmp_path):
        """If initial query returns no hits, the loop should stop."""
        from nexus.langgraph.mode3 import _run_iterative_for_queries

        case_dir = _make_case(tmp_path)
        with patch("nexus.langgraph.query_pack.n4_query") as mock_n4, \
             patch("nexus.langgraph.mode1.nl_to_needles") as mock_nl:
            mock_nl.return_value = {"needles": ["nothing"], "source": "heuristic"}
            mock_n4.return_value = {"hits": [], "count": 0, "backend": "csv", "error": None}
            result = _run_iterative_for_queries(case_dir, "nothing", model=None, max_iterations=3)

        assert len(result["iterations"]) == 1
        assert result["total_hits"] == 0

    def test_iterative_logged_to_agent_runs(self, tmp_path):
        """Iterative loop execution must be logged to agent_runs.jsonl."""
        from nexus.langgraph.mode3 import execute_plan

        case_dir = _make_case(tmp_path)
        with patch("nexus.langgraph.mode3._run_iterative_for_queries") as mock_iter:
            mock_iter.return_value = {
                "iterations": [{"iteration": 0, "hits": 1}],
                "total_hits": 1,
                "capped": False,
            }
            execute_plan(case_dir, [], ["mimikatz"])

        log_file = case_dir / "agent_runs.jsonl"
        assert log_file.is_file()
        entries = [json.loads(ln) for ln in log_file.read_text().strip().splitlines() if ln.strip()]
        assert any(e.get("action") == "mode3_iterative" for e in entries)


class TestAgentDraftFindings:
    """WP 3.7: Mode 3 agent should propose DRAFT findings with examiner_selected=False."""

    def test_propose_agent_draft_finding(self, tmp_path):
        """Agent should stage a DRAFT finding with examiner_selected=False."""
        from nexus.langgraph.mode3 import propose_agent_finding

        case_dir = _make_case(tmp_path)
        hits = [
            {"family": "hayabusa", "file": "t.csv", "line": "1",
             "text": "mimikatz.exe run", "terms": "mimikatz", "audit_id": "a1"},
            {"family": "prefetch", "file": "p.csv", "line": "1",
             "text": "mimikatz.exe", "terms": "mimikatz", "audit_id": "a2"},
        ]
        result = propose_agent_finding(case_dir, hits, "Credential access via mimikatz", model=None)
        assert "draft" in result
        draft = result["draft"]
        assert draft.get("examiner_selected") is False
        assert draft.get("status") == "DRAFT"
        assert "evidence" in draft
        assert len(draft["evidence"]) >= 1

    def test_agent_finding_has_corroboration(self, tmp_path):
        """Agent DRAFT finding should include corroboration check."""
        from nexus.langgraph.mode3 import propose_agent_finding

        case_dir = _make_case(tmp_path)
        hits = [
            {"family": "hayabusa", "file": "t.csv", "line": "1",
             "text": "mimikatz.exe", "terms": "mimikatz", "audit_id": "a1"},
            {"family": "prefetch", "file": "p.csv", "line": "1",
             "text": "mimikatz.exe", "terms": "mimikatz", "audit_id": "a2"},
        ]
        result = propose_agent_finding(case_dir, hits, "Test finding", model=None)
        assert "corroboration" in result
        corrob = result["corroboration"]
        assert "families" in corrob
        assert "ok" in corrob

    def test_agent_finding_rejects_empty_hits(self, tmp_path):
        """Agent should refuse to draft from no hits."""
        from nexus.langgraph.mode3 import propose_agent_finding

        case_dir = _make_case(tmp_path)
        result = propose_agent_finding(case_dir, [], "Empty finding", model=None)
        assert "error" in result

    def test_agent_finding_logged_to_agent_runs(self, tmp_path):
        """Agent DRAFT finding must be logged to agent_runs.jsonl."""
        from nexus.langgraph.mode3 import propose_agent_finding

        case_dir = _make_case(tmp_path)
        hits = [
            {"family": "hayabusa", "file": "t.csv", "line": "1",
             "text": "mimikatz.exe", "terms": "mimikatz", "audit_id": "a1"},
            {"family": "prefetch", "file": "p.csv", "line": "1",
             "text": "mimikatz.exe", "terms": "mimikatz", "audit_id": "a2"},
        ]
        propose_agent_finding(case_dir, hits, "Test", model=None)
        log_file = case_dir / "agent_runs.jsonl"
        assert log_file.is_file()
        entries = [json.loads(ln) for ln in log_file.read_text().strip().splitlines() if ln.strip()]
        assert any(e.get("action") == "mode3_draft_finding" for e in entries)

    def test_agent_finding_uses_llm_scribe(self, tmp_path):
        """When LLM is available, agent finding should use it for scribing."""
        from nexus.langgraph.mode3 import propose_agent_finding

        case_dir = _make_case(tmp_path)
        hits = [
            {"family": "hayabusa", "file": "t.csv", "line": "1",
             "text": "mimikatz.exe", "terms": "mimikatz", "audit_id": "a1"},
            {"family": "prefetch", "file": "p.csv", "line": "1",
             "text": "mimikatz.exe", "terms": "mimikatz", "audit_id": "a2"},
        ]
        model = MagicMock()
        result = propose_agent_finding(case_dir, hits, "LLM finding", model=model)
        assert "draft" in result
        # The draft should have been scribed (title/summary enriched)
        draft = result["draft"]
        assert "title" in draft

    def test_agent_finding_never_auto_approves(self, tmp_path):
        """Agent finding must always be DRAFT, never APPROVED."""
        from nexus.langgraph.mode3 import propose_agent_finding

        case_dir = _make_case(tmp_path)
        hits = [
            {"family": "hayabusa", "file": "t.csv", "line": "1",
             "text": "mimikatz.exe", "terms": "mimikatz", "audit_id": "a1"},
            {"family": "prefetch", "file": "p.csv", "line": "1",
             "text": "mimikatz.exe", "terms": "mimikatz", "audit_id": "a2"},
        ]
        result = propose_agent_finding(case_dir, hits, "Test", model=None)
        draft = result["draft"]
        assert draft.get("status") != "APPROVED"
        assert draft.get("status") == "DRAFT"
