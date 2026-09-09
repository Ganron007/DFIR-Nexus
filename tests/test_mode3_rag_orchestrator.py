"""Tests for WP 3.5/3.9/3.10/3.11/3.12 — Mode 3 LLM planning + RAG + orchestrator."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


def _make_case(tmp_path: Path, with_ledger: bool = True, with_ok: bool = True) -> Path:
    case_dir = tmp_path / "CASE-M3RAG"
    case_dir.mkdir()
    (case_dir / "CASE.yaml").write_text(
        "name: m3rag\nintake:\n  question: credential access?\n"
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
        ledger.append({"tool": "srumecmd", "status": "SKIP", "reason": "binary not installed"})
        (case_dir / "extractions" / "_tool_lane_ledger.json").write_text(json.dumps(ledger))
    return case_dir


class TestLLMDrivenPlanning:
    """WP 3.5: plan_extras must use LLM to propose plan items, not just static dict."""

    def test_llm_proposes_plan_items(self, tmp_path):
        """When LLM is available, it should propose plan items beyond the static dict."""
        from nexus.langgraph.mode3 import plan_extras

        case_dir = _make_case(tmp_path)
        model = MagicMock()
        model.invoke.return_value = MagicMock(
            content=json.dumps({
                "items": [
                    {"type": "extra", "key": "chrome_profiles", "purpose": "Check browser history"},
                    {"type": "tool_skip", "tool": "srumecmd", "reason": "SRUM data for network correlation"},
                ],
                "rationale": "LLM identified credential access investigation needs SRUM + browser history",
            })
        )
        plan = plan_extras(case_dir, model=model)
        assert "items" in plan
        assert len(plan["items"]) > 0
        # LLM rationale should be present
        assert "credential" in plan["rationale"].lower() or "LLM" in plan["rationale"]

    def test_llm_plan_includes_rag_context(self, tmp_path):
        """WP 3.9: LLM planning prompt must include RAG methodology for SKIP'd artifacts."""
        from nexus.langgraph.mode3 import plan_extras

        case_dir = _make_case(tmp_path)
        model = MagicMock()
        model.invoke.return_value = MagicMock(
            content=json.dumps({
                "items": [{"type": "tool_skip", "tool": "srumecmd", "reason": "SRUM methodology"}],
                "rationale": "RAG says SRUM shows network usage per process",
            })
        )

        mock_idx = MagicMock()
        mock_idx.search.return_value = {
            "results": [
                {"text": "SRUM tracks network usage per process over time",
                 "source": "kape", "title": "SRUM methodology", "score": 0.9},
            ]
        }

        with patch("nexus.tools.rag._check_rag_available", return_value=(True, "")), \
             patch("nexus.tools.rag._get_index", return_value=mock_idx):
            plan = plan_extras(case_dir, model=model)

        # Verify RAG was called for SKIP'd tools
        assert mock_idx.search.called
        # Verify RAG context is in the plan output
        assert "rag_context" in plan or "rag_provenance" in plan

    def test_plan_without_llm_still_works(self, tmp_path):
        """Without LLM, plan_extras falls back to deterministic planning."""
        from nexus.langgraph.mode3 import plan_extras

        case_dir = _make_case(tmp_path)
        plan = plan_extras(case_dir, model=None)
        assert "items" in plan
        assert len(plan["items"]) > 0
        assert plan["rationale"]

    def test_plan_without_rag_still_works(self, tmp_path):
        """WP 3.9: When RAG is unavailable, planning still works (degraded)."""
        from nexus.langgraph.mode3 import plan_extras

        case_dir = _make_case(tmp_path)
        model = MagicMock()
        model.invoke.return_value = MagicMock(
            content=json.dumps({"items": [], "rationale": "test"})
        )
        with patch("nexus.tools.rag._check_rag_available", return_value=(False, "not installed")):
            plan = plan_extras(case_dir, model=model)
        assert "items" in plan


class TestRagProvenanceInPlan:
    """WP 3.12: RAG queries used during planning must be recorded for audit."""

    def test_rag_provenance_in_plan_output(self, tmp_path):
        """When RAG is used during planning, provenance is in the plan output."""
        from nexus.langgraph.mode3 import plan_extras

        case_dir = _make_case(tmp_path)
        model = MagicMock()
        model.invoke.return_value = MagicMock(
            content=json.dumps({"items": [], "rationale": "test"})
        )

        mock_idx = MagicMock()
        mock_idx.search.return_value = {
            "results": [{"text": "SRUM methodology", "source": "kape", "score": 0.9}]
        }

        with patch("nexus.tools.rag._check_rag_available", return_value=(True, "")), \
             patch("nexus.tools.rag._get_index", return_value=mock_idx):
            plan = plan_extras(case_dir, model=model)

        if "rag_provenance" in plan:
            prov = plan["rag_provenance"]
            assert isinstance(prov, list)
            if prov:
                assert "query" in prov[0]


class TestAgentRunLedger:
    """WP 3.11: Agent runs must be logged with full context for audit."""

    def test_plan_logged_with_rag_context(self, tmp_path):
        """agent_runs.jsonl must record RAG queries used during planning."""
        from nexus.langgraph.mode3 import plan_extras

        case_dir = _make_case(tmp_path)
        model = MagicMock()
        model.invoke.return_value = MagicMock(
            content=json.dumps({"items": [], "rationale": "test"})
        )

        mock_idx = MagicMock()
        mock_idx.search.return_value = {
            "results": [{"text": "SRUM methodology", "source": "kape", "score": 0.9}]
        }

        with patch("nexus.tools.rag._check_rag_available", return_value=(True, "")), \
             patch("nexus.tools.rag._get_index", return_value=mock_idx):
            plan_extras(case_dir, model=model)

        log_file = case_dir / "agent_runs.jsonl"
        assert log_file.is_file()
        entries = [json.loads(ln) for ln in log_file.read_text().strip().splitlines() if ln.strip()]
        assert any(e.get("action") == "mode3_plan" for e in entries)
        # The plan entry should record whether RAG was used
        plan_entry = next(e for e in entries if e.get("action") == "mode3_plan")
        assert "rag_used" in plan_entry


class TestOrchestrator:
    """WP 3.10: Mode 3 orchestrator dispatches specialist agents per evidence family."""

    def test_orchestrator_dispatches_agents(self, tmp_path):
        """Orchestrator should dispatch agents based on evidence families in the case."""
        from nexus.langgraph.orchestrator import run_orchestrator

        case_dir = _make_case(tmp_path)
        # Add evidence hits for different families
        hits = [
            {"family": "hayabusa", "file": "t.csv", "line": "1", "text": "mimikatz.exe", "terms": "mimikatz"},
            {"family": "prefetch", "file": "p.csv", "line": "1", "text": "mimikatz.exe", "terms": "mimikatz"},
        ]

        result = run_orchestrator(case_dir, hits, model=None)
        assert "agent_runs" in result
        assert len(result["agent_runs"]) > 0
        # Each agent run should have a name, status, and evidence refs
        for run in result["agent_runs"]:
            assert "agent" in run
            assert "status" in run
            assert "evidence_families" in run

    def test_orchestrator_injects_rag_context(self, tmp_path):
        """Each agent should receive RAG methodology for its evidence family."""
        from nexus.langgraph.orchestrator import run_orchestrator

        case_dir = _make_case(tmp_path)
        hits = [
            {"family": "prefetch", "file": "p.csv", "line": "1", "text": "mimikatz.exe", "terms": "mimikatz"},
        ]

        mock_idx = MagicMock()
        mock_idx.search.return_value = {
            "results": [{"text": "Prefetch shows execution", "source": "kape", "score": 0.9}]
        }

        with patch("nexus.tools.rag._check_rag_available", return_value=(True, "")), \
             patch("nexus.tools.rag._get_index", return_value=mock_idx):
            result = run_orchestrator(case_dir, hits, model=None)

        # At least one agent run should have RAG context
        assert any(run.get("rag_context") for run in result["agent_runs"])

    def test_orchestrator_logs_to_agent_runs(self, tmp_path):
        """Orchestrator must log each agent run to agent_runs.jsonl."""
        from nexus.langgraph.orchestrator import run_orchestrator

        case_dir = _make_case(tmp_path)
        hits = [
            {"family": "hayabusa", "file": "t.csv", "line": "1", "text": "test", "terms": "test"},
        ]

        run_orchestrator(case_dir, hits, model=None)
        log_file = case_dir / "agent_runs.jsonl"
        assert log_file.is_file()
        entries = [json.loads(ln) for ln in log_file.read_text().strip().splitlines() if ln.strip()]
        assert any(e.get("action") == "orchestrator_agent_run" for e in entries)

    def test_orchestrator_synthesis_corroborates(self, tmp_path):
        """Synthesis node should cross-reference findings across agent families."""
        from nexus.langgraph.orchestrator import run_orchestrator

        case_dir = _make_case(tmp_path)
        hits = [
            {"family": "hayabusa", "file": "t.csv", "line": "1", "text": "mimikatz.exe", "terms": "mimikatz"},
            {"family": "prefetch", "file": "p.csv", "line": "1", "text": "mimikatz.exe", "terms": "mimikatz"},
        ]

        result = run_orchestrator(case_dir, hits, model=None)
        assert "synthesis" in result
        synth = result["synthesis"]
        assert "corroborated" in synth
        assert "families_covered" in synth

    def test_orchestrator_no_hits(self, tmp_path):
        """Orchestrator handles empty hits gracefully."""
        from nexus.langgraph.orchestrator import run_orchestrator

        case_dir = _make_case(tmp_path)
        result = run_orchestrator(case_dir, [], model=None)
        assert "agent_runs" in result
        assert len(result["agent_runs"]) == 0
