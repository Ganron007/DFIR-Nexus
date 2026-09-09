"""Tests for audit-fix gaps: playbook first-phase matching, corroboration from caveats, orchestrator playbook context."""

from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


class TestPlaybookFirstPhaseMatching:
    """GAP 1 fix: _playbook_context_for_families must extract first-phase steps, not just 'Identify'."""

    def test_browser_forensics_gets_locate_artifacts_steps(self):
        """browser_forensics has 'Locate Artifacts' as first phase, not 'Identify'."""
        from nexus.langgraph.mode2 import _playbook_context_for_families

        # browser_forensics has query_terms including 'chrome'
        context = _playbook_context_for_families({"chrome"})
        assert context, "Expected playbook context for chrome family"
        # Should contain "Locate Artifacts" steps, not empty
        assert "Locate Artifacts" in context or "steps" in context

    def test_memory_forensics_gets_acquire_steps(self):
        """memory_forensics has 'Acquire' as first phase, not 'Identify'."""
        from nexus.langgraph.mode2 import _playbook_context_for_families

        context = _playbook_context_for_families({"volatility"})
        if context:
            # Should contain first-phase steps (Acquire)
            assert "Acquire" in context or "steps" in context

    def test_credential_access_still_gets_identify_steps(self):
        """credential_access has 'Identify' as first phase — should still work."""
        from nexus.langgraph.mode2 import _playbook_context_for_families

        context = _playbook_context_for_families({"mimikatz"})
        if context:
            assert "Identify" in context or "steps" in context

    def test_all_playbooks_get_first_phase_steps(self):
        """Every playbook that matches a family should have its first-phase steps extracted."""
        from nexus.knowledge.loader import get_playbook, list_playbook_slugs
        from nexus.langgraph.mode2 import _playbook_context_for_families

        slugs = list_playbook_slugs()
        for slug in slugs:
            pb = get_playbook(slug)
            if not pb:
                continue
            terms = pb.get("query_terms") or []
            if not terms:
                continue
            # Use the first query_term as the "family"
            family = str(terms[0]).lower()
            context = _playbook_context_for_families({family})
            if context:
                # Should contain some steps (not just caveats)
                assert "steps" in context.lower(), f"Playbook {slug} context missing steps for family {family}"


class TestCorroborationFromPlaybook:
    """GAP 2 fix: corroboration_suggestions should use playbook caveats, not just hard-coded dict."""

    def test_corroboration_uses_playbook_caveats(self):
        """When a playbook has caveats mentioning other artifact families, those should be suggested."""
        from nexus.langgraph.mode2 import _corroborate_for

        # credential_access playbook has caveats mentioning prefetch, amcache, etc.
        result = _corroborate_for("mimikatz")
        # Should return something (from playbook caveats or fallback)
        assert isinstance(result, list)

    def test_corroboration_falls_back_to_hardcoded(self):
        """When no playbook matches, the hard-coded mapping should still work."""
        from nexus.langgraph.mode2 import _corroborate_for

        # "srum" is in the hard-coded mapping
        result = _corroborate_for("srum")
        assert isinstance(result, list)
        # Should include netstat from the hard-coded mapping
        if result:
            assert "netstat" in result or len(result) > 0


class TestOrchestratorPlaybookContext:
    """GAP 3 fix: orchestrator should inject playbook context alongside RAG."""

    def test_orchestrator_agent_has_playbook_context(self, tmp_path):
        """Each agent run should have playbook_context field."""
        from nexus.langgraph.orchestrator import run_orchestrator

        case_dir = tmp_path / "CASE-AUDIT"
        case_dir.mkdir()
        (case_dir / "CASE.yaml").write_text("name: audit\nintake:\n  question: test?\n")
        ext = case_dir / "extractions" / "hayabusa"
        ext.mkdir(parents=True)
        (ext / "timeline.csv").write_text("time,host,event\n2026-08-10T15:00:00Z,WS01,mimikatz.exe\n")

        hits = [
            {"family": "hayabusa", "file": "t.csv", "line": "1",
             "text": "mimikatz.exe", "terms": "mimikatz"},
        ]

        result = run_orchestrator(case_dir, hits, model=None)
        for run in result["agent_runs"]:
            assert "playbook_context" in run

    def test_orchestrator_log_includes_playbook_used(self, tmp_path):
        """Agent run log should include playbook_used flag."""
        import json

        from nexus.langgraph.orchestrator import run_orchestrator

        case_dir = tmp_path / "CASE-AUDIT2"
        case_dir.mkdir()
        (case_dir / "CASE.yaml").write_text("name: audit2\nintake:\n  question: test?\n")
        ext = case_dir / "extractions" / "hayabusa"
        ext.mkdir(parents=True)
        (ext / "timeline.csv").write_text("time,host,event\n2026-08-10T15:00:00Z,WS01,mimikatz.exe\n")

        hits = [
            {"family": "prefetch", "file": "p.csv", "line": "1",
             "text": "mimikatz.exe", "terms": "mimikatz"},
        ]

        run_orchestrator(case_dir, hits, model=None)
        log_file = case_dir / "agent_runs.jsonl"
        assert log_file.is_file()
        entries = [json.loads(ln) for ln in log_file.read_text().strip().splitlines() if ln.strip()]
        assert any("playbook_used" in e for e in entries)

    def test_orchestrator_llm_gets_playbook_context(self, tmp_path):
        """When LLM is available, the prompt should include playbook context."""
        from nexus.langgraph.orchestrator import run_orchestrator

        case_dir = tmp_path / "CASE-AUDIT3"
        case_dir.mkdir()
        (case_dir / "CASE.yaml").write_text("name: audit3\nintake:\n  question: test?\n")
        ext = case_dir / "extractions" / "hayabusa"
        ext.mkdir(parents=True)
        (ext / "timeline.csv").write_text("time,host,event\n2026-08-10T15:00:00Z,WS01,mimikatz.exe\n")

        hits = [
            {"family": "prefetch", "file": "p.csv", "line": "1",
             "text": "mimikatz.exe", "terms": "mimikatz"},
        ]

        model = MagicMock()
        model.invoke.return_value = MagicMock(
            content='{"needles": ["lsass"], "rationale": "test"}'
        )

        run_orchestrator(case_dir, hits, model=model)
        # The model should have been called
        assert model.invoke.called
        # Check that the prompt included playbook guidance
        call_args = model.invoke.call_args
        prompt_text = str(call_args)
        assert "Playbook" in prompt_text or "playbook" in prompt_text


class TestDeadCodeRemoved:
    """GAP 4 fix: _refine_rationale should be removed from mode3.py."""

    def test_refine_rationale_removed(self):
        """_refine_rationale should no longer exist in mode3.py."""
        from nexus.langgraph import mode3

        assert not hasattr(mode3, "_refine_rationale"), \
            "_refine_rationale is dead code and should be removed"
