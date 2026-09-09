"""Tests for WP 2.10/2.11/2.6 — RAG + playbook context in Mode 2 proposals."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


def _make_case(tmp_path: Path) -> Path:
    case_dir = tmp_path / "CASE-M2RAG"
    case_dir.mkdir()
    (case_dir / "CASE.yaml").write_text(
        "name: m2rag\nintake:\n  question: credential access?\n"
    )
    ext = case_dir / "extractions" / "hayabusa"
    ext.mkdir(parents=True)
    (ext / "timeline.csv").write_text(
        "time,host,event\n"
        "2026-08-10T15:00:00Z,WS01,mimikatz.exe run\n"
    )
    return case_dir


class TestRagContextInProposals:
    """WP 2.10: propose_next_needles must include RAG methodology context."""

    def test_propose_with_model_includes_rag_context(self, tmp_path):
        """When RAG is available, the LLM prompt must contain methodology text."""
        from nexus.langgraph.mode2 import propose_next_needles

        case_dir = _make_case(tmp_path)
        hits = [
            {"family": "prefetch", "file": "t.csv", "line": "1",
             "text": "mimikatz.exe executed", "terms": "mimikatz"},
        ]

        # Mock model that returns JSON
        model = MagicMock()
        model.invoke.return_value = MagicMock(
            content='{"needles": ["lsass", "sekurlsa"], "rationale": "credential access"}'
        )

        # Mock RAG as available with methodology text
        mock_idx = MagicMock()
        mock_idx.search.return_value = {
            "results": [
                {"text": "Prefetch shows program execution history. Look for mimikatz.exe.",
                 "source": "kape", "title": "Prefetch methodology", "score": 0.9},
            ]
        }

        with patch("nexus.tools.rag._check_rag_available", return_value=(True, "")), \
             patch("nexus.tools.rag._get_index", return_value=mock_idx):
            result = propose_next_needles(
                case_dir, "credential access?", hits, [], model=model
            )

        assert result["source"] == "llm"
        assert "rag_context" in result
        assert "Prefetch" in result["rag_context"]
        # Verify the LLM was called with a prompt containing RAG methodology
        call_args = model.invoke.call_args
        user_msg = call_args[0][0][1]["content"]  # second message (user)
        assert "RAG methodology" in user_msg or "methodology" in user_msg.lower()

    def test_propose_without_rag_still_works(self, tmp_path):
        """When RAG is unavailable, proposals still work (degraded, no crash)."""
        from nexus.langgraph.mode2 import propose_next_needles

        case_dir = _make_case(tmp_path)
        hits = [
            {"family": "prefetch", "file": "t.csv", "line": "1",
             "text": "mimikatz.exe", "terms": "mimikatz"},
        ]

        model = MagicMock()
        model.invoke.return_value = MagicMock(
            content='{"needles": ["lsass"], "rationale": "test"}'
        )

        with patch("nexus.tools.rag._check_rag_available", return_value=(False, "not installed")):
            result = propose_next_needles(
                case_dir, "credential access?", hits, [], model=model
            )

        assert result["source"] == "llm"
        # rag_context should be present but empty/minimal
        assert "rag_context" in result
        assert result["rag_context"] == "" or "Artifact families" in result["rag_context"]

    def test_rag_provenance_recorded(self, tmp_path):
        """WP 2.10: RAG queries and retrieved doc IDs must be in the output."""
        from nexus.langgraph.mode2 import propose_next_needles

        case_dir = _make_case(tmp_path)
        hits = [
            {"family": "prefetch", "file": "t.csv", "line": "1",
             "text": "mimikatz.exe", "terms": "mimikatz"},
        ]

        model = MagicMock()
        model.invoke.return_value = MagicMock(
            content='{"needles": ["lsass"], "rationale": "test"}'
        )

        mock_idx = MagicMock()
        mock_idx.search.return_value = {
            "results": [
                {"text": "Prefetch methodology", "source": "kape",
                 "title": "Prefetch", "score": 0.9},
            ]
        }

        with patch("nexus.tools.rag._check_rag_available", return_value=(True, "")), \
             patch("nexus.tools.rag._get_index", return_value=mock_idx):
            result = propose_next_needles(
                case_dir, "credential access?", hits, [], model=model
            )

        assert "rag_provenance" in result
        prov = result["rag_provenance"]
        assert isinstance(prov, list)
        assert len(prov) > 0
        assert "query" in prov[0]
        assert "doc_count" in prov[0]


class TestPlaybookContextInProposals:
    """WP 2.11: propose_next_needles must include playbook Identify/caveats."""

    def test_playbook_caveats_in_proposal_context(self, tmp_path):
        """When a playbook matches hit families, its caveats appear in context."""
        from nexus.langgraph.mode2 import propose_next_needles

        case_dir = _make_case(tmp_path)
        hits = [
            {"family": "prefetch", "file": "t.csv", "line": "1",
             "text": "mimikatz.exe", "terms": "mimikatz"},
        ]

        model = MagicMock()
        model.invoke.return_value = MagicMock(
            content='{"needles": ["lsass"], "rationale": "test"}'
        )

        # Mock playbook with caveats and Identify steps
        mock_pb = {
            "name": "Credential Access Investigation",
            "description": "Investigate credential theft",
            "query_terms": ["mimikatz", "lsass", "prefetch"],
            "caveats": [
                "Dumping LSASS requires SeDebugPrivilege",
                "Only lsass.exe should ever be running as LSASS",
            ],
            "phases": [
                {"phase": "Identify", "steps": [
                    "Check Prefetch for known credential tool execution",
                ]},
            ],
            "triggers": ["LSASS access detected"],
        }

        with patch("nexus.tools.rag._check_rag_available", return_value=(False, "")), \
             patch("nexus.knowledge.loader.get_playbook", return_value=mock_pb), \
             patch("nexus.knowledge.loader.list_playbook_slugs", return_value=["credential_access"]):
            result = propose_next_needles(
                case_dir, "credential access?", hits, [], model=model
            )

        assert result["source"] == "llm"
        assert "playbook_context" in result
        assert "SeDebugPrivilege" in result["playbook_context"]

    def test_playbook_context_empty_when_no_match(self, tmp_path):
        """When no playbook matches, playbook_context is empty but not crashing."""
        from nexus.langgraph.mode2 import propose_next_needles

        case_dir = _make_case(tmp_path)
        hits = [
            {"family": "unknown_family", "file": "t.csv", "line": "1",
             "text": "something", "terms": "something"},
        ]

        model = MagicMock()
        model.invoke.return_value = MagicMock(
            content='{"needles": ["test"], "rationale": "test"}'
        )

        with patch("nexus.tools.rag._check_rag_available", return_value=(False, "")), \
             patch("nexus.knowledge.loader.get_playbook", return_value=None):
            result = propose_next_needles(
                case_dir, "test?", hits, [], model=model
            )

        assert result["source"] == "llm"
        assert "playbook_context" in result
        assert result["playbook_context"] == ""


class TestContextEnrichment:
    """WP 2.6: LLM context must include aggregation summaries + top hits."""

    def test_aggregation_summary_in_prompt(self, tmp_path):
        """The LLM prompt must include hit counts per family and per host."""
        from nexus.langgraph.mode2 import propose_next_needles

        case_dir = _make_case(tmp_path)
        hits = [
            {"family": "prefetch", "file": "a.csv", "line": "1",
             "text": "mimikatz.exe", "terms": "mimikatz", "host": "WS01"},
            {"family": "prefetch", "file": "a.csv", "line": "2",
             "text": "procdump.exe", "terms": "procdump", "host": "WS01"},
            {"family": "evtx", "file": "b.csv", "line": "1",
             "text": "Event 10 lsass access", "terms": "lsass", "host": "WS02"},
        ]

        model = MagicMock()
        model.invoke.return_value = MagicMock(
            content='{"needles": ["test"], "rationale": "test"}'
        )

        with patch("nexus.tools.rag._check_rag_available", return_value=(False, "")):
            propose_next_needles(
                case_dir, "credential access?", hits, ["mimikatz"], model=model
            )

        # Check the LLM was called with aggregation context
        call_args = model.invoke.call_args
        user_msg = call_args[0][0][1]["content"]
        assert "prefetch" in user_msg.lower()
        assert "evtx" in user_msg.lower()
        # Already-searched needles must be in the context
        assert "mimikatz" in user_msg

    def test_top_hits_per_family_in_prompt(self, tmp_path):
        """Top hits per family (up to N) must appear with more text than before."""
        from nexus.langgraph.mode2 import _MAX_HIT_TEXT_ENRICHED

        # The enriched hit text cap should be larger than the old 160-char cap
        assert _MAX_HIT_TEXT_ENRICHED >= 400
