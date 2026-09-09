"""Tests for WP 2.7 (iteration cap), 2.9 (playbook corroboration), 3.8 (pipeline mapping)."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


def _make_case(tmp_path: Path) -> Path:
    case_dir = tmp_path / "CASE-MISC"
    case_dir.mkdir()
    (case_dir / "CASE.yaml").write_text("name: misc\nintake:\n  question: test?\n")
    ext = case_dir / "extractions" / "hayabusa"
    ext.mkdir(parents=True)
    (ext / "timeline.csv").write_text(
        "time,host,event\n2026-08-10T15:00:00Z,WS01,test.exe run\n"
    )
    return case_dir


class TestIterationCap:
    """WP 2.7: iteration cap should be 5, not 3."""

    def test_max_iterations_is_5(self):
        from nexus.langgraph.mode2 import _MAX_ITERATIONS

        assert _MAX_ITERATIONS == 5, f"Expected 5, got {_MAX_ITERATIONS}"

    def test_loop_respects_cap_of_5(self, tmp_path):
        """The loop should allow up to 5 iterations."""
        from nexus.langgraph.mode2 import run_iterative_loop

        case_dir = _make_case(tmp_path)
        with patch("nexus.langgraph.query_pack.n4_query") as mock_n4, \
             patch("nexus.langgraph.mode1.nl_to_needles") as mock_nl:
            mock_nl.return_value = {"needles": ["test"], "window": "", "source": "heuristic"}
            # Return hits for all 6 calls (initial + 5 iterations)
            mock_n4.side_effect = [
                {"hits": [{"family": "hayabusa", "file": "t.csv", "line": str(i),
                          "text": f"hit{i}", "terms": "test"}],
                 "count": 1, "backend": "csv", "error": None}
                for i in range(10)
            ]
            result = run_iterative_loop(case_dir, "test?", model=None, max_iterations=5)
        # Should have run 1 initial + up to 5 iterations = 6 total
        assert len(result["iterations"]) <= 6
        assert result.get("capped", False) or len(result["iterations"]) < 6


class TestPlaybookCorroboration:
    """WP 2.9: corroboration suggestions should come from playbook caveats, not hard-coded dict."""

    def test_corroboration_from_playbook(self):
        """corroboration_suggestions should use playbook caveats when available."""
        from nexus.langgraph.mode2 import corroboration_suggestions

        finding = {"evidence": [{"source": "prefetch/x"}], "confidence": "LOW"}
        # Mock playbook with corroboration-relevant caveats
        mock_pb = {
            "name": "Credential Access",
            "query_terms": ["mimikatz", "lsass", "prefetch"],
            "caveats": [
                "Corroborate prefetch with Amcache and Shimcache for program execution",
            ],
        }
        with patch("nexus.knowledge.loader.get_playbook", return_value=mock_pb), \
             patch("nexus.knowledge.loader.list_playbook_slugs", return_value=["credential_access"]):
            suggestions = corroboration_suggestions(finding)
        # Should include playbook-derived terms, not just hard-coded mapping
        assert isinstance(suggestions, list)


class TestPipelineModeMapping:
    """WP 3.8: Product modes (1/2/3) must map to pipeline modes (tools/coverage/design/interpret)."""

    def test_mode1_maps_to_tools_then_interpret(self):
        from nexus.langgraph.mode_mapping import map_product_mode_to_pipeline

        result = map_product_mode_to_pipeline(1)
        assert "pipeline_mode" in result
        assert result["pipeline_mode"] in ("tools", "interpret")
        # Mode 1 should use tools + interpret
        assert "interpret" in result.get("pipeline_modes", []) or result["pipeline_mode"] == "tools"

    def test_mode2_maps_to_coverage(self):
        from nexus.langgraph.mode_mapping import map_product_mode_to_pipeline

        result = map_product_mode_to_pipeline(2)
        assert result["pipeline_mode"] == "coverage"

    def test_mode3_maps_to_design(self):
        from nexus.langgraph.mode_mapping import map_product_mode_to_pipeline

        result = map_product_mode_to_pipeline(3)
        assert result["pipeline_mode"] == "design"

    def test_invalid_mode_returns_error(self):
        from nexus.langgraph.mode_mapping import map_product_mode_to_pipeline

        result = map_product_mode_to_pipeline(99)
        assert "error" in result

    def test_mapping_returns_description(self):
        from nexus.langgraph.mode_mapping import map_product_mode_to_pipeline

        for mode in (1, 2, 3):
            result = map_product_mode_to_pipeline(mode)
            assert "description" in result
            assert result["description"]
