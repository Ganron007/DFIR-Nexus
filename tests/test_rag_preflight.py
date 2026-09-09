"""Tests for WP 3.13 — RAG preflight: nexus doctor --rag + /portal/api/rag/status."""

from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


class TestRagPreflight:
    """WP 3.13: rag_preflight() must verify embedder + Chroma + test query."""

    def test_preflight_passes_when_rag_ready(self):
        """When RAG index is loaded and test query returns results, preflight passes."""
        from nexus.tools.rag_preflight import rag_preflight

        mock_idx = MagicMock()
        mock_idx.is_loaded = True
        mock_idx.collection = MagicMock()
        mock_idx.collection.count.return_value = 23000
        mock_idx.search.return_value = {
            "results": [{"text": "test result", "source": "kape", "score": 0.85}]
        }
        mock_idx.get_stats.return_value = {
            "document_count": 23000,
            "source_count": 12,
            "model": "BAAI/bge-base-en-v1.5",
            "model_source": "hf_hub_cache",
        }

        with patch("nexus.tools.rag._check_rag_available", return_value=(True, "")), \
             patch("nexus.tools.rag._get_index", return_value=mock_idx):
            result = rag_preflight()

        assert result["ready"] is True
        assert result["embedding_model"] == "BAAI/bge-base-en-v1.5"
        assert result["document_count"] == 23000
        assert result["test_query_returned"] is True
        assert "errors" not in result or len(result["errors"]) == 0

    def test_preflight_fails_when_rag_not_installed(self):
        """When RAG deps are not installed, preflight reports not ready."""
        from nexus.tools.rag_preflight import rag_preflight

        with patch("nexus.tools.rag._check_rag_available", return_value=(False, "not installed")):
            result = rag_preflight()

        assert result["ready"] is False
        assert "not installed" in result.get("error", "") or len(result.get("errors", [])) > 0

    def test_preflight_fails_when_index_missing(self):
        """When Chroma index directory doesn't exist, preflight reports not ready."""
        from nexus.tools.rag_preflight import rag_preflight

        mock_idx = MagicMock()
        mock_idx.is_loaded = False
        mock_idx.load.side_effect = FileNotFoundError("RAG index not found")

        with patch("nexus.tools.rag._check_rag_available", return_value=(True, "")), \
             patch("nexus.tools.rag._get_index", return_value=mock_idx):
            result = rag_preflight()

        assert result["ready"] is False
        assert "index" in result.get("error", "").lower() or \
               any("index" in e.lower() for e in result.get("errors", []))

    def test_preflight_fails_when_test_query_empty(self):
        """When test query returns no results, preflight reports degraded."""
        from nexus.tools.rag_preflight import rag_preflight

        mock_idx = MagicMock()
        mock_idx.is_loaded = True
        mock_idx.collection = MagicMock()
        mock_idx.collection.count.return_value = 23000
        mock_idx.search.return_value = {"results": []}
        mock_idx.get_stats.return_value = {
            "document_count": 23000,
            "source_count": 12,
            "model": "BAAI/bge-base-en-v1.5",
            "model_source": "hf_hub_cache",
        }

        with patch("nexus.tools.rag._check_rag_available", return_value=(True, "")), \
             patch("nexus.tools.rag._get_index", return_value=mock_idx):
            result = rag_preflight()

        assert result["ready"] is False
        assert result["test_query_returned"] is False

    def test_preflight_fails_when_index_too_small(self):
        """When index has < 1000 records, preflight reports not ready."""
        from nexus.tools.rag_preflight import rag_preflight

        mock_idx = MagicMock()
        mock_idx.is_loaded = True
        mock_idx.collection = MagicMock()
        mock_idx.collection.count.return_value = 50
        mock_idx.search.return_value = {
            "results": [{"text": "test", "source": "kape", "score": 0.8}]
        }
        mock_idx.get_stats.return_value = {
            "document_count": 50,
            "source_count": 2,
            "model": "BAAI/bge-base-en-v1.5",
            "model_source": "hf_hub_cache",
        }

        with patch("nexus.tools.rag._check_rag_available", return_value=(True, "")), \
             patch("nexus.tools.rag._get_index", return_value=mock_idx):
            result = rag_preflight()

        assert result["ready"] is False
        assert result["document_count"] == 50
