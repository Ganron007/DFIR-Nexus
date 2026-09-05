"""Tests for Mode 1 — Examiner-Led Query Desk.

Tests the three Mode 1 components:
1. NL -> needles translation (with and without LLM)
2. promote_hits_to_draft (examiner selects hits -> DRAFT skeleton)
3. scribe_finding (LLM formats the DRAFT with methodology)
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

from nexus.langgraph.mode1 import (
    _heuristic_needles,
    _heuristic_scribe,
    nl_to_needles,
    promote_hits_to_draft,
    scribe_finding,
)

# ---------------------------------------------------------------------------
# NL -> needles
# ---------------------------------------------------------------------------


class TestNlToNeedles:
    def test_empty_question_returns_empty(self):
        result = nl_to_needles("")
        assert result["needles"] == []
        assert result["source"] == "none"

    def test_heuristic_extracts_known_terms(self):
        result = _heuristic_needles("Was sdelete used to wipe files?")
        assert "sdelete" in result["needles"]
        assert result["source"] == "heuristic"

    def test_heuristic_extracts_event_ids(self):
        result = _heuristic_needles("Any event 1102 or 4624 in the logs?")
        assert "1102" in result["needles"]
        assert "4624" in result["needles"]

    def test_heuristic_extracts_window(self):
        result = _heuristic_needles(
            "Did anyone clear logs between 2026-08-10 and 2026-08-15?"
        )
        assert result["window"] == "2026-08-10..2026-08-15"

    def test_heuristic_no_window(self):
        result = _heuristic_needles("Was mimikatz used?")
        assert result["window"] == ""

    def test_heuristic_fallback_tokens(self):
        result = _heuristic_needles("Any evidence of credential dumping?")
        # Should get some tokens even without known term matches
        assert len(result["needles"]) > 0
        assert result["source"] == "heuristic"

    def test_nl_to_needles_no_model_uses_heuristic(self):
        result = nl_to_needles("Was sdelete used?", model=None)
        assert "sdelete" in result["needles"]
        assert result["source"] == "heuristic"

    def test_nl_to_needles_with_mock_model(self):
        mock_model = MagicMock()
        mock_model.invoke.return_value = MagicMock(
            content='{"needles": ["sdelete", "wipe", "fileoverwrite"], "window": ""}'
        )
        result = nl_to_needles("Was sdelete used?", model=mock_model)
        assert "sdelete" in result["needles"]
        assert result["source"] == "llm"

    def test_nl_to_needles_model_failure_falls_back(self):
        mock_model = MagicMock()
        mock_model.invoke.side_effect = RuntimeError("API error")
        result = nl_to_needles("Was sdelete used?", model=mock_model)
        assert "sdelete" in result["needles"]
        assert result["source"] == "heuristic"

    def test_nl_to_needles_bad_json_falls_back(self):
        mock_model = MagicMock()
        mock_model.invoke.return_value = MagicMock(content="not json at all")
        result = nl_to_needles("Was sdelete used?", model=mock_model)
        assert result["source"] == "heuristic"


# ---------------------------------------------------------------------------
# promote_hits_to_draft
# ---------------------------------------------------------------------------


class TestPromoteHitsToDraft:
    def test_basic_promotion(self, tmp_path: Path):
        hits = [
            {
                "family": "hayabusa",
                "file": "extractions/hayabusa/timeline.csv",
                "line": "42",
                "text": "2026-08-10T15:00:00Z,WS01,sdelete.exe,DELETE",
                "terms": "sdelete",
            },
            {
                "family": "hayabusa",
                "file": "extractions/hayabusa/timeline.csv",
                "line": "55",
                "text": "2026-08-10T15:01:00Z,WS01,sdelete.exe,DELETE",
                "terms": "sdelete",
            },
        ]
        draft = promote_hits_to_draft(
            tmp_path,
            hits=hits,
            title="sdelete file wipe on WS01",
            examiner="test_examiner",
        )
        assert draft["title"] == "sdelete file wipe on WS01"
        assert draft["status"] == "DRAFT"
        assert draft["examiner_selected"] is True
        assert len(draft["evidence"]) == 2
        assert draft["evidence"][0]["source"] == "hayabusa/extractions/hayabusa/timeline.csv"
        assert draft["evidence"][0]["detail"] == hits[0]["text"]
        assert draft["confidence"] == "LOW"
        assert draft["type"] == "finding"

    def test_empty_hits(self, tmp_path: Path):
        draft = promote_hits_to_draft(
            tmp_path,
            hits=[],
            title="Empty finding",
            examiner="test",
        )
        assert draft["title"] == "Empty finding"
        assert draft["evidence"] == []
        assert draft["event_timestamp"] == ""

    def test_interpretation_hint_preserved(self, tmp_path: Path):
        hits = [{"family": "evtxecmd", "file": "a.csv", "line": "1", "text": "hit", "terms": "x"}]
        draft = promote_hits_to_draft(
            tmp_path,
            hits=hits,
            title="Test",
            interpretation_hint="Possible insider staging",
        )
        assert draft["interpretation"] == "Possible insider staging"

    def test_evidence_capped_at_12(self, tmp_path: Path):
        hits = [
            {"family": "f", "file": "a.csv", "line": str(i), "text": f"hit{i}", "terms": "x"}
            for i in range(20)
        ]
        draft = promote_hits_to_draft(tmp_path, hits=hits, title="Test")
        assert len(draft["evidence"]) == 12


# ---------------------------------------------------------------------------
# scribe_finding
# ---------------------------------------------------------------------------


class TestScribeFinding:
    def test_heuristic_scribe_fills_fields(self):
        draft = {
            "title": "sdelete wipe",
            "observation": "",
            "interpretation": "",
            "confidence": "",
            "confidence_justification": "",
            "type": "",
            "audit_ids": [],
            "evidence": [],
        }
        hits = [
            {"family": "hayabusa", "file": "a.csv", "line": "1", "text": "sdelete hit", "terms": "sdelete"},
        ]
        result = _heuristic_scribe(draft, hits)
        assert result["observation"]  # non-empty
        assert result["interpretation"]  # non-empty
        assert result["confidence"] == "LOW"
        assert result["confidence_justification"]  # non-empty
        assert result["type"] == "finding"
        assert result["scribe_source"] == "heuristic"

    def test_scribe_no_model_uses_heuristic(self):
        draft = {"title": "test", "observation": "", "interpretation": ""}
        hits = [{"family": "f", "file": "a.csv", "line": "1", "text": "hit", "terms": "x"}]
        result = scribe_finding(draft, hits, model=None)
        assert result["scribe_source"] == "heuristic"
        assert result["observation"]  # filled

    def test_scribe_with_mock_model(self):
        mock_model = MagicMock()
        mock_model.invoke.return_value = MagicMock(
            content=json.dumps({
                "observation": "sdelete execution detected in Hayabusa timeline",
                "interpretation": "Examiner-selected hits show sdelete was used to wipe files",
                "confidence": "MEDIUM",
                "confidence_justification": "Multiple hits in Hayabusa timeline with sdelete process name",
                "mitre_ids": ["T1070.004"],
                "type": "execution",
            })
        )
        draft = {
            "title": "sdelete wipe",
            "observation": "",
            "interpretation": "",
            "audit_ids": ["hayabusa-examiner-20260822-001"],
            "evidence": [{"detail": "sdelete hit"}],
        }
        hits = [{"family": "hayabusa", "file": "a.csv", "line": "1", "text": "sdelete", "terms": "sdelete"}]
        result = scribe_finding(draft, hits, model=mock_model)
        assert result["scribe_source"] == "llm"
        assert "sdelete" in result["observation"]
        assert result["confidence"] == "MEDIUM"
        assert "T1070.004" in result.get("mitre_ids", [])

    def test_scribe_model_failure_falls_back(self):
        mock_model = MagicMock()
        mock_model.invoke.side_effect = RuntimeError("API error")
        draft = {"title": "test", "observation": "", "interpretation": ""}
        hits = [{"family": "f", "file": "a.csv", "line": "1", "text": "hit", "terms": "x"}]
        result = scribe_finding(draft, hits, model=mock_model)
        assert result["scribe_source"] == "heuristic"

    def test_scribe_does_not_overwrite_existing_title(self):
        draft = {"title": "Examiner's title", "observation": "", "interpretation": ""}
        hits = [{"family": "f", "file": "a.csv", "line": "1", "text": "hit", "terms": "x"}]
        result = scribe_finding(draft, hits, model=None)
        assert result["title"] == "Examiner's title"

    def test_scribe_preserves_audit_ids(self):
        draft = {
            "title": "test",
            "observation": "",
            "interpretation": "",
            "audit_ids": ["hayabusa-examiner-20260822-001"],
        }
        hits = [{"family": "f", "file": "a.csv", "line": "1", "text": "hit", "terms": "x"}]
        result = scribe_finding(draft, hits, model=None)
        assert result["audit_ids"] == ["hayabusa-examiner-20260822-001"]
