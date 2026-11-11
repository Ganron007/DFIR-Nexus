"""Tests for T2-38: Context assembly manifest."""
from __future__ import annotations

from pathlib import Path

from nexus.analysis.context_manifest import load_context_manifest, record_context_manifest


def test_record_and_load_context_manifest(tmp_path: Path):
    case_dir = tmp_path / "CASE-CONTEXT"
    case_dir.mkdir()

    blocks = [
        {"name": "evidence_summary", "chars": 1500, "tokens": 375, "truncated": False, "error": None},
        {"name": "leads_block", "chars": 2000, "tokens": 500, "truncated": True, "error": None},
    ]
    knowledge = {"skills_count": 37, "version": "v1.0"}

    path = record_context_manifest(case_dir, "RUN-CTX-1", blocks, knowledge_versions=knowledge)
    assert path.exists()

    loaded = load_context_manifest(case_dir, "RUN-CTX-1")
    assert loaded is not None
    assert loaded["case_id"] == "CASE-CONTEXT"
    assert loaded["run_id"] == "RUN-CTX-1"
    assert loaded["total_chars"] == 3500
    assert loaded["total_tokens"] == 875
    assert len(loaded["blocks"]) == 2
    assert loaded["blocks"][1]["truncated"] is True
    assert loaded["knowledge_versions"]["skills_count"] == 37
