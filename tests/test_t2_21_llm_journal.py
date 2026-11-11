"""Tests for T2-21: LLM invocation journal and correlation IDs."""
from __future__ import annotations

import json
from pathlib import Path

from langchain_core.language_models.fake_chat_models import FakeListChatModel

from nexus.analysis.llm_journal import LLMJournal
from nexus.analysis.model_calls import bind as bind_model_calls
from nexus.langgraph import llm_pipeline


def test_llm_journal_records_invocation_and_hashes(tmp_path: Path):
    case_dir = tmp_path / "CASE-JOURNAL"
    case_dir.mkdir()
    journal = LLMJournal(case_dir, run_id="RUN-101")

    entry = journal.record_call(
        correlation_id="corr-123",
        provider="openai",
        model="gpt-4o",
        latency_ms=150.5,
        input_tokens=100,
        output_tokens=50,
        prompt="Who breached the server?",
        response="Suspicious lateral movement observed.",
        status="completed",
        tool_calls=["es_search"],
    )

    assert entry["correlation_id"] == "corr-123"
    assert entry["case_id"] == "CASE-JOURNAL"
    assert entry["run_id"] == "RUN-101"
    assert entry["prompt_hash"] != ""
    assert entry["response_hash"] != ""
    assert entry["tool_calls"] == ["es_search"]
    assert entry["status"] == "completed"

    journal_file = case_dir / "analysis" / "llm_journal.jsonl"
    assert journal_file.exists()
    lines = [json.loads(line) for line in journal_file.read_text(encoding="utf-8").splitlines()]
    assert len(lines) == 1
    assert lines[0]["correlation_id"] == "corr-123"

    summary = journal.section()
    assert summary["status"] == "available"
    assert summary["total_calls"] == 1
    assert summary["completed_calls"] == 1
    assert summary["failed_calls"] == 0
    assert summary["total_input_tokens"] == 100
    assert summary["total_output_tokens"] == 50


def test_token_meter_automatically_journals_invocations(tmp_path: Path, monkeypatch):
    case_dir = tmp_path / "CASE-INTEGRATED"
    case_dir.mkdir()

    monkeypatch.setattr(llm_pipeline, "_construct_model", lambda *a: FakeListChatModel(responses=["Observed persistence via task."]))
    monkeypatch.setattr(llm_pipeline, "built_model_record", lambda: {"provider": "fake", "model": "fake-model"})

    model = llm_pipeline.get_model()

    from nexus.analysis.knowledge_record import recording

    with recording():
        bind_model_calls(case_dir, "RUN-TEST", model)
        # Call the model
        model.invoke("Summarize persistence.")

    journal_file = case_dir / "analysis" / "llm_journal.jsonl"
    assert journal_file.exists()
    records = [json.loads(line) for line in journal_file.read_text(encoding="utf-8").splitlines()]
    assert len(records) >= 1
    assert records[0]["case_id"] == "CASE-INTEGRATED"
    assert records[0]["status"] == "completed"
    assert "persistence" in records[0]["prompt_excerpt"].lower()
