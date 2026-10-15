"""NEXUS_LLM_EXTRA_BODY: an OpenAI-compatible host's own request fields reach every model call.

agnes-3.0-flash (2026-10-15) turns reasoning on with {"chat_template_kwargs": {"enable_thinking":
true}}; NEXUS_LLM_REASONING only ever reached OpenAI hosts, so "high" was dropped without a word.
"""
from __future__ import annotations

import pytest


def _model(monkeypatch, extra: str):
    from nexus.langgraph import llm_pipeline

    monkeypatch.setattr(llm_pipeline, "_load_dotenv", lambda: None)
    for key, value in {"NEXUS_LLM_MODEL": "agnes-3.0-flash",
                       "NEXUS_LLM_BASE_URL": "http://127.0.0.1:9/v1",
                       "NEXUS_LLM_API_KEY": "k", "NEXUS_LLM_REASONING": "high",
                       "NEXUS_LLM_EXTRA_BODY": extra}.items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv("NEXUS_LLM_PROVIDER", raising=False)
    return llm_pipeline.get_model()


def test_the_hosts_fields_reach_the_model(monkeypatch):
    model = _model(monkeypatch, '{"chat_template_kwargs": {"enable_thinking": true}}')
    assert model.extra_body == {"chat_template_kwargs": {"enable_thinking": True}}


def test_a_reasoning_level_the_host_does_not_take_is_not_sent_and_is_said(monkeypatch, caplog):
    """agnes-3.0-flash has no reasoning levels; NEXUS_LLM_REASONING=high was dropped without a word."""
    with caplog.at_level("WARNING", logger="nexus.langgraph.llm_pipeline"):
        model = _model(monkeypatch, '{"chat_template_kwargs": {"enable_thinking": true}}')
    assert "reasoning_effort" not in (model.extra_body or {})
    assert any("NEXUS_LLM_REASONING=high is not sent" in r.getMessage() for r in caplog.records)


def test_a_malformed_value_is_refused_not_dropped(monkeypatch):
    with pytest.raises(RuntimeError, match="NEXUS_LLM_EXTRA_BODY"):
        _model(monkeypatch, "enable_thinking=true")
    with pytest.raises(RuntimeError, match="must be a JSON object"):
        _model(monkeypatch, '["enable_thinking"]')
