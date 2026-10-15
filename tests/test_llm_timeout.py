"""D228: every model client has the call timeout, so a slow model makes a run slow and never holds it.

Operator, 2026-10-16: runs are slow on the models we can afford, and on local ones; that is accepted
as long as nothing waits forever for the model. Only the OpenAI-compatible client had a timeout: the
Anthropic, Ollama and legacy NEXUS_MODEL clients were built without one, and the two modules that
read NEXUS_LLM_TIMEOUT defaulted to 120 s and 180 s (SETUP.md documents 180).
"""
from __future__ import annotations

import pytest

_LLM_KEYS = ("NEXUS_LLM_MODEL", "NEXUS_LLM_BASE_URL", "NEXUS_LLM_API_KEY", "NEXUS_LLM_PROVIDER",
             "NEXUS_LLM_REASONING", "NEXUS_LLM_EXTRA_BODY", "NEXUS_LLM_TIMEOUT", "NEXUS_MODEL")


def _model(monkeypatch, **env: str):
    from nexus.langgraph import llm_pipeline

    monkeypatch.setattr(llm_pipeline, "_load_dotenv", lambda: None)
    for key in _LLM_KEYS:
        monkeypatch.delenv(key, raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    return llm_pipeline.get_model()


def test_the_documented_default_is_the_one_default(monkeypatch):
    from nexus.llm.providers import DEFAULT_LLM_TIMEOUT, llm_timeout

    monkeypatch.delenv("NEXUS_LLM_TIMEOUT", raising=False)
    assert llm_timeout() == DEFAULT_LLM_TIMEOUT == 180.0
    monkeypatch.setenv("NEXUS_LLM_TIMEOUT", "600")
    assert llm_timeout() == 600.0


@pytest.mark.parametrize("env", [
    {"NEXUS_LLM_MODEL": "agnes-3.0-flash", "NEXUS_LLM_BASE_URL": "http://127.0.0.1:9/v1", "NEXUS_LLM_API_KEY": "k"},
    {"NEXUS_MODEL": "openai/gpt-4o", "OPENAI_API_KEY": "k"},
])
def test_an_openai_client_has_the_timeout(monkeypatch, env):
    model = _model(monkeypatch, NEXUS_LLM_TIMEOUT="600", **env)
    assert model.request_timeout == 600.0


@pytest.mark.parametrize("env", [
    {"NEXUS_LLM_MODEL": "claude-sonnet-5-5", "NEXUS_LLM_PROVIDER": "anthropic", "NEXUS_LLM_API_KEY": "k"},
    {"NEXUS_MODEL": "claude-sonnet-5-5", "ANTHROPIC_API_KEY": "k"},
])
def test_an_anthropic_client_has_the_timeout(monkeypatch, env):
    pytest.importorskip("langchain_anthropic")
    model = _model(monkeypatch, NEXUS_LLM_TIMEOUT="600", **env)
    assert model.default_request_timeout == 600.0


@pytest.mark.parametrize("env", [
    {"NEXUS_LLM_MODEL": "qwen3:8b", "NEXUS_LLM_PROVIDER": "ollama"},
    {"NEXUS_MODEL": "ollama/qwen3:8b"},
])
def test_a_local_ollama_client_has_the_timeout(monkeypatch, env):
    pytest.importorskip("langchain_ollama")
    model = _model(monkeypatch, NEXUS_LLM_TIMEOUT="600", **env)
    assert model.client_kwargs == {"timeout": 600.0}
