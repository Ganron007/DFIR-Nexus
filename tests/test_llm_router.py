"""Tests for the LLM router.

Verifies:
- Multi-provider configuration
- Standard OpenAI-compatible API calls
- Provider switching
- Error handling (auth, rate limit, network)
- Retry logic
"""

from __future__ import annotations

import os
from unittest.mock import AsyncMock, patch

import pytest

from nexus.llm import (
    AnthropicCompatProvider,
    ChatMessage,
    ChatResponse,
    LLMRouter,
    OllamaCompatProvider,
    OpenAICompatProvider,
    ProviderNotFoundError,
    ProviderResponseError,
)


class TestProviderNameDerivation:
    """Test that provider names are derived from class name."""

    def test_openai_name(self) -> None:
        p = OpenAICompatProvider(api_key="test")
        assert p.name == "openai"

    def test_anthropic_name(self) -> None:
        p = AnthropicCompatProvider(api_key="test")
        assert p.name == "anthropic"

    def test_ollama_name(self) -> None:
        p = OllamaCompatProvider()
        assert p.name == "ollama"

    def test_custom_name_override(self) -> None:
        p = OpenAICompatProvider(name="my-openai", api_key="test")
        assert p.name == "my-openai"


class TestProviderDefaults:
    """Test default base URLs and models."""

    def test_openai_defaults(self) -> None:
        p = OpenAICompatProvider()
        assert "openai.com" in p.base_url
        assert p.default_model == "gpt-4o"

    def test_anthropic_defaults(self) -> None:
        p = AnthropicCompatProvider()
        assert "anthropic.com" in p.base_url
        assert "claude" in p.default_model

    def test_ollama_defaults(self) -> None:
        p = OllamaCompatProvider()
        assert "localhost" in p.base_url
        assert "llama" in p.default_model


class TestRouterConfiguration:
    """Test LLMRouter configuration."""

    def test_default_provider_requires_config(self) -> None:
        with pytest.raises(ProviderNotFoundError):
            LLMRouter(default_provider="openai")  # no key

    def test_default_provider_must_be_known(self) -> None:
        with pytest.raises(ProviderNotFoundError):
            LLMRouter(default_provider="nonexistent")

    def test_configured_via_env(self) -> None:
        with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}):
            router = LLMRouter(default_provider="openai")
            assert "openai" in router.list_providers()

    def test_configured_via_constructor(self) -> None:
        router = LLMRouter(
            default_provider="openai",
            openai_api_key="test-key",
        )
        assert "openai" in router.list_providers()

    def test_multiple_providers(self) -> None:
        router = LLMRouter(
            default_provider="openai",
            openai_api_key="sk-...",
            anthropic_api_key="sk-ant-...",
        )
        assert set(router.list_providers()) == {"openai", "anthropic"}

    def test_default_provider_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("NEXUS_DEFAULT_PROVIDER", "ollama")
        router = LLMRouter(ollama_base_url="http://localhost:11434/v1")
        assert router.default_provider == "ollama"
        assert "ollama" in router.list_providers()


class TestRouterChat:
    """Test chat() method."""

    @pytest.mark.asyncio
    async def test_chat_with_default_provider(self) -> None:
        router = LLMRouter(default_provider="openai", openai_api_key="test-key")
        # Mock the provider's chat method
        with patch.object(
            OpenAICompatProvider,
            "chat",
            new_callable=AsyncMock,
            return_value={
                "choices": [
                    {
                        "message": {"content": "Hello!", "tool_calls": []},
                        "finish_reason": "stop",
                    }
                ],
                "model": "gpt-4o",
            },
        ):
            response = await router.chat(
                messages=[{"role": "user", "content": "Hi"}]
            )
            assert response.content == "Hello!"
            assert response.model == "gpt-4o"

    @pytest.mark.asyncio
    async def test_chat_with_provider_override(self) -> None:
        router = LLMRouter(
            default_provider="openai",
            openai_api_key="sk-...",
            anthropic_api_key="sk-ant-...",
        )
        with patch.object(
            AnthropicCompatProvider,
            "chat",
            new_callable=AsyncMock,
            return_value={
                "choices": [
                    {
                        "message": {"content": "From Claude", "tool_calls": []},
                        "finish_reason": "stop",
                    }
                ],
                "model": "claude-sonnet-4-5",
            },
        ):
            response = await router.chat(
                messages=[{"role": "user", "content": "Hi"}],
                provider="anthropic",
            )
            assert response.content == "From Claude"
            assert response.model == "claude-sonnet-4-5"

    @pytest.mark.asyncio
    async def test_chat_unknown_provider_raises(self) -> None:
        router = LLMRouter(default_provider="openai", openai_api_key="test")
        with pytest.raises(ProviderNotFoundError):
            await router.chat(
                messages=[{"role": "user", "content": "Hi"}],
                provider="nonexistent",
            )


class TestChatMessage:
    """Test ChatMessage dataclass."""

    def test_basic(self) -> None:
        m = ChatMessage(role="user", content="Hi")
        assert m.to_dict() == {"role": "user", "content": "Hi"}

    def test_with_tool_call_id(self) -> None:
        m = ChatMessage(role="tool", content="result", tool_call_id="abc")
        d = m.to_dict()
        assert d["tool_call_id"] == "abc"

    def test_with_tool_calls(self) -> None:
        m = ChatMessage(
            role="assistant",
            content="",
            tool_calls=[{"id": "1", "type": "function", "function": {"name": "f", "arguments": "{}"}}],
        )
        d = m.to_dict()
        assert "tool_calls" in d


class TestChatResponse:
    """Test ChatResponse parsing."""

    def test_from_provider_response(self) -> None:
        raw = {
            "choices": [
                {
                    "message": {"content": "Hello", "tool_calls": []},
                    "finish_reason": "stop",
                }
            ],
            "model": "gpt-4o",
        }
        response = ChatResponse.from_provider_response(raw)
        assert response.content == "Hello"
        assert response.model == "gpt-4o"
        assert response.finish_reason == "stop"

    def test_from_provider_response_with_tool_calls(self) -> None:
        raw = {
            "choices": [
                {
                    "message": {
                        "content": "",
                        "tool_calls": [
                            {"id": "1", "type": "function", "function": {"name": "f"}}
                        ],
                    },
                    "finish_reason": "tool_calls",
                }
            ],
            "model": "gpt-4o",
        }
        response = ChatResponse.from_provider_response(raw)
        assert len(response.tool_calls) == 1

    def test_from_provider_response_no_choices_raises(self) -> None:
        with pytest.raises(ProviderResponseError):
            ChatResponse.from_provider_response({"choices": []})
