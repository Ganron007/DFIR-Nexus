"""LLM router for multi-provider support.

All providers in this module use the **OpenAI-compatible API standard**.
No vendor lock-in — any service implementing this standard works.
"""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass, field
from typing import Any

from nexus.llm.exceptions import (
    LLMRouterError,
    ProviderAuthError,
    ProviderNotFoundError,
    ProviderRateLimitError,
    ProviderResponseError,
)
from nexus.llm.providers import (
    AnthropicCompatProvider,
    LiteLLMCompatProvider,
    LLMProvider,
    OllamaCompatProvider,
    OpenAICompatProvider,
)
from nexus.utils.constants import ENV_DEFAULT_PROVIDER


@dataclass
class ChatMessage:
    """A chat message (OpenAI-compatible format)."""

    role: str  # "system" | "user" | "assistant" | "tool"
    content: str
    name: str | None = None
    tool_call_id: str | None = None
    tool_calls: list[dict[str, Any]] | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to OpenAI-compatible dict."""
        d: dict[str, Any] = {"role": self.role, "content": self.content}
        if self.name:
            d["name"] = self.name
        if self.tool_call_id:
            d["tool_call_id"] = self.tool_call_id
        if self.tool_calls:
            d["tool_calls"] = self.tool_calls
        return d


@dataclass
class ChatResponse:
    """Parsed chat response."""

    content: str
    model: str
    finish_reason: str
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_provider_response(cls, raw: dict[str, Any]) -> ChatResponse:
        """Parse OpenAI-compatible response into ChatResponse."""
        choices = raw.get("choices", [])
        if not choices:
            raise ProviderResponseError(
                f"Provider returned no choices. Response: {raw}"
            )
        choice = choices[0]
        message = choice.get("message", {})
        return cls(
            content=message.get("content", "") or "",
            model=raw.get("model", "unknown"),
            finish_reason=choice.get("finish_reason", "unknown"),
            tool_calls=message.get("tool_calls", []) or [],
            raw=raw,
        )


class LLMRouter:
    """Multi-LLM router with standard OpenAI-compatible API.

    Routes between configured providers based on the `provider` parameter
    or the default_provider. Each provider is a separate LLMProvider instance.
    """

    PROVIDERS: dict[str, type[LLMProvider]] = {
        "openai": OpenAICompatProvider,
        "anthropic": AnthropicCompatProvider,
        "ollama": OllamaCompatProvider,
        "litellm": LiteLLMCompatProvider,
    }

    def __init__(
        self,
        default_provider: str | None = None,
        default_model: str | None = None,
        openai_api_key: str | None = None,
        openai_base_url: str | None = None,
        openai_model: str | None = None,
        anthropic_api_key: str | None = None,
        anthropic_base_url: str | None = None,
        anthropic_model: str | None = None,
        ollama_base_url: str | None = None,
        ollama_model: str | None = None,
        litellm_base_url: str | None = None,
        litellm_api_key: str | None = None,
        litellm_model: str | None = None,
    ) -> None:
        del litellm_model  # unused for now
        self.default_provider = default_provider or os.environ.get(
            ENV_DEFAULT_PROVIDER, "openai"
        )
        self._providers: dict[str, LLMProvider] = {}

        # OpenAI
        if openai_api_key or os.environ.get("OPENAI_API_KEY"):
            self._providers["openai"] = OpenAICompatProvider(
                api_key=openai_api_key,
                base_url=openai_base_url,
                default_model=openai_model,
            )

        # Anthropic (OpenAI-compat endpoint)
        if anthropic_api_key or os.environ.get("ANTHROPIC_API_KEY"):
            self._providers["anthropic"] = AnthropicCompatProvider(
                api_key=anthropic_api_key,
                base_url=anthropic_base_url,
                default_model=anthropic_model,
            )

        # Ollama (no API key needed)
        if ollama_base_url or os.environ.get("OLLAMA_BASE_URL"):
            self._providers["ollama"] = OllamaCompatProvider(
                base_url=ollama_base_url or os.environ.get("OLLAMA_BASE_URL"),
                default_model=ollama_model,
            )

        # LiteLLM
        if litellm_base_url or os.environ.get("LITELLM_BASE_URL"):
            self._providers["litellm"] = LiteLLMCompatProvider(
                api_key=litellm_api_key,
                base_url=litellm_base_url,
            )

        # Validate default provider
        if self.default_provider not in self.PROVIDERS:
            raise ProviderNotFoundError(
                f"Unknown default provider: {self.default_provider}. "
                f"Available: {list(self.PROVIDERS.keys())}"
            )
        if self.default_provider not in self._providers:
            raise ProviderNotFoundError(
                f"Default provider '{self.default_provider}' not configured. "
                f"Set the appropriate API key env var or pass it to the constructor."
            )

        if default_model:
            self._providers[self.default_provider].default_model = default_model

    def get_provider(self, name: str | None = None) -> LLMProvider:
        """Get a provider by name (or default)."""
        name = name or self.default_provider
        if name not in self._providers:
            raise ProviderNotFoundError(
                f"Provider '{name}' not configured. "
                f"Configured: {list(self._providers.keys())}"
            )
        return self._providers[name]

    def list_providers(self) -> list[str]:
        """List configured providers."""
        return list(self._providers.keys())

    async def chat(
        self,
        messages: list[ChatMessage] | list[dict[str, Any]],
        provider: str | None = None,
        model: str | None = None,
        temperature: float = 1.0,
        max_tokens: int | None = None,
        tools: list[dict[str, Any]] | None = None,
        tool_choice: str | dict[str, str] | None = None,
    ) -> ChatResponse:
        """Send a chat completion request via the specified provider.

        `messages` can be a list of ChatMessage objects or pre-formatted dicts.
        `provider` defaults to the router's default_provider.
        `model` defaults to the provider's default_model.
        """
        # Normalize messages to dicts
        msg_dicts: list[dict[str, Any]] = []
        for m in messages:
            if isinstance(m, ChatMessage):
                msg_dicts.append(m.to_dict())
            else:
                msg_dicts.append(m)

        prov = self.get_provider(provider)
        try:
            raw = await prov.chat(
                messages=msg_dicts,
                model=model,
                temperature=temperature,
                max_tokens=max_tokens,
                tools=tools,
                tool_choice=tool_choice,
            )
        except (ProviderAuthError, ProviderRateLimitError):
            # Let auth/rate-limit errors propagate
            raise
        except ProviderResponseError as e:
            raise LLMRouterError(
                f"Provider '{prov.name}' failed: {e}"
            ) from e
        return ChatResponse.from_provider_response(raw)

    async def chat_with_retry(
        self,
        messages: list[ChatMessage] | list[dict[str, Any]],
        provider: str | None = None,
        model: str | None = None,
        max_retries: int = 3,
        **kwargs: Any,
    ) -> ChatResponse:
        """Chat with exponential-backoff retry on rate limits."""
        last_error: Exception | None = None
        for attempt in range(max_retries):
            try:
                return await self.chat(
                    messages=messages,
                    provider=provider,
                    model=model,
                    **kwargs,
                )
            except ProviderRateLimitError as e:
                last_error = e
                if attempt < max_retries - 1:
                    wait = 2 ** attempt
                    await asyncio.sleep(wait)
        raise last_error  # type: ignore[misc]

    async def close(self) -> None:
        """Close all provider clients."""
        for prov in self._providers.values():
            await prov.close()
