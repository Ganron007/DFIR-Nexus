"""LLM provider implementations.

Every provider in this module speaks the **OpenAI-compatible API standard**
(the same protocol used by OpenAI, OpenRouter, Ollama, vLLM, LiteLLM, and
~50 other services). The only thing that varies between providers is the
`base_url` (where to send the request) and the `default_model`.

This is intentional — the user can point DFIR-Nexus at ANY provider that
implements this standard without writing custom code.

Common providers and their base_urls:
    - OpenAI:        https://api.openai.com/v1
    - Anthropic:     https://api.anthropic.com/v1  (their OpenAI-compat endpoint,
                       NOT the native Anthropic SDK)
    - Ollama:        http://localhost:11434/v1   (local LLM)
    - LiteLLM:       http://localhost:4000/v1    (multi-provider proxy)
    - OpenRouter:    https://openrouter.ai/api/v1
    - vLLM:          http://<host>:8000/v1       (self-hosted)
    - Together:      https://api.together.xyz/v1
    - Groq:          https://api.groq.com/openai/v1
    - Mistral:       https://api.mistral.ai/v1
    - LocalAI:       http://localhost:8080/v1
    - Perplexity:    https://api.perplexity.ai
    - Cohere:        https://api.cohere.ai/v1

To use any of these, set the base_url and api_key via env vars or constructor
arguments. No code changes required.
"""

from __future__ import annotations

import os
from abc import ABC, abstractmethod
from typing import Any, cast

import httpx

from nexus.llm.exceptions import (
    ProviderAuthError,
    ProviderRateLimitError,
    ProviderResponseError,
)


class LLMProvider(ABC):
    """Abstract base class for LLM providers.

    All providers in this module use the **OpenAI-compatible API standard**:
    a POST request to `/chat/completions` with an OpenAI-format JSON body and
    `Authorization: Bearer <key>` header. Subclasses just configure base_url
    and default_model — the actual HTTP call is identical.
    """

    def __init__(
        self,
        name: str | None = None,
        api_key: str | None = None,
        base_url: str | None = None,
        default_model: str | None = None,
    ) -> None:
        # Derive name from class name if not provided (e.g., "OpenAICompatProvider" -> "openai")
        if name is None:
            name = self.__class__.__name__.replace("Provider", "").replace("Compat", "").lower()
        self.name = name
        self.api_key = api_key
        self.base_url = base_url or self._default_base_url()
        self.default_model = default_model or self._default_model()
        self._client: httpx.AsyncClient | None = None

    @abstractmethod
    def _default_base_url(self) -> str:
        """Default base URL for this provider."""
        ...

    @abstractmethod
    def _default_model(self) -> str:
        """Default model name for this provider."""
        ...

    @abstractmethod
    def _default_env_key(self) -> str:
        """Environment variable name for the API key."""
        ...

    def _get_api_key(self) -> str:
        """Get API key from constructor or env."""
        if self.api_key:
            return self.api_key
        env_key = os.environ.get(self._default_env_key())
        if env_key:
            return env_key
        raise ProviderAuthError(
            f"No API key for provider '{self.name}'. "
            f"Pass api_key= or set {self._default_env_key()} env var."
        )

    async def _get_client(self) -> httpx.AsyncClient:
        """Lazy-init async HTTP client."""
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                headers={
                    "Authorization": f"Bearer {self._get_api_key()}",
                    "Content-Type": "application/json",
                },
                timeout=httpx.Timeout(180.0, connect=10.0),
            )
        return self._client

    async def chat(
        self,
        messages: list[dict[str, str]],
        model: str | None = None,
        temperature: float = 1.0,
        max_tokens: int | None = None,
        tools: list[dict[str, Any]] | None = None,
        tool_choice: str | dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Send a chat completion request (OpenAI-compatible standard).

        Returns the parsed JSON response from the provider.
        """
        client = await self._get_client()
        payload: dict[str, Any] = {
            "model": model or self.default_model,
            "messages": messages,
            "temperature": temperature,
        }
        if max_tokens is not None:
            payload["max_tokens"] = max_tokens
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = tool_choice or "auto"
        try:
            response = await client.post("/chat/completions", json=payload)
        except httpx.HTTPStatusError as e:
            self._handle_http_error(e)
            raise
        if response.status_code != 200:
            self._handle_http_error_by_status(response.status_code, response.text)
        try:
            return cast(dict[str, Any], response.json())
        except Exception as e:
            raise ProviderResponseError(
                f"Provider '{self.name}' returned invalid JSON: {e}"
            ) from e

    def _handle_http_error(self, e: httpx.HTTPStatusError) -> None:
        """Map HTTP error to specific exception type."""
        self._handle_http_error_by_status(e.response.status_code, e.response.text)

    def _handle_http_error_by_status(self, status: int, body: str) -> None:
        """Map HTTP status to exception."""
        if status == 401:
            raise ProviderAuthError(
                f"Provider '{self.name}' returned 401. Check your API key. Body: {body[:200]}"
            )
        if status == 429:
            raise ProviderRateLimitError(
                f"Provider '{self.name}' rate-limited. Body: {body[:200]}"
            )
        raise ProviderResponseError(
            f"Provider '{self.name}' returned HTTP {status}. Body: {body[:200]}"
        )

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None


class OpenAICompatProvider(LLMProvider):
    """OpenAI's API (the reference implementation of the OpenAI-compat standard).

    Endpoint: https://api.openai.com/v1
    Default model: gpt-4o
    API key env: OPENAI_API_KEY
    """

    def _default_base_url(self) -> str:
        return "https://api.openai.com/v1"

    def _default_model(self) -> str:
        return "gpt-4o"

    def _default_env_key(self) -> str:
        return "OPENAI_API_KEY"


class AnthropicCompatProvider(LLMProvider):
    """Anthropic's OpenAI-compatible endpoint.

    NOTE: This uses Anthropic's OpenAI-compatibility endpoint at
    https://api.anthropic.com/v1 — NOT their native Anthropic SDK
    (which has a different /messages endpoint shape).

    Endpoint: https://api.anthropic.com/v1
    Default model: claude-sonnet-4-5
    API key env: ANTHROPIC_API_KEY
    """

    def _default_base_url(self) -> str:
        return "https://api.anthropic.com/v1"

    def _default_model(self) -> str:
        return "claude-sonnet-4-5"

    def _default_env_key(self) -> str:
        return "ANTHROPIC_API_KEY"


class OllamaCompatProvider(LLMProvider):
    """Ollama's OpenAI-compatible local LLM endpoint.

    Endpoint: http://localhost:11434/v1
    Default model: llama3.1
    API key env: OLLAMA_API_KEY (optional for local Ollama)
    """

    def _default_base_url(self) -> str:
        return "http://localhost:11434/v1"

    def _default_model(self) -> str:
        return "llama3.1"

    def _default_env_key(self) -> str:
        return "OLLAMA_API_KEY"


class LiteLLMCompatProvider(LLMProvider):
    """LiteLLM proxy's OpenAI-compatible endpoint.

    LiteLLM is a multi-provider router that exposes a single OpenAI-compat
    endpoint. Configure it with whatever providers you want, then point
    DFIR-Nexus at it.

    Endpoint: http://localhost:4000/v1
    Default model: gpt-4o
    API key env: LITELLM_API_KEY
    """

    def _default_base_url(self) -> str:
        return "http://localhost:4000/v1"

    def _default_model(self) -> str:
        return "gpt-4o"

    def _default_env_key(self) -> str:
        return "LITELLM_API_KEY"
