"""LLM router for multi-provider support.

Every provider in this module speaks the **OpenAI-compatible API standard**.
Any service that implements this protocol works out of the box (OpenAI,
Anthropic OpenAI-compat endpoint, OpenRouter, Ollama, vLLM, LiteLLM, Groq,
Together, Mistral, LocalAI, Perplexity, Cohere, etc.).
"""

from __future__ import annotations

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
from nexus.llm.router import ChatMessage, ChatResponse, LLMRouter

__all__ = [
    "LLMRouter",
    "ChatMessage",
    "ChatResponse",
    "LLMProvider",
    "OpenAICompatProvider",
    "AnthropicCompatProvider",
    "OllamaCompatProvider",
    "LiteLLMCompatProvider",
    "LLMRouterError",
    "ProviderNotFoundError",
    "ProviderAuthError",
    "ProviderRateLimitError",
    "ProviderResponseError",
]
