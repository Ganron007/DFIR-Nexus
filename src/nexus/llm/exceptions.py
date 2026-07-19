"""LLM router exceptions."""


class LLMRouterError(Exception):
    """Base error for LLM router."""


class ProviderNotFoundError(LLMRouterError):
    """Requested provider not configured."""


class ProviderAuthError(LLMRouterError):
    """Provider authentication failed (invalid API key, etc.)."""


class ProviderRateLimitError(LLMRouterError):
    """Provider rate limit hit."""


class ProviderResponseError(LLMRouterError):
    """Provider returned an unexpected response."""
