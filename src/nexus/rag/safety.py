"""RAG safety limits — query validation and model allowlist."""

from __future__ import annotations

MAX_QUERY_LENGTH = 2000
MAX_TOP_K = 50
ALLOWED_EMBED_MODELS = frozenset({"hash-embedder-v1", "BAAI/bge-base-en-v1.5", "bge-base-en-v1.5"})


class RAGSafetyError(ValueError):
    """Raised when a RAG request violates safety limits."""


def validate_query(query: str) -> str:
    """Normalize and validate a search query."""
    q = (query or "").strip()
    if not q:
        raise RAGSafetyError("Query must not be empty")
    if len(q) > MAX_QUERY_LENGTH:
        raise RAGSafetyError(f"Query exceeds {MAX_QUERY_LENGTH} characters")
    return q


def validate_top_k(top_k: int) -> int:
    """Clamp top_k to a safe range."""
    if top_k < 1:
        raise RAGSafetyError("top_k must be >= 1")
    return min(top_k, MAX_TOP_K)


def validate_embed_model(model: str) -> str:
    """Ensure embedding model is on the allowlist."""
    if model not in ALLOWED_EMBED_MODELS:
        raise RAGSafetyError(f"Embedding model not allowed: {model}")
    return model
