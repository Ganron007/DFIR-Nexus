"""DFIR-Nexus RAG — forensic knowledge search and retrieval."""

from nexus.rag.safety import RAGSafetyError, validate_query, validate_top_k
from nexus.rag.sources import (
    MatchQuality,
    RAGDocument,
    SearchHit,
    load_builtin_seed,
    load_directory,
    load_jsonl,
    score_quality,
)

__all__ = [
    "MatchQuality",
    "RAGDocument",
    "RAGSafetyError",
    "SearchHit",
    "load_builtin_seed",
    "load_directory",
    "load_jsonl",
    "score_quality",
    "validate_query",
    "validate_top_k",
]
