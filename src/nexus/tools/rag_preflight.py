"""RAG preflight — verify embedding model + Chroma index + test query before use.

WP 3.13: Mode 3 orchestrator and any RAG-dependent workflow must call
``rag_preflight()`` before starting. The preflight verifies:

1. RAG dependencies (chromadb, sentence_transformers) are installed
2. The embedding model loads (BAAI/bge-base-en-v1.5 or configured override)
3. The Chroma collection opens and has > 1000 records
4. A test query returns at least one result

If any check fails, ``ready`` is False and the caller must refuse to start
or degrade gracefully (no silent RAG-less operation).
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

_MIN_INDEX_RECORDS = 1000
_TEST_QUERY = "Windows forensic investigation event log prefetch methodology"
_TEST_QUERY_TOP_K = 3


def rag_preflight() -> dict[str, Any]:
    """Run RAG readiness preflight.

    Returns a dict with:
        ready: bool — all checks passed
        embedding_model: str — model id (if loaded)
        model_source: str — how the model was resolved (if loaded)
        document_count: int — Chroma collection size (if opened)
        source_count: int — number of knowledge sources (if loaded)
        test_query_returned: bool — test query returned results
        errors: list[str] — failure reasons (empty if ready)
        error: str — first error (convenience for single-failure case)
    """
    errors: list[str] = []

    # 1. Check RAG dependencies
    try:
        from nexus.tools.rag import _check_rag_available
        available, msg = _check_rag_available()
        if not available:
            return {
                "ready": False,
                "error": msg,
                "errors": [msg],
                "test_query_returned": False,
            }
    except Exception as exc:
        return {
            "ready": False,
            "error": f"RAG dependency check failed: {exc}",
            "errors": [f"RAG dependency check failed: {exc}"],
            "test_query_returned": False,
        }

    # 2. Load the index (embeds model load + Chroma open)
    try:
        from nexus.tools.rag import _get_index

        idx = _get_index()
        idx.load()
    except FileNotFoundError as exc:
        return {
            "ready": False,
            "error": f"RAG index not found: {exc}",
            "errors": [f"RAG index not found: {exc}"],
            "test_query_returned": False,
        }
    except Exception as exc:
        logger.exception("RAG preflight: index load failed")
        return {
            "ready": False,
            "error": f"RAG index load failed: {exc}",
            "errors": [f"RAG index load failed: {exc}"],
            "test_query_returned": False,
        }

    # 3. Verify index size
    stats: dict[str, Any] = {}
    try:
        stats = idx.get_stats()
        doc_count = stats.get("document_count", 0)
        if doc_count < _MIN_INDEX_RECORDS:
            errors.append(
                f"RAG index too small: {doc_count} records "
                f"(minimum {_MIN_INDEX_RECORDS})"
            )
    except Exception as exc:
        errors.append(f"RAG stats check failed: {exc}")
        doc_count = 0

    # 4. Test query — verify the embedder + collection actually return results
    test_returned = False
    try:
        result = idx.search(query=_TEST_QUERY, top_k=_TEST_QUERY_TOP_K)
        test_returned = bool(result.get("results"))
        if not test_returned:
            errors.append(
                "RAG test query returned no results — "
                "index may be corrupted or embedder mismatched"
            )
    except Exception as exc:
        errors.append(f"RAG test query failed: {exc}")

    ready = len(errors) == 0
    return {
        "ready": ready,
        "embedding_model": stats.get("model", ""),
        "model_source": stats.get("model_source", ""),
        "document_count": doc_count,
        "source_count": stats.get("source_count", 0),
        "test_query_returned": test_returned,
        "errors": errors,
        "error": errors[0] if errors else "",
    }
