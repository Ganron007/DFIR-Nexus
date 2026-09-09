"""Product mode ↔ pipeline mode mapping (WP 3.8).

Maps the examiner-facing product modes (1/2/3) to the LangGraph pipeline
modes (tools/coverage/design/interpret) so the examiner chooses a mode
and the system runs the right pipeline.

Target mapping:
    Mode 1 (examiner-driven)  → tools + interpret
    Mode 2 (LLM-guided)       → coverage
    Mode 3 (agentic)          → design
"""

from __future__ import annotations

from typing import Any

_MODE_MAP: dict[int, dict[str, Any]] = {
    1: {
        "pipeline_mode": "tools",
        "pipeline_modes": ["tools", "interpret"],
        "description": "Examiner-driven exploration: tools lane + interpret. "
                       "The examiner asks questions, reviews N4 results, and "
                       "manually selects evidence for findings.",
    },
    2: {
        "pipeline_mode": "coverage",
        "pipeline_modes": ["coverage"],
        "description": "LLM-guided iterative analysis: coverage pipeline with "
                       "iterative query proposals, corroboration, and LLM-drafted "
                       "findings. Examiner validates and redirects.",
    },
    3: {
        "pipeline_mode": "design",
        "pipeline_modes": ["design"],
        "description": "Agentic investigation: design pipeline with multi-agent "
                       "orchestration, RAG-grounded planning, specialist agents, "
                       "and synthesis. Examiner approves plan and findings.",
    },
}


def map_product_mode_to_pipeline(product_mode: int) -> dict[str, Any]:
    """Map a product mode (1/2/3) to the corresponding pipeline mode.

    Returns a dict with:
        pipeline_mode: str — the primary pipeline mode
        pipeline_modes: list[str] — all pipeline modes to run (in order)
        description: str — human-readable description of what this mode does

    Returns {"error": "..."} for invalid modes.
    """
    if product_mode not in _MODE_MAP:
        return {"error": f"Invalid product mode {product_mode}. Use 1, 2, or 3."}
    return dict(_MODE_MAP[product_mode])
