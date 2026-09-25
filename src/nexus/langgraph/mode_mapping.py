"""Product mode ↔ pipeline mode mapping (WP 3.8).

Maps the examiner-facing product modes (1/2/3) to the LangGraph pipeline
modes (tools/coverage/design/interpret) so the examiner chooses a mode
and the system runs the right pipeline.

Target mapping:
    Stored 1  Mode 1 LLM, examiner surface  → tools + interpret
    Stored 2  Mode 1 LLM, guided           → coverage
    Stored 3  Mode 2 multi-role pipeline   → design
    Stored 4  Mode 3 multi-agent team      → tools, then nexus mode4
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
        "description": "Mode 2 multi-role pipeline (stored 3): one specialist "
                       "order at a time. Examiner steers and stages DRAFTs.",
        "product_label": "Mode 2 — Multi-role",
    },
    4: {
        "pipeline_mode": "tools",
        "pipeline_modes": ["tools"],
        "description": "Mode 3 multi-agent team (stored 4): parsers, then a "
                       "concurrent supervisor with a shared board. Examiner "
                       "stops the run and stages DRAFTs.",
        "product_label": "Mode 3 — Multi-agent",
    },
}


def display_product_mode(stored_mode: int) -> dict[str, Any]:
    """Labels after the mode 1/2 merge. Stored values are unchanged."""
    labels = {
        1: ("Mode 1 — LLM", "examiner surface"),
        2: ("Mode 1 — LLM", "guided"),
        3: ("Mode 2 — Multi-role", "pipeline"),
        4: ("Mode 3 — Multi-agent", "concurrent"),
    }
    if stored_mode not in labels:
        return {"error": f"Invalid product mode {stored_mode}. Use 1, 2, 3, or 4."}
    label, depth = labels[stored_mode]
    mapped = map_product_mode_to_pipeline(stored_mode)
    mapped["product_label"] = label
    mapped["depth"] = depth
    return mapped


def map_product_mode_to_pipeline(product_mode: int) -> dict[str, Any]:
    """Map a product mode (1/2/3) to the corresponding pipeline mode.

    Returns a dict with:
        pipeline_mode: str — the primary pipeline mode
        pipeline_modes: list[str] — all pipeline modes to run (in order)
        description: str — human-readable description of what this mode does

    Returns {"error": "..."} for invalid modes.
    """
    if product_mode not in _MODE_MAP:
        return {"error": f"Invalid product mode {product_mode}. Use 1, 2, 3, or 4."}
    return dict(_MODE_MAP[product_mode])
