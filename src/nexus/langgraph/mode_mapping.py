"""Product mode → pipeline mode mapping + rename/merge aliases (WP 3.8).

Final three modes (canonical, stored in CASE.yaml ``investigation_mode``):

    1  Mode 1 — LLM         deterministic lane + LLM scribe / steering /
                            coverage / interpretation surfaces (old 1+2 merged)
    2  Mode 2 — Multi-role  deterministic lane, then the supervised multi-role
                            runtime (``nexus mode3`` / Agent Run)
    3  Mode 3 — Multi-agent deterministic lane, then the concurrent multi-agent
                            runtime (``nexus mode3`` / Investigation Board)

Cases written before ``mode_scheme: 2`` used the old values (1 examiner-led,
2 guided LLM, 3 multi-role, 4 multi-agent) and are aliased on read:
1→1, 2→1, 3→2, 4→3. New writes always store canonical 1–3 plus
``mode_scheme: 2``.
"""
from __future__ import annotations

from typing import Any

MODE_SCHEME = 2
CANONICAL_MODES = (1, 2, 3)
LEGACY_MODE_ALIASES: dict[int, int] = {1: 1, 2: 1, 3: 2, 4: 3}

_MODE_MAP: dict[int, dict[str, Any]] = {
    1: {
        "pipeline_mode": "tools",
        "pipeline_modes": ["tools", "interpret", "coverage"],
        "description": "Mode 1 - LLM: deterministic lane + LLM scribe, steering, "
                       "coverage and interpretation surfaces.",
    },
    2: {
        "pipeline_mode": "tools",
        "pipeline_modes": ["tools", "interpret"],
        "description": "Mode 2 - Multi-role: deterministic lane, then the "
                       "supervised multi-role run (nexus mode3 / Agent Run).",
    },
    3: {
        "pipeline_mode": "tools",
        "pipeline_modes": ["tools", "interpret"],
        "description": "Mode 3 - Multi-agent: deterministic lane, then the "
                       "concurrent multi-agent run (nexus mode3 / Board).",
    },
}

_MODE_LABELS: dict[int, str] = {
    1: "Mode 1 \u2014 LLM",
    2: "Mode 2 \u2014 Multi-role",
    3: "Mode 3 \u2014 Multi-agent",
}


def _int_or_none(raw: Any) -> int | None:
    try:
        return int(str(raw).strip())
    except (TypeError, ValueError):
        return None


def canonical_for_write(raw: Any) -> int | None:
    """Canonical mode for a NEW write (new UI values 1–3; legacy 4 → 3)."""
    value = _int_or_none(raw)
    if value in CANONICAL_MODES:
        return value
    if value == 4:
        return 3
    return None


def resolve_stored_mode(raw: Any, scheme: Any = None) -> int | None:
    """Canonical mode for a stored CASE.yaml value, respecting ``mode_scheme``.

    ``scheme >= MODE_SCHEME`` means the value is already canonical; anything
    else (missing/legacy) goes through the alias table.
    """
    value = _int_or_none(raw)
    if value is None:
        return None
    marker = _int_or_none(scheme) or 0
    if marker >= MODE_SCHEME:
        return value if value in CANONICAL_MODES else LEGACY_MODE_ALIASES.get(value)
    return LEGACY_MODE_ALIASES.get(value) or (
        value if value in CANONICAL_MODES else None)


def mode_label(canonical: int | None) -> str:
    return _MODE_LABELS.get(int(canonical or 0), "")


def display_product_mode(canonical_mode: int) -> dict[str, Any]:
    """Labels + depth for a canonical mode (1–3)."""
    try:
        canonical = int(canonical_mode)
    except (TypeError, ValueError):
        canonical = 0
    if canonical not in _MODE_MAP:
        return {"error": "Invalid product mode. Use 1, 2, or 3."}
    mapped = map_product_mode_to_pipeline(canonical)
    mapped["product_label"] = _MODE_LABELS[canonical]
    mapped["depth"] = ("llm" if canonical == 1
                       else "multi_role" if canonical == 2 else "multi_agent")
    return mapped


def map_product_mode_to_pipeline(product_mode: int) -> dict[str, Any]:
    """Map a canonical product mode (1/2/3) to its pipeline stage(s)."""
    try:
        canonical = int(product_mode)
    except (TypeError, ValueError):
        canonical = 0
    if canonical not in _MODE_MAP:
        return {"error": "Invalid product mode. Use 1, 2, or 3."}
    return dict(_MODE_MAP[canonical])
