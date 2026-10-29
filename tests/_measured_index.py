"""The index measurement a Mode 2 or Mode 3 run needs, for tests that run one (TA-5.1).

Both modes select knowledge by the case index's measured evidence groups (`index_mappings` ->
`es_native.knowledge_evidence_groups`) and refuse to run without them, as no mode may run on an index it could not
read. A test that drives a mode is given that measurement here, with each group built through the one family
registry exactly as the real builder builds it; every other backbone call goes to the real implementation.
"""
from __future__ import annotations

from typing import Any


def measured_index(monkeypatch, family_rows: dict[str, int]) -> dict[str, Any]:
    """Answer `index_mappings` with one measured group per family (its own source, no importer)."""
    from nexus.knowledge.family_registry import get_family_registry
    from nexus.langgraph import backbone

    registry = get_family_registry()
    measured = {
        "es_available": True,
        "family_rows": dict(family_rows),
        "evidence_groups": [
            {"source": family, "importers": [], "families": sorted(registry.evidence_group(family, [])), "rows": rows}
            for family, rows in family_rows.items()
        ],
    }
    real = backbone.backbone_call

    def call(name: str, audit: Any = None, **kwargs: Any) -> dict[str, Any]:
        if name == "index_mappings":
            return {**measured, "evidence_groups": [dict(group) for group in measured["evidence_groups"]]}
        return real(name, audit=audit, **kwargs)

    monkeypatch.setattr(backbone, "backbone_call", call)
    return measured
