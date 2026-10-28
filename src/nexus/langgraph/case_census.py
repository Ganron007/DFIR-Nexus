"""The setup census of a Mode 1 run: the case's typed entities, bound to the run's own case.

It used to be one pass over every indexed row (19 minutes on T22) typing values by pattern for the threat-intel
sweep and the entity inventory. Both now read typed fields: exact aggregations for the inventory
(``typed_entities.case_entities``) and the lead rows' ECS fields for threat intel (D455, Part 12 FM-2).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def build_setup_census(case_id: str) -> dict[str, Any]:
    """The run's case, named on the call (never the examiner pointer), and its typed entities."""
    from nexus.config import settings
    from nexus.langgraph.entity_inventory import build_entity_inventory
    from nexus.tools.evidence_index import _resolve_active_case

    case_dir, error = _resolve_active_case(case_id, settings.cases_root / case_id)
    if error or case_dir is None:
        raise ValueError(error or "no active case")
    return {"entity_inventory": build_entity_inventory(case_dir.name)}


def persist_setup_census(case_dir: Path, run_id: str, census: dict[str, Any]) -> Path | None:
    """Retain the complete census before any slow external enrichment starts."""
    if not run_id:
        return None
    from nexus.langgraph.pipeline_runs import _atomic_json, resolve_run

    run = resolve_run(Path(case_dir), mode="interpret", run_id=run_id)
    path = run.analysis / "setup_census.json"
    if path.exists():
        if json.loads(path.read_text(encoding="utf-8")) != census:
            raise ValueError("this run already retained a different setup census")
        return path
    _atomic_json(path, census)
    return path
