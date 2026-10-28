"""One complete indexed-hit pass for the entity inventory.

Threat intel no longer sweeps this stream: its observables come from the typed fields of the
rows the leads cite (D455, ``ti_context.select_lead_observables``).
"""
from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any


def iter_case_hits(case_id: str) -> Iterator[dict[str, Any]]:
    from nexus.config import settings
    from nexus.langgraph.query_pack import attach_hit_fields, iter_all_hits
    from nexus.tools.evidence_index import _resolve_active_case

    # In-process setup is bound to its run, independent of the examiner pointer.
    case_dir, error = _resolve_active_case(case_id, settings.cases_root / case_id)
    if error or case_dir is None:
        raise ValueError(error or "no active case")
    for hit in iter_all_hits(case_dir, [], (None, None), match_all=True):
        # The shared boundary owns preservation of stored fields and fallback parsing.
        yield attach_hit_fields(case_dir, [hit])[0]


def build_setup_census(case_id: str) -> dict[str, Any]:
    from nexus.langgraph.entity_inventory import EntityAccumulator
    from nexus.langgraph.ti_context import case_observables

    entities = EntityAccumulator()
    for hit in iter_case_hits(case_id):
        entities.add_hit(hit)
    return {"entity_inventory": entities.result(case_observables(case_id))}


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
