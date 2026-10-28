"""Typed entity inventory: the case's hosts, users, processes and observables, by field meaning.

Built by ``typed_entities.case_entities``: exact Elasticsearch aggregations over the index's typed fields (the
envelope host and user, ECS process, address, DNS, URL and hash fields), never patterns over row text (Part 12
FM-2, FM-7). On T22 the pattern census listed 1,416 "processes", 5,197 "paths" and 2,603 "users" under "address
EVERY item" (825K characters); the typed fields hold 4 hosts, 30 users and 73 process names.

The inventory is a reference for the loop, not a checklist: the loop aggregates or searches a typed field itself
for the rows behind a value. It is written to ``analysis/entity_inventory.json`` for the examiner. It is
investigation scaffolding; findings still cite evidence rows' audit_ids (FD-001).
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from nexus.langgraph import typed_entities
from nexus.langgraph.typed_entities import ENTITY_FIELDS, OBSERVABLE_KINDS

log = logging.getLogger(__name__)

#: The kinds the prompt lists whole: who, where and what ran. The others are listed by count and field, for the
#: loop to aggregate: a browser history or a Sysmon log can type thousands of URLs or hashes.
_LISTED = ("host", "user", "process")
KINDS = tuple(kind for kind, _ in ENTITY_FIELDS) + OBSERVABLE_KINDS


def build_entity_inventory(case_id: str) -> dict[str, Any]:
    """The case's typed entities and observables with their row counts."""
    return typed_entities.case_entities(case_id)


def inventory_size(inv: dict[str, Any]) -> int:
    """How many distinct typed values the inventory holds."""
    return sum(len(inv.get(kind) or []) for kind in KINDS)


def render_inventory_markdown(inv: dict[str, Any]) -> str:
    """The inventory's prompt block: what the typed fields hold, never an obligation."""
    lines = [
        "# Typed entities (by field meaning; a reference, not a checklist)",
        "",
        f"From {inv.get('source') or 'the typed index fields'}. For the rows behind a value, aggregate or "
        "search the field named.",
    ]
    fields = inv.get("fields") or {}
    for kind in KINDS:
        items = inv.get(kind) or []
        named = ", ".join(fields.get(kind) or []) or "no typed field in this index"
        if kind in _LISTED and items:
            lines.append(f"- {kind} ({len(items)}; {named}): "
                         + ", ".join(f"{item['value']} ({item['count']})" for item in items))
        else:
            lines.append(f"- {kind}: {len(items)} distinct ({named})")
    return "\n".join(lines) + "\n"


def write_entity_inventory(case_dir: Path, inv: dict[str, Any]) -> Path | None:
    """Persist the inventory to analysis/entity_inventory.json."""
    try:
        analysis = Path(case_dir) / "analysis"
        analysis.mkdir(parents=True, exist_ok=True)
        path = analysis / "entity_inventory.json"
        path.write_text(json.dumps(inv, indent=2, default=str), encoding="utf-8")
        return path
    except OSError as exc:
        log.warning("entity inventory write failed: %s", exc)
        return None
