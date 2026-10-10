"""Evidence rows: the one shape a DRAFT's evidence takes, whichever mode staged it (D70).

A hit that a real evidence query returned becomes one row here. Mode 1 builds its drafts from
these rows; the audited ``es_search`` call keeps the rows it returned in its audit entry; and
Mode 2/3 staging reads them back from the audit entries its candidates cite. Two drafts for
the same claim on the same rows then carry the same evidence, so the duplicate rule (title
plus evidence) recognises them whichever mode proposed them.

Nothing here imports the rest of ``nexus``: the module is imported from the backbone, which
the ``nexus.langgraph`` package loads.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

#: The most rows one draft (or one audit entry) keeps. Mode 1 has always capped at this.
EVIDENCE_ROW_CAP = 12


def render_hit_detail(hit: dict[str, Any]) -> str:
    """Readable 'what it shows' for a hit — parsed fields, not raw CSV."""
    from nexus.integration.evidence_table import render_hit_fields

    detail = render_hit_fields(hit.get("fields") or {})
    return detail[:500] if detail else str(hit.get("text") or "")[:500]


def hit_time_of(hit: dict[str, Any]) -> str:
    """The hit's time: its own field, else the first timestamp in the raw row text."""
    # n4_hits does not emit a time field — parse the first timestamp
    # from the raw row text so evidence rows carry a usable time.
    hit_time = hit.get("time") or ""
    if not hit_time:
        try:
            from nexus.langgraph.query_pack import _DATE_RE
            m = _DATE_RE.search(str(hit.get("text", "")))
            if m:
                hit_time = m.group(1) + (f"T{m.group(2)}" if m.group(2) else "")
        except Exception:
            pass
    return hit_time


def evidence_rows_for_hits(hits: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The evidence rows for the first ``EVIDENCE_ROW_CAP`` hits, in order."""
    evidence_rows = []
    for h in hits[:EVIDENCE_ROW_CAP]:
        hit_time = hit_time_of(h)
        fields = h.get("fields") or {}
        row = {
            "time": hit_time,
            # family must be non-empty: consumers derive the FD-006 family
            # with split("/")[0], and an empty family made that "" (EH-8).
            "source": f"{h.get('family') or 'other'}/{h.get('file', '')}",
            "artifact": h.get("file", ""),
            "detail": render_hit_detail(h),
            "loc": f"{h.get('file', '')}:{h.get('line', '')}",
        }
        if fields:
            row["fields"] = {
                k: str(v)[:240] for k, v in list(fields.items())[:24]
            }
        evidence_rows.append(row)
    return evidence_rows


def evidence_rows_for_audit_ids(case_dir: Path, audit_ids: list[str]) -> list[dict[str, Any]]:
    """The rows the cited audit entries returned, in citation order (D70).

    Reads the case's audit trail and returns the rows each cited entry stored when its
    query ran. An id with no stored rows (a call that returned none, or a non-search tool)
    contributes nothing, so the caller can fall back to what the model wrote.
    """
    wanted = [a for a in audit_ids if a]
    path = Path(case_dir) / "audit" / "nexus.jsonl"
    if not wanted or not path.is_file():
        return []
    stored: dict[str, list[Any]] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        rows = (rec.get("result_summary") or {}).get("evidence_rows")
        aid = rec.get("audit_id")
        if aid in wanted and isinstance(rows, list):
            stored[aid] = rows
    out: list[dict[str, Any]] = []
    seen: set[tuple[Any, Any, Any]] = set()
    for aid in wanted:
        for row in stored.get(aid, []):
            if not isinstance(row, dict):
                continue
            key = (row.get("source"), row.get("loc"), row.get("detail"))
            if key in seen:
                continue
            seen.add(key)
            out.append(row)
    return out[:EVIDENCE_ROW_CAP]
