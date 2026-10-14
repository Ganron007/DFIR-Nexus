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
    # No cut (operator decision 2026-10-11): an evidence row quotes the whole detail.
    return detail or str(hit.get("text") or "")


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
                k: str(v) for k, v in fields.items()
            }
        # What the row is about, from the hit's own envelope (WO-1C item 4, option b). Kept whole.
        for key in ("event_id", "host", "user"):
            value = str(h.get(key) or "").strip()
            if value:
                row[key] = value
        # The subject fields the hit's ECS leaves give (operator decision 2026-10-12): the account,
        # address, process, file and registry the row is about. The top-level host stays first.
        from nexus.langgraph.subject import family_subject_fields, subject_fields
        for key, value in subject_fields(h.get("ecs")).items():
            row.setdefault(key, value)
        # The subject fields the family's own columns give (item 3): PECmd, prefetch and SRUM rows carry no ECS.
        for key, value in family_subject_fields(h).items():
            row.setdefault(key, value)
        evidence_rows.append(row)
    return evidence_rows


def stored_rows_by_audit_id(case_dir: Path, audit_ids: list[str]) -> dict[str, list[Any]]:
    """The rows each cited audit entry stored when its call ran, read once for all the ids (D70).

    An id with no stored rows (a call that returned none, or a non-search tool) is absent from the result.
    """
    wanted = {a for a in audit_ids if a}
    path = Path(case_dir) / "audit" / "nexus.jsonl"
    stored: dict[str, list[Any]] = {}
    if not wanted or not path.is_file():
        return stored
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
    return stored


def unique_rows(stored: dict[str, list[Any]], audit_ids: list[str]) -> list[dict[str, Any]]:
    """The stored rows of the given ids, duplicates dropped, capped at EVIDENCE_ROW_CAP.

    Taken in turn from each cited id, in citation order (D194). Taking the first id's rows first
    let one call fill the cap: on 2026-10-14 a call returned 63 rows, so every claim that cited it
    first got the same 12 rows, the same subject, and was linked to another claim's DRAFT.
    """
    queues = [[r for r in stored.get(aid, []) if isinstance(r, dict)]
              for aid in dict.fromkeys(audit_ids)]
    out: list[dict[str, Any]] = []
    seen: set[tuple[Any, Any, Any]] = set()
    depth = 0
    while len(out) < EVIDENCE_ROW_CAP and any(depth < len(q) for q in queues):
        for queue in queues:
            if depth >= len(queue) or len(out) >= EVIDENCE_ROW_CAP:
                continue
            row = queue[depth]
            key = (row.get("source"), row.get("loc"), row.get("detail"))
            if key in seen:
                continue
            seen.add(key)
            out.append(row)
        depth += 1
    return out


def evidence_rows_for_audit_ids(case_dir: Path, audit_ids: list[str]) -> list[dict[str, Any]]:
    """The rows the cited audit entries returned, in citation order (D70).

    Reads the case's audit trail and returns the rows each cited entry stored when its query ran. An id
    with no stored rows contributes nothing, so the caller can fall back to what the model wrote.
    """
    wanted = [a for a in audit_ids if a]
    return unique_rows(stored_rows_by_audit_id(case_dir, wanted), wanted)
