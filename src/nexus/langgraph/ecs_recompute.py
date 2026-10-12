"""Recompute the ``ecs`` of stored EVTX documents after an ecs_map change (D113, 2026-10-13).

The index builder normalizes each row once, when the row is indexed. A map change therefore reaches only the rows
indexed after it. This recomputes the stored documents of the named events from their source rows, with the same
record reader, field builder, sanitiser and ``normalize`` the builder uses, and writes only ``ecs``.

Guarantees:
- A document is recomputed only when its source row, at the stored starting line, carries the stored
  ``EventRecordId`` and ``RecordNumber``. Otherwise nothing is written for it.
- A recompute that would drop or change a stored leaf is refused. The report lists the leaves it adds.
- Nothing is written unless ``apply`` is set.
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from nexus.langgraph.case_index import (
    _client,
    _index_header,
    _open_text_auto,
    index_name,
    iter_indexable_rows,
)
from nexus.langgraph.ecs_normalize import normalize
from nexus.langgraph.path_sanitize import machine_roots, sanitize_field_map

FAMILY = "evtxecmd"
EVENT_IDS = ("4634", "4776")
_SEARCH_SIZE = 10000
_BATCH = 500


def flatten(node: Any, prefix: str = "") -> dict[str, str]:
    """Every leaf of a nested ``ecs`` object as ``{dotted path: text}``. A list is one leaf (its JSON text)."""
    out: dict[str, str] = {}
    if isinstance(node, dict):
        for key, value in node.items():
            out.update(flatten(value, f"{prefix}.{key}" if prefix else str(key)))
    elif node is not None and prefix:
        out[prefix] = json.dumps(node, ensure_ascii=False, sort_keys=True) if isinstance(node, list) else str(node)
    return out


def diff_ecs(old: Any, new: Any) -> dict[str, list[str]]:
    """What a recompute changes: leaves it would drop, leaves whose text it changes, and leaves it adds."""
    before, after = flatten(old), flatten(new)
    return {
        "lost": sorted(k for k in before if k not in after),
        "changed": sorted(k for k in before if k in after and before[k] != after[k]),
        "added": sorted(k for k in after if k not in before),
    }


def stored_documents(case_id: str, event_ids: tuple[str, ...] = EVENT_IDS) -> list[dict[str, Any]]:
    """The indexed documents of the named events that carry an EventData Payload, whatever their family.

    The map change reaches a document only through its Payload (``normalize`` step 1), so the scope is the
    Payload, not one family: EvtxECmd output and the MemProcFS event log both carry it. Each entry holds id,
    index, family, file, starting line, stored ``ecs`` and the identity fields.
    """
    body = {
        "size": _SEARCH_SIZE,
        # An exact total, so the guard below cannot be fooled by ES's default lower bound of 10,000.
        "track_total_hits": True,
        "_source": ["family", "file", "line", "event_id", "ecs", "fields.EventRecordId", "fields.RecordNumber"],
        "query": {"bool": {"filter": [
            {"terms": {"event_id": list(event_ids)}},
            {"exists": {"field": "fields.Payload"}},
        ]}},
    }
    with _client() as client:
        resp = client.post(f"/{index_name(case_id)}/_search", json=body)
        resp.raise_for_status()
        data = resp.json()
    total = int(data["hits"]["total"]["value"])
    if total > _SEARCH_SIZE:
        raise RuntimeError(f"{total} documents match; this recompute reads at most {_SEARCH_SIZE} at a time")
    out: list[dict[str, Any]] = []
    for hit in data["hits"]["hits"]:
        src = hit.get("_source") or {}
        out.append({
            "id": hit["_id"],
            "index": hit["_index"],
            "family": src.get("family"),
            "file": src.get("file"),
            "line": src.get("line"),
            "ecs": src.get("ecs") or {},
            "fields": src.get("fields") or {},
        })
    return out


def extraction_candidates(case_dir: Path, rel: str) -> list[Path]:
    """Every extraction file a document may have been indexed from: ``runs/<run>/extractions/<rel>``, newest first."""
    found = list((Path(case_dir) / "runs").glob(f"*/extractions/{rel}"))
    return sorted(found, key=lambda p: p.stat().st_mtime, reverse=True)


def rows_for_lines(
    case_dir: Path, path: Path, wanted: dict[int, dict[str, Any]], family: str = FAMILY,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Recompute the ``ecs`` of the documents whose source rows start at the given lines of one extraction file.

    ``wanted`` maps a starting line to its stored document. Returns ``(updates, problems)``: one update per
    verified document, changed or not, as ``{id, index, new, diff}``; a problem names a line that could not be
    verified or a recompute that was refused, and nothing is written for it.
    """
    roots = machine_roots(case_dir)
    header = _index_header(path)
    updates: list[dict[str, Any]] = []
    problems: list[str] = []
    seen: set[int] = set()
    with _open_text_auto(path) as fh:
        for start, _raw, row_fields in iter_indexable_rows(path, fh, header, file_label=path.name):
            doc = wanted.get(start)
            if doc is None:
                continue
            seen.add(start)
            stored = doc["fields"]
            if any(str(row_fields.get(k, "")) != str(stored.get(k, "")) for k in ("EventRecordId", "RecordNumber")):
                problems.append(f"line {start}: EventRecordId or RecordNumber differs from the stored document")
                continue
            # The indexer's own steps, in the same order (see case_index._add).
            full_fields = sanitize_field_map(row_fields, case_dir, roots=roots, family=family)
            new_ecs = normalize(family, full_fields, None)
            change = diff_ecs(doc["ecs"], new_ecs)
            if change["lost"] or change["changed"]:
                problems.append(f"line {start}: the recompute would drop or change stored leaves; refused")
                continue
            updates.append({"id": doc["id"], "index": doc["index"], "new": new_ecs, "diff": change})
            if len(seen) == len(wanted):
                break
    for start in sorted(set(wanted) - seen):
        problems.append(f"line {start}: no row starts at this line in {path.name}")
    return updates, problems


def write_updates(case_id: str, updates: list[dict[str, Any]]) -> int:
    """Partial updates of ``ecs`` through the bulk API, in batches. Returns the number of documents written."""
    written = 0
    with _client() as client:
        for start in range(0, len(updates), _BATCH):
            lines: list[str] = []
            for u in updates[start:start + _BATCH]:
                lines.append(json.dumps({"update": {"_index": u["index"], "_id": u["id"]}}))
                lines.append(json.dumps({"doc": {"ecs": u["new"]}}, ensure_ascii=False))
            resp = client.post(
                "/_bulk",
                content=("\n".join(lines) + "\n").encode("utf-8"),
                headers={"Content-Type": "application/x-ndjson"},
            )
            resp.raise_for_status()
            items = resp.json().get("items", [])
            failed = [i for i in items if (i.get("update") or {}).get("error")]
            if failed:
                raise RuntimeError(f"{len(failed)} updates failed; first: {failed[0]['update']['error']}")
            written += len(items)
    return written


def recompute_case(
    case_id: str,
    case_dir: Path,
    *,
    event_ids: tuple[str, ...] = EVENT_IDS,
    apply: bool = False,
) -> dict[str, Any]:
    """Recompute the named events' documents of one case. Writes only when ``apply`` is True."""
    docs = stored_documents(case_id, event_ids)
    # Grouped by family and file: a row is normalized as its own family's indexer normalized it.
    by_file: dict[tuple[str, str], dict[int, dict[str, Any]]] = {}
    no_line: list[str] = []
    for doc in docs:
        if not doc["file"] or doc["line"] is None or not doc["family"]:
            no_line.append(doc["id"])
            continue
        by_file.setdefault((str(doc["family"]), str(doc["file"])), {})[int(doc["line"])] = doc

    problems: list[str] = [f"document {doc_id}: no family, source file or line stored" for doc_id in no_line]
    updates: list[dict[str, Any]] = []
    added: Counter[str] = Counter()
    for (family, rel), wanted in sorted(by_file.items()):
        best: tuple[list[dict[str, Any]], list[str]] | None = None
        for path in extraction_candidates(case_dir, rel):
            u, p = rows_for_lines(case_dir, path, wanted, family)
            if best is None or len(u) > len(best[0]):
                best = (u, p)
            if not p:
                break
        if best is None:
            problems.append(f"{rel}: no extraction file under runs/*/extractions/")
            continue
        u, p = best
        problems.extend(f"{rel}: {x}" for x in p)
        updates.extend(u)
        for up in u:
            added.update(up["diff"]["added"])

    # A verified document whose ecs does not change is not written.
    changed = [u for u in updates if u["diff"]["added"]]
    written = write_updates(case_id, changed) if (apply and changed) else 0
    return {
        "case": case_id,
        "documents": len(docs),
        "files": len(by_file),
        "verified": len(updates),
        "changed": len(changed),
        "written": written,
        "problems": problems,
        "leaves_added": dict(added.most_common()),
    }
