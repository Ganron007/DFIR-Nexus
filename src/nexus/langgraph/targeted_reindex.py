"""Targeted re-index of named indexed files (D116, D118, D119; operator-approved 2026-10-13).

The incremental build re-reads only the files whose digest changed. A reader change therefore never reaches the
documents already indexed from unchanged files. This module replaces the documents of the files named, with what the
current readers produce for them.

The dry run is the default. It counts the documents the readers would write and the documents the index holds for the
same files, and it writes nothing. With apply it deletes those files' documents by their ``file`` value, writes the new
ones, refreshes the index, and records the new document count in ``analysis/index_state.json``. The count is recorded so
the next incremental build does not read the change as a failed run and rebuild everything.
"""
from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from nexus.langgraph.case_index import _bulk_insert, _client, index_name, iter_index_doc_batches


def new_documents(case_dir: Path, rels: set[str], run_id: str = "") -> dict[str, int]:
    """The documents the current readers produce for each named file, counted without writing anything."""
    counts = {rel: 0 for rel in sorted(rels)}
    for batch in iter_index_doc_batches(case_dir, only_files=set(rels), run_id=run_id):
        for doc in batch:
            counts[doc["file"]] = counts.get(doc["file"], 0) + 1
    return counts


def indexed_documents(case_id: str, rels: set[str]) -> dict[str, int]:
    """The documents the index holds for each named file."""
    counts: dict[str, int] = {}
    with _client() as client:
        for rel in sorted(rels):
            resp = client.post(
                f"/{index_name(case_id)}/_count",
                json={"query": {"term": {"file": rel}}},
                timeout=300,
            )
            resp.raise_for_status()
            counts[rel] = int(resp.json().get("count") or 0)
    return counts


def apply_targeted_reindex(case_dir: Path, rels: set[str], run_id: str = "") -> dict[str, Any]:
    """Replace the named files' documents: delete by file, write the new ones, refresh, and record the new total.

    Re-running it is safe: each run deletes the named files' documents before it writes them again.
    """
    name = index_name(case_dir.name)
    written = 0
    errors = 0
    with _client() as client:
        for rel in sorted(rels):
            resp = client.post(
                f"/{name}/_delete_by_query",
                params={"refresh": "true", "conflicts": "proceed"},
                json={"query": {"term": {"file": rel}}},
                timeout=1800,
            )
            resp.raise_for_status()
        for batch in iter_index_doc_batches(case_dir, only_files=set(rels), run_id=run_id):
            errors += _bulk_insert(client, name, batch)
            written += len(batch)
        if errors:
            raise RuntimeError(f"{errors} document(s) were refused by the index; the index was not recorded")
        refreshed = client.post(f"/{name}/_refresh", timeout=1800)
        refreshed.raise_for_status()
        total = int(client.post(f"/{name}/_count", timeout=300).json().get("count") or 0)
    _record_total(case_dir, total, rels)
    return {"written": written, "total_docs": total}


def _record_total(case_dir: Path, total: int, rels: set[str]) -> None:
    """Set the index state's document count to the index's own, and log the re-index in the state file."""
    state_path = case_dir / "analysis" / "index_state.json"
    state = json.loads(state_path.read_text(encoding="utf-8")) if state_path.is_file() else {}
    state["docs"] = total
    state.setdefault("targeted_reindex", []).append({
        "at": datetime.now(UTC).isoformat(),
        "files": sorted(rels),
        "total_docs": total,
    })
    tmp = state_path.with_suffix(".json.tmp")
    tmp.parent.mkdir(parents=True, exist_ok=True)
    tmp.write_text(json.dumps(state, indent=2), encoding="utf-8")
    os.replace(tmp, state_path)
