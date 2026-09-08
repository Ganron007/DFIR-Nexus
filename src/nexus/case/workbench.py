"""Examiner workbench — server-side bookmarked hits per case.

Bookmarks live in ``<case>/workbench.json`` (atomic writes). The examiner
stars hits during exploration, collects them here, then promotes a set to
a DRAFT finding. The LLM never writes to this file.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from nexus.langgraph.query_pack import _DATE_RE


def _atomic_write(path: Path, content: str) -> None:
    tmp = Path(str(path) + ".tmp")
    tmp.write_text(content, encoding="utf-8")
    os.replace(tmp, path)


def _wb_path(case_dir: Path) -> Path:
    return Path(case_dir) / "workbench.json"


def load_bookmarks(case_dir: Path) -> list[dict]:
    p = Path(case_dir) / "workbench.json"
    if not p.is_file():
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except (OSError, ValueError):
        return []


def add_bookmark(case_dir: Path, hit: dict, note: str = "") -> dict:
    """Bookmark one hit. Dedupes on (family, file, line)."""
    case_dir = Path(case_dir)
    hits = load_bookmarks(case_dir)
    fam = str(hit.get("family") or "")
    file_rel = str(hit.get("file") or "")
    line = str(hit.get("line") or "")
    for h in hits:
        if (h.get("family"), h.get("file"), str(h.get("line"))) == (fam, file_rel, line):
            return {"status": "exists", "bookmark_id": h.get("id", ""), "total": len(hits)}

    seq = len(hits) + 1
    text = str(hit.get("text") or "")
    m = _DATE_RE.search(text)
    entry = {
        "id": f"B-{seq:03d}",
        "family": fam,
        "file": file_rel,
        "line": line,
        "time": m.group(1) + (f"T{m.group(2)}" if m.group(2) else "") if m else "",
        "text": text[:500],
        "note": str(note or "")[:300],
        "bookmarked_at": _now_iso(),
    }
    hits.append(entry)
    _atomic_write(case_dir / "workbench.json", json.dumps(hits, indent=2, default=str))
    return {"status": "added", "bookmark_id": entry["id"], "total": len(hits)}


def remove_bookmark(case_dir: Path, bookmark_id: str) -> dict:
    case_dir = Path(case_dir)
    hits = load_bookmarks(case_dir)
    remaining = [h for h in hits if str(h.get("id")) != str(bookmark_id)]
    if len(remaining) == len(hits):
        return {"status": "not_found", "total": len(hits)}
    _atomic_write(case_dir / "workbench.json", json.dumps(remaining, indent=2, default=str))
    return {"status": "removed", "total": len(remaining)}


def clear_bookmarks(case_dir: Path) -> dict:
    p = Path(case_dir) / "workbench.json"
    if p.exists():
        p.unlink()
    return {"status": "cleared"}


def _now_iso() -> str:
    from datetime import UTC, datetime

    return datetime.now(UTC).isoformat()
