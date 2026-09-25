"""Examiner-saved answers — bookmarked for the report's Saved-answers section.

Canonical file: ``analysis/mode1_saved_answers.json``. Cases written before the
final mode numbering keep ``analysis/mode2_saved_answers.json``; the loader
merges the legacy file so old bookmarks still reach the report, and new saves
are written only to the canonical file. Existing case data is never rewritten.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

CANONICAL_NAME = "mode1_saved_answers.json"
LEGACY_NAMES = ("mode2_saved_answers.json",)


def saved_answers_path(case_dir: str | Path) -> Path:
    return Path(case_dir) / "analysis" / CANONICAL_NAME


def _read_rows(path: Path) -> list[dict[str, Any]]:
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    return [row for row in loaded if isinstance(row, dict)] if isinstance(loaded, list) else []


def _write_rows(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(rows, indent=2, default=str), encoding="utf-8")
    os.replace(tmp, path)


def load_saved_answers(case_dir: str | Path) -> list[dict[str, Any]]:
    """Canonical rows first, then legacy rows not already present (by ``ts``)."""
    analysis = Path(case_dir) / "analysis"
    merged = _read_rows(analysis / CANONICAL_NAME)
    seen = {str(row.get("ts") or "") for row in merged}
    for name in LEGACY_NAMES:
        for row in _read_rows(analysis / name):
            key = str(row.get("ts") or "")
            if key and key in seen:
                continue
            merged.append(row)
            seen.add(key)
    return merged


def append_saved_answer(case_dir: str | Path, entry: dict[str, Any]) -> list[dict[str, Any]]:
    """Append one row to the canonical file unless its ``ts`` is already saved.

    Returns the merged list (canonical + legacy) so callers can report the
    total. The legacy file is read-only here — old case data is never touched.
    """
    rows = load_saved_answers(case_dir)
    ts = str(entry.get("ts") or "")
    if ts and any(str(row.get("ts") or "") == ts for row in rows):
        return rows
    canonical = saved_answers_path(case_dir)
    canonical_rows = _read_rows(canonical)
    canonical_rows.append(entry)
    _write_rows(canonical, canonical_rows)
    return load_saved_answers(case_dir)
