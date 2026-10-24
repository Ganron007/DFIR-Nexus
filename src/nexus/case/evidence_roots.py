"""What a case's evidence is, defined once (D383, 2026-10-25).

The lane plans jobs on the case's evidence and the case-pipeline guard (``tools.windows.case_pipeline_refusal``)
refuses a command that names no path inside it. Each side used to build that set itself: the guard read the
evidence registry, and the lane added its own expansion of the registered archives. When the expansion was added only
the lane knew it, so T22's 15 Volatility jobs on the expanded memory image were planned and then refused (D382).
Every reader of "this case's evidence" uses ``case_evidence_roots``; ``tests/test_d383_plan_passes_guard.py`` checks
that every job the lane plans on the staged tiny cases passes the guard.
"""
from __future__ import annotations

import json
from pathlib import Path

#: The lane expands each registered archive into ``<case>/evidence/_expanded/<name>-<digest>/``
#: (``langgraph.evidence_archives.expand_archives``).
EXPANSION_DIRNAME = "_expanded"


def expansion_root(case_dir: Path | str) -> Path:
    """The folder the lane expands the case's registered archives into."""
    return Path(case_dir) / "evidence" / EXPANSION_DIRNAME


def registered_evidence_paths(case_dir: Path | str) -> list[Path]:
    """The paths the examiner registered, from the flat mirror (``evidence.json``) or the registry."""
    paths: list[Path] = []
    for name in ("evidence.json", "evidence_registry.json"):
        path = Path(case_dir) / name
        if not path.is_file():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        rows = data if isinstance(data, list) else []
        if isinstance(data, dict):
            rows = data.get("evidence") or data.get("items") or []
        if isinstance(rows, dict):
            rows = list(rows.values())
        for row in rows:
            raw = ""
            if isinstance(row, dict):
                raw = str(row.get("path") or row.get("file_path") or "")
            elif isinstance(row, str):
                raw = row
            if raw:
                paths.append(Path(raw))
        if paths:
            break
    return paths


def case_evidence_roots(case_dir: Path | str) -> list[Path]:
    """The case's evidence: what was registered, and the lane's own expansion of the registered archives."""
    return [*registered_evidence_paths(case_dir), expansion_root(case_dir)]
