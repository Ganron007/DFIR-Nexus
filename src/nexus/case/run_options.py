"""Per-case interpretation run options (rounds + context window).

Canonical file: ``analysis/mode1_run_options.json``. Cases written before the
final mode numbering keep ``analysis/mode2_run_options.json``; readers fall
back to the legacy file and new writes use the canonical name. Existing case
data is never rewritten.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

CANONICAL_NAME = "mode1_run_options.json"
LEGACY_NAMES = ("mode2_run_options.json",)


def run_options_path(case_dir: str | Path) -> Path:
    return Path(case_dir) / "analysis" / CANONICAL_NAME


def load_run_options(case_dir: str | Path) -> dict[str, Any]:
    """Canonical options first, then the legacy file; ``{}`` when neither exists."""
    analysis = Path(case_dir) / "analysis"
    for name in (CANONICAL_NAME, *LEGACY_NAMES):
        path = analysis / name
        if not path.is_file():
            continue
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(loaded, dict):
            return loaded
    return {}


def save_run_options(case_dir: str | Path, options: dict[str, Any]) -> Path:
    """Atomic write to the canonical file; returns the path written."""
    path = run_options_path(case_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(options, indent=2), encoding="utf-8")
    os.replace(tmp, path)
    return path
