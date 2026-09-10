"""Examiner needle overlay — feedback promoted into a local vocabulary.

Promotion writes to ``~/.nexus/knowledge/needles/overlay.yaml`` (override with
``NEXUS_NEEDLE_OVERLAY``). It is local, never committed to the repo, and never
silently merged into the shipped playbooks — the examiner explicitly promotes.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import yaml

_OVERLAY_FILENAME = "overlay.yaml"


def overlay_path() -> Path:
    raw = (os.environ.get("NEXUS_NEEDLE_OVERLAY") or "").strip()
    if raw:
        return Path(raw)
    return Path.home() / ".nexus" / "knowledge" / "needles" / _OVERLAY_FILENAME


def load_overlay() -> dict[str, list[str]]:
    path = overlay_path()
    if not path.is_file():
        return {}
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return {}
    out: dict[str, list[str]] = {}
    if isinstance(data, dict):
        for family, terms in data.items():
            if isinstance(terms, list):
                cleaned = [str(t).strip() for t in terms if str(t).strip()]
                if cleaned:
                    out[str(family).lower()] = cleaned
    return out


def overlay_terms_for_families(families: set[str] | list[str] | None) -> list[str]:
    overlay = load_overlay()
    if not overlay:
        return []
    out: list[str] = []
    seen: set[str] = set()
    for family in {str(f).lower() for f in (families or []) if str(f).strip()}:
        for term in overlay.get(family, []):
            key = term.lower()
            if key not in seen:
                seen.add(key)
                out.append(term)
    return out


def promote_needles(family: str, terms: list[str]) -> dict:
    """Merge terms into the local overlay for a family (atomic write)."""
    overlay = load_overlay()
    fam = (family or "general").strip().lower() or "general"
    merged = list(dict.fromkeys(
        [str(t).strip() for t in (overlay.get(fam, []) + list(terms)) if str(t).strip()]
    ))
    overlay[fam] = merged
    path = overlay_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    try:
        os.close(fd)
        Path(tmp).write_text(yaml.safe_dump(overlay, sort_keys=False), encoding="utf-8")
        os.replace(tmp, path)
    except BaseException:
        with __import__("contextlib").suppress(OSError):
            os.unlink(tmp)
        raise
    return {"family": fam, "terms": merged, "count": len(merged), "path": str(path)}
