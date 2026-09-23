"""ITM-derived hard-artifact needles (Mode 1/2).

Data lives in ``data/knowledge/needles/itm_needles.yaml`` (pack = ITM section
-> families + hard-artifact needles/strong + caveat). Only standout artifacts
are shipped (tool names, exact command fragments, service domains) - numbers,
IDs and generic words stay out of keyword scanning by design. Companion to
``attack_needles.py``/``sigma_needles.py``; grounding for Mode 1's signal map
with an Insider Threat Matrix section id per pack.
"""

from __future__ import annotations

from typing import Any

from nexus.knowledge.loader import get_itm_needles


def _dedupe(items: list[str], cap: int) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        key = str(item).strip().lower()
        if key and key not in seen:
            seen.add(key)
            out.append(str(item).strip())
    return out[:cap]


def itm_packs_for(
    families: set[str] | list[str] | None = None,
    limit: int = 8,
) -> list[dict[str, Any]]:
    """Needle packs whose families intersect the case's evidence families."""
    fams = {str(f).lower() for f in (families or []) if str(f).strip()}
    if not fams:
        return []
    selected = [
        pack for pack in (get_itm_needles().get("packs") or [])
        if fams & {str(f).lower() for f in (pack.get("families") or [])}
    ]
    return selected[: max(1, limit)]


def itm_needles_for(
    families: set[str] | list[str] | None = None,
    limit: int = 8,
    cap: int = 40,
) -> list[str]:
    needles: list[str] = []
    for pack in itm_packs_for(families, limit):
        needles.extend(str(n) for n in (pack.get("needles") or []) if str(n).strip())
    return _dedupe(needles, cap)


def itm_strong_for(
    families: set[str] | list[str] | None = None,
    limit: int = 8,
    cap: int = 20,
) -> list[str]:
    needles: list[str] = []
    for pack in itm_packs_for(families, limit):
        needles.extend(str(n) for n in (pack.get("strong") or []) if str(n).strip())
    return _dedupe(needles, cap)
