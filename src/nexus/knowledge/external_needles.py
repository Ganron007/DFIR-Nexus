"""External-threat hard-artifact needles (Mode 1/2) — ATT&CK-grounded.

Data lives in ``data/knowledge/needles/external_needles.yaml`` (pack = ATT&CK
technique -> families + hard-artifact needles/strong + caveat). Mirrors the
external pattern chains; technique ids are validated against the deep ATT&CK
registry at load (unknown ids drop the pack). Only standout artifacts ship —
the vocabulary gate in ``needle_terms`` is applied at export too.
"""

from __future__ import annotations

from typing import Any

from nexus.knowledge.loader import get_external_needles
from nexus.knowledge.needle_terms import filter_scannable


def _dedupe(items: list[str], cap: int) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        key = str(item).strip().lower()
        if key and key not in seen:
            seen.add(key)
            out.append(str(item).strip())
    return out[:cap]


def _valid_techniques() -> set[str]:
    try:
        from nexus.knowledge.loader import get_attack_registry

        return {
            str(t.get("id") or "").upper()
            for t in (get_attack_registry().get("techniques") or [])
        }
    except Exception:  # noqa: BLE001 — registry optional
        return set()


def external_packs_for(
    families: set[str] | list[str] | None = None,
    limit: int = 8,
) -> list[dict[str, Any]]:
    """Packs whose families intersect the case's evidence families."""
    fams = {str(f).lower() for f in (families or []) if str(f).strip()}
    if not fams:
        return []
    valid = _valid_techniques()
    selected = [
        pack for pack in (get_external_needles().get("packs") or [])
        if fams & {str(f).lower() for f in (pack.get("families") or [])}
        and (not valid or str(pack.get("attack") or "").upper() in valid)
    ]
    return selected[: max(1, limit)]


def external_needles_for(
    families: set[str] | list[str] | None = None,
    limit: int = 8,
    cap: int = 40,
) -> list[str]:
    needles: list[str] = []
    for pack in external_packs_for(families, limit):
        needles.extend(str(n) for n in (pack.get("needles") or []) if str(n).strip())
    return filter_scannable(_dedupe(needles, cap))


def external_strong_for(
    families: set[str] | list[str] | None = None,
    limit: int = 8,
    cap: int = 20,
) -> list[str]:
    needles: list[str] = []
    for pack in external_packs_for(families, limit):
        needles.extend(str(n) for n in (pack.get("strong") or []) if str(n).strip())
    return filter_scannable(_dedupe(needles, cap))
