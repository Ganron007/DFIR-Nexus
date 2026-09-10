"""MITRE ATT&CK needle packs — technique-grounded search vocabulary.

Data lives in ``data/knowledge/needles/attack_needles.yaml`` (technique id ->
needles + families + FD-004 caveats). Selection is explicit:

- techniques named in the case intake (`T1059.001`), or
- coverage: techniques from the playbooks that match the evidence families
  actually present in the case.

Mode 1 uses this to ground the scribe; the same helper can serve Mode 2/3.
"""

from __future__ import annotations

import re
from typing import Any

from nexus.knowledge.loader import get_attack_needles

_TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)


def extract_techniques(text: str) -> list[str]:
    """Technique ids mentioned in free text (intake question/hypothesis)."""
    out: list[str] = []
    for match in _TECHNIQUE_RE.finditer(text or ""):
        value = match.group(0).upper()
        if value not in out:
            out.append(value)
    return out


def _matches(pack: dict[str, Any], families: set[str], techniques: set[str]) -> bool:
    if techniques and str(pack.get("technique", "")).upper() in techniques:
        return True
    pack_families = {str(f).lower() for f in (pack.get("families") or [])}
    return bool(families & pack_families)


def attack_packs_for(
    families: set[str] | list[str] | None = None,
    techniques: set[str] | list[str] | None = None,
    limit: int = 4,
) -> list[dict[str, Any]]:
    """Packs matching the case's technique ids first, then its families."""
    fams = {str(f).lower() for f in (families or []) if str(f).strip()}
    techs = {str(t).upper() for t in (techniques or []) if str(t).strip()}
    selected = [p for p in get_attack_needles() if _matches(p, fams, techs)]
    selected.sort(key=lambda p: (
        0 if str(p.get("technique", "")).upper() in techs else 1,
        str(p.get("technique", "")),
    ))
    return selected[: max(1, limit)]


def attack_needles_for(
    families: set[str] | list[str] | None = None,
    techniques: set[str] | list[str] | None = None,
    limit: int = 4,
    cap: int = 30,
) -> list[str]:
    """Flattened needles from the selected packs (order preserved, deduped)."""
    needles: list[str] = []
    for pack in attack_packs_for(families, techniques, limit):
        needles.extend(str(n) for n in (pack.get("needles") or []) if str(n).strip())
    seen: set[str] = set()
    out: list[str] = []
    for needle in needles:
        key = needle.strip().lower()
        if key and key not in seen:
            seen.add(key)
            out.append(needle.strip())
    return out[:cap]


def attack_context_for(packs: list[dict[str, Any]], cap: int = 4) -> str:
    """Compact prompt block: technique, terms, and the false-positive caveat."""
    lines: list[str] = []
    for pack in packs[:cap]:
        technique = str(pack.get("technique") or "")
        name = str(pack.get("name") or "")
        terms = ", ".join(str(n) for n in (pack.get("needles") or [])[:12])
        lines.append(f"{technique} {name}: {terms}")
        caveats = [str(c) for c in (pack.get("caveats") or [])[:1] if str(c).strip()]
        if caveats:
            lines.append(f"  caveat: {caveats[0][:200]}")
    return "\n".join(lines)
