"""SigmaHQ-derived needle packs — high-signal strings from known rules.

Data lives in ``data/knowledge/needles/sigma_needles.yaml`` (family -> needles
+ FD-004 caveats). Companion to ``attack_needles.py``: ATT&CK is technique-
first, Sigma is detection-field-first. Both ground Mode 1 and the Explore
suggestions.
"""

from __future__ import annotations

from typing import Any

from nexus.knowledge.loader import get_sigma_needles


def _dedupe(items: list[str], cap: int) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        key = str(item).strip().lower()
        if key and key not in seen:
            seen.add(key)
            out.append(str(item).strip())
    return out[:cap]


def sigma_packs_for(
    families: set[str] | list[str] | None = None,
    limit: int = 5,
) -> list[dict[str, Any]]:
    fams = {str(f).lower() for f in (families or []) if str(f).strip()}
    if not fams:
        return []
    selected = [
        pack
        for pack in get_sigma_needles()
        if fams & {str(f).lower() for f in (pack.get("families") or [])}
    ]
    return selected[: max(1, limit)]


def sigma_needles_for(
    families: set[str] | list[str] | None = None,
    limit: int = 5,
    cap: int = 30,
) -> list[str]:
    needles: list[str] = []
    for pack in sigma_packs_for(families, limit):
        needles.extend(str(n) for n in (pack.get("needles") or []) if str(n).strip())
    from nexus.knowledge.needle_terms import filter_scannable

    return filter_scannable(_dedupe(needles, cap))


def sigma_context_for(packs: list[dict[str, Any]], cap: int = 5) -> str:
    """Render Sigma packs for prompts, vocabulary-gated (F6).

    Scannable needles render as terms; bare numbers (event IDs) and container
    file names render as typed hints instead of keywords.
    """
    from nexus.knowledge.needle_terms import split_terms

    lines: list[str] = []
    for pack in packs[:cap]:
        scan_terms, hints = split_terms(pack.get("needles") or [])
        line = str(pack.get("name", "") or "Sigma").strip()
        if scan_terms:
            line += ": " + ", ".join(str(n) for n in scan_terms[:14])
        if hints["event_ids"]:
            line += f" | event ids: {', '.join(hints['event_ids'][:8])}"
        if hints["artifacts"]:
            line += f" | artifact files: {', '.join(hints['artifacts'][:4])}"
        lines.append(line)
        caveats = [str(c) for c in (pack.get("caveats") or [])[:1] if str(c).strip()]
        if caveats:
            lines.append(f"  caveat: {caveats[0][:200]}")
    return "\n".join(lines)
