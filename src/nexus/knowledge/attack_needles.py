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
    from nexus.knowledge.needle_terms import filter_scannable

    return filter_scannable(out)[:cap]


def attack_detections_for(
    techniques: set[str] | list[str] | None = None,
    cap: int = 4,
) -> list[dict[str, Any]]:
    """ATT&CK detection-strategy guidance for technique ids (deep registry).

    Returns ``[{technique, name, strategy, platform, text, log_sources}]`` -
    the v19 replacement for the removed ``x_mitre_detection`` field. One
    strategy/analytic per technique keeps prompts compact.
    """
    from nexus.knowledge.loader import get_attack_registry

    wanted = {str(t).strip().upper() for t in (techniques or []) if str(t).strip()}
    if not wanted:
        return []
    out: list[dict[str, Any]] = []
    for tech in get_attack_registry().get("techniques") or []:
        if tech.get("id") not in wanted:
            continue
        for strategy in (tech.get("detection") or [])[:1]:
            analytics = strategy.get("analytics") or []
            if not analytics:
                continue
            analytic = analytics[0]
            out.append({
                "technique": tech.get("id"),
                "name": tech.get("name"),
                "strategy": f"{strategy.get('id')} {strategy.get('name')}".strip(),
                "platform": ", ".join(analytic.get("platforms") or []),
                "text": analytic.get("description") or "",
                "log_sources": analytic.get("log_sources") or [],
            })
        if len(out) >= cap:
            break
    return out[:cap]


def attack_context_for(packs: list[dict[str, Any]], cap: int = 4) -> str:
    """Compact prompt block: technique, terms, detection guidance, caveat.

    Raw pack terms are split by the vocabulary gate (F6): scannable needles
    render as terms, event IDs / artifact files render as typed hints so a
    prompt never teaches bare numbers as keywords.
    """
    from nexus.knowledge.needle_terms import split_terms

    lines: list[str] = []
    for pack in packs[:cap]:
        technique = str(pack.get("technique") or "")
        name = str(pack.get("name") or "")
        scan_terms, hints = split_terms(pack.get("needles") or [])
        line = f"{technique} {name}".strip()
        if scan_terms:
            line += ": " + ", ".join(str(n) for n in scan_terms[:12])
        if hints["event_ids"]:
            line += f" | event ids: {', '.join(hints['event_ids'][:8])}"
        if hints["artifacts"]:
            line += f" | artifact files: {', '.join(hints['artifacts'][:4])}"
        lines.append(line)
        detection = attack_detections_for([technique], cap=1)
        if detection:
            found = detection[0]
            text = str(found.get("text") or "")[:220]
            if text:
                line = f"  detection ({found.get('strategy')}): {text}"
                logs = ", ".join(found.get("log_sources") or [])
                if logs:
                    line += f" | logs: {logs}"
                lines.append(line)
        caveats = [str(c) for c in (pack.get("caveats") or [])[:1] if str(c).strip()]
        if caveats:
            lines.append(f"  caveat: {caveats[0][:200]}")
    return "\n".join(lines)
