"""Skill selection — WP 4i.6.

Matches the case's evidence families, intake keywords, and ATT&CK
techniques against skill trigger blocks. Returns skills ranked by
specificity — technique match outranks keyword match outranks family-only.
"""

from __future__ import annotations

from typing import Any

from nexus.knowledge.loader import get_skills, validate_skill


def skills_for(
    families: set[str] | list[str] | None = None,
    keywords: set[str] | list[str] | None = None,
    techniques: set[str] | list[str] | None = None,
    limit: int = 6,
) -> list[dict[str, Any]]:
    """Skills whose trigger block intersects the case context.

    Ranking: each technique match +3, each keyword match +2, each family
    match +1. A skill with NO trigger hits is never returned — agents only
    run procedures that are relevant to the evidence and suspicion.
    """
    fams = {str(f).lower() for f in (families or []) if str(f).strip()}
    kws = {str(k).lower() for k in (keywords or []) if str(k).strip()}
    techs = {str(t).upper() for t in (techniques or []) if str(t).strip()}

    scored: list[tuple[int, dict[str, Any]]] = []
    for skill in get_skills():
        if validate_skill(skill):
            continue
        trig = skill.get("trigger") or {}
        score = 0
        if techs:
            score += 3 * len(techs & {str(t).upper() for t in (trig.get("techniques") or [])})
        if kws:
            score += 2 * len(kws & {str(k).lower() for k in (trig.get("keywords") or [])})
        if fams:
            score += len(fams & {str(f).lower() for f in (trig.get("families") or [])})
        if score > 0:
            scored.append((score, skill))
    scored.sort(key=lambda t: -t[0])
    return [s for _score, s in scored[: max(1, limit)]]


def skill_queries(skill: dict[str, Any]) -> list[str]:
    """Ordered query strings from a skill's steps."""
    return [
        str(st.get("query"))
        for st in (skill.get("steps") or [])
        if isinstance(st, dict) and str(st.get("query") or "").strip()
    ]


def skill_context_for(skills: list[dict[str, Any]], cap: int = 4) -> str:
    """Compact prompt block summarizing selected skills for an agent."""
    lines: list[str] = []
    for s in skills[:cap]:
        steps = skill_queries(s)
        lines.append(
            f"skill={s.get('skill')} mitre={','.join(s.get('mitre') or [])} "
            f"steps={len(steps)}"
        )
        for st in (s.get("steps") or [])[:4]:
            if isinstance(st, dict):
                lines.append(f"  - {st.get('name', '')}: {st.get('query', '')}")
    return "\n".join(lines)
