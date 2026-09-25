"""Skill selection — WP 4i.6 / runtime retrieval — WP 9.5.

Matches the case's evidence families, intake keywords, and ATT&CK techniques
against skill trigger blocks. Returns skills ranked by specificity — technique
match outranks keyword match outranks family-only.

WP 9.5 adds runtime retrieval with match reasons + content versions + citations
so a spawned agent (and the finding it drafts) can be traced to the
exact skill version and KB source that produced it.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from nexus.knowledge.loader import get_skills, skill_sources, validate_skill

_TECH_WEIGHT = 3
_KEY_WEIGHT = 2
_FAM_WEIGHT = 1


def _score_skill(
    skill: dict[str, Any],
    fams: set[str],
    kws: set[str],
    techs: set[str],
) -> tuple[int, list[str]]:
    """(score, why) for one skill against the case context."""
    trig = skill.get("trigger") or {}
    why: list[str] = []
    score = 0
    if techs:
        hit = techs & {str(t).upper() for t in (trig.get("techniques") or [])}
        score += _TECH_WEIGHT * len(hit)
        why.extend(f"technique {t}" for t in sorted(hit))
    if kws:
        hit = kws & {str(k).lower() for k in (trig.get("keywords") or [])}
        score += _KEY_WEIGHT * len(hit)
        why.extend(f"keyword {k}" for k in sorted(hit))
    if fams:
        hit = fams & {str(f).lower() for f in (trig.get("families") or [])}
        score += _FAM_WEIGHT * len(hit)
        why.extend(f"family {f}" for f in sorted(hit))
    return score, why[:6]


def _context(
    families: set[str] | list[str] | None,
    keywords: set[str] | list[str] | None,
    techniques: set[str] | list[str] | None,
) -> tuple[set[str], set[str], set[str]]:
    fams = {str(f).lower() for f in (families or []) if str(f).strip()}
    kws = {str(k).lower() for k in (keywords or []) if str(k).strip()}
    techs = {str(t).upper() for t in (techniques or []) if str(t).strip()}
    return fams, kws, techs


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
    fams, kws, techs = _context(families, keywords, techniques)
    scored: list[tuple[int, dict[str, Any]]] = []
    for skill in get_skills():
        if validate_skill(skill):
            continue
        score, _why = _score_skill(skill, fams, kws, techs)
        if score > 0:
            scored.append((score, skill))
    scored.sort(key=lambda t: -t[0])
    return [s for _score, s in scored[: max(1, limit)]]


def skill_version(skill: dict[str, Any]) -> str:
    """Stable content hash (12 hex) — the version an agent/finding ran.

    Hashes only the semantically relevant content (trigger, steps, mitre,
    caveats, negative), so cosmetic edits don't churn versions.
    """
    canon = {
        "skill": str(skill.get("skill") or ""),
        "trigger": skill.get("trigger") or {},
        "steps": [
            {"name": st.get("name"), "query": st.get("query"),
             "look_for": st.get("look_for"), "corroborate": st.get("corroborate")}
            for st in (skill.get("steps") or []) if isinstance(st, dict)
        ],
        "mitre": [str(t) for t in (skill.get("mitre") or [])],
        "caveats": [str(c) for c in (skill.get("caveats") or [])],
        "negative": str(skill.get("negative") or ""),
    }
    blob = json.dumps(canon, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:12]


def skill_provenance(skill: dict[str, Any]) -> dict[str, Any]:
    """Agent/finding-facing provenance: id, title, version, KB citations."""
    return {
        "skill": str(skill.get("skill") or ""),
        "title": str(skill.get("title") or ""),
        "version": skill_version(skill),
        "citations": [str(s.get("chunk_id") or "") for s in skill_sources(skill)],
    }


def retrieve_skills(
    families: set[str] | list[str] | None = None,
    keywords: set[str] | list[str] | None = None,
    techniques: set[str] | list[str] | None = None,
    limit: int = 6,
) -> list[dict[str, Any]]:
    """Runtime skill retrieval for spawned agents (WP 9.5).

    Same ranking as :func:`skills_for`, but returns ranked entries with the
    match reasons, content version, and KB citations — so an agent run records
    *why* a procedure was selected and *which* version/citation it came from:

        [{skill, title, version, score, why, citations, mitre}]
    """
    fams, kws, techs = _context(families, keywords, techniques)
    scored: list[tuple[int, dict[str, Any], list[str]]] = []
    for skill in get_skills():
        if validate_skill(skill):
            continue
        score, why = _score_skill(skill, fams, kws, techs)
        if score > 0:
            scored.append((score, skill, why))
    scored.sort(key=lambda t: -t[0])
    out: list[dict[str, Any]] = []
    for score, skill, why in scored[: max(1, limit)]:
        prov = skill_provenance(skill)
        out.append({
            "skill": prov["skill"],
            "title": prov["title"],
            "version": prov["version"],
            "score": score,
            "why": why,
            "citations": prov["citations"],
            "mitre": [str(t) for t in (skill.get("mitre") or [])],
        })
    return out


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
