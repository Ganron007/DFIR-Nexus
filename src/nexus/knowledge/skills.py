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


# A trigger family that is a generic *output format* is not evidence of anything.
# Every case in a Windows corpus has a `csv` family because that is how the
# parsers write, so a skill listing csv/jsonl in its trigger families fires on
# every case regardless of content - which is how `mobile_forensics` surfaced on a
# Windows EVTX investigation. Formatting is not a finding.
_NON_DISCRIMINATIVE_FAMILIES = frozenset({
    "csv", "tsv", "jsonl", "json", "txt", "log", "xml", "html", "md",
    "sqlite", "db", "dat", "bin", "output", "raw", "text",
})

# Platform-specific skills must not fire on a case from another platform. The 37
# skills carried no platform field at all, so `mobile_forensics`, `macos_forensics`,
# `linux_compromise` and `container_forensics` were indistinguishable from Windows
# skills to the matcher.
_SKILL_PLATFORMS = frozenset({"windows", "linux", "macos", "mobile", "any"})

# Windows parser/artifact families, used to infer a case's platform.
_WINDOWS_FAMILIES = frozenset({
    "evtx", "evtxecmd", "hayabusa", "chainsaw", "suzaku", "sysmon", "security",
    "system", "application", "prefetch", "pecmd", "amcache", "appcompat",
    "mft", "mftecmd", "usn", "i30", "registry", "recmd", "lnk", "lecmd",
    "jlecmd", "jumplist", "srum", "srumecmd", "sru", "shimcache", "setupapi",
    "services", "scheduled_tasks", "bits", "tasks", "wmi", "wer",
    "rpcmd", "recycle", "shellbags", "sbecmd", "thumbcache",
})
_LINUX_FAMILIES = frozenset({
    "syslog", "authlog", "journal", "journald", "bash_history", "systemd",
    "sysdig", "audit", "wtmp", "btmp", "lastlog", "cron",
})


def skill_platforms(skill: dict[str, Any]) -> set[str]:
    """The platforms a skill applies to. Absent or unrecognised means ``any``."""
    raw = skill.get("platform") or skill.get("platforms")
    if raw is None:
        return {"any"}
    if isinstance(raw, str):
        raw = [raw]
    out = {str(p).strip().lower() for p in raw if str(p).strip()}
    out &= _SKILL_PLATFORMS
    return out or {"any"}


def infer_case_platform(families) -> set[str]:
    """Platforms a set of parser families is consistent with."""
    fams = {str(f).lower().strip() for f in (families or ()) if str(f).strip()}
    out: set[str] = set()
    if fams & _WINDOWS_FAMILIES:
        out.add("windows")
    if fams & _LINUX_FAMILIES:
        out.add("linux")
    return out or {"any"}


def platform_compatible(skill: dict[str, Any], case_platforms: set[str]) -> bool:
    """False when a skill is scoped to a platform the case is not from."""
    declared = skill_platforms(skill)
    if "any" in declared or "any" in case_platforms:
        return True
    return bool(declared & case_platforms)


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
        declared = {str(f).lower() for f in (trig.get("families") or [])}
        # A generic output format is not evidence of a hypothesis.
        hit = (fams & declared) - _NON_DISCRIMINATIVE_FAMILIES
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


def _surfaceable(
    skill: dict[str, Any],
    score: int,
    kws: set[str],
    techs: set[str],
    fams: set[str],
) -> bool:
    """Whether a positive score is enough to hand this skill to an agent.

    A single family hit is weak: a skill whose trigger lists eight Windows
    families - USB, timeline, event-log methodology - matches *any* EVTX case, so
    every hypothesis surfaced on every case and the analyst got noise instead of
    a lead. Two rules close that:

    * A skill explicitly marked ``kind: methodology`` is satisfied by one family,
      because the artifact type *is* its subject - "how to read event logs" is
      the right skill to hand someone holding an event log.
    * Otherwise a keyword or technique hit is required, or the case must have
      matched **two or more** of the skill's declared families. A combination is
      the signal: LNK + prefetch + browser artifacts together are the
      initial-access signature, while a single `evtx` hit should not hand an
      analyst a USB hypothesis.
    """
    if str(skill.get("kind") or "").lower() == "methodology":
        return True
    trig = skill.get("trigger") or {}
    if kws & {str(k).lower() for k in (trig.get("keywords") or [])}:
        return True
    if techs & {str(x).upper() for x in (trig.get("techniques") or [])}:
        return True
    declared = {str(f).lower() for f in (trig.get("families") or [])} - _NON_DISCRIMINATIVE_FAMILIES
    return len(fams & declared) >= 2


def _ranked_skills(
    families: set[str] | list[str] | None = None,
    keywords: set[str] | list[str] | None = None,
    techniques: set[str] | list[str] | None = None,
) -> list[tuple[int, dict[str, Any], list[str]]]:
    """**The one ranking path.** Platform-filtered and surface-gated, then ranked.

    Both :func:`skills_for` (interpret + briefing) and :func:`retrieve_skills`
    (Mode 2 work orders + the validation harness) call this, so a skill can never
    be handed to an agent on one path and correctly withheld on the other. The
    filter used to live in ``skills_for`` alone, so Mode 2 work orders carried
    procedures for evidence they did not have — `email_phishing`,
    `browser_artifact_analysis`, `mobile_forensics` and `c2_beaconing` on an
    EVTX-only case (V11/D26).

    Returns ``(score, skill, why)`` sorted by score descending; the caller
    truncates, so both surfaces agree on the top-N as well as on the filter.
    """
    fams, kws, techs = _context(families, keywords, techniques)
    case_platforms = infer_case_platform(fams)
    scored: list[tuple[int, dict[str, Any], list[str]]] = []
    for skill in get_skills():
        if validate_skill(skill):
            continue
        # A skill scoped to another platform never fires. Without this,
        # `mobile_forensics` surfaced on a Windows EVTX case because its
        # trigger listed csv/jsonl - output formats every case has.
        if not platform_compatible(skill, case_platforms):
            continue
        score, why = _score_skill(skill, fams, kws, techs)
        if score > 0 and _surfaceable(skill, score, kws, techs, fams):
            scored.append((score, skill, why))
    scored.sort(key=lambda t: -t[0])
    return scored


def skills_for(
    families: set[str] | list[str] | None = None,
    keywords: set[str] | list[str] | None = None,
    techniques: set[str] | list[str] | None = None,
    limit: int = 6,
) -> list[dict[str, Any]]:
    """Skills whose trigger block intersects the case context.

    Ranking: each technique match +3, each keyword match +2, each family
    match +1. A skill with NO trigger hits is never returned — agents only
    run procedures that are relevant to the evidence and suspicion. Platform
    and surfacing filters are applied by :func:`_ranked_skills`, shared with
    :func:`retrieve_skills`.
    """
    ranked = _ranked_skills(families, keywords, techniques)
    return [skill for _score, skill, _why in ranked[: max(1, limit)]]


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

    The SAME ranking as :func:`skills_for` — literally the same helper
    (:func:`_ranked_skills`), so the two cannot diverge — with the match
    reasons, content version and KB citations added on top, so an agent run
    records *why* a procedure was selected and *which* version/citation it came
    from:

        [{skill, title, version, score, why, citations, mitre}]
    """
    ranked = _ranked_skills(families, keywords, techniques)
    out: list[dict[str, Any]] = []
    for score, skill, why in ranked[: max(1, limit)]:
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
