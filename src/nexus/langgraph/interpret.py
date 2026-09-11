"""Hit interpretation layer — WP 4j.1.

Every hit/alert the examiner sees should carry "what this means + what to
check next" — pulled from the matching skill's ``look_for`` / ``corroborate``
/ ``negative`` / ``caveats``, the family-matched playbook caveats, and an
optional RAG methodology chunk. Deterministic first: the skill + playbook
layers need no LLM and no index; RAG is opt-in per call so the briefing
scan stays fast.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from nexus.knowledge.attack_needles import extract_techniques
from nexus.knowledge.skills import skills_for

_TOKEN_RE = re.compile(r"[A-Za-z0-9_.\\-]{3,}")
_MAX_SKILLS = 3
_MAX_STEPS_PER_SKILL = 3
_MAX_LOOK_FOR = 6
_MAX_CORROBORATE = 4
_MAX_CAVEATS = 6
_MAX_NEXT_QUERIES = 6
_MAX_PIVOTS = 6
_MAX_RAG_CHARS = 1200

# Fields whose values carry the row's meaning (rule names, event ids,
# technique tags) — prioritised when building the match blob.
_TITLE_FIELDS = (
    "RuleTitle", "Title", "RuleName", "EventID", "EventId",
    "MitreTags", "MitreTechniques", "Detection", "RuleFile",
)


def _hit_blob(hit: dict[str, Any]) -> str:
    """Text blob for matching: terms + title-ish fields + raw text (bounded)."""
    parts: list[str] = [str(hit.get("terms") or "")]
    fields = hit.get("fields") or {}
    if isinstance(fields, dict):
        for k in _TITLE_FIELDS:
            v = str(fields.get(k) or "").strip()
            if v:
                parts.append(v)
    parts.append(str(hit.get("text") or "")[:2000])
    return " ".join(parts)


def _hit_keywords(hit: dict[str, Any]) -> set[str]:
    """Keyword tokens from the hit — terms + title fields + text words.

    Dotted/pathed tokens (``powershell.exe``, ``C:\\Windows\\svchost.exe``)
    also contribute their ≥4-char segments so process names match skill
    keywords like ``powershell`` / ``svchost``.
    """
    blob = _hit_blob(hit)
    out: set[str] = set()
    for tok in _TOKEN_RE.findall(blob):
        out.add(tok.lower())
        for part in re.split(r"[.\\/-]", tok):
            if len(part) >= 4:
                out.add(part.lower())
    return out


def _matched_steps(
    skill: dict[str, Any],
    hit_tokens: set[str],
    limit: int = _MAX_STEPS_PER_SKILL,
) -> list[dict[str, Any]]:
    """Steps whose query vocabulary overlaps the hit — the examiner is
    standing on this step; ``look_for``/``pivot``/``corroborate`` are the
    'what to check next' for it."""
    scored: list[tuple[int, int, dict[str, Any]]] = []
    for i, st in enumerate(skill.get("steps") or []):
        if not isinstance(st, dict):
            continue
        q_tokens = {t.lower() for t in _TOKEN_RE.findall(str(st.get("query") or ""))}
        score = len(q_tokens & hit_tokens)
        scored.append((score, -i, st))
    # Steps with token overlap first (hit order preserved via -i), then the
    # skill's first step so a family-only match still yields guidance.
    scored.sort(key=lambda t: (-t[0], -t[1]))
    picked = [st for score, _i, st in scored if score > 0][:limit]
    if not picked:
        steps = [s for s in (skill.get("steps") or []) if isinstance(s, dict)]
        picked = steps[:1]
    return picked


def _playbook_caveats(family: str, limit: int = _MAX_CAVEATS) -> tuple[list[str], list[str]]:
    """(caveats, identify-steps) from playbooks matched to the hit family."""
    if not family:
        return [], []
    try:
        from nexus.langgraph.query_pack import _family_matched_playbooks
    except Exception:  # noqa: BLE001
        return [], []
    caveats: list[str] = []
    identify: list[str] = []
    for pb in _family_matched_playbooks({family})[:4]:
        for c in (pb.get("caveats") or []):
            c = str(c).strip()
            if c and c not in caveats:
                caveats.append(c)
        phases = pb.get("phases") or []
        if isinstance(phases, list) and phases:
            first = phases[0]
            if isinstance(first, dict):
                for s in (first.get("steps") or []):
                    s = str(s).strip()
                    if s and s not in identify:
                        identify.append(s)
    return caveats[:limit], identify[:4]


def _rag_methodology(family: str) -> str:
    """Optional RAG chunk for the hit's family — methodology, never evidence."""
    if not family:
        return ""
    try:
        from nexus.tools.rag import _check_rag_available, _get_index

        available, _ = _check_rag_available()
        if not available:
            return ""
        idx = _get_index()
        result = idx.search(
            query=f"how to interpret forensic {family} evidence methodology",
            top_k=2,
        )
        docs = result.get("results") or []
        out: list[str] = []
        for d in docs[:2]:
            text = str(d.get("text") or d.get("document") or "").strip()
            if text:
                out.append(text)
        return "\n".join(out)[:_MAX_RAG_CHARS]
    except Exception:  # noqa: BLE001
        return ""


def interpret_hit(
    case_dir: Path | None,
    hit: dict[str, Any],
    *,
    include_rag: bool = False,
    max_skills: int = _MAX_SKILLS,
) -> dict[str, Any]:
    """Interpret one N4 hit / briefing alert.

    Args:
        case_dir: case directory (reserved — kept for parity with callers
            that resolve case context; interpretation itself is case-agnostic)
        hit: hit dict — ``family``, ``terms``, ``text``, optional ``fields``
        include_rag: append a RAG methodology chunk for the hit's family
        max_skills: cap on matched skills

    Returns:
        meaning        — one-line 'what this is' (top skill or playbook)
        skills         — matched skills: {name, title, mitre, matched_steps}
        look_for       — what to verify in/around this row
        corroborate    — what would raise confidence
        next_queries   — concrete queries from matched skill steps
        pivots         — field names worth pivoting on
        negative       — what absence would mean (skill 'negative' text)
        caveats        — skill + playbook false-positive cautions
        confidence_rules — top skill's confidence rules (high/medium/low)
        methodology    — RAG methodology chunk (include_rag only)
        sources        — which knowledge layers contributed
    """
    hit = hit if isinstance(hit, dict) else {}
    family = str(hit.get("family") or "").lower().strip()
    blob = _hit_blob(hit)
    techniques = extract_techniques(blob)
    keywords = _hit_keywords(hit)

    matched = skills_for(
        families={family} if family else None,
        keywords=keywords,
        techniques=techniques,
        limit=max(1, max_skills),
    )

    skills_out: list[dict[str, Any]] = []
    look_for: list[str] = []
    corroborate: list[str] = []
    next_queries: list[str] = []
    pivots: list[str] = []
    negative: list[str] = []
    caveats: list[str] = []
    confidence_rules: dict[str, Any] = {}

    for skill in matched:
        steps = _matched_steps(skill, keywords)
        step_rows: list[dict[str, Any]] = []
        for st in steps:
            q = str(st.get("query") or "").strip()
            lf = str(st.get("look_for") or "").strip()
            co = str(st.get("corroborate") or "").strip()
            pv = str(st.get("pivot") or "").strip()
            step_rows.append({
                "name": str(st.get("name") or ""),
                "query": q,
                "look_for": lf,
                "corroborate": co,
                "pivot": pv,
            })
            if lf and lf not in look_for:
                look_for.append(lf)
            if co and co not in corroborate:
                corroborate.append(co)
            if q and q not in next_queries:
                next_queries.append(q)
            if pv and pv not in pivots:
                pivots.append(pv)
        neg = str(skill.get("negative") or "").strip()
        if neg and neg not in negative:
            negative.append(neg)
        for c in (skill.get("caveats") or []):
            c = str(c).strip()
            if c and c not in caveats:
                caveats.append(c)
        if not confidence_rules and isinstance(skill.get("confidence_rules"), dict):
            confidence_rules = skill["confidence_rules"]
        skills_out.append({
            "name": str(skill.get("skill") or ""),
            "title": str(skill.get("title") or skill.get("skill") or ""),
            "mitre": [str(t) for t in (skill.get("mitre") or [])],
            "matched_steps": step_rows,
        })

    pb_caveats, pb_identify = _playbook_caveats(family)
    for c in pb_caveats:
        if c not in caveats:
            caveats.append(c)
    # Playbook first-phase steps are also 'what to check next' candidates
    for s in pb_identify:
        if s not in look_for:
            look_for.append(s)

    meaning = ""
    if skills_out:
        top = matched[0]
        meaning = str(top.get("description") or top.get("title") or "")
    elif family:
        meaning = f"{family} parser row — no skill covers this family yet."

    out: dict[str, Any] = {
        "meaning": meaning[:400],
        "skills": skills_out,
        "techniques": techniques,
        "look_for": look_for[:_MAX_LOOK_FOR],
        "corroborate": corroborate[:_MAX_CORROBORATE],
        "next_queries": next_queries[:_MAX_NEXT_QUERIES],
        "pivots": pivots[:_MAX_PIVOTS],
        "negative": negative[:3],
        "caveats": caveats[:_MAX_CAVEATS],
        "confidence_rules": confidence_rules,
        "sources": [
            s for s, have in (
                ("skills", bool(skills_out)),
                ("playbooks", bool(pb_caveats or pb_identify)),
            ) if have
        ],
    }
    if include_rag:
        meth = _rag_methodology(family)
        if meth:
            out["methodology"] = meth
            out["sources"].append("rag")
    return out


def interpret_hits(
    case_dir: Path | None,
    hits: list[dict[str, Any]],
    *,
    include_rag: bool = False,
) -> list[dict[str, Any]]:
    """Interpret a batch (briefing alerts). Same payload per hit — callers
    decide how much to render."""
    return [interpret_hit(case_dir, h, include_rag=include_rag) for h in hits]
