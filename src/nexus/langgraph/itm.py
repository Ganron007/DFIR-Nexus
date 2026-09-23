"""Insider Threat Matrix — registry-grounded prompt block, retrieval, validation.

The registry (``data/knowledge/itm/itm_registry.yaml``) is compiled from the
Apache-2.0 ITM JSON (insiderthreatmatrix.org, Forscie Limited; NOTICE retained
next to the raw dump) by ``scripts/build_itm_registry.py``:

- articles AR1-AR5 = stages Motive / Means / Preparation / Infringement /
  Anti-Forensics;
- section ids (MT/ME/PR/IF/AF), subsections (``PR026.001``), detections (DT),
  preventions (PV), platforms, and the ATT&CK crosswalk (168 mappings).

Findings may only cite IDs that exist here — invented technique ids are
rejected at staging (``validate_itm_ids``), the same discipline FD-001 applies
to evidence references.
"""

from __future__ import annotations

import re
from functools import lru_cache

ITM_URL = "https://insiderthreatmatrix.org/"

_STAGE_BY_ARTICLE = {
    "AR1": "Motive",
    "AR2": "Means",
    "AR3": "Preparation",
    "AR4": "Infringement",
    "AR5": "Anti-Forensics",
}
_STAGES = tuple(_STAGE_BY_ARTICLE.values())
_TOKEN = re.compile(r"[a-z0-9][a-z0-9_.-]{2,}")
_STOP = frozenset({
    "the", "and", "for", "with", "from", "did", "was", "were", "are", "you",
    "not", "can", "get", "use", "any", "all", "out", "its", "our", "their",
    "explain", "connection", "detail", "details", "came", "which", "where",
    "what", "that", "this", "have", "does", "when",
    "there", "into", "about", "also", "list", "show", "find", "case", "host",
    "user", "users", "evidence", "event", "events", "logs", "data", "source",
    "external", "check", "lookup", "table", "tabular", "readable", "present",
})


@lru_cache(maxsize=1)
def _registry() -> dict:
    try:
        from nexus.knowledge.loader import get_itm_registry

        return get_itm_registry()
    except Exception:  # noqa: BLE001 — KB must never break a prompt
        return {}


@lru_cache(maxsize=1)
def itm_index() -> dict[str, dict]:
    """Flattened id -> section/subsection info (canonical citation targets)."""
    out: dict[str, dict] = {}
    for article in _registry().get("articles") or []:
        aid = str(article.get("id") or "")
        stage = _STAGE_BY_ARTICLE.get(aid, str(article.get("title") or ""))
        for section in article.get("sections") or []:
            sid = str(section.get("id") or "")
            if not sid:
                continue
            base = {
                "id": sid,
                "title": str(section.get("title") or ""),
                "article": aid,
                "stage": stage,
                "kind": "section",
            }
            out[sid] = base
            for sub in section.get("subsections") or []:
                sub_id = str(sub.get("id") or "")
                if sub_id:
                    out[sub_id] = {
                        "id": sub_id,
                        "title": str(sub.get("title") or ""),
                        "article": aid,
                        "stage": stage,
                        "kind": "subsection",
                        "section": sid,
                    }
    return out


@lru_cache(maxsize=1)
def itm_sections() -> list[dict]:
    """All sections (registry order) with article/stage attached."""
    out: list[dict] = []
    for article in _registry().get("articles") or []:
        aid = str(article.get("id") or "")
        stage = _STAGE_BY_ARTICLE.get(aid, str(article.get("title") or ""))
        for section in article.get("sections") or []:
            row = dict(section)
            row["article"] = aid
            row["stage"] = stage
            out.append(row)
    return out


def _tokens(text: str) -> set[str]:
    return {
        t for t in _TOKEN.findall(str(text or "").lower())
        if t not in _STOP
    }


def itm_sections_for(
    question: str = "",
    families: set[str] | list[str] | None = None,
    limit: int = 8,
) -> list[dict]:
    """Registry sections most relevant to a question / case vocabulary.

    Deterministic: token overlap on title (weight 3), description (1),
    platforms (1), plus a small boost when a family name appears in the
    description. Used to ground prompts with *relevant* options instead of a
    full dump — the agent still decides what to cite.
    """
    tokens = _tokens(question)
    fams = {str(f).lower() for f in (families or []) if str(f).strip()}
    if not tokens and not fams:
        return []
    scored: list[tuple[int, int, dict]] = []
    for i, section in enumerate(itm_sections()):
        title_tokens = _tokens(section.get("title"))
        desc_tokens = _tokens(section.get("description"))
        platforms = {str(p).lower() for p in (section.get("platforms") or [])}
        score = 3 * len(tokens & title_tokens) + len(tokens & desc_tokens)
        score += len(fams & platforms)
        if score <= 0:
            continue
        scored.append((score, -i, section))
    scored.sort(key=lambda item: (item[0], item[1]), reverse=True)
    return [section for _score, _i, section in scored[: max(1, limit)]]


def _canonical(item: dict) -> str:
    return f"{item.get('article')}/{item.get('id')}"


def validate_itm_ids(
    stage: str = "",
    objects: list[str] | str | None = None,
) -> dict[str, object]:
    """Validate stage + object ids against the registry.

    Accepts stage names (``Preparation``), article ids (``AR3``), and object
    forms ``PR026`` / ``AR3/PR016`` / ``PR026.001`` (case-insensitive).
    Returns ``{stage, objects, unknown}``; unknown ids are reported so callers
    can omit them from findings instead of rendering invented techniques.
    """
    index = itm_index()
    raw_objects = objects if isinstance(objects, list) else ([objects] if objects else [])

    stage_norm = str(stage or "").strip()
    resolved_stage = ""
    if stage_norm:
        for name in _STAGES:
            if stage_norm.lower() == name.lower():
                resolved_stage = name
                break
        if not resolved_stage:
            article = stage_norm.upper()
            if article in _STAGE_BY_ARTICLE:
                resolved_stage = _STAGE_BY_ARTICLE[article]
            elif index.get(stage_norm.upper()):
                resolved_stage = str(index[stage_norm.upper()]["stage"])

    valid: list[str] = []
    unknown: list[str] = []
    for item in raw_objects:
        raw = str(item or "").strip()
        if not raw:
            continue
        candidate = raw.split("/", 1)[1] if "/" in raw else raw
        info = index.get(candidate.upper())
        if info is None:
            unknown.append(raw)
            continue
        canonical = _canonical(info)
        if canonical not in valid:
            valid.append(canonical)
        if not resolved_stage:
            resolved_stage = str(info["stage"])
    return {"stage": resolved_stage, "objects": valid, "unknown": unknown}


def itm_prompt_block(
    question: str = "",
    families: set[str] | list[str] | None = None,
    limit: int = 8,
    full_taxonomy: bool = True,
) -> str:
    """Prompt block: stages + the registry sections relevant to this case.

    ``full_taxonomy=False`` drops the (large) citation listing - use it for
    query-proposal prompts where only the relevant lens matters.
    """
    relevance = itm_sections_for(question, families, limit)
    lines = [
        "HYPOTHESIS LENSES (both apply; evidence chooses which fits):",
        "A) External compromise / intrusion - MITRE ATT&CK when justified "
        "(initial access, execution, persistence, C2, credential access). "
        "Do not invent an APT name or campaign.",
        f"B) Insider misuse - Insider Threat Matrix ({ITM_URL}): stages "
        f"{' | '.join(_STAGES)}.",
    ]
    if relevance:
        lines.append(
            "RELEVANT ITM SECTIONS FOR THIS CASE (cite ids exactly as shown; "
            "ids outside this registry are rejected at staging):"
        )
        for section in relevance:
            subs = [
                str(s.get("title") or "")
                for s in (section.get("subsections") or [])[:4]
                if s.get("title")
            ]
            extra = f" - e.g. {', '.join(subs)}" if subs else ""
            lines.append(
                f"  {_canonical(section)} {section.get('title')} "
                f"[{', '.join(section.get('platforms') or []) or 'any platform'}]{extra}"
            )
    else:
        lines.append(
            "No ITM section matched this case context - cite an id only when "
            "you can name it exactly from the taxonomy."
        )
    # Full taxonomy: every valid id, compact. The model cites from this set;
    # anything else is rejected at staging (no invented techniques).
    if full_taxonomy:
        lines.append("FULL ITM TAXONOMY (valid ids; cite 'ARx/ID'):")
        for article in _registry().get("articles") or []:
            aid = str(article.get("id") or "")
            stage = _STAGE_BY_ARTICLE.get(aid, str(article.get("title") or ""))
            titles = ", ".join(
                f"{aid}/{s.get('id')} {s.get('title')}"
                for s in (article.get("sections") or [])
                if s.get("id")
            )
            lines.append(f"  {stage} ({aid}): {titles}")
    lines.append(
        "Record ITM only when the facts support an authorized user abusing "
        "access: itm_stage + itm_objects (canonical 'ARx/ID'). Omit ITM fields "
        "for external-only or benign evidence. "
        "Call forensic_rag_search only for QUERY PACK hit families (how to read "
        "those artifacts). Do not dump unrelated methodology."
    )
    return "\n".join(lines) + "\n"
