"""Term-matched registry context: MITRE ATLAS (AI/ML) + MBC (malware behaviors).

The registries are large; prompts get only what the question's tokens match —
and nothing at all when there is no match (a thin prompt beats a noisy one).
Attribution lives with each registry (``atlas/NOTICE.txt``, ``mbc/NOTICE.txt``).
"""

from __future__ import annotations

import re
from functools import lru_cache

_TOKEN = re.compile(r"[a-z0-9][a-z0-9_.-]{3,}")
_STOP = frozenset({
    "this", "that", "these", "those", "with", "from", "have", "has", "had",
    "does", "did", "were", "was", "are", "been", "being", "what", "which",
    "where", "when", "while", "there", "here", "into", "onto", "about",
    "above", "below", "under", "over", "also", "case", "host", "hosts",
    "user", "users", "evidence", "event", "events", "logs", "data", "source",
    "check", "lookup", "list", "show", "find", "explain", "detail", "details",
    "table", "they", "them", "their", "such", "some", "most", "more", "less",
    "nothing", "something", "anything", "everything", "thing", "things",
    "would", "could", "should", "must", "will", "just", "even", "back",
    "down", "again", "still", "first", "last", "next", "after", "before",
    "during", "since", "make", "makes", "made", "take", "takes", "give",
    "gives", "work", "works", "need", "needs", "want", "wants", "know",
    "like", "really", "very", "much", "many", "other", "others", "same",
    "used", "using", "use", "uses", "get", "gets", "got", "can", "cannot",
    "please", "tell", "help", "question", "answer",
})
_NAME_WEIGHT = 3
_DESC_WEIGHT = 1
_MIN_SCORE = 2


def _tokens(text: str) -> set[str]:
    return {t for t in _TOKEN.findall(str(text or "").lower()) if t not in _STOP}


@lru_cache(maxsize=1)
def _atlas_techniques() -> tuple[dict, ...]:
    from nexus.knowledge.loader import get_atlas_registry

    return tuple(get_atlas_registry().get("techniques") or [])


@lru_cache(maxsize=1)
def _mbc_behaviors() -> tuple[dict, ...]:
    from nexus.knowledge.loader import get_mbc_registry

    return tuple(get_mbc_registry().get("behaviors") or [])


def _score(tokens: set[str], name: str, description: str) -> int:
    """Name matches weigh more than description matches; generic noise cannot
    pass on description hits alone (threshold applies)."""
    name_low = str(name or "").lower()
    desc_low = str(description or "").lower()
    score = 0
    for token in tokens:
        if token in name_low:
            score += _NAME_WEIGHT
        elif token in desc_low:
            score += _DESC_WEIGHT
    return score


def atlas_context_for(question: str, cap: int = 4) -> str:
    """ATLAS techniques whose name/description match the question tokens."""
    tokens = _tokens(question)
    if not tokens:
        return ""
    scored: list[tuple[int, int, dict]] = []
    for index, tech in enumerate(_atlas_techniques()):
        score = _score(tokens, tech.get("name", ""), tech.get("description", ""))
        if score >= _MIN_SCORE:
            scored.append((score, -index, tech))
    scored.sort(key=lambda row: (row[0], row[1]), reverse=True)
    lines: list[str] = []
    for _rank, _index, tech in scored[: max(1, cap)]:
        refs = ", ".join(
            str(r.get("id") or "") for r in (tech.get("attack_refs") or [])[:3]
        )
        line = f"{tech.get('id')} {tech.get('name')} ({tech.get('maturity') or 'n/a'})"
        desc = str(tech.get("description") or "").strip()
        if desc:
            line += f": {desc[:160]}"
        if refs:
            line += f" [ATT&CK: {refs}]"
        lines.append(line)
    return "\n".join(lines)


def mbc_context_for(question: str, cap: int = 4) -> str:
    """MBC behaviors whose name/description match the question tokens."""
    tokens = _tokens(question)
    if not tokens:
        return ""
    scored: list[tuple[int, int, dict]] = []
    for index, behavior in enumerate(_mbc_behaviors()):
        score = _score(
            tokens, behavior.get("name", ""), behavior.get("description", "")
        )
        if score >= _MIN_SCORE:
            scored.append((score, -index, behavior))
    scored.sort(key=lambda row: (row[0], row[1]), reverse=True)
    lines: list[str] = []
    for _rank, _index, behavior in scored[: max(1, cap)]:
        rules = [
            str(r.get("rule_name") or "")
            for r in (behavior.get("detection_rules") or [])[:2]
            if r.get("rule_name")
        ]
        line = (
            f"{behavior.get('id')} {behavior.get('name')}: "
            f"methods={len(behavior.get('methods') or [])} "
            f"families={', '.join((behavior.get('families') or [])[:3]) or '-'}"
        )
        if rules:
            line += f" | capa/YARA: {', '.join(rules)}"
        lines.append(line)
    return "\n".join(lines)
