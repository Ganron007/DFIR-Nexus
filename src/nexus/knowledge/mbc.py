"""capa output -> MBC behavior mapping (F7).

The MBC v3 registry carries 1,160 capa/YARA rule references per behavior
(``detection_rules[].rule_name``). When capa runs over a sample, its rule hits
ARE capability evidence - mapping them onto MBC behaviors gives the report and
the prompts a verified behavior name instead of a bare rule id, and ties the
"capa on our own tool" requirement to the registry.
"""

from __future__ import annotations

import re
from functools import lru_cache
from typing import Any

_RULE_SPLIT = re.compile(r"[/\\]")


def _norm(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", str(name or "").lower()).strip()


@lru_cache(maxsize=1)
def _rule_index() -> dict[str, list[dict[str, Any]]]:
    """normalized capa/YARA rule name -> behaviors referencing it."""
    from nexus.knowledge.loader import get_mbc_registry

    index: dict[str, list[dict[str, Any]]] = {}
    for behavior in get_mbc_registry().get("behaviors") or []:
        for rule in behavior.get("detection_rules") or []:
            name = str(rule.get("rule_name") or "").strip()
            if not name:
                continue
            key = _norm(name)
            index.setdefault(key, []).append({
                "behavior_id": str(behavior.get("id") or ""),
                "behavior_name": str(behavior.get("name") or ""),
                "families": list(behavior.get("families") or []),
                "rule_type": str(rule.get("rule_type") or ""),
            })
    return index


def mbc_behaviors_for_capa_rules(
    rule_names: list[str] | set[str] | None,
    cap: int = 10,
) -> list[dict[str, Any]]:
    """Map capa/YARA rule names onto MBC behaviors.

    Matching is exact on the normalized name, then bidirectional containment
    for the common ``family_rule`` capa naming style. Returns one row per
    (rule, behavior) with the rule as it appeared in the output.
    """
    index = _rule_index()
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for raw in rule_names or []:
        name = str(raw or "").strip()
        if not name:
            continue
        key = _norm(name)
        hits = list(index.get(key, []))
        if not hits:
            for indexed, behaviors in index.items():
                if indexed and (indexed in key or key in indexed):
                    hits.extend(behaviors)
                    if len(hits) >= cap:
                        break
        for behavior in hits:
            dedupe = (name.lower(), behavior["behavior_id"])
            if dedupe in seen:
                continue
            seen.add(dedupe)
            out.append({
                "rule_name": name,
                **behavior,
            })
            if len(out) >= cap:
                return out
    return out


def mbc_capa_context(
    rule_names: list[str] | set[str] | None,
    cap: int = 6,
) -> str:
    """Render mapped behaviors for prompts (one line per behavior)."""
    mapped = mbc_behaviors_for_capa_rules(rule_names, cap=cap)
    if not mapped:
        return ""
    lines: list[str] = []
    for row in mapped:
        line = (
            f"{row['behavior_id']} {row['behavior_name']} "
            f"(capa rule: {row['rule_name']})"
        )
        families = ", ".join(row.get("families") or [])
        if families:
            line += f" | families: {families}"
        lines.append(line)
    return "\n".join(lines)
