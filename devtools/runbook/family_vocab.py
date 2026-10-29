"""TA-5 (c): the family names the case indexes hold against the names the knowledge declares. Read only.

    python devtools/runbook/family_vocab.py

Lists every family the current `nexus-case-*` indexes hold, every family name a skill (trigger, primary, step
`requires`) or a playbook declares that resolves to none of them through `knowledge.skills.families_intersect`, and
every produced family no skill or playbook names. 2026-10-29 (22 tiny-case indexes): 59 produced, 54 declared names
resolve to none, 17 produced families named by none.
"""
from __future__ import annotations

from collections import defaultdict
from pathlib import Path

import yaml

from nexus.knowledge.loader import get_playbook, list_playbook_slugs
from nexus.knowledge.skills import families_intersect
from nexus.langgraph.case_index import _client

SKILLS = Path(__file__).resolve().parents[2] / "src" / "nexus" / "data" / "knowledge" / "skills"


def produced_families() -> dict[str, set[str]]:
    out: dict[str, set[str]] = defaultdict(set)
    with _client() as c:
        for row in c.get("/_cat/indices/nexus-case-*?format=json").json():
            body = {"size": 0, "aggs": {"f": {"terms": {"field": "family", "size": 1000}}}}
            resp = c.post(f"/{row['index']}/_search", json=body).json()
            for bucket in resp.get("aggregations", {}).get("f", {}).get("buckets", []):
                out[bucket["key"]].add(row["index"])
    return out


def declared_families() -> dict[str, set[str]]:
    out: dict[str, set[str]] = defaultdict(set)
    for path in sorted(SKILLS.glob("*.yaml")):
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        for skill in doc if isinstance(doc, list) else [doc]:
            if not isinstance(skill, dict):
                continue
            sid = skill.get("id") or skill.get("name") or path.stem
            trigger = skill.get("trigger") or {}
            for where, names in (("trigger", trigger.get("families")), ("primary", skill.get("primary_families")),
                                 ("trigger.primary", trigger.get("primary_families"))):
                for name in names or []:
                    out[str(name).lower()].add(f"skill:{sid}:{where}")
            for step in skill.get("steps") or []:
                if isinstance(step, dict):
                    for name in (step.get("requires") or {}).get("families") or []:
                        out[str(name).lower()].add(f"skill:{sid}:step")
    for slug in list_playbook_slugs():
        for name in (get_playbook(slug) or {}).get("families") or []:
            out[str(name).lower()].add(f"playbook:{slug}")
    return out


def main() -> int:
    produced = produced_families()
    declared = declared_families()
    names = set(produced)
    print(f"produced families ({len(names)}):", ", ".join(sorted(names)))
    dead = sorted(d for d in declared if not families_intersect(names, {d}))
    print(f"\ndeclared names that resolve to no produced family ({len(dead)}):")
    for name in dead:
        users = sorted(declared[name])
        print(f"  {name}: {', '.join(users[:5])}{' ...' if len(users) > 5 else ''}")
    unnamed = sorted(p for p in names if not families_intersect({p}, set(declared)))
    print(f"\nproduced families no skill or playbook names ({len(unnamed)}):", ", ".join(unnamed))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
