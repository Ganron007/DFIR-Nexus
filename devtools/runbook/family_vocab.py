"""TA-5 (c): the family names the case indexes hold against the names the knowledge declares. Read only.

    python devtools/runbook/family_vocab.py

Lists every family the registered tiny-case indexes hold, every family name a skill (trigger, primary, step
`requires`) or a playbook declares that resolves to none of them through `knowledge.skills.families_intersect`, and
every produced family no skill or playbook names. 2026-10-29 (22 tiny-case indexes): 59 produced, 54 declared names
resolve to none, 17 produced families named by none.
"""
from __future__ import annotations

from collections import defaultdict
from pathlib import Path

import yaml

from nexus.knowledge.family_registry import decode_evidence_group, get_family_registry
from nexus.knowledge.loader import get_playbook, list_playbook_slugs
from nexus.knowledge.skills import families_intersect
from nexus.langgraph.case_index import _client, index_name

SKILLS = Path(__file__).resolve().parents[2] / "src" / "nexus" / "data" / "knowledge" / "skills"
TINY = Path(__file__).resolve().parents[2] / "Docs" / "internal" / "eval" / "tiny-cases.yaml"


def tiny_snapshot() -> tuple[dict[str, set[str]], list[set[str]], dict[str, int]]:
    """Read only registered tiny indexes and retain incomplete metadata explicitly."""
    manifest = yaml.safe_load(TINY.read_text(encoding="utf-8")) or {}
    cases = manifest.get("cases") or {}
    case_ids = [str(entry.get("case_id") or "") for entry in cases.values()]
    if not case_ids or any(not case for case in case_ids) or len(set(case_ids)) != len(case_ids):
        raise ValueError("tiny case manifest has missing or duplicate case IDs")
    out: dict[str, set[str]] = defaultdict(set)
    grouped: list[set[str]] = []
    missing: dict[str, int] = {}
    registry = get_family_registry()
    with _client() as c:
        for case in case_ids:
            name = index_name(case)
            body = {"size": 0, "track_total_hits": True, "aggs": {
                "f": {"terms": {"field": "family", "size": 1000}},
                "g": {"terms": {"field": "evidence_group", "size": 1000}},
                "missing": {"missing": {"field": "evidence_group"}},
            }}
            response = c.post(f"/{name}/_search", json=body)
            response.raise_for_status()
            result = response.json()
            shards = result.get("_shards")
            if not isinstance(shards, dict) or not isinstance(shards.get("failed"), int):
                raise ValueError(f"missing shard status for {case}")
            if result.get("timed_out") or shards["failed"]:
                raise ValueError(f"incomplete aggregation for {case}")
            aggregations = result.get("aggregations") or {}
            families, groups, absent = (aggregations.get(key) for key in ("f", "g", "missing"))
            if any(not isinstance(item, dict) for item in (families, groups, absent)):
                raise ValueError(f"missing aggregation data for {case}")
            if (not isinstance(families.get("buckets"), list) or not isinstance(groups.get("buckets"), list)
                    or "sum_other_doc_count" not in families or "sum_other_doc_count" not in groups
                    or not isinstance(absent.get("doc_count"), int)):
                raise ValueError(f"incomplete aggregation data for {case}")
            if families.get("sum_other_doc_count") or groups.get("sum_other_doc_count"):
                raise ValueError(f"truncated family aggregation for {case}")
            total = (result.get("hits") or {}).get("total") or {}
            if total.get("relation") != "eq":
                raise ValueError(f"inexact row total for {case}")
            missing_rows = int(absent.get("doc_count") or 0)
            if sum(int(b.get("doc_count") or 0) for b in groups.get("buckets") or []) + missing_rows != total.get("value"):
                raise ValueError(f"evidence groups do not cover {case}")
            if missing_rows:
                missing[case] = missing_rows
            for bucket in families.get("buckets") or []:
                out[str(bucket["key"])].add(name)
            for bucket in groups.get("buckets") or []:
                source, importers = decode_evidence_group(bucket["key"])
                grouped.append(registry.evidence_group(source, importers))
    return out, grouped, missing


#: OD-T6 (operator 2026-10-24): these skills are "not exercised in v1" in the coverage statement.
OD_T6_SKILLS = frozenset({"container_forensics", "mobile_forensics", "macos_forensics", "ics_ot_forensics"})
UNIVERSE = Path(__file__).resolve().parents[2] / "Docs" / "internal" / "eval" / "tiny-coverage-universe.yaml"


def _expected_coverage() -> tuple[dict[str, dict], dict[str, list], set[str]]:
    """The planner's expected coverage, as the coverage matrix reads it: lane tools by class, importer sources by
    the tiny cases expected to reach them, and every registered importer source."""
    import sys

    sys.path.insert(0, str(UNIVERSE.parents[3]))
    from devtools.runbook.coverage_matrix import universe_lists

    universe = yaml.safe_load(UNIVERSE.read_text(encoding="utf-8")) or {}
    return universe.get("tools") or {}, universe.get("importers_expected") or {}, set(universe_lists()["importers"])


def _scope(name: str, users: set[str] | None = None) -> str:
    """Why the tiny cases do not produce a declared name, from a recorded decision, or "" when nothing records one."""
    registry = get_family_registry()
    if users and all(user.split(":")[1] in OD_T6_SKILLS for user in users if user.startswith("skill:")) \
            and all(user.startswith("skill:") for user in users):
        return "OD-T6: skill not exercised in v1"
    tools, importers_expected, importer_sources = _expected_coverage()
    selector = name.lower()
    producers = (registry.producers_for(selector) if selector.startswith("kind:") or selector in registry._known_kinds
                 else {selector})
    reasons = []
    for producer in sorted({registry.canonical_family(p) for p in producers}):
        spellings = registry.names(producer) - {f"kind:{k}" for k in registry._known_kinds}
        spec = next((tools[s] for s in spellings if s in tools), None)
        if spec is not None:
            cls = spec.get("class")
            if cls in ("required",):
                return ""
            reasons.append(f"universe {cls}" + (" (TA-6, OD-T23)" if cls == "opt_in" else ""))
            continue
        source = next((s for s in spellings if s in importer_sources), None)
        if source is not None and not importers_expected.get(source):
            reasons.append("importer no tiny case reaches (OD-T5)")
            continue
        return ""
    return "; ".join(sorted(set(reasons)))


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
    produced, groups, missing = tiny_snapshot()
    declared = declared_families()
    registry = get_family_registry()
    names = set(produced) | {name for group in groups for name in group}
    print(f"produced source families ({len(produced)}):", ", ".join(sorted(produced)))
    print(f"indexed groups with importer metadata unavailable ({len(missing)} cases): "
          + ", ".join(f"{case}={rows}" for case, rows in sorted(missing.items())))
    # Vocabulary: a declared name the registry does not know can never match any case.
    unknown = sorted(d for d in declared if not registry.known(d))
    print(f"\ndeclared names the registry does not know ({len(unknown)}):")
    for name in unknown:
        users = sorted(declared[name])
        print(f"  {name}: {', '.join(users[:5])}{' ...' if len(users) > 5 else ''}")
    # Coverage: a known producer or kind the tiny indexes do not produce, each with the decision that scopes it.
    absent = sorted(d for d in declared if registry.known(d) and not families_intersect(names, {d}))
    scopes = {d: _scope(d, declared[d]) for d in absent}
    unscoped = [d for d in absent if not scopes[d]]
    print(f"\nknown declared names no tiny index produces ({len(absent)}; {len(unscoped)} with no recorded scope):")
    for name in absent:
        users = sorted(declared[name])
        print(f"  {name} [{scopes[name] or 'NO RECORDED SCOPE'}]: "
              f"{', '.join(users[:4])}{' ...' if len(users) > 4 else ''}")
    dead = unknown + unscoped
    containers = sorted(p for p in produced if registry.is_container(p))
    unnamed = sorted(p for p in produced if not registry.is_container(p) and not families_intersect({p}, set(declared)))
    print(f"\nproduced containers (their rows are whatever the input held; never named) ({len(containers)}):",
          ", ".join(containers))
    print(f"produced families no skill or playbook names ({len(unnamed)}):", ", ".join(unnamed))
    unnamed_groups = sorted({tuple(sorted(group)) for group in groups if not families_intersect(group, declared)})
    completeness = f"; incomplete: {len(missing)} cases lack group metadata" if missing else ""
    print(f"\nindexed source/importer groups no knowledge names ({len(unnamed_groups)}{completeness}):")
    for group in unnamed_groups:
        print("  " + ", ".join(group))
    return 1 if missing or dead else 0


if __name__ == "__main__":
    raise SystemExit(main())
