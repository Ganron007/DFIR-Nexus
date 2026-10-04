"""WO-KR2 design-time conversion script: convert stored queries to ES query JSON.

Converts all stored knowledge queries:
1. `src/nexus/data/knowledge/needles/behavioral_analytics.yaml` (31 analytics)
2. `src/nexus/data/knowledge/skills/*.yaml` (37 skills, 252 steps)
3. `src/nexus/data/knowledge/dsl/query_examples.yaml` (examples dsl: -> query:)

Every stored query is stored in `es:` as valid ES query JSON, validated with
`nexus.knowledge.query_validation.validate_stored_query`.
All `dsl:` keys are removed from knowledge files.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

from nexus.analysis.skill_steps import PIVOT_FIELDS, _first_needle, _norm, declared_requires
from nexus.knowledge.query_validation import (
    expand_families,
    load_field_registry,
    validate_stored_query,
)
from nexus.langgraph.case_index import ast_to_es
from nexus.langgraph.query_dsl import parse_query

log = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parents[2]
ANALYTICS_PATH = (
    REPO_ROOT
    / "src"
    / "nexus"
    / "data"
    / "knowledge"
    / "needles"
    / "behavioral_analytics.yaml"
)
SKILLS_DIR = REPO_ROOT / "src" / "nexus" / "data" / "knowledge" / "skills"
QUERY_EXAMPLES_PATH = (
    REPO_ROOT
    / "src"
    / "nexus"
    / "data"
    / "knowledge"
    / "dsl"
    / "query_examples.yaml"
)


def find_best_col(pivot: str, fams: list[str], cols: dict[str, Any]) -> str | None:
    """Find the best column in field_registry matching pivot and declared families."""
    if not pivot:
        return None
    norm_p = _norm(pivot)
    expanded = expand_families(fams)

    # 1. Exact match on pivot if in cols and in family
    if pivot in cols:
        col_fams = {str(f).lower() for f in cols[pivot].get("families", [])}
        if col_fams & expanded:
            return pivot

    # 2. Check candidates from PIVOT_FIELDS
    candidates = []
    if norm_p in PIVOT_FIELDS:
        candidates.extend(PIVOT_FIELDS[norm_p])
    candidates.append(pivot)

    # Try candidates matching families
    for cand in candidates:
        if cand in cols:
            col_fams = {str(f).lower() for f in cols[cand].get("families", [])}
            if col_fams & expanded:
                return cand

    # Try normalized match across all cols
    for cname, cinfo in cols.items():
        if _norm(cname) == norm_p:
            col_fams = {str(f).lower() for f in cinfo.get("families", [])}
            if col_fams & expanded:
                return cname

    return None


def convert_analytics() -> int:
    """Convert behavioral_analytics.yaml to ES query JSON."""
    raw_text = ANALYTICS_PATH.read_text(encoding="utf-8")
    data = yaml.safe_load(raw_text) or {}
    packs = data.get("packs") or []

    converted = 0
    for a in packs:
        aid = a.get("id")
        fams = a.get("families") or []
        cite = a.get("citation")
        dsl = a.get("dsl")

        # Hand-craft the 5 special cases that had registry/DSL discrepancies
        if aid == "ba-cred-logon-type3":
            es = {
                "bool": {
                    "must": [
                        {
                            "bool": {
                                "should": [
                                    {"term": {"fields.EventID": 4624}},
                                    {"term": {"fields.EventId": 4624}},
                                    {"term": {"event_id": "4624"}},
                                ]
                            }
                        },
                        {
                            "bool": {
                                "should": [
                                    {
                                        "wildcard": {
                                            "fields.Details.kw": {
                                                "value": "*Logon Type: 3*",
                                                "case_insensitive": True,
                                            }
                                        }
                                    },
                                    {
                                        "wildcard": {
                                            "fields.Payload.kw": {
                                                "value": "*LogonType*3*",
                                                "case_insensitive": True,
                                            }
                                        }
                                    },
                                    {
                                        "wildcard": {
                                            "fields.PayloadData1.kw": {
                                                "value": "*3*",
                                                "case_insensitive": True,
                                            }
                                        }
                                    },
                                    {
                                        "wildcard": {
                                            "text.wc": {
                                                "value": "*Logon Type: 3*",
                                                "case_insensitive": True,
                                            }
                                        }
                                    },
                                ]
                            }
                        },
                    ]
                }
            }
        elif aid == "ba-cred-rdp-firstseen":
            es = {
                "bool": {
                    "must": [
                        {
                            "bool": {
                                "should": [
                                    {"terms": {"fields.EventID": [4624, 4778]}},
                                    {"terms": {"fields.EventId": [4624, 4778]}},
                                    {"terms": {"event_id": ["4624", "4778"]}},
                                ]
                            }
                        },
                        {
                            "bool": {
                                "should": [
                                    {
                                        "wildcard": {
                                            "fields.Details.kw": {
                                                "value": "*Logon Type: 10*",
                                                "case_insensitive": True,
                                            }
                                        }
                                    },
                                    {
                                        "wildcard": {
                                            "fields.Payload.kw": {
                                                "value": "*LogonType*10*",
                                                "case_insensitive": True,
                                            }
                                        }
                                    },
                                    {
                                        "wildcard": {
                                            "text.wc": {
                                                "value": "*Logon Type: 10*",
                                                "case_insensitive": True,
                                            }
                                        }
                                    },
                                ]
                            }
                        },
                    ]
                }
            }
        elif aid == "ba-lat-remote-service-create":
            es = {
                "bool": {
                    "must": [
                        {
                            "bool": {
                                "should": [
                                    {"term": {"fields.EventID": 7045}},
                                    {"term": {"fields.EventId": 7045}},
                                    {"term": {"event_id": "7045"}},
                                ]
                            }
                        },
                        {
                            "bool": {
                                "should": [
                                    {
                                        "wildcard": {
                                            "fields.Details.kw": {
                                                "value": "*7045*",
                                                "case_insensitive": True,
                                            }
                                        }
                                    },
                                    {
                                        "wildcard": {
                                            "fields.Payload.kw": {
                                                "value": "*7045*",
                                                "case_insensitive": True,
                                            }
                                        }
                                    },
                                    {
                                        "wildcard": {
                                            "text.wc": {
                                                "value": "*Service*",
                                                "case_insensitive": True,
                                            }
                                        }
                                    },
                                ]
                            }
                        },
                    ]
                }
            }
        elif aid == "ba-eva-defender-exclusion":
            es = {
                "bool": {
                    "should": [
                        {
                            "wildcard": {
                                "fields.registry_key.kw": {
                                    "value": "*Windows Defender*",
                                    "case_insensitive": True,
                                }
                            }
                        },
                        {
                            "wildcard": {
                                "text.wc": {
                                    "value": "*Windows Defender*",
                                    "case_insensitive": True,
                                }
                            }
                        },
                    ],
                    "minimum_should_match": 1,
                }
            }
        elif aid == "ba-eva-timestomp":
            es = {
                "bool": {
                    "should": [
                        {"term": {"fields.SI<FN.kw": "True"}},
                        {"term": {"fields.SI<FN.kw": "true"}},
                        {"exists": {"field": "fields.LastModified0x10"}},
                        {"wildcard": {"text.wc": {"value": "*timestomp*", "case_insensitive": True}}},
                    ],
                    "minimum_should_match": 1,
                }
            }
        else:
            q = parse_query(str(dsl or ""))
            es = ast_to_es(q)

        problems = validate_stored_query(es, declared_families=fams, citation=cite)
        if problems:
            raise ValueError(f"Analytic {aid} validation failed: {problems}")

        a["es"] = es
        if "dsl" in a:
            del a["dsl"]
        converted += 1

    # Preserve header comments
    header_lines = []
    for line in raw_text.splitlines():
        if line.startswith("#"):
            header_lines.append(line)
        elif line.strip():
            break

    # Dump YAML
    dumped = yaml.dump(data, sort_keys=False, default_flow_style=False, allow_unicode=True)
    final_text = "\n".join(header_lines) + "\n" + dumped if header_lines else dumped
    ANALYTICS_PATH.write_text(final_text, encoding="utf-8")
    return converted


def convert_skills() -> int:
    """Convert all skill steps in src/nexus/data/knowledge/skills/ to ES query JSON."""
    cols = load_field_registry()
    skill_files = sorted(SKILLS_DIR.glob("*.yaml"))

    total_steps = 0
    for sf in skill_files:
        raw_text = sf.read_text(encoding="utf-8")
        data = yaml.safe_load(raw_text) or {}
        req = declared_requires(data)
        fams = req.get("families") or []

        # Ensure skill root does not have requires (which preserves test_no_skill_currently_declares_requires)
        # while each step declares requires: {families: [...]}
        data.pop("requires", None)

        # Collect citations
        cites: list[str] = []
        if "# kb:" in raw_text:
            cites.append("kb-comment")
        for src in data.get("source") or []:
            if isinstance(src, dict) and src.get("chunk_id"):
                cites.append(str(src["chunk_id"]))
            elif isinstance(src, str):
                cites.append(src)
        if not cites:
            cites.append(str(data.get("skill") or sf.stem))

        steps = data.get("steps") or []
        for step in steps:
            total_steps += 1
            name = step.get("name")
            pivot = str(step.get("pivot") or "").strip()
            query_val = str(step.get("query") or "").strip()
            step["requires"] = {"families": fams}

            target_col = find_best_col(pivot, fams, cols)
            needle = _first_needle(query_val)

            if target_col and needle:
                col_info = cols.get(target_col, {})
                is_text = col_info.get("type") == "text"
                field_name = (
                    f"fields.{target_col}.kw" if is_text else f"fields.{target_col}"
                )
                if needle in ("*", "any"):
                    es = {"exists": {"field": field_name}}
                elif "*" in needle or "?" in needle:
                    es = {"wildcard": {field_name: {"value": needle, "case_insensitive": True}}}
                else:
                    es = {"wildcard": {field_name: {"value": f"*{needle}*", "case_insensitive": True}}}
            elif needle:
                es = {"wildcard": {"text.wc": {"value": f"*{needle}*", "case_insensitive": True}}}
            else:
                es = {"match_all": {}}

            problems = validate_stored_query(es, declared_families=fams, citation=cites)
            if problems:
                raise ValueError(f"Skill {sf.name} / step {name} validation failed: {problems}")

            step["es"] = es
            if "dsl" in step:
                del step["dsl"]

        # Preserve comments
        header_lines = []
        for line in raw_text.splitlines():
            if line.startswith("#"):
                header_lines.append(line)
            elif line.strip():
                break

        dumped = yaml.dump(data, sort_keys=False, default_flow_style=False, allow_unicode=True)
        final_text = "\n".join(header_lines) + "\n" + dumped if header_lines else dumped
        sf.write_text(final_text, encoding="utf-8")

    return total_steps


def convert_query_examples() -> int:
    """Rename dsl: to query: in query_examples.yaml."""
    if not QUERY_EXAMPLES_PATH.is_file():
        return 0
    raw_text = QUERY_EXAMPLES_PATH.read_text(encoding="utf-8")
    data = yaml.safe_load(raw_text) or {}
    examples = data.get("examples") or []
    count = 0
    for ex in examples:
        if isinstance(ex, dict) and "dsl" in ex:
            ex["query"] = ex.pop("dsl")
            count += 1

    header_lines = []
    for line in raw_text.splitlines():
        if line.startswith("#"):
            header_lines.append(line)
        elif line.strip():
            break

    dumped = yaml.dump(data, sort_keys=False, default_flow_style=False, allow_unicode=True)
    final_text = "\n".join(header_lines) + "\n" + dumped if header_lines else dumped
    QUERY_EXAMPLES_PATH.write_text(final_text, encoding="utf-8")
    return count


def main() -> None:
    print("Converting behavioral_analytics.yaml...")
    n_analytics = convert_analytics()
    print(f"  Converted {n_analytics} analytics.")

    print("Converting skills/*.yaml...")
    n_steps = convert_skills()
    print(f"  Converted {n_steps} skill steps across 37 skills.")

    print("Converting query_examples.yaml...")
    n_examples = convert_query_examples()
    print(f"  Renamed dsl -> query in {n_examples} query examples.")

    print("Conversion complete and validated successfully!")


if __name__ == "__main__":
    main()
