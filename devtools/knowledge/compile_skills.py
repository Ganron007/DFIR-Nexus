"""IC-6 (Part 9): compile every skill step's `search:` into its stored `es:`, with the pinned-source checks.

This replaces the KR2b free-text conversion for skill steps (`convert_to_es.convert_skills`, removed), whose
output glued free terms into literal wildcard phrases. A step is one of:

* `kind: search`    - `search:` compiled to `es:` (`step_search.compile_search`);
* `kind: aggregate` - `search:` compiled to `es:` plus `aggregate:` compiled to `es_aggs:`: an
  inventory step ("which programs ran") counts values instead of returning every row;
* `kind: procedure` - an investigation order with no query, and `procedure_reason` says why.

    python devtools/knowledge/compile_skills.py            # write es:/es_aggs:, print the counts
    python devtools/knowledge/compile_skills.py --check    # fail on drift or on a check problem
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import yaml

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from step_search import (  # noqa: E402
    check_step,
    compile_aggs,
    compile_search,
    compile_source,
    source_label,
)

REPO = HERE.parents[1]
SKILLS_DIR = REPO / "src" / "nexus" / "data" / "knowledge" / "skills"
KINDS = ("search", "aggregate", "procedure")
#: The families the index records for event-log rows (EvtxECmd's parse and Hayabusa's read-back, D232).
EVENT_FAMILIES = ["evtxecmd", "hayabusa"]


def search_families(search: dict[str, Any]) -> list[str]:
    """The index families a search reads: the event-log families when it names events, plus its own."""
    return list(dict.fromkeys((EVENT_FAMILIES if search.get("events") else [])
                              + [str(f) for f in (search.get("families") or [])]))


def _read(path: Path) -> tuple[dict[str, Any], list[str]]:
    raw = path.read_text(encoding="utf-8")
    header: list[str] = []
    for line in raw.splitlines():
        if line.startswith("#"):
            header.append(line)
        elif line.strip():
            break
    return yaml.safe_load(raw) or {}, header


def _write(path: Path, data: dict[str, Any], header: list[str]) -> None:
    dumped = yaml.dump(data, sort_keys=False, default_flow_style=False, allow_unicode=True, width=110)
    path.write_text(("\n".join(header) + "\n" if header else "") + dumped, encoding="utf-8")


def compile_step(step: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """The compiled keys for one step, and the problems found."""
    kind = str(step.get("kind") or "search")
    if kind not in KINDS:
        return {}, [f"kind {kind!r} is not one of {KINDS}"]
    if kind == "procedure":
        problems = [] if str(step.get("procedure_reason") or "").strip() else ["a procedure step says why"]
        if step.get("search"):
            problems.append("a procedure step has no search")
        return {}, problems
    if not isinstance(step.get("search"), dict):
        return {}, ["a search or aggregate step has a `search:`"]
    problems, _prov = check_step(step)
    out: dict[str, Any] = {}
    try:
        out["es"] = compile_search(step["search"])
        # What the step reads, for the seat block: the label, and its source alone, which the runtime counts
        # on the case to say whether the case holds that log (the step's prose names a log source; read
        # without it, "Sysmon EventID 10" primed a claim on a case with no Sysmon log, IC-1).
        out["source"] = source_label(step["search"])
        # What the step needs the case to hold is what it reads: the event-log families when it names events,
        # and its own families. The KR2b conversion copied the skill's trigger families onto every step, so a
        # browser step that reads SQLECmd rows declared EVTX families and failed its own registry check.
        out["requires"] = {"families": search_families(step["search"])}
        source = compile_source(step["search"])
        if source:
            out["es_source"] = source
        if kind == "aggregate":
            out["es_aggs"] = compile_aggs(step.get("aggregate") or {})
    except ValueError as exc:
        problems.append(str(exc))
    if kind == "search" and step.get("aggregate"):
        problems.append("a search step has no `aggregate:`; make it kind: aggregate")
    return out, problems


#: Keys the KR2b conversion wrote that the compiled form replaces.
_RETIRED = ("es_dropped", "es_text_only_reason", "es_authored_reason")


def run(check: bool = False) -> dict[str, Any]:
    stats: dict[str, Any] = {"skills": 0, "steps": 0, "search": 0, "aggregate": 0, "procedure": 0,
                             "uncompiled": [], "problems": [], "drift": [], "authored_values": 0,
                             "sourced_values": 0}
    for path in sorted(SKILLS_DIR.glob("*.yaml")):
        data, header = _read(path)
        stats["skills"] += 1
        dirty = False
        for step in data.get("steps") or []:
            if not isinstance(step, dict):
                continue
            stats["steps"] += 1
            name = f"{data.get('skill')}/{step.get('name')}"
            if "search" not in step and str(step.get("kind") or "search") != "procedure":
                stats["uncompiled"].append(name)
                continue
            kind = str(step.get("kind") or "search")
            stats[kind] = stats.get(kind, 0) + 1
            compiled, problems = compile_step(step)
            stats["problems"].extend(f"{name}: {p}" for p in problems)
            if kind != "procedure":
                _p, prov = check_step(step)
                stats["authored_values"] += sum(1 for v in prov if v["source"] == "authored")
                stats["sourced_values"] += sum(1 for v in prov if v["source"] != "authored")
            for key in ("es", "es_aggs", "es_source", "source", "requires"):
                want = compiled.get(key)
                if step.get(key) != want:
                    if check:
                        stats["drift"].append(f"{name}: {key}")
                    elif want is None:
                        step.pop(key, None)
                        dirty = True
                    else:
                        step[key] = want
                        dirty = True
            for key in _RETIRED:
                if key in step:
                    if check:
                        stats["drift"].append(f"{name}: retired key {key}")
                    else:
                        step.pop(key)
                        dirty = True
        if dirty and not check:
            _write(path, data, header)
    return stats


ANALYTICS = REPO / "src" / "nexus" / "data" / "knowledge" / "needles" / "behavioral_analytics.yaml"
def run_analytics(check: bool = False) -> dict[str, Any]:
    """IC-7: compile each behavioural analytic's `search:` into its `es:` the same way, with the same checks.

    An analytic's `families` (what the lead builder checks the case holds before running it) are the
    families its search reads: the event-log families when it names events, plus its own `families`.
    """
    data, header = _read(ANALYTICS)
    stats: dict[str, Any] = {"analytics": 0, "uncompiled": [], "problems": [], "drift": []}
    dirty = False
    for item in data.get("packs") or []:
        if not isinstance(item, dict):
            continue
        stats["analytics"] += 1
        ident = str(item.get("id") or "")
        if not isinstance(item.get("search"), dict):
            stats["uncompiled"].append(ident)
            continue
        compiled, problems = compile_step(item)
        stats["problems"].extend(f"{ident}: {p}" for p in problems)
        search = item["search"]
        families = search_families(search)
        # The analytic's source alone, so the lead builder asks whether a case holds that log before running it.
        want = {"es": compiled.get("es"), "es_source": compiled.get("es_source"), "families": families}
        for key, value in want.items():
            if item.get(key) != value:
                if check:
                    stats["drift"].append(f"{ident}: {key}")
                else:
                    item[key] = value
                    dirty = True
        for key in _RETIRED + ("es_aggs",):
            if key in item:
                if check:
                    stats["drift"].append(f"{ident}: retired key {key}")
                else:
                    item.pop(key)
                    dirty = True
    if dirty and not check:
        _write(ANALYTICS, data, header)
    return stats


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args(argv)
    stats = run(check=args.check)
    an = run_analytics(check=args.check)
    print(json.dumps({k: (len(v) if isinstance(v, list) else v) for k, v in an.items()}))
    for key in ("problems", "drift", "uncompiled"):
        for line in an[key][:60]:
            print(f"  analytics {key}: {line}")
    print(json.dumps({k: (len(v) if isinstance(v, list) else v) for k, v in stats.items()}))
    for key in ("problems", "drift", "uncompiled"):
        for line in stats[key][:60]:
            print(f"  {key}: {line}")
    bad = any(s["problems"] or s["drift"] or (args.check and s["uncompiled"]) for s in (stats, an))
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
