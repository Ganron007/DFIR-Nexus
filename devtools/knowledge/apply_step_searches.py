"""IC-6 (Part 9): merge authored step searches into the skill files, then compile them.

The authoring file maps `skill id -> step name -> {kind?, search?, aggregate?, procedure_reason?}`. For each
named step this sets the authored keys and drops what the KR2b conversion wrote (`es`, `es_dropped`,
`es_text_only_reason`, `es_authored_reason`); `compile_skills.py` then writes the compiled `es:`/`es_aggs:`.
A step name the skill does not have is an error, so nothing lands on the wrong step.

It also moves each skill's technique ids to the ids ATT&CK v20 uses: a revoked id follows its
`revoked_by` in the pinned registry (T1070.001 -> T1685.005), never a typed mapping.

    python devtools/knowledge/apply_step_searches.py <authoring.yaml>
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import yaml

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(HERE))

from compile_skills import SKILLS_DIR, _read, _write  # noqa: E402

_AUTHORED = ("kind", "search", "aggregate", "procedure_reason")
_DROPPED = ("es", "es_aggs", "es_dropped", "es_text_only_reason", "es_authored_reason")


def _current_ids(ids: list[Any]) -> list[str]:
    from nexus.knowledge.attack_method import current_technique

    return list(dict.fromkeys(current_technique(str(i)) or str(i) for i in ids))


def apply_analytics(specs: dict[str, Any], new: list[dict[str, Any]]) -> list[str]:
    """IC-7: the same for the behavioural analytics (`__analytics__` by id; `__new_analytics__` appended)."""
    from compile_skills import ANALYTICS

    data, header = _read(ANALYTICS)
    packs = [a for a in data.get("packs") or [] if isinstance(a, dict)]
    by_id = {str(a.get("id")): a for a in packs}
    log: list[str] = []
    for item in new or []:
        ident = str(item.get("id") or "")
        if ident and ident not in by_id:
            data.setdefault("packs", []).append(dict(item))
            by_id[ident] = data["packs"][-1]
            log.append(f"analytic {ident}: added")
    for ident, spec in (specs or {}).items():
        item = by_id.get(ident)
        if item is None:
            raise SystemExit(f"no analytic {ident!r}")
        for key in _DROPPED + ("search",):
            item.pop(key, None)
        for key in ("search", "name", "rationale"):
            if key in spec:
                item[key] = spec[key]
        log.append(f"analytic {ident}: search")
    for item in data.get("packs") or []:
        if isinstance(item, dict) and item.get("techniques"):
            item["techniques"] = _current_ids(item["techniques"])
    _write(ANALYTICS, data, header)
    return log


def apply(authoring: dict[str, Any]) -> list[str]:
    authoring = dict(authoring)
    analytic_log = apply_analytics(authoring.pop("__analytics__", {}), authoring.pop("__new_analytics__", []))
    by_id: dict[str, Path] = {}
    for path in sorted(SKILLS_DIR.glob("*.yaml")):
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        by_id[str(doc.get("skill") or path.stem)] = path
    log: list[str] = []
    for skill_id, steps in authoring.items():
        path = by_id.get(skill_id)
        if path is None:
            raise SystemExit(f"no skill {skill_id!r}")
        data, header = _read(path)
        names = {str(s.get("name")): s for s in data.get("steps") or [] if isinstance(s, dict)}
        for name, spec in (steps or {}).items():
            step = names.get(name)
            if step is None:
                raise SystemExit(f"{skill_id}: no step {name!r}")
            for key in _AUTHORED + _DROPPED:
                step.pop(key, None)
            kind = str(spec.get("kind") or "search")
            if kind != "search":
                step["kind"] = kind
            for key in ("search", "aggregate", "procedure_reason"):
                if key in spec:
                    step[key] = spec[key]
            log.append(f"{skill_id}/{name}: {kind}")
        trig = data.get("trigger") or {}
        if trig.get("techniques"):
            trig["techniques"] = _current_ids(trig["techniques"])
        if data.get("mitre"):
            data["mitre"] = _current_ids(data["mitre"])
        _write(path, data, header)
    return analytic_log + log


def main(argv: list[str]) -> int:
    authoring = yaml.safe_load(Path(argv[1]).read_text(encoding="utf-8")) or {}
    for line in apply(authoring):
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
