"""The reviewer's other R0'' check, done properly: 5 map entries against the PINNED source.

The .map files are YAML whose `PropertyValue` and `Value` lines are quoted strings, so
`\\"` resolves to `"` and `\\\\` to `\\`. Parsing them with line splitting leaves the
escapes in and reports a mismatch against a correct import - which is what a first
version of this checker did. Comparing against anything other than what the importer
parses proves nothing about the import.

Two further lessons are baked in, both found by running this:
* a check that cannot find its source must FAIL, not pass vacuously;
* a check that finds no mapping columns in a file must FAIL too, for the same reason.
"""
from __future__ import annotations

import os
import random
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

MAPS = REPO / "src" / "nexus" / "data" / "schema" / "evtxecmd_maps.yaml"

#: The generic columns the importer keeps. `Username`/`UserName` both normalise to the
#: latter - the source spells it BOTH ways, and the importer records a
#: `GENERIC_ALIASES` map for it. A column outside this set is deliberately NOT
#: imported, so a source property outside it is not a defect.
GENERIC = {"PayloadData1", "PayloadData2", "PayloadData3", "PayloadData4",
           "PayloadData5", "PayloadData6", "ExecutableInfo", "UserName", "RemoteHost"}
#: normalise the importer's own alias, so this checker compares the same names.
GENERIC_ALIASES = {"Username": "UserName"}


def _find_source() -> Path | None:
    """The pinned EZTools/evtx clone, located EXACTLY as the importer locates it.

    Same env var, same default (TEMP/kl2b-snapshots), same nested path. A checker that
    guesses its own paths reports "source not found" while the source is right there -
    which is what this one did when first written against repo-relative paths.
    """
    root = Path(os.environ.get("NEXUS_KL2B_SNAPSHOTS")
                or (Path(os.environ.get("TEMP", "/tmp")) / "kl2b-snapshots"))
    cand = root / "evtx" / "evtx"
    return cand if (cand / "Maps").is_dir() else None


def _parse_map_file(path: Path) -> dict[str, dict]:
    """column -> {template, sources:[{name, xpath}]}, as YAML resolves the file."""
    import yaml

    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8", errors="replace")) or {}
    except Exception:
        return {}
    out: dict[str, dict] = {}
    for m in (doc.get("Maps") or []):
        if not isinstance(m, dict):
            continue
        prop = GENERIC_ALIASES.get(str(m.get("Property") or "").strip(),
                                   str(m.get("Property") or "").strip())
        template = str(m.get("PropertyValue") or "")
        if not prop or not template:
            continue
        sources = [{"name": str(v.get("Name") or ""), "xpath": str(v.get("Value") or "")}
                   for v in (m.get("Values") or []) if isinstance(v, dict)]
        out[prop] = {"template": template, "sources": sources}
    return out


def compare(entry: dict, truth: dict[str, dict]) -> list[str]:
    """Every way an imported entry disagrees with its pinned file."""
    problems: list[str] = []
    ours = entry.get("columns") or {}
    for col, meta in ours.items():
        t = str((meta or {}).get("template") or "")
        if col not in truth:
            problems.append(f"{col}: we have a template, the source has no such property")
            continue
        if t != truth[col]["template"]:
            problems.append(f"{col}: ours={t[:44]!r} source={truth[col]['template'][:44]!r}")
            continue
        a = (meta or {}).get("sources") or []
        b = truth[col]["sources"]
        if len(a) != len(b):
            problems.append(f"{col}: {len(a)} sources recorded, the source names {len(b)}")
            continue
        # strict=True: the counts were just compared, so a silently-short zip would
        # hide exactly the truncation this check exists to catch.
        for x, y in zip(a, b, strict=True):
            if (x.get("xpath") or "") != (y["xpath"] or ""):
                problems.append(f"{col}.xpath: ours={(x.get('xpath') or '')[:36]!r} "
                                f"source={y['xpath'][:36]!r}")
    for col in truth:
        if col not in ours:
            problems.append(f"{col}: present in the source, missing from ours")
    return problems


def main() -> int:
    import yaml

    if not MAPS.is_file():
        print(f"  maps file missing: {MAPS.relative_to(REPO)}")
        return 2
    data = yaml.safe_load(MAPS.read_text(encoding="utf-8")) or {}
    recorded = str((data.get("source") if isinstance(data.get("source"), dict) else {})
                   .get("commit") or data.get("source_version") or "")
    src = _find_source()
    if src is None:
        print("  BAD the pinned EZTools/evtx clone is not present; a check that cannot "
              "run is not a passing check")
        return 2
    head = subprocess.run(["git", "-C", str(src), "rev-parse", "HEAD"],
                          capture_output=True, text=True).stdout.strip()
    print(f"  recorded commit: {recorded}")
    print(f"  source at      : {src.name} ({head[:12]})")
    same = recorded.startswith(head) or head.startswith(recorded)
    print(f"  {'OK ' if same else 'BAD'} the clone is at the pinned commit: {same}")
    if not same:
        return 1

    packs = [p for p in (data.get("packs") or []) if p.get("source_key")]
    rng = random.Random(20261006)
    sample = rng.sample(packs, 5)
    ok = True
    for entry in sample:
        key = str(entry.get("source_key"))
        path = src / "Maps" / key
        if not path.is_file():
            print(f"  BAD {key}: not in the pinned source")
            ok = False
            continue
        truth = _parse_map_file(path)
        if not truth:
            print(f"  BAD {key}: the pinned file states no columns, so nothing can be "
                  f"verified - the check would be vacuous")
            ok = False
            continue
        problems = compare(entry, truth)
        if problems:
            ok = False
            print(f"  BAD {key}")
            for p in problems[:3]:
                print(f"        {p}")
        else:
            print(f"  OK  {key}: {len(entry.get('columns') or {})} columns, templates + "
                  f"XPaths match")
    print()
    print("  5 map entries verified against the pinned source:", ok)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
