"""Derive an ES-Mapping catalog entry (`Evidence-files/ES-Mapping/es_mappings/<family>.yaml`) from a real tool output.

The catalog is the observed tool-run record that `scripts/build_field_registry.py` builds the field registry from. An
entry is derived here from the CSV a tool wrote on the catalog's staged evidence, never typed: each column's type is
read from its values (every non-empty value an integer -> long, a timestamp -> date, else keyword), and its example is
the first non-empty value. Then append the run to `RUNS.md` and rebuild the registry.

    python devtools/knowledge/derive_es_mapping.py --csv <output.csv> --family <family> --tool <Tool> \
        --evidence <evidence path, relative to ES-Mapping> --notes "<what it is>" [--rows 200000] --out <yaml>
"""
from __future__ import annotations

import argparse
import csv
import re
import sys
from datetime import date
from pathlib import Path

_INT = re.compile(r"-?\d+")
_DATE = re.compile(r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:?\d{2})?")


def derive(csv_path: Path, rows: int) -> list[tuple[str, str, str]]:
    csv.field_size_limit(sys.maxsize)
    with csv_path.open(encoding="utf-8-sig", errors="replace", newline="") as fh:
        reader = csv.reader(fh)
        header = next(reader)
        kinds: list[set[str]] = [set() for _ in header]
        examples = [""] * len(header)
        for n, row in enumerate(reader):
            if n >= rows:
                break
            for i, value in enumerate(row[: len(header)]):
                if value == "":
                    continue
                if not examples[i]:
                    examples[i] = value
                kinds[i].add("long" if _INT.fullmatch(value) else "date" if _DATE.fullmatch(value) else "keyword")
    out = []
    for name, seen, example in zip(header, kinds, examples, strict=True):
        es_type = next(iter(seen)) if len(seen) == 1 else "keyword"
        out.append((name, es_type, example))
    return out


def _quote(text: str) -> str:
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"')[:200] + '"'


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", required=True, type=Path)
    ap.add_argument("--family", required=True)
    ap.add_argument("--tool", required=True)
    ap.add_argument("--evidence", required=True)
    ap.add_argument("--notes", default="")
    ap.add_argument("--rows", type=int, default=200_000)
    ap.add_argument("--out", required=True, type=Path)
    args = ap.parse_args()
    fields = derive(args.csv, args.rows)
    lines = [
        f"family: {args.family}",
        f"tool: {args.tool}",
        f"evidence: {args.evidence}",
        f"output: {args.csv.resolve()}",
        f"validated: true   # derived {date.today().isoformat()} by devtools/knowledge/derive_es_mapping.py",
        f"notes: {args.notes}",
        "fields:",
    ]
    for name, es_type, example in fields:
        lines += [f"  - name: {name}", f"    es_type: {es_type}", f"    example: {_quote(example)}"]
    args.out.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    print(f"{len(fields)} fields -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
