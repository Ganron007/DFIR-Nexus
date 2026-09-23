"""Audit machine-source paths in lane-tool outputs — raw and post-sanitizer.

The parsers write the absolute path of the file they read on the *analysis
host* into their outputs (EvtxECmd ``SourceFile``, RECmd ``HivePath``,
Hindsight ``profile``, Plaso ``filename``, console banners, ...). Derived text
(index, scan, export) is sanitized by ``nexus.langgraph.path_sanitize`` — this
script proves it over a real run corpus:

- default (raw audit): per tool, which column/free-text carries a machine
  marker, how many rows, and one example;
- ``--verify``: apply the production sanitizer and report survivors (exit
  code 1 when any survive, so it can gate a release).

Usage:
    python scripts/audit_machine_paths.py                     # raw table
    python scripts/audit_machine_paths.py --verify            # 0-survivor proof
    python scripts/audit_machine_paths.py --root <dir> --rows 4000
"""

from __future__ import annotations

import argparse
import csv
import io
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from nexus.langgraph.case_index import _row_fields  # noqa: E402
from nexus.langgraph.path_sanitize import (  # noqa: E402
    machine_roots,
    sanitize_machine_paths,
    sanitize_row_text,
)

TEXT_SUFFIX = {".csv", ".txt", ".json", ".jsonl", ".log", ".out"}
DEFAULT_ROOT = Path("Evidence-files") / "ES-Mapping" / "outputs"
# SIFT-side staging/home markers: the run corpus was produced on the SIFT VM,
# so the local machine_roots() (this host) cannot see them.
SIFT_MARKERS = ("nexus-es-mapping", "/home/sansforensics")


def machine_markers(extra: list[str]) -> list[str]:
    markers: set[str] = {prefix for prefix, _ in machine_roots(None) if prefix}
    markers.update(SIFT_MARKERS)
    markers.update(m for m in extra if m)
    return sorted(markers, key=len, reverse=True)


def _hit_columns(text: str, markers: list[str]) -> list[str]:
    low = text.lower()
    return [m for m in markers if m.lower() in low]


def _safe(text: str) -> str:
    return str(text).encode("ascii", "replace").decode("ascii")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root", type=Path, default=DEFAULT_ROOT, help="corpus to scan"
    )
    parser.add_argument("--rows", type=int, default=4000, help="rows/file cap")
    parser.add_argument(
        "--verify",
        action="store_true",
        help="apply the sanitizer and report survivors (exit 1 if any)",
    )
    parser.add_argument("--marker", action="append", default=[], help="extra marker")
    args = parser.parse_args()

    root: Path = args.root
    if not root.is_dir():
        print(f"corpus not found: {root}")
        return 2
    markers = machine_markers(args.marker)

    per_tool: dict[str, Counter] = defaultdict(Counter)
    examples: dict[tuple[str, str], str] = {}
    survivors: Counter = Counter()
    survivor_example: dict[str, str] = {}
    files_scanned = 0
    rows_checked = 0

    def raw_hit(tool: str, column: str, value: str) -> None:
        per_tool[tool][column] += 1
        examples.setdefault((tool, column), value[:120].replace("\n", " "))

    def verify_row(tool: str, cleaned: str) -> None:
        nonlocal rows_checked
        rows_checked += 1
        found = _hit_columns(cleaned, markers)
        if found:
            for marker in found:
                survivors[f"{tool} :: {marker}"] += 1
            survivor_example.setdefault(tool, cleaned[:160].replace("\n", " "))

    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        if path.suffix.lower() not in TEXT_SUFFIX:
            continue
        rel = path.relative_to(root)
        tool = rel.parts[0] if len(rel.parts) > 1 else "(root)"
        files_scanned += 1
        text = path.read_bytes()[:8_000_000].decode("utf-8", errors="replace")
        if text.startswith("\ufeff"):
            text = text[1:]

        if path.suffix.lower() == ".csv":
            reader = csv.reader(io.StringIO(text))
            try:
                header = next(reader, None)
            except csv.Error:
                header = None
            if header and not args.verify:
                for cell in header:
                    for marker in _hit_columns(cell, markers):
                        raw_hit(tool, f"{cell} (header)", marker)
            n = 0
            try:
                for row in reader:
                    n += 1
                    if n > args.rows:
                        break
                    line = ",".join(row)
                    fields = _row_fields(line, header) if header else None
                    if args.verify:
                        verify_row(
                            tool, sanitize_row_text(line, fields, None, family=tool)
                        )
                        continue
                    rows_checked += 1
                    for key, value in (fields or {}).items():
                        if _hit_columns(str(value), markers):
                            raw_hit(tool, str(key), str(value))
            except csv.Error:
                pass  # truncated tail row
        elif path.suffix.lower() in {".json", ".jsonl"}:
            n = 0
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                n += 1
                if n > args.rows:
                    break
                if args.verify:
                    verify_row(tool, sanitize_machine_paths(line, None))
                    continue
                rows_checked += 1
                if _hit_columns(line, markers):
                    raw_hit(tool, "(json line)", line)
        else:
            n = 0
            for line in text.splitlines():
                n += 1
                if n > args.rows:
                    break
                if not line.strip():
                    continue
                if args.verify:
                    verify_row(tool, sanitize_machine_paths(line, None))
                    continue
                rows_checked += 1
                if _hit_columns(line, markers):
                    raw_hit(tool, "(free text line)", line)

    mode = "verify" if args.verify else "raw audit"
    print(f"mode: {mode}   files: {files_scanned}   rows checked: {rows_checked}")
    if args.verify:
        if not survivors:
            print("PASS: no machine marker survives sanitization.")
            return 0
        print(f"SURVIVORS: {sum(survivors.values())}")
        for label, count in survivors.most_common(30):
            print(f"  {_safe(label):70} {count:6}")
        return 1

    for tool in sorted(per_tool):
        total = sum(per_tool[tool].values())
        print(f"== {tool}: {total} hit(s)")
        for column, count in per_tool[tool].most_common(8):
            example = examples.get((tool, column), "")
            print(f"   {_safe(column):46} {count:6}   e.g. {_safe(example)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
