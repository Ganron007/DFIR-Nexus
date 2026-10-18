"""Detection over every text-like file of an evidence tree, and the files whose detection two builds disagree on.

Any change to `nexus.ingest.detect` or an importer's `can_handle` is checked this way before it is committed
(TIER1-WORK-ORDERS Part 10, P6): run `dump` with the current code and with the change, then `diff`. Every file
that changes is named and justified in the commit message.

    python devtools/runbook/detect_sweep.py dump --src <tree>/src --root Evidence-files --out before.tsv
    python devtools/runbook/detect_sweep.py dump --src <worktree>/src --root Evidence-files --out after.tsv
    python devtools/runbook/detect_sweep.py diff before.tsv after.tsv
"""
from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

SUFFIXES = {".csv", ".tsv", ".log", ".txt", ".json", ".jsonl", ".xml", ".gz", ".mfdb", ".xlsx", ""}


def dump(src: str, root: Path, out: Path) -> int:
    sys.path.insert(0, src)
    from nexus.ingest.detect import detect_format  # noqa: PLC0415

    lines = []
    for p in sorted(root.rglob("*")):
        if not p.is_file() or p.suffix.lower() not in SUFFIXES or "_expanded" in p.parts:
            continue
        try:
            if p.stat().st_size == 0:
                continue
            found = detect_format(p)
        except Exception as exc:  # noqa: BLE001 - a crash is a result to compare
            found = f"ERROR {type(exc).__name__}"
        lines.append(f"{p}\t{getattr(found, 'value', found)}")
    out.write_text("\n".join(lines), encoding="utf-8")
    print(f"{len(lines)} file(s) -> {out}")
    return 0


def diff(before: Path, after: Path) -> int:
    def load(path: Path) -> dict[str, str]:
        rows = (line.split("\t", 1) for line in path.read_text(encoding="utf-8").splitlines() if "\t" in line)
        return dict(rows)

    a, b = load(before), load(after)
    changed = [(k, a.get(k), b.get(k)) for k in sorted(set(a) | set(b)) if a.get(k) != b.get(k)]
    print(f"{len(changed)} of {len(b)} file(s) change detection")
    for (old, new), n in Counter((o, n) for _k, o, n in changed).most_common():
        print(f"  {n:>5}  {old} -> {new}")
    for k, old, new in changed[:200]:
        print(f"    {old} -> {new}  {k}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("dump")
    d.add_argument("--src", required=True)
    d.add_argument("--root", required=True, type=Path)
    d.add_argument("--out", required=True, type=Path)
    c = sub.add_parser("diff")
    c.add_argument("before", type=Path)
    c.add_argument("after", type=Path)
    args = ap.parse_args()
    return dump(args.src, args.root, args.out) if args.cmd == "dump" else diff(args.before, args.after)


if __name__ == "__main__":
    raise SystemExit(main())
