"""Group a case's unprocessed gate items by tool, file kind and reason, with example paths (Part 10, P2).

Where `gate_unread.py` lists every item, this answers "what kinds of thing were not read": a large collection can
leave thousands of rows, most of a few kinds.

    python devtools/runbook/gate_breakdown.py CASE-X [--examples 2]
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))


def _kind(path: str) -> str:
    """A file's kind: its extension, or its name when it has none (Zimmerman-style hives, `$J`, `.expanded.json`)."""
    name = re.split(r"[\\/]", path)[-1]
    if name.startswith(".") or "." not in name:
        return name
    return "*." + name.rsplit(".", 1)[-1].lower()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("case")
    ap.add_argument("--examples", type=int, default=2)
    args = ap.parse_args()
    from nexus.config import settings

    folder = Path(args.case) if Path(args.case).is_dir() else Path(settings.cases_root) / args.case
    gate = json.loads((folder / "analysis" / "lane_gate.json").read_text(encoding="utf-8"))
    rows = gate.get("unprocessed") or []
    groups: Counter = Counter()
    examples: dict[tuple, list[str]] = defaultdict(list)
    for r in rows:
        purpose = str(r.get("purpose") or "")
        path = purpose[len("import "):] if purpose.startswith("import ") else purpose
        reason = re.sub(r"[A-Za-z]:\\\S+|/\S+", "<path>", str(r.get("reason") or ""))[:70]
        key = (str(r.get("tool") or ""), _kind(path), reason)
        groups[key] += 1
        if len(examples[key]) < args.examples:
            examples[key].append(path[-140:])
    print(f"{folder.name}: gate {gate.get('status')}, {len(rows)} unprocessed in {len(groups)} group(s)")
    for (tool, kind, reason), n in groups.most_common():
        print(f"{n:>6}  {tool:22} {kind:24} {reason}")
        for ex in examples[(tool, kind, reason)]:
            print(f"          e.g. {ex}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
