"""Prune dummy cases from the cases root.

Test runs and pipeline retries create throwaway cases (``CASE-<hex>``,
``INC-<timestamp>``, ``TEST-*``). This script removes them; real cases
(anything not matching the dummy patterns, or names passed via --keep)
are never touched.

Usage:
    python scripts/prune_cases.py            # dry-run: list what would go
    python scripts/prune_cases.py --apply    # actually delete
    python scripts/prune_cases.py --keep CASE-UI-DEMO --apply
"""

from __future__ import annotations

import argparse
import re
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

DUMMY_PATTERNS = (
    re.compile(r"^CASE-[0-9A-Fa-f]{8}$"),      # auto-hex from tests
    re.compile(r"^INC-\d{14}$"),                # pipeline auto-created
    re.compile(r"^TEST-", re.I),                # explicit test cases
)


def is_dummy(name: str, keep: set[str]) -> bool:
    if name in keep:
        return False
    return any(p.match(name) for p in DUMMY_PATTERNS)


def main() -> int:
    from nexus.config import settings

    ap = argparse.ArgumentParser(description="Prune dummy cases (dry-run by default)")
    ap.add_argument("--apply", action="store_true", help="Actually delete (default: dry-run)")
    ap.add_argument("--keep", action="append", default=[], help="Case ID to keep (repeatable)")
    ap.add_argument("--root", default="", help="Override cases root")
    args = ap.parse_args()

    root = Path(args.root) if args.root else settings.cases_root
    if not root.is_dir():
        print(f"Cases root not found: {root}")
        return 0

    keep = set(args.keep)
    dummies = sorted(d for d in root.iterdir() if d.is_dir() and is_dummy(d.name, keep))

    if not dummies:
        print(f"No dummy cases under {root}")
        return 0

    for d in dummies:
        print(f"{'DELETE' if args.apply else 'WOULD DELETE'}  {d.name}")
        if args.apply:
            shutil.rmtree(d, ignore_errors=True)

    print(f"\n{len(dummies)} dummy case(s) {'deleted' if args.apply else 'found (dry-run)'} under {root}")
    if not args.apply:
        print("Re-run with --apply to delete.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
