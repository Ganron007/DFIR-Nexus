"""Prune dummy cases from the cases root.

Test runs and pipeline retries create throwaway cases (``CASE-<hex>``,
``INC-<timestamp>``, ``TEST-*``). This script removes them; real cases
(anything not matching the dummy patterns, or names passed via --keep)
are never touched.

Deletion goes through ``nexus.case.cleanup.delete_case_data`` so a pruned case
is *actually* gone: folder (read-only flags cleared), DB rows and ES indexes.
The first version used ``shutil.rmtree(..., ignore_errors=True)``, which
swallowed read-only failures and left ES indexes and DB rows behind while
reporting success (reviewer, R1 / WO-R1F step 0b).

Usage:
    python scripts/prune_cases.py            # dry-run: list what would go
    python scripts/prune_cases.py --apply    # actually delete
    python scripts/prune_cases.py --keep CASE-UI-DEMO --apply
"""

from __future__ import annotations

import argparse
import re
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


def has_real_data(case_dir: Path) -> bool:
    """True when a case holds evidence or findings, so it is never a dummy.

    A NAME CANNOT TELL A TEST CASE FROM A REAL ONE. `CASE-D6B93BF1` — the SC1
    development case, whose evidence is a 15.6 GB triage volume — matches
    ``^CASE-[0-9A-Fa-f]{8}$`` exactly like a throwaway hex id, so the pattern
    alone made `--apply` willing to delete it. The signal that actually
    distinguishes them is what the case holds: a test case has no registered
    evidence and no findings.

    Read-only and cheap: two small JSON files, and a parse failure is treated as
    "has data" (fail safe — never delete on doubt).
    """
    import json

    case_dir = Path(case_dir)
    for filename in ("evidence.json", "findings.json"):
        path = case_dir / filename
        if not path.is_file():
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            return True
        rows = payload if isinstance(payload, list) else (
            payload.get("findings") if isinstance(payload, dict) else None
        )
        if isinstance(rows, list) and rows:
            return True
    return False


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
    candidates = sorted(d for d in root.iterdir() if d.is_dir() and is_dummy(d.name, keep))
    # A name is not proof. A matched case that holds evidence or findings is a
    # real case whatever its id looks like, and is skipped rather than deleted.
    dummies: list[Path] = []
    protected: list[Path] = []
    for d in candidates:
        (protected if has_real_data(d) else dummies).append(d)

    for d in protected:
        print(f"PROTECTED (has evidence/findings)  {d.name}")

    if not dummies:
        print(f"No dummy cases under {root}")
        return 0

    if not args.apply:
        for d in dummies:
            print(f"WOULD DELETE  {d.name}")
        print(f"\n{len(dummies)} dummy case(s) found (dry-run) under {root}")
        print("Re-run with --apply to delete.")
        return 0

    from nexus.case.cleanup import delete_case_data

    failed = 0
    for d in dummies:
        res = delete_case_data(d.name, cases_root=root)
        # Every part is printed; a partial deletion is not a deletion.
        for name, good, detail in res.parts:
            mark = "OK  " if good else "FAIL"
            print(f"{mark} {d.name}: {name}: {detail}")
        if not res.ok:
            failed += 1

    print(
        f"\n{len(dummies) - failed} of {len(dummies)} dummy case(s) fully deleted "
        f"under {root}; {failed} incomplete."
    )
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
