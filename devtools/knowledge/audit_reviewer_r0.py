"""The reviewer's own R0'' check, run by me: 10 profile entries against raw tool output.

WO-KM1: "Reviewer check at R0: 10 profile entries are spot-checked against the raw
tool output, and 5 map entries against the pinned source."

I have asserted the profile's contents a great deal and verified it against the index,
but never against the RAW TOOL OUTPUT - which is the one source that cannot be
produced by the same code path. So this reaches past the profile, to the operator's
actual staged files, and re-derives each entry independently.

A profile entry is right when, for that (family, column): the count of non-empty values
in the raw staged output equals the profile's `filled`, and every stored sample appears
verbatim in that output. Anything else is a fabrication or a lossy projection.
"""
from __future__ import annotations

import csv
import json
import random
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

PROFILE = REPO / "Evidence-files" / "ES-Mapping" / "es_mappings" / "_population.json"
CORPUS = REPO / "Evidence-files" / "ES-Mapping" / "_population"
STAGED = json.loads((CORPUS / "_staged.json").read_text(encoding="utf-8")) if \
    (CORPUS / "_staged.json").is_file() else {"families": {}}


def raw_rows(family: str) -> list[dict[str, str]]:
    """Every row of the raw staged output for a family, as the tool wrote it."""
    out: list[dict[str, str]] = []
    for rel in STAGED.get("families", {}).get(family, []):
        p = Path(rel)
        if not p.is_file() or p.suffix.lower() != ".csv":
            continue
        with p.open(encoding="utf-8-sig", errors="replace", newline="") as fh:
            out.extend(dict(r) for r in csv.DictReader(fh))
    return out


def check_entry(family: str, column: str, meta: dict) -> tuple[bool, str]:
    rows = raw_rows(family)
    if not rows:
        return False, "no raw csv rows for this family"
    # A family can stage SEVERAL csv files with DIFFERENT schemas - suzaku stages
    # AuditLog_*.csv (4 columns) and UnifiedAuditLog_SRL.csv (7 columns). Looking for
    # the column in rows[0]'s header alone would report a column that is present in the
    # second file as missing, which is a defect in THIS CHECKER, not the profile.
    headers = list(rows[0] or {})
    for r in rows[1:]:
        for h in r:
            if h not in headers:
                headers.append(h)
    actual = next((h for h in headers if h.lower() == column.lower()), None)
    if actual is None:
        return False, f"the raw output has no column like {column!r}"
    n_filled = sum(1 for r in rows if (r.get(actual) or "").strip())
    if n_filled != int(meta.get("filled") or 0):
        return False, (f"filled={meta.get('filled')} but the raw output has "
                       f"{n_filled} non-empty {actual!r} values")
    # every sample must be present verbatim in the raw output. `_sanitize` truncates a
    # sample at 120 chars with a trailing "...", so a sample is a PREFIX of the raw
    # value, not necessarily equal to it. Demanding containment would report correct
    # samples as lost - which is what this check did on `suzaku/AuditData`, whose raw
    # values are 1,453 characters and whose samples are the 120-char prefix.
    blob = "\n".join((r.get(actual) or "") for r in rows)
    for s in (meta.get("samples") or []):
        if s == "<redacted-path>":
            continue  # the profile redacts machine paths; provenance, not evidence
        if s.endswith("..."):
            s = s[:-3]
        if s not in blob:
            # the trailing "..." is the only permitted normalisation
            return False, f"sample {s[:40]!r} is NOT in the raw output"
    return True, f"{n_filled} filled, {len(meta.get('samples') or [])} samples verified"


def main() -> int:
    prof = json.loads(PROFILE.read_text(encoding="utf-8"))
    fams = prof.get("families") or {}

    # Candidate entries: a family WITH raw csv rows, a column with a non-trivial fill
    # count. Families whose evidence is only JSON/parsed text are excluded here - this
    # check needs the tool's own CSV to compare against.
    candidates: list[tuple[str, str, dict]] = []
    for fam, body in fams.items():
        if not raw_rows(fam):
            continue
        for col, meta in (body.get("columns") or {}).items():
            if int((meta or {}).get("filled") or 0) >= 3 and meta.get("samples"):
                candidates.append((fam, col, meta))
    rng = random.Random(20261006)
    sample = rng.sample(candidates, min(10, len(candidates)))

    print(f"  eligible entries: {len(candidates)}  sampling 10")
    ok = True
    for fam, col, meta in sample:
        good, why = check_entry(fam, col, meta)
        ok = ok and good
        print(f"  {'OK ' if good else 'BAD'} {fam:14s} {col:22s} {why}")
    print()
    print("  10 profile entries verified against raw tool output:", ok)
    return 0 if ok else 1

if __name__ == "__main__":
    raise SystemExit(main())
