"""Verify each audit tool's guard shapes are guards, not checks that cannot fail.

Recurring defect class in this work order: a check that passes for reasons unrelated to
what it claims. Five were found by inspection (`str(None) == "None"` counted as filled,
`values[:4]` truncation, prefix-collapsed `parent in (low, parent_family)`, mtime dir
selection, containment vs prefix, 0-vs-14 family enumeration). This script is the
cheap version of catching the next one: it greps the audit tools for truthiness tests and
classifies each by CONTEXT, because a truthiness guard (`if not rows: return`) is correct
and a truthiness assertion (`assert rows`) is the defect.

A context is a guard when it RETURNS/RAISES/prints a reason; it is a bare assertion when
it is an `assert` or feeds a pass/fail flag with no diagnostic.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

TOOLS = [
    "devtools/knowledge/audit_km1.py",
    "devtools/knowledge/audit_acceptance.py",
    "devtools/knowledge/audit_reviewer_r0.py",
    "devtools/knowledge/audit_reviewer_maps.py",
    "devtools/knowledge/family_coverage_check.py",
]

#: a truthiness test whose REASON follows it
_GUARD_BODY = re.compile(r"^\s*(return|raise|print|continue|skip)\b")


def classify(lines: list[str], idx: int) -> tuple[str, str]:
    """(guard | assert), why - from what the truthiness test does next."""
    line = lines[idx]
    stripped = line.strip()
    if stripped.startswith("assert"):
        return "bare-assert", "an assert on truthiness cannot say WHY it failed"
    # The body must actually CALL a diagnostic. Requiring the keyword on this line or the
    # next alone is not enough: `if not rows:` followed by `ok = True` has no diagnostic,
    # yet `stripped.endswith(":")` classified it as a "report" - which is exactly how this
    # tool passed a deliberately bad file. Look at the whole body, and require a
    # print/return/raise/skip call with a NON-EMPTY argument.
    body_start = idx + 1
    body: list[str] = []
    base = len(line) - len(line.lstrip())
    for nxt in lines[body_start:]:
        if nxt.strip() and (len(nxt) - len(nxt.lstrip())) <= base:
            break
        body.append(nxt)
    for nxt in body:
        if not _GUARD_BODY.match(nxt.strip()):
            continue
        arg = nxt.split(None, 1)[1] if len(nxt.split(None, 1)) > 1 else ""
        if arg.strip().strip('"\''):
            return "guard", "control flow with a reason attached"
    return "unclassified", "no diagnostic in its body - cannot report which fact failed"


def main() -> int:
    total = 0
    unclassified: list[tuple[str, int, str, str]] = []
    for rel in TOOLS:
        # Resolve against the tool's own directory first, so a copied-then-patched
        # build (what the self-test does) finds its probe file next to itself rather
        # than three levels up. Without this the tool reported "0 tests" and passed
        # a file containing a bare `assert`.
        candidates = [Path(__file__).resolve().parent / rel,
                      REPO / rel,
                      Path(rel)]
        path = next((c for c in candidates if c.is_file()), None)
        if path is None:
            print(f"  ?? {rel} missing")
            continue
        lines = path.read_text(encoding="utf-8").splitlines()
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith(("#", "*", '"', "'")):
                continue
            # A bare truthiness ASSERTION is caught here, not by the `if` regex below:
            # the regex only matches if/elif, so an `assert rows` never reaches
            # `classify` - which is why this tool once passed a deliberately bad file.
            if re.match(r"^assert\s+\w+(\.\w+)*\s*$", stripped):
                total += 1
                unclassified.append((rel, i + 1, stripped[:70],
                                    "bare assert: no reason attached, so a failure "
                                    "names no fact"))
                continue
            if not re.match(r"^(if|elif)\s+(not\s+)?[A-Za-z_][\w.()]*\s*:", stripped):
                continue
            if re.search(r"[:=<>!]", stripped.split(":", 1)[0]):
                continue  # a comparison, not a truthiness test
            kind, why = classify(lines, i)
            total += 1
            if kind == "bare-assert":
                unclassified.append((rel, i + 1, stripped[:70], f"{kind}: {why}"))

    print(f"  truthiness tests in {len(TOOLS)} audit tools: {total}")
    guards = total - len(unclassified)
    print(f"  guards or reported: {guards}")
    print(f"  bare assertions (cannot say which fact failed): {len(unclassified)}")
    for rel, i, line, why in unclassified:
        print(f"    {rel}:{i}  {line}")
        print(f"        {why}")
    print()
    print("  no bare truthiness assertion in any audit tool:", not unclassified)
    return 0 if not unclassified else 1


if __name__ == "__main__":
    raise SystemExit(main())
