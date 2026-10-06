"""Prove audit_tool_hygiene can FAIL - a checker that cannot fail is the defect.

Feed it the exact shape that has cost this work order five times: a truthiness test with
no reason attached. If the tool reports it, the tool works; if it stays green, the tool
is decoration and I should say so rather than claim a passing result.
"""
from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
TOOL = REPO / "devtools" / "knowledge" / "audit_tool_hygiene.py"

GOOD = '''"""good.py - a truthiness test WITH a reason."""


def main() -> int:
    rows = []
    if not rows:
        print("no rows")
        return 1
    return 0
'''

BAD = '''"""bad.py - a bare truthiness ASSERTION: it cannot say which fact failed."""


def main() -> int:
    rows = []
    assert rows
    return 0
'''


def run(candidate: str) -> int:
    """Copy the tool with its TOOLS list pointed at one file, run it, return rc."""
    src = TOOL.read_text(encoding="utf-8")
    patched = src.replace(
        'TOOLS = [',
        f'TOOLS = ["{candidate}"] or [').replace(
        'or [\n    "devtools/',
        'or [').replace(
        'family_coverage_check.py",', 'family_coverage_check.py",')
    # simpler: rewrite the whole list
    import re

    patched = re.sub(
        r"TOOLS = \[.*?\]\n",
        f'TOOLS = ["{candidate}"]\n',
        src, count=1, flags=re.S)
    with tempfile.TemporaryDirectory() as tmp:
        t = Path(tmp) / "tool.py"
        t.write_text(patched, encoding="utf-8")
        r = subprocess.run([sys.executable, str(t)], cwd=str(REPO),
                          capture_output=True, text=True)
        return r.returncode, r.stdout


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        good = Path(tmp) / "good_check.py"
        good.write_text(GOOD, encoding="utf-8")
        bad = Path(tmp) / "bad_check.py"
        bad.write_text(BAD, encoding="utf-8")

        for label, path, expect in (("good (reason attached)", good, 0),
                                    ("bad (no reason)", bad, 1)):
            rc, out = run(str(path).replace("\\", "/"))
            verdict = "OK " if rc == expect else "BAD"
            tail = [l for l in out.strip().splitlines() if l.strip()]
            print(f"  {verdict} {label}: rc={rc} expected={expect}")
            if tail:
                print(f"        {tail[-1][:88]}")

    print()
    print("  the hygiene tool fails when it should:", True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
