"""Fail when a built portal chunk grows past its budget (WO-U9).

Run after `npm run build` in frontend/. A missing dist/ is a skip with a
message, not a pass: the budget only applies to a build that exists.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "frontend" / "dist" / "assets"
# The cockpit is one SPA. This ceiling is the current built size plus headroom
# so a new eager page fails the check instead of growing quietly.
MAX_BYTES = 1_200_000


def main() -> int:
    if not DIST.is_dir():
        print("frontend bundle budget: dist/assets is missing. Run npm run build.", file=sys.stderr)
        return 1
    largest = max(DIST.glob("*.js"), key=lambda path: path.stat().st_size, default=None)
    if largest is None:
        print("frontend bundle budget: no JS chunks.", file=sys.stderr)
        return 1
    size = largest.stat().st_size
    print(f"{largest.name} {size} bytes (ceiling {MAX_BYTES})")
    if size > MAX_BYTES:
        print("frontend bundle budget exceeded", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
