"""Guard a standalone script against writing the operator's real ``~/.nexus``.

The pytest fixtures in ``conftest.py`` redirect every path a test could reach,
but the script suites run **outside** pytest: they import no fixture, so nothing
redirects them. Observed 2026-10-03 (register D25/V9):

- ``tests/test_integration.py`` left the real ``~/.nexus/active_case`` pointing
  at a deleted temp case (``TEST-001``).
- ``tests/functional_audit.py`` appended fixture approvals to the real
  ``~/.nexus/transparency/`` (76 files there match no case in the store).
- ``~/.nexus/chroma.sqlite3`` was touched by the concurrent runs.

Run beside pytest they also tripped its credential tripwire, which covers all of
``~/.nexus`` — a false red for the suite, but a real write to the operator's
store.

Usage, at the very top of a script, **before** importing anything that captures
a path at import time::

    from _nexus_guard import nexus_snapshot, nexus_guard_end

    _before = nexus_snapshot()
    ...  # the script
    nexus_guard_end(_before, "test_integration")

``nexus_guard_end`` exits non-zero when anything under ``~/.nexus`` changed, and
prints exactly what changed — the same ``(size, mtime_ns)`` shape conftest's
credential tripwire uses, so the two agree on what "changed" means.
"""
from __future__ import annotations

import sys
from pathlib import Path

#: The one root the scripts must not write. Mirrors conftest's
#: ``_TRIPWIRE_ROOTS``; conftest additionally watches the repo ``.env``, which a
#: script has no business writing either — kept out here so a legitimate
#: ``.env`` edit by the operator does not fail a script run.
NEXUS_HOME = Path.home() / ".nexus"


def nexus_snapshot() -> dict[str, tuple[int, int]]:
    """``(size, mtime_ns)`` for every file under ``~/.nexus``. Stat only."""
    out: dict[str, tuple[int, int]] = {}
    if not NEXUS_HOME.is_dir():
        return out
    for path in NEXUS_HOME.rglob("*"):
        try:
            if path.is_file():
                st = path.stat()
                out[str(path)] = (st.st_size, st.st_mtime_ns)
        except OSError:
            continue
    return out


def nexus_diff(before: dict[str, tuple[int, int]],
               after: dict[str, tuple[int, int]]) -> list[str]:
    """Human-readable changes, in the shape the pytest tripwire reports."""
    lines = [f"+ created  {p}" for p in sorted(set(after) - set(before))]
    lines += [f"- deleted  {p}" for p in sorted(set(before) - set(after))]
    lines += [
        f"~ modified {p}"
        for p in sorted(set(before) & set(after))
        if before[p] != after[p]
    ]
    return lines


def nexus_guard_end(before: dict[str, tuple[int, int]], label: str) -> None:
    """Fail the script when it wrote the operator's store."""
    lines = nexus_diff(before, nexus_snapshot())
    if not lines:
        print(f"\n[{label}] ~/.nexus untouched")
        return
    print(
        f"\n[{label}] FAIL: this script wrote the operator's real ~/.nexus:\n  "
        + "\n  ".join(lines[:40])
        + (f"\n  ... {len(lines) - 40} more" if len(lines) > 40 else ""),
        file=sys.stderr,
    )
    print(
        "  Redirect the path (NEXUS_ACTIVE_CASE_FILE, "
        "transparency.TRANSPARENCY_DIR, ...) to a temp dir before importing the "
        "module that captures it. See tests/_nexus_guard.py.",
        file=sys.stderr,
    )
    raise SystemExit(1)
