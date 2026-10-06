"""WO-R0F item 1b(6): no shipped/dev tool references the removed scaffold.

`stage_ingest_columns.py` was the fabricated-data generator; it now lives only in
`tests/fixtures/` and must never be read by a generator of shipped data. No file
under `devtools/` or `scripts/` may reference it (or the deleted
`stage_ingest_for_profile.py`, or `tests/fixtures`) — that was the dead scaffold
path the reviewer flagged.
"""
from __future__ import annotations

from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
FORBIDDEN = ("stage_ingest_columns", "stage_ingest_for_profile", "tests/fixtures")


def _scan(directory: Path) -> list[str]:
    hits: list[str] = []
    for p in sorted(directory.rglob("*.py")):
        if "__pycache__" in p.parts:
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for token in FORBIDDEN:
            if token in text:
                hits.append(f"{p.relative_to(REPO)} references {token!r}")
    return hits


def test_no_devtools_or_scripts_reference_the_scaffold() -> None:
    hits = _scan(REPO / "devtools") + _scan(REPO / "scripts")
    assert not hits, "dead scaffold reference(s):\n  " + "\n  ".join(hits)


def test_the_scaffold_lives_only_in_fixtures() -> None:
    # The generator may exist as a fixture, but nowhere under src/ (shipped).
    shipped = _scan(REPO / "src")
    assert not shipped, "shipped code references the fixture:\n  " + "\n  ".join(shipped)
