"""WO-R0F item 4: the translated Sigma pack is gone; the hand pack is the only pack.

Sigma detection is what Hayabusa and Chainsaw do in the lane (indexed, and turned
into leads by `analysis/rule_leads.py`). Our own translation re-implemented
detection, against the product principle. The `detection/` Sigma rule *search* (a
reference lookup) stays.
"""
from __future__ import annotations

from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "src"


def test_the_loader_returns_the_hand_pack_only() -> None:
    import sys
    sys.path.insert(0, str(SRC))
    from nexus.analysis.behavioural_analytics import PACK_PATHS, analytics

    names = [Path(p).name for p in PACK_PATHS]
    assert names == ["behavioral_analytics.yaml"], names
    items = analytics()
    assert items, "the hand pack loaded nothing"
    # Nothing from the deleted Sigma translation survives.
    assert all("sigma" not in str(i.get("citation") or "").lower() for i in items), \
        "an analytic still cites Sigma"


def test_the_sigma_pack_and_its_generators_are_deleted() -> None:
    gone = [
        SRC / "nexus" / "data" / "knowledge" / "needles" / "sigma_analytics.yaml",
        REPO / "devtools" / "knowledge" / "sigma_import.py",
        REPO / "devtools" / "knowledge" / "sigma_family_fields.py",
        REPO / "devtools" / "knowledge" / "sigma_population_check.py",
        REPO / "devtools" / "knowledge" / "sigma-population.json",
    ]
    for p in gone:
        assert not p.exists(), f"still present: {p}"


def test_no_shipped_file_references_the_sigma_pack() -> None:
    patterns = ("sigma_analytics", "sigma_import", "sigma_family_fields",
                "sigma_population_check")
    offenders = []
    this_file = Path(__file__).resolve()
    for base in (SRC, REPO / "tests", REPO / "scripts", REPO / "devtools"):
        for p in base.rglob("*.py"):
            if "__pycache__" in p.parts or p.resolve() == this_file:
                continue
            text = p.read_text(encoding="utf-8", errors="replace")
            for pat in patterns:
                # a comment recording the removal is allowed; an import/call is not
                for line in text.splitlines():
                    if pat in line and not line.lstrip().startswith("#"):
                        offenders.append(f"{p.relative_to(REPO)}: {line.strip()[:70]}")
    assert not offenders, "references to the removed Sigma pack:\n  " + "\n  ".join(offenders)
