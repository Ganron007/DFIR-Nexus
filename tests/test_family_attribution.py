"""Family attribution: a hint that is a prefix of another must not shadow it.

`_family()` returns the FIRST hint that appears in the relative path, so
`_FAMILY_HINTS` order is part of the contract. `srum` preceded `srumecmd` and `lecmd`
preceded `sqlecmd`, which meant:

    extractions/srumecmd/srumecmd-sample.csv  -> 'srum'    (not srumecmd)
    extractions/sqlecmd/sqlecmd-sample.log    -> 'lecmd'   (not sqlecmd)

so SrumECmd's and SqLiteCmd's own evidence was indexed as a different family. The
population profile could therefore never measure them, and KM1 item 5 recorded them as
absent while a sample sat right there.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from nexus.langgraph.query_pack import _family  # noqa: E402

#: `_family()` matches hint text against the path RELATIVE to the case root, so the
#: tests use a real root and absolute paths under it.
CASE = REPO / "_case_root_under_test"

#: (relative path, the family the index must derive)
ATTRIBUTIONS = {
    "extractions/sqlecmd/sqlecmd-sample.log": "sqlecmd",
    "extractions/sqlecmd/10-messages.json": "sqlecmd",
    "extractions/lecmd/10-messages.json": "lecmd",
    "extractions/srumecmd/srumecmd-sample.csv": "srumecmd",
    "extractions/srum/srum-sample.csv": "srum",
    "extractions/pecmd/prefetch-sample.csv": "pecmd",
    "extractions/hayabusa/evtx-timeline-sample.csv": "hayabusa",
    "extractions/evtxecmd/2-Application.json": "evtxecmd",
    "extractions/mftecmd/mft.csv": "mftecmd",
    "extractions/appcompat/appcompat.csv": "appcompat",
    "extractions/recmd/recmd-SYSTEM.csv": "recmd",
    "extractions/vol/sift-vol/vol-pslist.txt": "vol",
}


@pytest.mark.parametrize("rel,want", sorted(ATTRIBUTIONS.items()))
def test_a_family_is_attributed_to_itself(rel, want):
    """A family's own evidence is indexed as that family, not as an earlier prefix."""
    got = _family(CASE / rel, CASE)
    assert got == want, f"{rel} derived as {got!r}, expected {want!r}"


def test_prefix_hints_are_ordered_after_the_family_they_prefix():
    """`srumecmd`/`sqlecmd` are checked before `srum`/`lecmd`."""
    from nexus.langgraph.query_pack import _FAMILY_HINTS

    order = list(_FAMILY_HINTS)
    for shorter, longer in (("srum", "srumecmd"), ("lecmd", "sqlecmd")):
        if shorter in order and longer in order:
            assert order.index(longer) < order.index(shorter), (
                f"{longer!r} must precede {shorter!r} in _FAMILY_HINTS, or every path "
                f"containing {longer!r} is attributed to {shorter!r}")
