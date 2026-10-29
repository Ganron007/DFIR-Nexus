"""Core family-registry contract: kinds are directional, aliases are unambiguous."""
import pytest

from nexus.knowledge.family_registry import FamilyRegistry


def test_kind_matching_does_not_make_distinct_producers_equivalent():
    registry = FamilyRegistry({"families": {
        "evtxecmd": {"aliases": [], "kinds": ["evtx"]},
        "memprocfs": {"aliases": [], "kinds": ["evtx", "memory"]},
        "vol": {"aliases": ["volatility3"], "kinds": ["memory"]},
    }})
    assert registry.intersect({"memprocfs"}, {"evtx"}) == {"evtx"}
    assert registry.intersect({"evtxecmd"}, {"evtx"}) == {"evtx"}
    assert not registry.intersect({"evtxecmd"}, {"memory"})
    assert not registry.intersect({"evtxecmd"}, {"memprocfs"})
    assert registry.intersect({"volatility3"}, {"vol"}) == {"vol"}
    assert registry.producers_for("evtx") == {"evtxecmd", "memprocfs"}


def test_duplicate_aliases_fail_instead_of_silently_reassigning_a_family():
    with pytest.raises(ValueError, match="belongs to both"):
        FamilyRegistry({"families": {"first": {"aliases": ["shared"]},
                                     "second": {"aliases": ["shared"]}}})


def test_kind_selector_can_share_a_name_with_a_producer():
    registry = FamilyRegistry({"families": {
        "evtx": {"kinds": ["evtx"]},
        "memprocfs": {"kinds": ["evtx", "memory"]},
    }})
    assert registry.intersect({"memprocfs"}, {"evtx"}) == {"evtx"}
    assert not registry.intersect({"evtx"}, {"memory"})
    assert registry.producers_for("evtx") == {"evtx", "memprocfs"}


def test_duplicate_normalized_family_names_are_rejected():
    with pytest.raises(ValueError, match="duplicate family"):
        FamilyRegistry({"families": {"Example": {}, "example": {}}})
