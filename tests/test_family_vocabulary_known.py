"""TA-5.1: every family name the knowledge declares is a name the one family registry knows.

`family_vocab.py` measured 20 declared names (2026-10-29) that were neither a registry producer nor an evidence kind
(`security`, `sysmon`, `dns`, `netstat`, `eml`, `apache`, ...): no matcher could match them, so they declared evidence
a skill could never be chosen by. `devtools/knowledge/resolve_family_vocabulary.py` renamed or dropped each one with
its reason; this keeps a dead name from coming back. A known producer the tiny cases do not produce is coverage, not
vocabulary, and `family_vocab.py` reports it with the decision that scopes it.
"""
from __future__ import annotations

from devtools.runbook.family_vocab import declared_families
from nexus.knowledge.family_registry import FamilyRegistry, get_family_registry


def test_every_declared_family_name_is_a_producer_or_an_evidence_kind():
    registry = get_family_registry()
    unknown = {name: sorted(users)[:3] for name, users in declared_families().items() if not registry.known(name)}
    assert unknown == {}


def test_known_separates_vocabulary_from_coverage():
    registry = FamilyRegistry({"families": {
        "evtxecmd": {"kinds": ["evtx"]},
        "vol": {"aliases": ["volatility"], "kinds": ["memory"]},
    }})
    assert registry.known("evtxecmd") and registry.known("volatility")
    assert registry.known("evtx") and registry.known("kind:memory")
    assert not registry.known("sysmon") and not registry.known("kind:sysmon")


def test_the_vocabulary_plan_has_nothing_left_to_change():
    """The plan was applied: running it again finds no dead name in any skill."""
    from devtools.knowledge.resolve_family_vocabulary import SKILLS, plan_file

    assert [notes for path in sorted(SKILLS.glob("*.yaml")) for notes in plan_file(path)[1]] == []
