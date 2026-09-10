"""Phase 4g-B — MITRE ATT&CK needle packs.

Data integrity, technique/family selection, prompt context, and Mode 1
grounding (needles include pack vocabulary even without an LLM).
"""
from __future__ import annotations

from nexus.knowledge.attack_needles import (
    attack_context_for,
    attack_needles_for,
    attack_packs_for,
    extract_techniques,
)
from nexus.knowledge.loader import get_attack_needles
from nexus.langgraph.mode1 import nl_to_needles
from nexus.langgraph.query_pack import playbook_techniques_for_families


def test_packs_load_and_are_well_formed():
    packs = get_attack_needles()
    assert len(packs) >= 20
    techniques = [str(pack["technique"]) for pack in packs]
    assert len(techniques) == len(set(techniques))
    for pack in packs:
        assert pack.get("needles"), pack.get("technique")
        assert pack.get("families"), pack.get("technique")
        assert pack.get("caveats"), pack.get("technique")


def test_extract_techniques():
    assert extract_techniques("check T1003.001 and t1059.001") == [
        "T1003.001",
        "T1059.001",
    ]
    assert extract_techniques("no ids here") == []


def test_technique_selection_wins_over_family_order():
    packs = attack_packs_for(families={"prefetch"}, techniques={"T1003.001"}, limit=2)
    assert packs and packs[0]["technique"] == "T1003.001"
    assert "lsass" in {str(n).lower() for n in packs[0]["needles"]}


def test_family_selection_yields_needles():
    needles = attack_needles_for(
        families={"evtx", "hayabusa", "prefetch"}, techniques=None, limit=3
    )
    assert needles
    assert {n.lower() for n in needles} & {"lsass", "mimikatz", "ntds.dit"}


def test_attack_context_has_caveats():
    packs = attack_packs_for(families=set(), techniques={"T1486"}, limit=1)
    block = attack_context_for(packs)
    assert "T1486" in block
    assert "caveat:" in block


def test_attack_needles_ground_mode1_without_llm():
    result = nl_to_needles(
        "What happened on the host?",
        model=None,
        context={"attack_needles": ["lsass", "procdump"]},
    )
    assert result["source"] == "heuristic"
    assert "lsass" in result["needles"]
    assert "procdump" in result["needles"]


def test_playbook_techniques_for_families():
    techniques = playbook_techniques_for_families({"evtx", "powershell"})
    assert any(str(t).upper().startswith("T") for t in techniques)
