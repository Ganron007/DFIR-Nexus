"""Insider Threat Matrix registry — compile, retrieve, validate.

The registry is compiled from the Apache-2.0 ITM JSON (v2.13.0, Forscie
Limited; NOTICE retained in ``data/knowledge/itm/``) by
``scripts/build_itm_registry.py``. Findings may only cite ids that exist;
invented ids are rejected (same discipline as FD-001 for evidence refs).
"""

from __future__ import annotations


def test_registry_counts_and_version():
    from nexus.knowledge.loader import get_itm_registry

    reg = get_itm_registry()
    assert reg, "itm_registry.yaml missing — run scripts/build_itm_registry.py"
    assert reg["version"] == "2.13.0"
    assert reg["mitre_version"] == "19.2"
    assert reg["counts"] == {
        "articles": 5,
        "sections": 183,
        "subsections": 432,
        "detections": 776,
        "preventions": 610,
        "attack_maps": 168,
    }
    articles = {a["id"] for a in reg["articles"]}
    assert articles == {"AR1", "AR2", "AR3", "AR4", "AR5"}


def test_index_and_id_validation():
    from nexus.langgraph.itm import itm_index, validate_itm_ids

    index = itm_index()
    assert "PR026" in index and index["PR026"]["stage"] == "Preparation"
    assert index["PR026"]["title"].startswith("Remote Desktop")
    assert "PR026.001" in index and index["PR026.001"]["kind"] == "subsection"

    ok = validate_itm_ids(
        "Preparation", ["PR026", "AR3/PR016", "PR026.001", "PR999", "AF999", ""]
    )
    assert ok["stage"] == "Preparation"
    assert ok["objects"] == ["AR3/PR026", "AR3/PR016", "AR3/PR026.001"]
    assert ok["unknown"] == ["PR999", "AF999"]

    # Stage can be implied by the object / article id.
    implied = validate_itm_ids("", ["AF020"])
    assert implied["stage"] == "Anti-Forensics"
    assert implied["objects"] == ["AR5/AF020"]


def test_sections_for_rdp_question():
    from nexus.langgraph.itm import itm_sections_for

    got = itm_sections_for(
        "Explain the RDP connection: did it come from outside, whois the IP",
        families=["evtxecmd", "hayabusa"],
        limit=6,
    )
    ids = [s["id"] for s in got]
    assert "PR026" in ids, ids


def test_prompt_block_is_grounded_and_bounded():
    from nexus.langgraph.itm import itm_prompt_block

    block = itm_prompt_block("RDP connection from an external source", ["evtxecmd"], 5)
    assert "AR3/PR026" in block
    assert "Preparation" in block and "Anti-Forensics" in block
    assert "insiderthreatmatrix.org" in block
    # Unknown-id discipline is stated in the prompt.
    assert "rejected" in block

    empty = itm_prompt_block("")
    assert "No ITM section matched" in empty


def test_hunt_parser_omits_invented_ids():
    from nexus.langgraph.hunt_parser import normalize_candidate

    finding = normalize_candidate({
        "title": "RDP configuration change",
        "observation": "RDP enabled via registry",
        "itm_stage": "Preparation",
        "itm_objects": ["PR026", "PR999"],
    })
    text = str(finding.get("interpretation") or "")
    assert "AR3/PR026" in text
    assert "PR999" not in text.replace("Unrecognised ITM id(s) omitted: PR999", "")
    assert "Unrecognised ITM id(s) omitted" in text
