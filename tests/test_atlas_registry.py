"""MITRE ATLAS registry — AI/ML adversarial techniques, mitigations, cases.

Compiled from the Apache-2.0 atlas-data by ``scripts/build_atlas_registry.py``
(C) 2021-2026 MITRE; attribution in ``atlas/NOTICE.txt``. ATLAS is the AI-era
counterpart of ATT&CK and grounds the AI-forensics track (WIRING-PLAN 10.17/18).
"""

from __future__ import annotations


def test_atlas_registry_counts_and_license():
    from nexus.knowledge.loader import get_atlas_registry

    reg = get_atlas_registry()
    assert reg, "atlas_registry.yaml missing — run scripts/build_atlas_registry.py"
    counts = reg["counts"]
    assert counts["tactics"] == 16
    assert counts["techniques"] == 170
    assert counts["mitigations"] == 35
    assert counts["case_studies"] == 57
    assert counts["subtechniques"] == sum(
        1 for t in reg["techniques"] if t["sub"]
    )
    assert 0 < counts["subtechniques"] < counts["techniques"]
    assert "Apache-2.0" in reg["license"]
    assert reg["raw_sha256"]


def test_atlas_technique_sample_and_reference_integrity():
    from nexus.knowledge.loader import get_atlas_registry

    reg = get_atlas_registry()
    by_id = {t["id"]: t for t in reg["techniques"]}

    prompt = by_id["AML.T0051"]
    assert prompt["name"] == "LLM Prompt Injection"
    assert prompt["maturity"] in {"realized", "demonstrated", "feasible"}
    assert prompt["tactics"]

    tactic_ids = {t["id"] for t in reg["tactics"]}
    for technique in reg["techniques"]:
        for tactic in technique["tactics"]:
            assert tactic in tactic_ids, (technique["id"], tactic)

    technique_ids = set(by_id)
    for mitigation in reg["mitigations"]:
        for ref in mitigation["techniques"]:
            assert ref["id"] in technique_ids, (mitigation["id"], ref["id"])

    # ATT&CK cross-references point at real ATT&CK ids with URLs.
    refs = [r for t in reg["techniques"] for r in t["attack_refs"]]
    assert refs
    assert all(r["id"].startswith("T") for r in refs)
