"""MITRE MBC v3 registry — malware behaviors, methods, families, capa rules.

Compiled from the Apache-2.0 `MBCProject/mbc-stix2.1` bundle by
``scripts/build_mbc_registry.py`` (C) The MITRE Corporation; attribution in
``mbc/NOTICE.txt``. MBC is the malware-capability complement of ATT&CK.
"""

from __future__ import annotations


def test_mbc_registry_counts_and_license():
    from nexus.knowledge.loader import get_mbc_registry

    reg = get_mbc_registry()
    assert reg, "mbc_registry.yaml missing — run scripts/build_mbc_registry.py"
    counts = reg["counts"]
    assert counts["objectives"] == 21
    assert counts["behaviors"] == 150
    assert counts["methods"] == 482
    assert counts["families"] == 50
    assert counts["detection_rules"] >= 1000
    assert "Apache-2.0" in reg["license"]
    assert reg["raw_sha256"]


def test_methods_and_families_resolve():
    from nexus.knowledge.loader import get_mbc_registry

    reg = get_mbc_registry()
    behavior_ids = {b["id"] for b in reg["behaviors"]}

    # Every method hangs off an existing behavior (no orphans).
    assert all(m["behavior"] in behavior_ids for m in reg["methods"])
    attached = sum(len(b["methods"]) for b in reg["behaviors"])
    assert attached == len(reg["methods"])

    sample = next(b for b in reg["behaviors"] if b["id"] == "B0029")
    assert sample["methods"], "B0029 should carry methods"

    # Families reference real behaviors and vice versa.
    family_ids = {f["id"] for f in reg["families"]}
    for behavior in reg["behaviors"]:
        for fid in behavior["families"]:
            assert fid in family_ids, (behavior["id"], fid)
    badusb = next((f for f in reg["families"] if f["id"] == "X0046"), None)
    assert badusb and badusb["name"] == "BadUSB" and badusb["behaviors"]


def test_detection_rules_and_objectives():
    from nexus.knowledge.loader import get_mbc_registry

    reg = get_mbc_registry()
    objective_ids = {o["id"] for o in reg["objectives"]}
    for behavior in reg["behaviors"]:
        for objective in behavior["objectives"]:
            assert objective in objective_ids, (behavior["id"], objective)

    rules = [r for b in reg["behaviors"] for r in b["detection_rules"]]
    assert rules, "MBC detection rules missing"
    assert any(r["rule_type"] == "capa" for r in rules)
    assert any(r.get("url") for r in rules)
