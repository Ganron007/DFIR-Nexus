"""Deep ATT&CK registry — compile integrity, cross-check, grounding fields.

Compiled from CC BY 4.0 attack-stix-data (enterprise/ICS/mobile) by
``scripts/build_attack_registry.py``; attribution in ``attack/NOTICE.txt``.
The registry is the single source for technique names + detection strategies +
mitigations + procedure examples, and the id validator for everything we ship.
"""

from __future__ import annotations

from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_registry_counts():
    from nexus.knowledge.loader import get_attack_registry

    reg = get_attack_registry()
    assert reg, "attack_registry.yaml missing — run scripts/build_attack_registry.py"
    counts = reg["counts"]
    # ATT&CK v20.0 (released 2026-10-13), pinned by version in scripts/build_attack_registry.py.
    assert reg["version"] == "v20.0"
    assert counts["techniques"] == 1158
    assert counts["active"] == 935
    assert counts["subtechniques"] == 570
    assert counts["detection_strategies"] == 931
    assert set(counts["per_matrix"]) == {"enterprise", "ics", "mobile"}
    assert "CC BY 4.0" in reg["license"]
    assert reg["raw_sha256"]


def test_an_analytic_keeps_its_log_sources_event_codes_and_tunables():
    """D247: ATT&CK's method for a technique reaches the registry whole, not cut to 220 characters."""
    from nexus.knowledge.loader import get_attack_registry

    tech = next(t for t in get_attack_registry()["techniques"] if t["id"] == "T1053.005")
    analytic = next(a for d in tech["detection"] for a in d["analytics"] if a["name"] == "Analytic 1221")
    assert analytic["description"].endswith("especially those created under SYSTEM or suspicious user contexts.")
    assert {"name": "WinEventLog:Security", "channel": "EventCode=4698",
            "data_component": "Scheduled Job Creation"} in analytic["log_source_refs"]
    assert "UserContext" in {t["field"] for t in analytic["tunables"]}


def test_sample_technique_fields():
    from nexus.knowledge.loader import get_attack_registry

    reg = get_attack_registry()
    by_id = {t["id"]: t for t in reg["techniques"]}

    rdp = by_id["T1021.001"]
    assert rdp["name"] == "Remote Desktop Protocol"
    assert rdp["parent"] == "T1021"
    assert "lateral-movement" in rdp["tactics"]
    assert rdp["detection"], rdp["id"]
    assert rdp["detection"][0]["analytics"], rdp["id"]
    assert rdp["mitigations"] and rdp["procedures"]

    sub = by_id["T1055.011"]
    assert sub["sub"] is True and sub["parent"] == "T1055"

    # Revoked entries stay resolvable (legacy references must not auto-fail).
    assert any(t["revoked"] for t in reg["techniques"])


def test_every_shipped_mitre_id_resolves():
    """Skills, playbooks, needles and both pattern libraries must only cite
    technique ids that exist in the registry — no fabricated technique ids."""
    from nexus.knowledge.loader import (
        get_attack_needles,
        get_attack_registry,
        get_playbook,
        get_skills,
        list_playbook_slugs,
    )

    ids = {t["id"] for t in get_attack_registry()["techniques"]}
    refs: dict[str, list[str]] = {}

    def add(source: str, values) -> None:
        for value in values or []:
            ref = str(value).strip().upper()
            if ref.startswith("T") and ref[1:2].isdigit():
                refs.setdefault(ref, []).append(source)

    for skill in get_skills() or []:
        add(f"skill:{skill.get('skill')}", skill.get("mitre"))
    for slug in list_playbook_slugs():
        add(f"playbook:{slug}", (get_playbook(slug) or {}).get("mitre"))
    for pack in get_attack_needles() or []:
        add(f"needle:{pack.get('technique')}", [pack.get("technique")])
    for fname in ("attack_patterns.yaml", "attack_patterns_itm.yaml",
                  "attack_patterns_external.yaml"):
        data = yaml.safe_load(
            (REPO_ROOT / "src" / "nexus" / "data" / "knowledge" / fname)
            .read_text(encoding="utf-8")
        ) or {}
        for pattern in data.get("patterns") or []:
            add(f"pattern:{pattern.get('name')}", pattern.get("mitre"))

    assert len(refs) >= 100, len(refs)
    missing = {ref: src for ref, src in refs.items() if ref not in ids}
    assert not missing, missing
