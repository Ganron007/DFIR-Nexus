"""WO-KL2c — the artifact families the skills genuinely cover are declared.

`derive_requires` reads `trigger.families`, and the skills named *alias* families
(`evtx`, `mft`, `registry`) while the case index reports *tool* families
(`evtxecmd`, `mftecmd-usn`, `sbecmd`). A skill whose procedure already read
shellbags was therefore not offered for the `sbecmd` family, and the coverage table
read **16 of 61** when far more was genuinely covered.

`devtools/knowledge/declare_families.py` declares the registry family name on the
skill that already analyses that artifact. It adds no new claim: the steps and
citations are unchanged, only the name of the data they read.

These tests pin the result, so a later edit cannot silently drop a family.
"""
from __future__ import annotations

import glob
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
REGISTRY = REPO / "src" / "nexus" / "data" / "schema" / "field_registry.yaml"
PLAYBOOKS = REPO / "src" / "nexus" / "data" / "knowledge" / "discipline" / "playbooks"

#: skill -> the registry families its procedure reads (the KL2c declaration).
DECLARED = {
    "windows_event_log_analysis": ["deepbluecli", "zircolite", "evtxecmd", "hayabusa"],
    "registry_artifact_analysis": ["sbecmd"],
    "browser_artifact_analysis": ["hindsight", "sqlecmd", "thumbcache"],
    "mft_file_activity": ["mftecmd-i30", "mftecmd-usn"],
    "timeline_construction": ["mactime"],
    "network_session_analysis": ["nfdump", "tshark-flows"],
    "malware_analysis_triage": ["capa", "densityscout", "yara"],
    "usb_device_intrusion": ["usbdeview"],
}

#: The one non-`ingest-*` family with no skill or playbook, and why.
UNCOVERED = {
    "logfileparser": "generic log parser; no skill analyses the family itself",
}


def _registry_families() -> set[str]:
    reg = yaml.safe_load(REGISTRY.read_text(encoding="utf-8")) or {}
    fams: set[str] = set()
    for key in ("families", "fields"):
        v = reg.get(key)
        if isinstance(v, dict):
            fams |= set(v.keys())
        elif isinstance(v, list):
            for item in v:
                if isinstance(item, dict) and item.get("family"):
                    fams.add(str(item["family"]))
    return fams


def _covered() -> set[str]:
    import sys

    sys.path.insert(0, str(REPO / "src"))
    from nexus.analysis.skill_steps import derive_requires
    from nexus.knowledge.loader import get_skills

    cov: set[str] = set()
    for skill in get_skills():
        cov |= set((derive_requires(skill) or {}).get("families") or [])
    for path in glob.glob(str(PLAYBOOKS / "*.yaml")):
        doc = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        for key in ("families", "requires"):
            v = doc.get(key)
            if isinstance(v, dict):
                cov |= {str(f) for f in (v.get("families") or [])}
            elif isinstance(v, list):
                cov |= {str(f) for f in v}
        trigger = doc.get("trigger") or {}
        if isinstance(trigger, dict):
            cov |= {str(f) for f in (trigger.get("families") or [])}
    return cov


def test_the_skills_declare_the_families_they_already_analyse():
    """The KL2c declarations survive - a dropped family is the original defect."""
    import sys

    sys.path.insert(0, str(REPO / "src"))
    from nexus.analysis.skill_steps import derive_requires
    from nexus.knowledge.loader import get_skills

    by_name = {str(s.get("skill")): s for s in get_skills()}
    missing: list[str] = []
    for skill, families in DECLARED.items():
        assert skill in by_name, f"{skill} is gone"
        declared = set((derive_requires(by_name[skill]) or {}).get("families") or [])
        for family in families:
            if family not in declared:
                missing.append(f"{skill}: {family}")
    assert missing == [], f"undeclared families: {missing}"


def test_coverage_is_at_least_the_measured_improvement():
    """The measured result: 16 -> 31 of 61, with only the generic parser left out.

    Pinned as a floor rather than an exact number, so adding coverage is welcome and
    losing it fails.
    """
    fams = _registry_families()
    cov = _covered()
    assert len(fams) >= 60, f"only {len(fams)} registry families - did the registry load?"
    covered = len(fams & cov)
    assert covered >= 31, f"coverage fell to {covered} of {len(fams)}"


def test_the_only_uncovered_real_family_is_the_documented_one():
    """WO-KL2c: "Any family left uncovered gets an explicit line."

    `ingest-*` families are source adapters, not artefacts, so they are excluded -
    a skill per adapter is not what the layer needs.
    """
    fams = _registry_families()
    cov = _covered()
    uncovered = sorted(f for f in fams - cov if not f.startswith("ingest-"))
    assert uncovered == sorted(UNCOVERED), (
        "the uncovered set changed; record the new family with its reason - "
        f"got {uncovered}"
    )
