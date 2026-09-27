"""Skills must fire on evidence, not on formatting.

Found by auditing what the agents actually consumed on the first real case. The
Mode 1 interpretations credited 32 skill matches, and among them
`mobile_forensics` on a **Windows EVTX** investigation, plus
`impact_ransomware` and `ad_credential_attacks` seven times each. Two defects,
both real:

**No platform gate.** None of the 37 skills declared a platform, so the matcher
could not tell a mobile acquisition skill from a Windows event-log skill.

**Generic output formats were treated as evidence.** `mobile_forensics` triggers
on `families: [csv, jsonl, sqlite, syslog]` - but `csv` is how every parser in
this corpus writes, so it fired on every case. `container_forensics` had the
same shape. Formatting is not a finding.

And one over-broad match on its own: `usb_device_intrusion` lists eight Windows
families, so a single `evtx` hit surfaced a USB hypothesis on any event log.
"""
from __future__ import annotations

import pytest

from nexus.knowledge.skills import (
    get_skills,
    infer_case_platform,
    platform_compatible,
    skill_platforms,
    skills_for,
)

WINDOWS = {"evtxecmd", "hayabusa", "chainsaw", "security", "recmd", "mft"}
LINUX = {"syslog", "authlog", "journal", "bash_history"}


def _names(**kw) -> set[str]:
    return {str(s.get("skill")) for s in skills_for(limit=20, **kw)}


# --------------------------------------------------------------------------
# the real failures
# --------------------------------------------------------------------------

def test_a_windows_case_never_surfaces_the_mobile_skill():
    for fam in ({"evtxecmd"}, {"csv"}, {"evtx", "recmd"}, {"evtxecmd", "hayabusa"}):
        assert "mobile_forensics" not in _names(families=fam), fam


def test_the_backup_keyword_does_not_reach_the_mobile_skill():
    """"backup" is everywhere in Windows evidence - VSS, Backup Operators, restore points."""
    got = _names(families=WINDOWS, keywords={"backup"})
    assert "mobile_forensics" not in got, got


def test_container_forensics_is_linux_scoped():
    assert "container_forensics" not in _names(families=WINDOWS)
    assert "container_forensics" not in _names(families=LINUX)
    # It fires on a container signal, not on a generic linux event log.
    assert "container_forensics" in _names(
        families=LINUX, keywords={"docker", "containerd", "kubelet"})


def test_a_bare_event_log_does_not_surfice_a_usb_hypothesis():
    """One broad family match is weak context, not a lead."""
    got = _names(families={"evtxecmd"})
    assert "usb_device_intrusion" not in got, got


def test_usb_evidence_does_surface_the_usb_skill():
    got = _names(families={"recmd", "registry", "setupapi"},
                 keywords={"usb", "usbstor"})
    assert "usb_device_intrusion" in got
    assert got and list(
        s["skill"] for s in skills_for(families={"recmd", "registry", "setupapi"},
                                       keywords={"usb", "usbstor"}, limit=8)
    )[0] == "usb_device_intrusion", "the strongest signal should rank first"


# --------------------------------------------------------------------------
# what must keep working
# --------------------------------------------------------------------------

def test_methodology_survives_a_single_family_match():
    """Handing someone an event log should still yield 'how to read event logs'."""
    got = _names(families={"evtxecmd"})
    assert "windows_event_log_analysis" in got, got


def test_the_initial_access_signature_still_fires():
    """LNK + prefetch + browser artifacts together are the initial-access shape."""
    got = _names(families={"lnk", "prefetch", "browser"})
    assert "initial_access" in got, got


def test_a_real_lsass_signal_ranks_its_skill_first():
    got = skills_for(families={"evtxecmd", "hayabusa", "security"},
                     keywords={"lsass", "lsa"}, limit=6)
    assert got and got[0]["skill"] == "lsass_credential_access", [s["skill"] for s in got]


def test_a_linux_case_gets_linux_method():
    got = _names(families=LINUX, keywords={"sudo", "sshd", "auth"})
    assert "linux_compromise" in got, got
    assert "mobile_forensics" not in got
    assert "macos_forensics" not in got


def test_two_families_are_enough_but_one_is_not():
    two = _names(families={"mftecmd", "usn"})
    assert "deleted_file_recovery" in two, two


# --------------------------------------------------------------------------
# the primitives
# --------------------------------------------------------------------------

def test_generic_formats_alone_never_surface_a_skill():
    """csv/jsonl/sqlite are how parsers write, not what the evidence is."""
    assert _names(families={"csv", "jsonl", "json"}) == set()
    assert _names(families={"sqlite"}) == set()


def test_platform_inference_from_families():
    assert infer_case_platform(WINDOWS) == {"windows"}
    assert infer_case_platform(LINUX) == {"linux"}
    assert infer_case_platform({"unknownthing"}) == {"any"}


def test_platform_compatible_is_symmetric_in_effect():
    mobile = next(s for s in get_skills() if s.get("skill") == "mobile_forensics")
    assert skill_platforms(mobile) == {"mobile"}
    assert platform_compatible(mobile, {"windows"}) is False
    assert platform_compatible(mobile, {"mobile"}) is True
    # An undeclared platform means "any" - a Linux case is not starved.
    other = next(s for s in get_skills() if s.get("skill") == "windows_event_log_analysis")
    assert skill_platforms(other) == {"any"}
    assert platform_compatible(other, {"linux"}) is True


def test_every_skill_still_validates():
    from nexus.knowledge.skills import validate_skill

    bad = [s.get("skill") for s in get_skills() if validate_skill(s)]
    assert bad == [], f"skills failing validation: {bad}"


def test_an_unknown_context_still_returns_nothing():
    assert skills_for(families={"nonexistent_family"},
                      keywords={"nonexistentword"}) == []


@pytest.mark.parametrize("fam", ["evtx", "evtxecmd", "prefetch", "mft", "recmd"])
def test_no_windows_family_reaches_a_non_windows_skill(fam):
    got = _names(families={fam})
    assert not (got & {"mobile_forensics", "macos_forensics", "linux_compromise",
                       "container_forensics"}), (fam, got)
