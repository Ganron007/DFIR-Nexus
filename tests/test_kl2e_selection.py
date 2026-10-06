"""WO-KL2e tests: coverage measured as runtime selection, on real family names.

The reviewer's R0' finding, as tests: "Runtime selection misses single-source
evidence, because the two-family surfacing rule applies. Probed on 2026-10-05:
CloudTrail-only -> no skill; Zeek-only -> no skill; Zeek+Suricata -> only
`ics_ot_forensics`; memory-only (`vol`) -> only `evidence_acquisition_handling`, **not**
`memory_process_analysis`; Amcache-only -> none. 'Covered' means declared, not selected
when it matters."

Each test below is one of those probes, plus the alias resolution and the negative
that must stay negative.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from nexus.knowledge.skills import (  # noqa: E402
    families_intersect,
    get_skills,
    retrieve_skills,
    skills_for,
)


@pytest.mark.parametrize("family,expected", [
    # the WO's acceptance, one probe per reviewer finding
    ("cloudtrail", "cloud_identity_forensics"),
    ("zeek", "network_session_analysis"),
    ("vol", "memory_process_analysis"),
    ("amcache", "execution_anomaly"),
])
def test_one_primary_family_hit_surfaces_the_skill(family, expected):
    """KL2e 2: a skill's SUBJECT, in isolation, must be selected."""
    for surface in (skills_for, retrieve_skills):
        got = [str(s.get("skill")) for s in surface({family})]
        assert expected in got, f"{surface.__name__}({{{family!r}}}) = {got}"


def test_both_family_spellings_select_the_same_skill():
    """KL2e 1: the runtime name and the registry's `ingest-*` spelling agree.

    `iter_ingest_records` indexes `record.source`, so a real case carries
    `cloudtrail`; the registry spells it `ingest-cloudtrail`. A comparison that only
    understands one of them is the reviewer's "the registry's `ingest-*` names do not
    match the runtime".
    """
    for runtime, registry in (("cloudtrail", "ingest-cloudtrail"),
                              ("zeek", "ingest-zeek"),
                              ("amcache", "ingest-amcache"),
                              ("cloudtrail", "ingest-cloudtrail")):
        a = {str(s.get("skill")) for s in skills_for({runtime})}
        b = {str(s.get("skill")) for s in skills_for({registry})}
        assert a == b and a, (runtime, registry, sorted(a), sorted(b))


def test_alias_table_resolves_both_directions():
    """A case on either spelling intersects a skill naming the other."""
    for runtime, registry in (("cloudtrail", "ingest-cloudtrail"),
                              ("authlog", "ingest-authlog"),
                              ("zeek", "ingest-zeek"),
                              ("vol", "memory"),
                              ("windows_registry", "registry")):
        assert families_intersect({runtime}, {registry}), (runtime, registry)


@pytest.mark.parametrize("family", ["evtx", "security", "sysmon", "hayabusa",
                                    "chainsaw"])
def test_evtx_only_selects_no_usb_mobile_or_email_skill(family):
    """The WO's negative: the EVTX noise fix must survive the primary-family rule."""
    noise = {"mobile_forensics", "usb_device_intrusion", "email_phishing"}
    for surface in (skills_for, retrieve_skills):
        got = {str(s.get("skill")) for s in surface({family})}
        assert not (got & noise), (surface.__name__, family, sorted(got & noise))


def test_a_declared_primary_family_is_one_the_skill_tolerates():
    """No invented subjects: a primary must appear in the skill's own trigger."""
    for skill in get_skills():
        prim = [str(f).lower() for f in (skill.get("primary_families") or [])]
        if not prim:
            continue
        trig = {str(f).lower() for f in ((skill.get("trigger") or {}).get("families") or [])}
        wide: set[str] = set()
        for f in trig:
            wide |= families_intersect({f}, {f}) or set()
        for p in prim:
            assert (p in trig) or families_intersect({p}, trig), (
                f"{skill.get('skill')}: primary {p!r} is not in its trigger families")


def test_zeek_plus_suricata_still_prefers_the_network_skill():
    """KL2e 2: the combination keeps the network skill, not only the OT skill."""
    got = [str(s.get("skill")) for s in skills_for({"zeek", "suricata"})]
    assert "network_session_analysis" in got, got


#: Skills whose subject is another platform or another artifact class. An EVTX-only case
#: is not a USB intrusion, not a phone and not an email investigation, so none may
#: surface on event-log evidence alone.
_NOISE_SKILLS = {"usb_device_intrusion", "usb_device_analysis", "email_phishing",
                 "mobile_forensics", "macos_forensics", "browser_artifact_analysis"}

#: Every EVTX lane family the corpus now stages. The corpus grew from 33 to 47 families
#: after the original acceptance was measured, so the negative is asserted at the new
#: size rather than at the size it first passed.
_EVTX_FAMILIES = ("evtx", "security", "sysmon", "hayabusa", "chainsaw", "zircolite",
                  "deepbluecli", "evtxecmd", "suzaku")


@pytest.mark.parametrize("family", _EVTX_FAMILIES)
@pytest.mark.parametrize("surface", [skills_for, retrieve_skills])
def test_evtx_only_case_selects_no_other_platform_skill(family, surface):
    """KL2e acceptance: the EVTX-only noise case still selects no USB/mobile/email skill.

    The two-family rule is what keeps this true. Adding families to the population
    corpus cannot be allowed to loosen it, so every EVTX lane family is checked on both
    selection surfaces.
    """
    got = {str(s.get("skill")) for s in surface({family})}
    leak = sorted(got & _NOISE_SKILLS)
    assert not leak, f"{surface.__name__}({{{family!r}}}) leaked {leak}"
    # and the event-log skill IS selected, so a broken gate cannot pass by selecting
    # nothing at all
    assert "windows_event_log_analysis" in got, got


@pytest.mark.parametrize("pair", [("evtx", "security"), ("security", "sysmon"),
                                  ("evtx", "hayabusa"), ("sysmon", "hayabusa")])
@pytest.mark.parametrize("surface", [skills_for, retrieve_skills])
def test_two_evtx_families_surface_the_evtx_analysis_skills(pair, surface):
    """Two EVTX families is the signal for the event-log analysis skills.

    The positive half of the same rule: a combination IS meant to surface hypotheses,
    so the gate rejecting everything would also be a failure.
    """
    got = {str(s.get("skill")) for s in surface(set(pair))}
    assert got & {"ad_credential_attacks", "lsass_credential_access",
                  "execution_artifact_analysis", "lateral_movement",
                  "log_clearing"}, sorted(got)
    assert not (got & _NOISE_SKILLS), sorted(got & _NOISE_SKILLS)
