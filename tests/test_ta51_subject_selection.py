"""TA-5.1 close-out: a tiny case selects the skill its evidence is the subject of, and a container is no evidence.

Measured on the 22 tiny indexes (2026-10-29, `scratch/agent/never_used.py`): T06 (`$MFT`/USN), T08 (PST/OST) and T21
(browser profiles) selected no skill, because `mft_file_activity`, `email_phishing` and `browser_artifact_analysis`
named their subject evidence once and declared no primary family (one hit on a primary is the signal, KL2e 2). And
T18 and T21 selected `container_forensics` and `mobile_forensics` from generic CSV/JSONL rows alone: TA-5.1's
vocabulary plan had renamed their format words `csv`/`jsonl` to the generic importers' families. The family sets
below are the ones those indexes hold.
"""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from nexus.knowledge.family_registry import FamilyRegistry, families_intersect, get_family_registry
from nexus.knowledge.skills import skills_for

T18 = {"auditd", "authlog", "generic_csv", "linux_log", "nfdump", "syslog", "utmp"}
T21 = {"generic_csv", "generic_jsonl", "hindsight"}
#: T15-R1z5's evidence groups (schema 22): the two .eml rows are generic_jsonl read by the EmailImporter.
T15_GROUPS = [{"generic_jsonl", "email"}, {"network"}, {"wireshark"}, {"zeek"}, {"suricata"}]


def _chosen(families, groups=None) -> set[str]:
    return {str(s.get("skill")) for s in skills_for(families, family_groups=groups, limit=8)}


@pytest.mark.parametrize("case,families,skill", [
    ("T06", {"mftecmd"}, "mft_file_activity"),
    ("T08", {"email"}, "email_phishing"),
    ("T21", T21, "browser_artifact_analysis"),
    ("T18", T18, "linux_compromise"),
])
def test_a_case_selects_the_skill_its_evidence_is_the_subject_of(case, families, skill):
    assert skill in _chosen(families), case


def test_t15s_email_rows_select_the_email_skill_through_their_group():
    assert "email_phishing" in _chosen(set().union(*T15_GROUPS), T15_GROUPS)


@pytest.mark.parametrize("families", [T18, T21, {"generic_csv"}, {"generic_jsonl", "spreadsheet"}])
def test_a_container_is_no_evidence(families):
    assert not _chosen(families) & {"container_forensics", "mobile_forensics"}
    assert _chosen(families & {"generic_csv", "generic_jsonl", "spreadsheet"}) == set()


def test_the_registry_marks_the_containers_and_refuses_a_container_with_a_kind():
    registry = get_family_registry()
    assert all(registry.is_container(name) for name in ("generic_csv", "generic_jsonl", "spreadsheet"))
    assert not any(registry.is_container(name) for name in ("email", "encoded_file", "evtxecmd"))
    with pytest.raises(ValueError, match="container"):
        FamilyRegistry({"families": {"x": {"container": True, "kinds": ["file"]}}})


@pytest.mark.parametrize("producer", ["bind", "aws_vpc_flow"])
def test_dns_query_logs_and_vpc_flows_are_network_evidence(producer):
    assert families_intersect({producer}, {"kind:network"})


SRC = Path(__file__).resolve().parents[1] / "src" / "nexus"


def test_every_platform_fact_is_its_sources():
    """D484: a platform comes from the pinned artifact entry it cites (its `platform:`) or the Linux importer it
    names, never a typed list."""
    doc = yaml.safe_load((SRC / "data" / "schema" / "family_registry.yaml").read_text(encoding="utf-8"))
    facts = [(kind, spec["platform"], spec["source"]) for kind, spec in doc["kind_platforms"].items()]
    facts += [(name, spec["platform"], spec["platform_source"]) for name, spec in doc["families"].items()
              if spec.get("platform")]
    assert facts
    for subject, platform, source in facts:
        if source.startswith("knowledge/"):
            artifact = yaml.safe_load((SRC / "data" / source).read_text(encoding="utf-8"))
            assert artifact["platform"] == platform, (subject, source)
        else:
            assert source.startswith(f"ingest/{platform}/") and (SRC / source).is_file(), (subject, source)


@pytest.mark.parametrize("case,families,platforms", [
    ("T22", {"memprocfs", "vol"}, {"windows"}),     # memory read on a Windows host: its event logs are EVTX
    ("T18", T18, {"linux"}),
    ("T13", {"bind", "network", "suricata", "syslog", "wireshark", "zeek"}, {"linux"}),
    ("T15", {"email", "generic_jsonl", "network", "suricata", "wireshark", "zeek"}, {"any"}),
    ("T01", {"amcache", "appcompat", "pecmd", "recmd"}, {"windows"}),
])
def test_a_tiny_case_is_placed_on_its_platform_by_the_registry(case, families, platforms):
    from nexus.knowledge.skills import infer_case_platform

    assert infer_case_platform(families) == platforms, case
