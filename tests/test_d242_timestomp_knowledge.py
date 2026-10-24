"""D242: pinned timestamp semantics must reach real investigator surfaces."""
from __future__ import annotations

from copy import deepcopy

from nexus.analysis.behavioural_analytics import analytics
from nexus.knowledge.loader import get_skill
from nexus.knowledge.skills import skill_version
from nexus.langgraph.case_digest import lead_citation
from nexus.modes.multi_role import WorkOrder, _skill_procedure_block


def test_timestomp_analytic_does_not_overstate_mftecmd_flags():
    by_id = {item["id"]: item for item in analytics()}
    si_fn = by_id["ba-eva-timestomp"]
    usn = by_id["ba-eva-timestomp-usn"]

    assert "whole seconds" not in si_fn["name"].lower()
    assert "pinned_source_facts" in si_fn
    assert "pinned_source_facts" in usn
    facts = {fact["id"]: fact for fact in si_fn["pinned_source_facts"]}
    assert {"mftecmd.si_fn", "mftecmd.usec_zeros", "mftecmd.copied"} <= facts.keys()
    assert "millisecond" in facts["mftecmd.usec_zeros"]["claim"].lower()
    assert "contentmodifiedon" in facts["mftecmd.copied"]["claim"].lower()
    assert all(fact.get("source") and fact.get("source_version") and fact.get("source_key")
               for fact in facts.values())
    assert any("attribute" in fact["claim"].lower() and "timestamp" in fact["claim"].lower()
               for fact in usn["pinned_source_facts"])
    lead_sources = lead_citation({"audit_ids": [], "pinned_source_facts": usn["pinned_source_facts"]})
    assert "pinned sources:" in lead_sources
    assert "656e9656bfaef34dd29cd7ee9e1146aec17e924c" in lead_sources
    assert "sha256=" in lead_sources


def test_mode3_skill_seat_gets_pinned_timestomp_facts_and_citations():
    order = WorkOrder(
        order_id="wo-d242",
        role="host",
        task="assess possible timestomping",
        skill_refs=[{
            "skill": "windows_data_hiding",
            "version": "test",
            "role": "host",
            "citations": [],
        }],
    )

    block = _skill_procedure_block(order)

    assert "MFTECmd exports SI<FN as its Timestomped flag" in block
    assert "Millisecond == 0" in block
    # The imported source fact explicitly compares $SI ContentModifiedOn to
    # $SI CreatedOn; keep both attribute scopes in this rendered-path check.
    assert "$SI ContentModifiedOn < $SI CreatedOn" in block
    assert "USN_REASON_BASIC_INFO_CHANGE" in block
    # The shipped parser is pinned to its matching source snapshot; newer upstream
    # commits describe a different product version. Since TA-Z (2026-10-24) the lane
    # runs MFTECmd 2026.10.2 (.NET 10), whose source is 2919ded.
    assert "2919ded0738d1533c8ab6b627a5aed2c9f67859c" in block
    assert "656e9656bfaef34dd29cd7ee9e1146aec17e924c" in block
    assert "source_sha256" in block


def test_pinned_source_revision_changes_skill_version():
    skill = get_skill("windows_data_hiding")
    assert skill is not None
    baseline = skill_version(skill)
    changed = deepcopy(skill)
    fact = next(
        fact
        for step in changed["steps"]
        for fact in (step.get("pinned_source_facts") or [])
        if fact.get("id") == "mftecmd.si_fn"
    )
    fact["source_sha256"] = "0" * 64

    assert skill_version(changed) != baseline
