"""IC-5: ATT&CK's method (v20) for the seats - what a technique looks like in evidence, what a detected tool does.

Everything asserted here comes from the pinned registry (MITRE ATT&CK v20.0 STIX): nothing is typed in the code.
"""
from __future__ import annotations

from nexus.knowledge.attack_method import (
    family_of,
    method_block,
    software_block,
    software_for,
    technique_by_name,
    threats_in,
)


def test_a_threat_name_maps_to_attack_software_by_its_family():
    # MemProcFS YARA (Elastic rules) and Defender (Microsoft naming) name the same family two ways.
    assert family_of("Windows.Trojan.CobaltStrike") == "CobaltStrike"
    assert family_of("Behavior:Win32/CobaltStrike.E!sms") == "CobaltStrike"
    assert software_for("Windows.Trojan.CobaltStrike")["id"] == "S0154"
    assert software_for("Behavior:Win32/CobaltStrike.E!sms")["id"] == "S0154"
    assert software_for("HackTool:Win32/Mimikatz.D")["id"] == "S0002"
    # A family ATT&CK does not record maps to nothing, never to a guess.
    assert software_for("VirTool:Win32/Kekeo.B") is None
    assert threats_in("Threat: Behavior:Win32/CobaltStrike.E!sms ¦ Severity: Severe") == ["Behavior:Win32/CobaltStrike"]


def test_a_persistence_entry_is_its_attack_technique_by_attacks_own_name():
    assert technique_by_name("Scheduled Task", parent="Scheduled Task/Job") == "T1053.005"
    assert technique_by_name("Windows Service", parent="Create or Modify System Process") == "T1543.003"


def test_the_method_block_carries_the_analytic_its_event_codes_and_what_to_tune():
    block = method_block(["T1053.005"], platforms=["Windows"])
    assert "T1053.005 Scheduled Task/Job: Scheduled Task" in block
    assert "WinEventLog:Security EventCode=4698 (Scheduled Job Creation)" in block
    assert "especially those created under SYSTEM or suspicious user contexts" in block
    assert "UserContext:" in block
    # An unknown id renders nothing rather than an invented entry.
    assert method_block(["T9999"]) == ""


def test_the_software_block_is_attacks_hunt_list_for_the_detected_tool():
    block = software_block(["S0154"])
    assert "S0154 Cobalt Strike (malware)" in block
    for technique in ("T1003.001 OS Credential Dumping: LSASS Memory", "T1021.002 Remote Services: SMB/Windows Admin Shares",
                      "T1543.003 Create or Modify System Process: Windows Service"):
        assert technique in block
    assert "not a finding" in block


def test_a_mode2_order_from_these_leads_carries_attacks_method_into_the_prompt(tmp_path):
    """The real path: leads -> order -> the work order's prompt. The persistence lead names T1053.005 and the
    memory lead names Cobalt Strike; the seat reads ATT&CK's analytic and the software's hunt list."""
    import json
    from unittest.mock import patch

    from nexus.analysis.work_orders import orders_from_leads
    from nexus.modes import multi_role as mr

    leads = [
        {"kind": "baseline", "subject": r"C:\Windows\System32\STUN.exe", "family": "triage baseline",
         "detail": r"STUN.exe is run by task \SRL Update Service", "rows": [], "audit_ids": ["a-1"], "score": 1.0,
         "extra": {"crit_high": True, "engine": "triage baseline", "attack_ids": ["T1053.005"]}},
        {"kind": "rule_engine", "subject": "STUN.exe (pid 1912)", "family": "memprocfs",
         "detail": "MemProcFS YARA: Windows.Trojan.CobaltStrike", "rows": [], "audit_ids": ["a-2"], "score": 1.0,
         "extra": {"crit_high": True, "engine": "memprocfs-yara", "software": [{"id": "S0154", "name": "Cobalt Strike"}]}},
    ]
    orders = orders_from_leads(tmp_path, "Compromise suspected.", families=[], leads=leads, max_orders=2)
    assert [o["techniques"] for o in orders] == [[], ["T1053.005"]] or [o["techniques"] for o in orders] == [
        ["T1053.005"], []]
    item = next(o for o in orders if o["techniques"])
    order = mr.WorkOrder(order_id="wo-ic5", role="evidence", task=item["task"], techniques=tuple(item["techniques"]),
                         software=("S0154",))
    case = tmp_path / "CASE-IC5"
    (case / "audit").mkdir(parents=True)
    seen = {}

    def fake_loop(**kwargs):
        seen["question"] = kwargs.get("question") or ""
        return {"reply": json.dumps({"notes": [], "candidate_findings": [], "coverage": {}}), "tool_calls": [],
                "hits": [], "aggregations": [], "audit_id": "ctx-1", "partial": False, "partial_reason": ""}

    with patch.object(mr, "run_context_loop", side_effect=fake_loop), \
         patch("nexus.knowledge.attack_method.case_platforms_cached", return_value=("Windows",)):
        mr.run_work_order(order, case_dir=case, model=object(), run_id="M2-ic5", sink=mr.EventSink(case, "M2-ic5"))
    assert "ATT&CK v20 METHOD" in seen["question"]
    assert "EventCode=4698 (Scheduled Job Creation)" in seen["question"]
    assert "S0154 Cobalt Strike" in seen["question"] and "T1003.001 OS Credential Dumping: LSASS Memory" in seen["question"]
