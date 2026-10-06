"""WO-R0F item 5 (KL2e): the reviewer's probe set.

Each family ALONE and in its usual set: the standard EVTX set must not select
`usb_device_intrusion` (it is a USB-artifact skill, not an event-log skill), and
single-source auditd / scheduled_tasks / suricata / wireshark must select their
subject skill.
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))


def _ids(families):
    from nexus.knowledge.skills import skills_for
    return {str(s.get("skill")) for s in skills_for(families)}


def test_standard_evtx_set_does_not_select_usb_device_intrusion():
    ids = _ids({"evtx", "security", "sysmon", "hayabusa", "chainsaw"})
    assert "usb_device_intrusion" not in ids, sorted(ids)


def test_single_source_families_select_their_subject_skill():
    for fam, want in (("auditd", "linux_compromise"),
                      ("scheduled_tasks", "persistence"),
                      ("suricata", "network_session_analysis"),
                      ("wireshark", "network_session_analysis")):
        ids = _ids({fam})
        assert want in ids, f"{fam}-only did not select {want}: {sorted(ids)}"


def test_the_subject_skill_is_also_selected_in_its_usual_set():
    # each family in its usual company, not only alone
    assert "linux_compromise" in _ids({"auditd", "authlog", "syslog"})
    assert "persistence" in _ids({"scheduled_tasks", "registry", "evtx"})
    assert "network_session_analysis" in _ids({"suricata", "zeek", "tshark-flows"})
