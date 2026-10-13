"""D112 and D117 (2026-10-13): the category of a row the pinned table does not name, from its family and file.

A rule classifies a row only when the row names the subject its category needs (``requires``). A family whose rows
name no file, registry key, program or destination stays ``other``, and is never given the host as its subject. The
sources below are the ``family/file`` strings the product builds (``evidence_rows.evidence_rows_for_hits``).
"""
from __future__ import annotations

from nexus.langgraph.event_categories import (
    OTHER,
    _family_rules,
    family_categories,
    family_category,
    present,
    row_category,
)
from nexus.langgraph.subject import FIELD_ROW_KEY, GROUP_OF_CATEGORY, derive_subject


def test_every_family_category_has_a_subject_group():
    assert family_categories() <= set(GROUP_OF_CATEGORY)


def test_every_requires_key_is_a_subject_row_key():
    # A rule can only require a subject that derive_subject reads, so a typo cannot silently never match.
    subject_keys = set(FIELD_ROW_KEY.values())
    for _family, _glob, _category, requires in _family_rules():
        assert set(requires) <= subject_keys, requires


def test_a_file_rule_applies_to_its_own_files_only():
    netusage = "srumecmd/srum/20261011150610_SrumECmd_NetworkUsages_Output.csv"
    assert family_category(netusage, {"process": "chrome.exe"}) == "network_connection"
    assert family_category(netusage) == OTHER  # no program named: nothing to classify
    appres = "srumecmd/srum/20261011150610_SrumECmd_AppResourceUseInfo_Output.csv"
    assert family_category(appres, {"process": "chrome.exe"}) == "process_creation"
    assert family_category("srumecmd/srum/20261011150610_SrumECmd_EnergyUsage_Output.csv",
                           {"process": "chrome.exe"}) == OTHER
    shell = "sbecmd/sbecmd/1UsrClass_rsydow-a-shellbags.csv"
    assert family_category(shell, {"file_path": "Desktop\\Quick Access"}) == "file_event"
    assert family_category("sbecmd/sbecmd/!SBECmd_Messages.txt", {"file_path": "x"}) == OTHER


def test_a_family_rule_applies_to_the_families_files_when_the_subject_is_named():
    assert family_category("mftecmd/mftecmd/mft.csv", {"file_path": ".\\Users\\a\\x.exe"}) == "file_event"
    assert family_category("mftecmd/mftecmd/mft.csv") == OTHER
    assert family_category("recmd/recmd/20261011110620/20261011110620_FirewallRules__SYSTEM.csv",
                           {"registry_path": "ROOT\\ControlSet001"}) == "registry_event"
    assert family_category("pecmd/pecmd/prefetch.csv", {"process": "chrome.exe"}) == "process_creation"


def test_a_usn_row_is_a_file_event_only_when_its_parent_resolved():
    usn = "mftecmd/mftecmd-usn/usn.csv"
    # A USN row carries a path only when the MFT join resolved its parent (D116); a bare name is not a path.
    assert family_category(usn, {"file_path": ".\\Users\\a\\x.tmp"}) == "file_event"
    assert family_category(usn, {"file_path": ""}) == OTHER
    assert family_category(usn) == OTHER


def test_a_family_whose_rows_name_no_file_key_or_program_stays_other():
    for source in (
        "mplog/mplog/MPLog_Ems.csv",
        "pstranscript/pstranscript/transcript.txt",
        "wer/wer/NonCritical_report.wer.txt",
        "csv/memprocfs/SRL_Evidence/forensic/csv/timeline_registry.csv",
        "generic_csv/ingest/artifacts.jsonl",
    ):
        assert family_category(source, {"host": "ws01"}) == OTHER, source


def test_a_pinned_category_wins_over_the_family_rule():
    row = {"source": "mftecmd/mftecmd/mft.csv", "provider": "Microsoft-Windows-Sysmon", "event_id": "1",
           "file_path": ".\\x.exe"}
    assert row_category(row) == "process_creation"
    assert row_category({"source": "mftecmd/mftecmd/mft.csv", "file_path": ".\\x.exe"}) == "file_event"
    assert row_category({"source": "mplog/mplog/MPLog_Ems.csv"}) == OTHER


def test_a_zeek_connection_and_a_flow_are_network_connections_about_their_destination():
    conn = "zeek/network/http-bro-org/zeek/conn.log"
    assert family_category(conn, {"destination_ip": "192.150.187.43"}) == "network_connection"
    assert family_category(conn, {"source_ip": "10.0.2.15"}) == OTHER  # no destination: not classified
    flow = "network/ingest/network/capture-flows.csv"
    assert family_category(flow, {"destination_ip": "192.150.187.43"}) == "network_connection"


def test_a_suricata_event_with_a_destination_is_a_network_connection():
    eve = "suricata/network/conn-size/suricata/eve.json"
    assert family_category(eve, {"destination_ip": "192.150.187.43"}) == "network_connection"
    assert family_category(eve, {}) == OTHER


def test_an_unspecified_address_is_not_a_destination():
    # A listening socket names 0.0.0.0 (or ::) as its foreign end: that is no destination (D117).
    assert present("0.0.0.0") == ""
    assert present("::") == ""
    assert present("*") == ""  # Volatility's netscan writes * for an unbound socket's foreign end
    assert present("192.150.187.43") == "192.150.187.43"
    assert family_category("vol/vol-windows-x.txt", {"destination_ip": present("0.0.0.0")}) == OTHER


def test_a_prefetch_row_is_a_process_creation_about_its_program():
    rows = [{"source": "pecmd/pecmd/prefetch.csv", "loc": "prefetch.csv:3", "process": "CHROME.EXE"}]
    assert derive_subject(rows) == {
        "entity": {"type": "process", "value": "chrome.exe"},
        "category": "process_creation",
    }


def test_a_mft_row_is_a_file_event_about_its_path():
    rows = [{"source": "mftecmd/mftecmd/mft.csv", "loc": "mft.csv:9",
             "file_path": "C:\\Users\\a\\Desktop\\x.exe"}]
    assert derive_subject(rows) == {
        "entity": {"type": "file", "value": "c:\\users\\a\\desktop\\x.exe"},
        "category": "file_event",
    }
