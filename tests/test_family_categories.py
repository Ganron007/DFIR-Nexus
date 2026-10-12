"""D112 (2026-10-13): the category of a row the pinned table does not name, from its family and file.

A row is classified only when it names the subject its category needs, so a family whose rows name no file,
registry key or program stays ``other``. The sources below are the ``family/file`` strings the product builds
(``evidence_rows.evidence_rows_for_hits``); the real rows were checked against the case index.
"""
from __future__ import annotations

from nexus.langgraph.event_categories import OTHER, family_categories, family_category, row_category
from nexus.langgraph.subject import GROUP_OF_CATEGORY, derive_subject


def test_every_family_category_has_a_subject_group():
    assert family_categories() <= set(GROUP_OF_CATEGORY)


def test_a_file_rule_applies_to_its_own_files_only():
    assert family_category("srumecmd/srum/20261011150610_SrumECmd_NetworkUsages_Output.csv") == "network_connection"
    assert family_category(
        "srumecmd/srum/20261011150610_SrumECmd_AppResourceUseInfo_Output.csv"
    ) == "process_creation"
    assert family_category("srumecmd/srum/20261011150610_SrumECmd_EnergyUsage_Output.csv") == OTHER
    assert family_category("sbecmd/sbecmd/1UsrClass_rsydow-a-shellbags.csv") == "file_event"
    assert family_category("sbecmd/sbecmd/!SBECmd_Messages.txt") == OTHER


def test_a_family_rule_applies_to_the_families_files():
    assert family_category("mftecmd/mftecmd/mft.csv") == "file_event"
    # USN journal rows name no file path in the case index (checked 2026-10-13), so they stay other.
    assert family_category("mftecmd/mftecmd-usn/usn.csv") == OTHER
    assert family_category("recmd/recmd/20261011110620/20261011110620_FirewallRules__SYSTEM.csv") == "registry_event"
    assert family_category("pecmd/pecmd/prefetch.csv") == "process_creation"


def test_a_family_whose_rows_name_no_file_key_or_program_stays_other():
    for source in (
        "mplog/mplog/MPLog_Ems.csv",
        "pstranscript/pstranscript/transcript.txt",
        "wer/wer/NonCritical_report.wer.txt",
        "csv/memprocfs/SRL_Evidence/forensic/csv/timeline_registry.csv",
        "generic_csv/ingest/artifacts.jsonl",
    ):
        assert family_category(source) == OTHER, source


def test_a_pinned_category_wins_over_the_family_rule():
    row = {"source": "mftecmd/mftecmd/mft.csv", "provider": "Microsoft-Windows-Sysmon", "event_id": "1"}
    assert row_category(row) == "process_creation"
    assert row_category({"source": "mftecmd/mftecmd/mft.csv"}) == "file_event"
    assert row_category({"source": "mplog/mplog/MPLog_Ems.csv"}) == OTHER


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
