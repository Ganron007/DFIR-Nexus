"""Family subjects: the columns a family's own rows name the subject with (item 3, operator decision 2026-10-12).

Each fixture has the shape the case index holds (checked 2026-10-12): PECmd's ExecutableName, the prefetch
Process column, SRUM's ExeInfo and envelope user, and SRUM's numeric AppId and UserId. Each document goes through
the product's shaper and row builder, so the test runs the real path.
"""

from __future__ import annotations

from typing import Any

from nexus.langgraph.es_native import _shape_hit
from nexus.langgraph.evidence_rows import evidence_rows_for_hits
from nexus.langgraph.subject import derive_subject


def _entity(doc: dict[str, Any]) -> dict[str, Any]:
    row = evidence_rows_for_hits([_shape_hit(doc)])[0]
    return derive_subject([row])["entity"]


def _doc(family: str, fields: dict[str, Any], **envelope: Any) -> dict[str, Any]:
    return {"family": family, "file": f"{family}.csv", "line": "1", "text": "", "fields": fields, **envelope}


def test_a_pecmd_row_is_about_the_program_it_ran():
    doc = _doc("pecmd", {"ExecutableName": "\\VOLUME{01d8bd78c0b06af4-20c0ddb3}\\WINDOWS\\SYSTEM32\\SVCHOST.EXE"})
    assert _entity(doc) == {
        "type": "process",
        "value": "\\volume{01d8bd78c0b06af4-20c0ddb3}\\windows\\system32\\svchost.exe",
    }


def test_a_prefetch_row_with_a_process_column_is_about_that_process():
    assert _entity(_doc("prefetch", {"Process": "SVCHOST.EXE", "RunCount": "3"})) == {
        "type": "process", "value": "svchost.exe",
    }


def test_a_memprocfs_row_with_a_process_column_is_about_that_process():
    """D210: MemProcFS's output is one family; its prefetch, module and connection rows name their process."""
    for fields in ({"Process": "SVCHOST.EXE", "RunCount": "3"},
                   {"PID": "692", "Process": "lsass.exe", "Module": "samsrv.dll"},
                   {"PID": "2376", "Process": "svchost.exe", "Protocol": "TCPv4", "State": "ESTABLISHED"}):
        doc = {**_doc("memprocfs", fields), "file": "memprocfs/rd01-memory.img/forensic/csv/net.csv"}
        assert _entity(doc) == {"type": "process", "value": fields["Process"].lower()}


def test_a_prefetch_timeline_row_names_no_subject_because_its_program_is_free_text():
    doc = _doc("prefetch", {"Type": "PREF", "Text": "SVCHOST.EXE                      - run_count:3675 file:[x.pf]"})
    assert _entity(doc) == {}


def test_a_srum_row_is_about_the_app_before_the_account():
    doc = _doc("srumecmd", {"ExeInfo": "svchost.exe", "AppId": "72", "UserId": "4",
                            "UserName": "systemprofile", "Sid": "S-1-5-18"}, user="systemprofile")
    assert _entity(doc) == {"type": "process", "value": "svchost.exe"}


def test_a_srum_row_without_an_app_name_is_about_the_account():
    doc = _doc("srumecmd", {"ExeInfo": "-", "AppId": "72", "UserId": "4"}, user="tdungan")
    assert _entity(doc) == {"type": "account", "value": "tdungan"}


def test_srum_numeric_table_ids_are_never_a_subject():
    doc = _doc("srumecmd", {"AppId": "72", "UserId": "4", "Sid": "S-1-0-0"})
    assert _entity(doc) == {}


def test_an_amcache_row_names_no_subject_because_its_key_is_a_guid():
    doc = _doc("amcache", {"KeyName": "{094230ee-9132-ef22-cc49-ec4f13ef441d}", "ModelName": "device"})
    assert _entity(doc) == {}


def test_a_pinned_category_decides_the_order_over_the_family():
    # Sysmon event 3 is a network connection in the pinned table, so the destination is its subject even
    # though the row came from SRUM, whose order is process first.
    doc = {
        "family": "srumecmd", "file": "sysmon.evtx", "line": "1", "text": "", "event_id": "3",
        "fields": {"ExeInfo": "svchost.exe"},
        "ecs": {"event": {"provider": "Microsoft-Windows-Sysmon"}, "destination": {"ip": "10.0.0.5"}},
    }
    assert _entity(doc) == {"type": "address", "value": "10.0.0.5"}
