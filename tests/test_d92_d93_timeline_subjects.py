"""Tests for D92 and D93 — MemProcFS memory timeline free-text parsing.
"""
from __future__ import annotations

from nexus.langgraph.subject import family_subject_fields, parse_memprocfs_timeline_text


def test_memprocfs_timeline_prefetch_parsing():
    text = "SEARCHFILTERHOST.EXE             - run_count:27560 file:[SEARCHFILTERHOST.EXE-77482212.pf]"
    parsed = parse_memprocfs_timeline_text(text)
    assert parsed.get("process") == "SEARCHFILTERHOST.EXE"

    hit = {
        "family": "memprocfs",
        "fields": {"Text": text, "Type": "PREF"},
    }
    fields = family_subject_fields(hit)
    assert fields.get("process") == "SEARCHFILTERHOST.EXE"


def test_memprocfs_timeline_process_parsing():
    # Standard exe process
    text1 = "SearchFilterHost.exe [*SYSTEM] \\Device\\HarddiskVolume2\\Windows\\System32\\SearchFilterHost.exe"
    parsed1 = parse_memprocfs_timeline_text(text1)
    assert parsed1.get("process") == "SearchFilterHost.exe"

    hit1 = {
        "family": "memprocfs",
        "fields": {"Text": text1, "Type": "PROC"},
    }
    assert family_subject_fields(hit1).get("process") == "SearchFilterHost.exe"

    # Non-exe system process (e.g. MemCompression, System)
    text2 = "MemCompression [*SYSTEM] MemCompression"
    parsed2 = parse_memprocfs_timeline_text(text2)
    assert parsed2.get("process") == "MemCompression"

    text3 = "System [*SYSTEM] System"
    parsed3 = parse_memprocfs_timeline_text(text3)
    assert parsed3.get("process") == "System"


def test_memprocfs_timeline_amcache_parsing():
    text = (
        "AmCache file inventory record updated: "
        "c:\\program files\\common files\\microsoft shared\\clicktorun\\updates\\16.0.11929.20606\\officeclicktorun.exe"
    )
    parsed = parse_memprocfs_timeline_text(text)
    assert parsed.get("process") == "officeclicktorun.exe"
    assert parsed.get("file_path") == (
        "c:\\program files\\common files\\microsoft shared\\clicktorun\\updates\\16.0.11929.20606\\officeclicktorun.exe"
    )

    hit = {
        "family": "memprocfs",
        "fields": {"Text": text, "Type": "AMCA"},
    }
    fields = family_subject_fields(hit)
    assert fields.get("process") == "officeclicktorun.exe"
    assert "officeclicktorun.exe" in fields.get("file_path", "")


def test_memprocfs_timeline_net_parsing():
    text = "TCPv4  ESTABLISHED  172.16.6.101:62466            172.16.4.10:8080            "
    parsed = parse_memprocfs_timeline_text(text)
    assert parsed.get("source_ip") == "172.16.6.101"
    assert parsed.get("destination_ip") == "172.16.4.10"

    hit = {
        "family": "memprocfs",
        "fields": {"Text": text, "Type": "Net"},
    }
    fields = family_subject_fields(hit)
    assert fields.get("source_ip") == "172.16.6.101"
    assert fields.get("destination_ip") == "172.16.4.10"
