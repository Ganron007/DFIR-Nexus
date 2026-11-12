"""Unit tests for T2-3 to T2-9 (2A Advanced Forensic Analytics)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from nexus.analysis.analytics_2a import (
    column_frequency_stack,
    detect_account_hopping,
    detect_ransomware_patterns,
    detect_timestomp_drift,
    extract_motw_urls,
    fuzzy_search,
    reconstruct_process_tree,
    score_process_ancestry,
)


def test_fuzzy_search_and_typosquatting():
    candidates = ["powershell.exe", "powrshell.exe", "cmd.exe", "svchost.exe", "svch0st.exe", "explorer.exe"]

    # Search for powershell typosquatting
    matches = fuzzy_search("powershell.exe", candidates, max_distance=2)
    assert len(matches) == 1
    assert matches[0]["candidate"] == "powrshell.exe"
    assert matches[0]["distance"] == 1

    # Search for svchost typosquatting
    matches_svc = fuzzy_search("svchost.exe", candidates, max_distance=1)
    assert len(matches_svc) == 1
    assert matches_svc[0]["candidate"] == "svch0st.exe"


def test_column_frequency_stack():
    # 95 normal values, 5 rare values
    values = ["svchost.exe"] * 95 + ["rare_tool.exe"] * 3 + ["evil.exe"] * 2
    res = column_frequency_stack(values, rare_threshold_pct=5.0)

    assert res["total_count"] == 100
    assert res["unique_count"] == 3
    assert len(res["rare_values"]) == 2

    rare_names = [r["value"] for r in res["rare_values"]]
    assert "rare_tool.exe" in rare_names
    assert "evil.exe" in rare_names


def test_reconstruct_process_tree():
    events = [
        {"pid": "100", "ppid": "4", "process_name": "services.exe", "parent_process_name": "wininit.exe", "host": "WS01"},
        {"pid": "200", "ppid": "100", "process_name": "svchost.exe", "parent_process_name": "services.exe", "host": "WS01"},
        {"pid": "300", "ppid": "200", "process_name": "cmd.exe", "parent_process_name": "svchost.exe", "host": "WS01"},
    ]

    tree = reconstruct_process_tree(events)
    assert tree["node_count"] == 3
    assert tree["edge_count"] == 3

    child_pairs = [(e["parent_name"], e["child_name"]) for e in tree["edges"]]
    assert ("services.exe", "svchost.exe") in child_pairs
    assert ("svchost.exe", "cmd.exe") in child_pairs


def test_score_process_ancestry():
    # Protected process with wrong parent
    res_lsass = score_process_ancestry("cmd.exe", "lsass.exe")
    assert res_lsass["suspicious"] is True
    assert res_lsass["score"] >= 90
    assert res_lsass["rule"] == "illegal_system_parent"

    # Server spawning shell
    res_iis = score_process_ancestry("w3wp.exe", "powershell.exe")
    assert res_iis["suspicious"] is True
    assert res_iis["score"] >= 90
    assert res_iis["rule"] == "server_shell_spawn"

    # Normal process
    res_normal = score_process_ancestry("explorer.exe", "notepad.exe")
    assert res_normal["suspicious"] is False


def test_detect_account_hopping():
    base_time = datetime(2026, 11, 12, 10, 0, 0, tzinfo=UTC)
    logons = [
        {"user": "compromised_admin", "host": "DC01", "timestamp": base_time.isoformat()},
        {"user": "compromised_admin", "host": "FILE01", "timestamp": (base_time + timedelta(minutes=15)).isoformat()},
        {"user": "compromised_admin", "host": "SQL01", "timestamp": (base_time + timedelta(minutes=30)).isoformat()},
        {"user": "regular_user", "host": "WS01", "timestamp": base_time.isoformat()},
    ]

    hops = detect_account_hopping(logons, window_seconds=3600, min_hosts=3)
    assert len(hops) == 1
    assert hops[0]["user"] == "compromised_admin"
    assert hops[0]["host_count"] == 3
    assert set(hops[0]["hosts"]) == {"dc01", "file01", "sql01"}


def test_detect_ransomware_patterns():
    file_events = [
        {"path": "C:\\Docs\\HOW_TO_DECRYPT.txt", "action": "created"},
        {"path": "C:\\Docs\\Financials.xlsx.locked", "action": "modify"},
        {"path": "C:\\Docs\\Customers.db.locked", "action": "modify"},
    ]

    res = detect_ransomware_patterns(file_events, burst_threshold=2)
    assert res["is_ransomware_detected"] is True
    assert res["ransom_note_count"] == 1
    assert res["encrypted_file_count"] == 2
    assert "C:\\Docs\\HOW_TO_DECRYPT.txt" in res["sample_ransom_notes"]


def test_detect_timestomp_drift():
    # SI backdated to 2020, but FN shows 2026
    si_time = "2020-01-01T12:00:00.000000Z"
    fn_time = "2026-11-12T12:00:00.123456Z"

    drift = detect_timestomp_drift(si_time, fn_time, drift_threshold_seconds=3600)
    assert drift["timestomped"] is True
    assert drift["drift_seconds"] > 3600
    assert drift["zero_subseconds"] is True
    assert len(drift["reasons"]) == 2


def test_extract_motw_urls():
    content = (
        "[ZoneTransfer]\n"
        "ZoneId=3\n"
        "ReferrerUrl=https://malicious-site.com/download.php\n"
        "HostUrl=https://malicious-site.com/files/invoice.zip\n"
    )

    motw = extract_motw_urls(content)
    assert motw["zone_id"] == "3"
    assert motw["zone_name"] == "Internet"
    assert motw["referrer_url"] == "https://malicious-site.com/download.php"
    assert motw["host_url"] == "https://malicious-site.com/files/invoice.zip"
