"""WO-KL2 — tests for knowledge layer research and improvements.

Verifies:
1. LOLDrivers lookups by name and hash in ContextDB and examiner_checks.
2. LOTS domains lookups (Living Off Trusted Sites) and C2/exfiltration classification.
3. LOOBins lookups (macOS Living Off The Land Binaries) and execution/persistence traits.
4. LOLRMM tools in suspicious filenames and filename triage.
5. SANS Hunt Evil process expectations (parents, paths, users, injection guards).
6. HijackLibs DLLs in search-order hijacking database.
7. Behavioural analytics validation for newly cited CAR/Sigma analytics.
8. Authority table completeness (all 37 skills covered with zero conflicts).
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
import yaml

from nexus.analysis import examiner_checks as ec
from nexus.analysis.skill_steps import authority_conflicts, authority_table
from nexus.knowledge.loader import get_skills
from nexus.knowledge.query_validation import validate_stored_query
from nexus.triage.db import CONTEXT_SCHEMA, ContextDB


@pytest.fixture
def memory_context_db(tmp_path: Path) -> ContextDB:
    db_file = tmp_path / "test_context.db"
    conn = sqlite3.connect(str(db_file))
    conn.executescript(CONTEXT_SCHEMA)
    conn.commit()
    conn.close()
    db = ContextDB(db_file, read_only=False)
    db.connect()
    return db


# =============================================================================
# 1. LOLDrivers
# =============================================================================

def test_loldrivers_lookup_by_name(memory_context_db: ContextDB):
    driver = memory_context_db.check_driver_by_name("gdrv.sys")
    assert driver is not None
    assert driver["vendor"] == "GIGABYTE"
    assert driver["cve"] == "CVE-2018-19320"

    # Extension-less resolution
    driver2 = memory_context_db.check_driver_by_name("mhyprot2")
    assert driver2 is not None
    assert driver2["vendor"] == "miHoYo"


def test_loldrivers_lookup_by_hash(memory_context_db: ContextDB):
    # rtcore64.sys hash
    match = memory_context_db.check_vulnerable_driver(
        "89fe837b0266016e7886a0b59b583416a206bb41209b5527a2eb17112003c27e",
        "sha256",
    )
    assert match is not None
    assert match["filename_lower"] == "rtcore64.sys"
    assert match["match_type"] == "file_hash"


def test_examiner_check_driver(memory_context_db: ContextDB):
    result = ec.check_driver(memory_context_db, driver_name="dbutil_2_3.sys")
    assert result["found"] is True
    assert result["verdict"] == "SUSPICIOUS_VULNERABLE_DRIVER"
    assert "CVE-2021-21551" in result["cve"]
    assert "known vulnerable BYOVD driver" in result["interpretation_constraint"]

    # Unknown driver
    unknown = ec.check_driver(memory_context_db, driver_name="innocent_custom_driver.sys")
    assert unknown["found"] is False
    assert unknown["verdict"] == "UNKNOWN"


# =============================================================================
# 2. Living Off Trusted Sites (LOTS)
# =============================================================================

def test_lots_domains_lookup(memory_context_db: ContextDB):
    entry = memory_context_db.check_lots_domain("discordapp.com")
    assert entry is not None
    assert entry["category"] == "c2_exfil"
    assert entry["mitre_technique"] == "T1102.002"

    # Subdomain resolution
    sub = memory_context_db.check_lots_domain("payload.raw.githubusercontent.com")
    assert sub is not None
    assert sub["domain_lower"] == "raw.githubusercontent.com"


def test_examiner_check_lots_domain(memory_context_db: ContextDB):
    res = ec.check_lots_domain(memory_context_db, domain="webhook.site")
    assert res["found"] is True
    assert res["verdict"] == "SUSPICIOUS_LOTS_DOMAIN"
    assert "T1567.002" in res["mitre_technique"]

    unknown = ec.check_lots_domain(memory_context_db, domain="example.internal.corp")
    assert unknown["found"] is False
    assert unknown["verdict"] == "UNKNOWN"


# =============================================================================
# 3. macOS Living Off The Land Binaries (LOOBins)
# =============================================================================

def test_loobins_lookup(memory_context_db: ContextDB):
    osascript = memory_context_db.check_loobin("osascript")
    assert osascript is not None
    assert "execute" in osascript["functions"]
    assert "/usr/bin/osascript" in osascript["paths"]

    launchctl = memory_context_db.check_loobin("launchctl")
    assert launchctl is not None
    assert "persistence" in launchctl["functions"]


def test_examiner_check_loobin(memory_context_db: ContextDB):
    res = ec.check_loobin(memory_context_db, binary_name="security")
    assert res["found"] is True
    assert res["verdict"] == "EXPECTED_LOOBIN"
    assert "credentials" in res["functions"]

    unknown = ec.check_loobin(memory_context_db, binary_name="unknown_mac_tool")
    assert unknown["found"] is False
    assert unknown["verdict"] == "UNKNOWN"


# =============================================================================
# 4. LOLRMM Tools in Suspicious Filenames
# =============================================================================

def test_lolrmm_filenames(memory_context_db: ContextDB):
    rmm_tools = ["anydesk.exe", "teamviewer.exe", "rustdesk.exe", "screenconnect.exe", "parsec.exe"]
    for tool in rmm_tools:
        match = memory_context_db.check_suspicious_filename(tool)
        assert match is not None, f"Expected {tool} in suspicious filenames"
        assert match["category"] == "lotrmm"

    # Filename triage integration
    triage = ec.analyze_filename_triage(memory_context_db, filename="rustdesk.exe")
    assert triage["is_suspicious"] is True
    assert any(f.get("tool_name") == "rustdesk" for f in triage["findings"])


# =============================================================================
# 5. SANS Hunt Evil Process Tree Expectations
# =============================================================================

def test_hunt_evil_process_baselines(memory_context_db: ContextDB):
    lsass = memory_context_db.get_expected_process("lsass.exe")
    assert lsass is not None
    assert lsass["never_spawns_children"] == 1
    assert "wininit.exe" in lsass["valid_parents"]

    # Legitimate lsass tree
    ok = ec.check_process_tree(
        memory_context_db,
        process_name="lsass.exe",
        parent_name="wininit.exe",
        path=r"C:\Windows\System32\lsass.exe",
        user=r"NT AUTHORITY\SYSTEM",
    )
    assert ok["verdict"] == "EXPECTED"

    # Illegitimate parent (cmd spawning lsass or lsass under explorer)
    bad_parent = ec.check_process_tree(
        memory_context_db,
        process_name="lsass.exe",
        parent_name="explorer.exe",
        path=r"C:\Windows\System32\lsass.exe",
        user=r"NT AUTHORITY\SYSTEM",
    )
    assert bad_parent["verdict"] == "SUSPICIOUS"
    assert "Unexpected parent process" in bad_parent["reasons"]


# =============================================================================
# 6. HijackLibs
# =============================================================================

def test_hijackable_dlls(memory_context_db: ContextDB):
    res = ec.check_hijackable_dll(memory_context_db, dll_name="version.dll")
    assert res["hijackable"] is True
    assert len(res["entries"]) > 0

    res2 = ec.check_hijackable_dll(memory_context_db, dll_name="amsi.dll")
    assert res2["hijackable"] is True


# =============================================================================
# 7. Behavioural Analytics
# =============================================================================

def test_behavioural_analytics_pack():
    yaml_path = Path("src/nexus/data/knowledge/needles/behavioral_analytics.yaml")
    assert yaml_path.exists()
    content = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    packs = content.get("packs", [])
    assert len(packs) >= 36

    new_ids = {
        "ba-lat-wmi-process-create",
        "ba-pers-schtask-reg-mod",
        "ba-c2-living-off-trusted-sites",
        "ba-priv-printspooler-exploit",
        "ba-cred-lsass-minidump-write",
    }
    found_ids = {p["id"] for p in packs}
    assert new_ids.issubset(found_ids)

    for p in packs:
        if p["id"] in new_ids:
            assert "citation" in p
            assert p["citation"].get("id")
            es_query = p["es"]
            errs = validate_stored_query(
                es_query,
                declared_families=p.get("families"),
                citation=[p["citation"]["id"]],
            )
            assert errs == [], f"{p['id']} query errors: {errs}"


# =============================================================================
# 8. Authority Table Completeness
# =============================================================================

def test_authority_table_covers_all_skills():
    skills = get_skills()
    assert len(skills) == 37
    table = authority_table()
    assert len(table) >= 37
    conflicts = authority_conflicts(skills)
    assert conflicts == []
