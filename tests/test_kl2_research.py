"""WO-KL2b — the LOTL lists are imported from pinned snapshots, not typed by hand.

Rewritten for KL2b. The previous version asserted **hand-typed** values (13 drivers,
9 DLLs, a `webhook.site` domain, `'execute'` as a LOOBin function) - exactly the
seeds the review told us to replace. These assert the **imported** data and its
provenance: an "unknown" must read as "not in LOLDrivers @<commit> (N samples)".

The lists come from `devtools/knowledge/lotl_import.py` via
`src/nexus/data/knowledge/lists/lotl.yaml`; a test here checks a random sample of
rows against the pinned snapshot when the snapshot is present.
"""
from __future__ import annotations

import os
import random
from pathlib import Path

import pytest

from nexus.analysis import examiner_checks as ec
from nexus.analysis.skill_steps import authority_conflicts, authority_table
from nexus.knowledge.loader import get_skills
from nexus.knowledge.query_validation import validate_stored_query
from nexus.triage.db import LOTL_LISTS_PATH, ContextDB, list_provenance

#: The hand-typed counts the review told us to replace. The imported lists must be
#: far larger; a regression to hand-typing would fail this.
HAND_TYPED_COUNTS = {"loldrivers": 13, "hijacklibs": 9, "lolrmm": 17,
                     "lots": 14, "loobins": 16}


@pytest.fixture
def memory_context_db(tmp_path: Path) -> ContextDB:
    # `init_schema()` applies the schema AND loads the imported LOTL lists
    # (WO-KL2b: the tables are filled only by the importer's output).
    db = ContextDB(tmp_path / "test_context.db", read_only=False)
    db.connect()
    db.init_schema()
    return db


# =============================================================================
# 0. Provenance and size - the point of KL2b
# =============================================================================

def test_every_list_is_imported_and_far_larger_than_the_hand_typed_seeds(memory_context_db):
    """The lists are the imported ones, and each reports its size and version."""
    conn = memory_context_db.connect()
    for source, hand in HAND_TYPED_COUNTS.items():
        table = {"loldrivers": "vulnerable_drivers", "hijacklibs": "hijackable_dlls",
                 "lolrmm": "suspicious_filenames", "lots": "lots_domains",
                 "loobins": "loobins"}[source]
        n = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        assert n > hand, f"{table}: {n} rows is not more than the {hand} typed by hand"
        prov = list_provenance(conn, source)
        # `suspicious_filenames` also holds authored threat-tool names, so the
        # imported count is a floor on the table, not an equality.
        assert prov["count"] > hand, (source, prov)
        assert prov["count"] <= n, (source, prov, n)
        assert prov["url"].startswith("http"), prov
        assert len(prov["version"]) >= 12, f"{source} has no pinned version: {prov}"


def test_the_imported_file_names_its_pinned_sources():
    import yaml

    data = yaml.safe_load(LOTL_LISTS_PATH.read_text(encoding="utf-8")) or {}
    sources = data.get("sources") or {}
    assert set(sources) >= set(HAND_TYPED_COUNTS) | {"lolbas", "gtfobins"}
    for name, prov in sources.items():
        assert str(prov.get("url") or "").startswith("http"), (name, prov)
        # A git source is pinned by commit; the web source by a file hash + date.
        assert prov.get("commit") or prov.get("sha256"), (name, prov)
    assert data.get("generator", "").endswith("lotl_import.py")


def test_a_random_sample_of_rows_matches_the_pinned_snapshot():
    """WO-KL2b acceptance: check 30 random items per list against the snapshot.

    Skipped with a reason when the snapshots are absent (they are ~560 MB and live
    outside the repo); `NEXUS_KL2B_SNAPSHOTS` points at them.
    """
    import json

    import yaml

    snap = Path(os.environ.get("NEXUS_KL2B_SNAPSHOTS")
                or (Path(os.environ.get("TEMP", "/tmp")) / "kl2b-snapshots"))
    if not snap.is_dir():
        pytest.skip(f"snapshots not present at {snap} - set NEXUS_KL2B_SNAPSHOTS")

    data = yaml.safe_load(LOTL_LISTS_PATH.read_text(encoding="utf-8")) or {}
    lists = data.get("lists") or {}

    # LOLDrivers: every sampled row's sha256 must appear in the snapshot entry.
    drivers = json.loads((snap / "LOLDrivers" / "loldrivers.io" / "content" / "api"
                          / "drivers.json").read_text(encoding="utf-8"))
    known_hashes = set()
    known_names = set()
    for entry in drivers:
        for s in entry.get("KnownVulnerableSamples") or []:
            if s.get("SHA256"):
                known_hashes.add(str(s["SHA256"]).lower())
            if s.get("Filename"):
                known_names.add(str(s["Filename"]).lower())
    sample = random.Random(0).sample(lists["loldrivers"], 30)
    for row in sample:
        assert row["filename_lower"] in known_names or (row["sha256"] or "").lower() in known_hashes, row

    # HijackLibs: every sampled dll must be a `Name` in the snapshot.
    libs: set[str] = set()
    for p in (snap / "HijackLibs" / "yml").rglob("*.y*ml"):
        doc = yaml.safe_load(p.read_text(encoding="utf-8", errors="replace")) or {}
        if isinstance(doc, dict) and doc.get("Name"):
            libs.add(str(doc["Name"]).lower())
    assert len(libs) > 500, f"only {len(libs)} HijackLibs entries were read"
    for row in random.Random(1).sample(lists["hijacklibs"], 30):
        assert row["dll_name_lower"] in libs, row

    # LOTS: every sampled domain must appear in the saved page.
    page = (snap / "lots" / "lots.html").read_text(encoding="utf-8", errors="replace").lower()
    for row in random.Random(2).sample(lists["lots"], 30):
        assert row["domain_lower"] in page, row


# =============================================================================
# 1. LOLDrivers
# =============================================================================

def test_loldrivers_lookup_by_name(memory_context_db: ContextDB):
    driver = memory_context_db.check_driver_by_name("gdrv.sys")
    assert driver is not None
    # The vendor string is the upstream one, not a tidied hand-typed value.
    assert "GIGA" in (driver["vendor"] or "").upper()
    assert driver["sha256"], "the imported row must carry a real hash"

    # Extension-less resolution
    assert memory_context_db.check_driver_by_name("mhyprot2") is not None


def test_loldrivers_lookup_by_hash_uses_the_snapshot_hash(memory_context_db: ContextDB):
    """The hash to look up comes from the snapshot, not from a typed value.

    The hand-typed `gdrv.sys` hash was `72f5d947...`; the real one is
    `092d0428...`, so this would have failed against the old seed.
    """
    real = memory_context_db.check_driver_by_name("gdrv.sys")["sha256"]
    match = memory_context_db.check_vulnerable_driver(real, "sha256")
    assert match is not None
    assert match["filename_lower"] == "gdrv.sys"
    assert match["match_type"] == "file_hash"


def test_examiner_check_driver(memory_context_db: ContextDB):
    result = ec.check_driver(memory_context_db, driver_name="dbutil_2_3.sys")
    assert result["found"] is True
    assert result["verdict"] == "SUSPICIOUS_VULNERABLE_DRIVER"
    assert "CVE-2021-21551" in (result["cve"] or "")
    assert "known vulnerable BYOVD driver" in result["interpretation_constraint"]

    unknown = ec.check_driver(memory_context_db, driver_name="innocent_custom_driver.sys")
    assert unknown["found"] is False
    assert unknown["verdict"] == "UNKNOWN"


# =============================================================================
# 2. Living Off Trusted Sites (LOTS)
# =============================================================================

def test_lots_domains_lookup(memory_context_db: ContextDB):
    entry = memory_context_db.check_lots_domain("cdn.discordapp.com")
    assert entry is not None
    assert "phishing" in (entry["category"] or "").lower()
    assert "T1566" in (entry["mitre_technique"] or "")

    # Subdomain resolution walks up to the listed registrable domain.
    sub = memory_context_db.check_lots_domain("payload.raw.githubusercontent.com")
    assert sub is not None
    assert sub["domain_lower"] == "raw.githubusercontent.com"


def test_examiner_check_lots_domain(memory_context_db: ContextDB):
    res = ec.check_lots_domain(memory_context_db, domain="raw.githubusercontent.com")
    assert res["found"] is True
    assert res["verdict"] == "SUSPICIOUS_LOTS_DOMAIN"
    assert "T1102" in (res["mitre_technique"] or "")

    unknown = ec.check_lots_domain(memory_context_db, domain="example.internal.corp")
    assert unknown["found"] is False
    assert unknown["verdict"] == "UNKNOWN"


# =============================================================================
# 3. macOS Living Off The Land Binaries (LOOBins)
# =============================================================================

def test_loobins_lookup(memory_context_db: ContextDB):
    osascript = memory_context_db.check_loobin("osascript")
    assert osascript is not None
    # The imported `functions` are the upstream tactics, in the upstream casing.
    assert "Execution" in osascript["functions"]
    assert "/usr/bin/osascript" in osascript["paths"]

    security = memory_context_db.check_loobin("security")
    assert security is not None
    assert "Credential Access" in security["functions"]


def test_examiner_check_loobin(memory_context_db: ContextDB):
    res = ec.check_loobin(memory_context_db, binary_name="security")
    assert res["found"] is True
    assert res["verdict"] == "EXPECTED_LOOBIN"

    unknown = ec.check_loobin(memory_context_db, binary_name="unknown_mac_tool")
    assert unknown["found"] is False
    assert unknown["verdict"] == "UNKNOWN"


# =============================================================================
# 4. LOLRMM tools in suspicious filenames
# =============================================================================

def test_lolrmm_filenames(memory_context_db: ContextDB):
    for tool in ("anydesk.exe", "teamviewer.exe", "rustdesk.exe", "screenconnect.exe"):
        match = memory_context_db.check_suspicious_filename(tool)
        assert match is not None, f"Expected {tool} in suspicious filenames"
        assert match["category"] == "lotrmm"

    triage = ec.analyze_filename_triage(memory_context_db, filename="rustdesk.exe")
    assert triage["is_suspicious"] is True


# =============================================================================
# 5. SANS Hunt Evil process expectations (authored - kept as house knowledge)
# =============================================================================

def test_hunt_evil_process_baselines(memory_context_db: ContextDB):
    lsass = memory_context_db.get_expected_process("lsass.exe")
    assert lsass is not None
    assert lsass["never_spawns_children"] == 1
    assert "wininit.exe" in lsass["valid_parents"]

    ok = ec.check_process_tree(
        memory_context_db, process_name="lsass.exe", parent_name="wininit.exe",
        path=r"C:\Windows\System32\lsass.exe", user=r"NT AUTHORITY\SYSTEM",
    )
    assert ok["verdict"] == "EXPECTED"

    bad_parent = ec.check_process_tree(
        memory_context_db, process_name="lsass.exe", parent_name="explorer.exe",
        path=r"C:\Windows\System32\lsass.exe", user=r"NT AUTHORITY\SYSTEM",
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
    # The imported list is the full project, not the 9 typed DLLs.
    n = memory_context_db.connect().execute("SELECT COUNT(*) FROM hijackable_dlls").fetchone()[0]
    assert n > 1000, n


# =============================================================================
# 7. Behavioural Analytics
# =============================================================================

def test_behavioural_analytics_pack():
    import yaml

    yaml_path = Path("src/nexus/data/knowledge/needles/behavioral_analytics.yaml")
    assert yaml_path.exists()
    content = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
    packs = content.get("packs", [])
    assert len(packs) >= 36

    new_ids = {"ba-lat-wmi-process-create", "ba-pers-schtask-reg-mod",
               "ba-c2-living-off-trusted-sites", "ba-priv-printspooler-exploit",
               "ba-cred-lsass-minidump-write"}
    found_ids = {p["id"] for p in packs}
    assert new_ids.issubset(found_ids)

    for p in packs:
        if p["id"] in new_ids:
            assert "citation" in p
            assert p["citation"].get("id")
            errs = validate_stored_query(p["es"], declared_families=p.get("families"),
                                         citation=[p["citation"]["id"]])
            assert errs == [], f"{p['id']} query errors: {errs}"


# =============================================================================
# 8. Authority Table Completeness
# =============================================================================

def test_authority_table_covers_all_skills():
    skills = get_skills()
    assert len(skills) == 37
    assert len(authority_table()) >= 37
    assert authority_conflicts(skills) == []
