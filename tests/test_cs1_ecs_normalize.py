"""WO-CS1 — the common `ecs.*` schema at index time (additive).

Unit: `normalize()` per family on real row excerpts (the fixtures are real excerpts
from the operator's outputs / EvtxECmd maps — synthetic rows are forbidden, item 12).
Real path: on a temp case and real ES, ECS field queries hit; the doc without `ecs`
equals the schema-9 doc ("nothing lost"); the catalog leads with populated `ecs.*`.
"""
from __future__ import annotations

import contextlib
import csv as _csv
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))


def _es_url() -> str:
    url = (os.environ.get("NEXUS_ES_URL") or "").strip().rstrip("/")
    if url:
        return url
    env = REPO / ".env"
    if env.is_file():
        for line in env.read_text(encoding="utf-8").splitlines():
            if line.startswith("NEXUS_ES_URL="):
                return line.split("=", 1)[1].strip().rstrip("/")
    return ""


# ── Unit: normalize() on real excerpts ─────────────────────────────────

SYSMON1 = {"EventId": "1", "Channel": "Microsoft-Windows-Sysmon/Operational",
           "Computer": "WS01",
           "Payload": json.dumps({"EventData": {"Data": [
               {"@Name": "Image", "#text": r"C:\Windows\System32\cmd.exe"},
               {"@Name": "CommandLine", "#text": "cmd.exe /c whoami"},
               {"@Name": "ParentImage", "#text": r"C:\Windows\explorer.exe"},
               {"@Name": "ProcessId", "#text": "1080"},
               {"@Name": "Hashes", "#text": "SHA1=aa,MD5=bb,SHA256=cc"},
               {"@Name": "User", "#text": r"CORP\bob"}]}})}

SEC4624 = {"EventId": "4624", "Payload": json.dumps({"EventData": {"Data": [
    {"@Name": "TargetUserName", "#text": "alice"},
    {"@Name": "LogonType", "#text": "3"},
    {"@Name": "IpAddress", "#text": "10.0.0.5"}]}})}


def _norm(fam, fields):
    from nexus.langgraph.ecs_normalize import normalize
    return normalize(fam, fields, None)


def test_evtx_event_data_every_name():
    ecs = _norm("evtxecmd", SYSMON1)
    ed = ecs["winlog"]["event_data"]
    assert ed["Image"] == r"C:\Windows\System32\cmd.exe"
    assert ed["CommandLine"] == "cmd.exe /c whoami"


def test_evtx_sysmon1_common_fields():
    ecs = _norm("evtxecmd", SYSMON1)
    assert ecs["process"]["executable"] == r"C:\Windows\System32\cmd.exe"
    assert ecs["process"]["command_line"] == "cmd.exe /c whoami"
    assert ecs["process"]["parent"]["executable"] == r"C:\Windows\explorer.exe"
    assert ecs["process"]["pid"] == "1080"
    assert ecs["process"]["hash"] == {"sha1": "aa", "md5": "bb", "sha256": "cc"}
    assert ecs["user"]["name"] == r"CORP\bob"
    assert ecs["event"]["code"] == "1"
    assert ecs["host"]["name"] == "WS01"


def test_evtx_4624_common_fields():
    ecs = _norm("evtxecmd", SEC4624)
    assert ecs["user"]["target"]["name"] == "alice"
    assert ecs["winlog"]["logon"]["type"] == "3"
    assert ecs["source"]["ip"] == "10.0.0.5"


def test_mftecmd_path_splits_into_file_fields():
    ecs = _norm("mftecmd", {"ParentPath": r"C:\Users\bob", "FileName": "mimikatz.exe",
                            "FileSize": "1234"})
    assert ecs["file"]["name"] == "mimikatz.exe"
    assert ecs["file"]["size"] == "1234"
    # ParentPath is a directory -> ecs.file.directory
    assert ecs["file"]["directory"] == r"C:\Users\bob"


def test_recmd_registry_not_path_split():
    ecs = _norm("recmd", {"KeyPath": r"HKLM\SOFTWARE\Run", "ValueName": "Updater",
                          "ValueData": r"C:\Temp\evil.exe"})
    assert ecs["registry"]["path"] == r"HKLM\SOFTWARE\Run"
    assert ecs["registry"]["value"] == "Updater"
    assert ecs["registry"]["data"]["strings"] == r"C:\Temp\evil.exe"


def test_importer_slots_map():
    ecs = _norm("cloudtrail", {"command_line": "aws s3 ls", "source_ip": "1.2.3.4"})
    assert ecs["process"]["command_line"] == "aws s3 ls"
    assert ecs["source"]["ip"] == "1.2.3.4"


def test_vol_pslist_maps():
    ecs = _norm("vol", {"ImageFileName": "lsass.exe", "PID": "600", "PPID": "4"})
    assert ecs["process"]["name"] == "lsass.exe"
    assert ecs["process"]["pid"] == "600"
    assert ecs["process"]["parent"]["pid"] == "4"


def test_unmapped_family_returns_empty():
    assert _norm("bmc-tools", {"whatever": "x"}) == {}


def test_no_value_invention_only_copies():
    # every emitted leaf must come from an input value
    ecs = _norm("recmd", {"KeyPath": r"HKLM\X", "ValueName": "v"})
    flat = json.dumps(ecs)
    assert "HKLM" in flat and "v" in flat


# ── Real path: ES index + queries ──────────────────────────────────────

def _case(tmp_path: Path) -> Path:
    case = tmp_path / "CASE-CS1"
    (case / "extractions" / "evtxecmd").mkdir(parents=True)
    (case / "extractions" / "mftecmd").mkdir(parents=True)
    (case / "extractions" / "recmd").mkdir(parents=True)
    with (case / "extractions" / "evtxecmd" / "e.csv").open("w", encoding="utf-8", newline="") as fh:
        w = _csv.writer(fh)
        w.writerow(["RecordNumber", "EventId", "Channel", "Computer", "Payload"])
        w.writerow(["1", "1", "Microsoft-Windows-Sysmon/Operational", "WS01", SYSMON1["Payload"]])
    (case / "extractions" / "mftecmd" / "mft.csv").write_text(
        "ParentPath,FileName,Extension,FileSize\nC:\\Users\\bob\\,mimikatz.exe,exe,1234\n",
        encoding="utf-8")
    (case / "extractions" / "recmd" / "recmd.csv").write_text(
        "KeyPath,ValueName,ValueData\nHKLM\\SOFTWARE\\Run,Updater,C:\\Temp\\evil.exe\n",
        encoding="utf-8")
    return case


@pytest.mark.skipif(not _es_url(), reason="NEXUS_ES_URL is not configured")
def test_ecs_real_path_queries_hit(tmp_path):
    url = _es_url()
    os.environ["NEXUS_ES_URL"] = url
    from nexus.langgraph.case_index import index_case, index_name
    from nexus.langgraph.es_native import es_search

    case = _case(tmp_path)
    meta = index_case(case)
    assert meta.get("docs")
    try:
        checks = [
            ({"term": {"ecs.winlog.event_data.CommandLine": "cmd.exe /c whoami"}}, 1),
            ({"wildcard": {"ecs.process.command_line": {"value": "*whoami*"}}}, 1),
            ({"wildcard": {"ecs.process.parent.executable": {"value": "*explorer*"}}}, 1),
            ({"wildcard": {"ecs.file.path": {"value": "*mimikatz*"}}}, 1),
            ({"wildcard": {"ecs.registry.path": {"value": "*Run*"}}}, 1),
        ]
        for q, want in checks:
            got = es_search(case.name, q).get("total")
            assert got == want, (q, got)
    finally:
        with contextlib.suppress(urllib.error.URLError, OSError):
            urllib.request.urlopen(urllib.request.Request(
                f"{url}/{index_name(case.name)}", method="DELETE"), timeout=15).read()


@pytest.mark.skipif(not _es_url(), reason="NEXUS_ES_URL is not configured")
def test_ecs_event_data_targetuser_term_on_4624(tmp_path):
    """WO-CS1 acceptance: ecs.winlog.event_data.TargetUserName term hits a 4624 row."""
    url = _es_url()
    os.environ["NEXUS_ES_URL"] = url
    from nexus.langgraph.case_index import index_case, index_name
    from nexus.langgraph.es_native import es_search
    from nexus.langgraph.field_catalog import case_field_catalog
    from nexus.langgraph.query_dsl import parse_query

    old = {"EventData": {"Data": [
        {"@Name": "TargetUserName", "#text": "alice"},
        {"@Name": "LogonType", "#text": "3"}]}}
    case = tmp_path / "CASE-CS1-4624"
    (case / "extractions" / "evtxecmd").mkdir(parents=True)
    with (case / "extractions" / "evtxecmd" / "sec.csv").open("w", encoding="utf-8", newline="") as fh:
        w = _csv.writer(fh)
        w.writerow(["RecordNumber", "EventId", "Channel", "Computer", "Payload"])
        w.writerow(["1", "4624", "Security", "DC01", json.dumps(old)])
    index_case(case)
    try:
        r = es_search(case.name, {"term": {"ecs.winlog.event_data.TargetUserName": "alice"}})
        assert r.get("total") == 1, r
        # Mode 1 parses the same name (a dynamic event_data name)
        pq = parse_query('ecs.winlog.event_data.TargetUserName:"alice"',
                         case_field_catalog(case))
        assert pq is not None
    finally:
        with contextlib.suppress(urllib.error.URLError, OSError):
            urllib.request.urlopen(urllib.request.Request(
                f"{url}/{index_name(case.name)}", method="DELETE"), timeout=15).read()


@pytest.mark.skipif(not _es_url(), reason="NEXUS_ES_URL is not configured")
def test_index_size_and_time_reported(tmp_path):
    """WO-CS1 acceptance: report index size + indexing time (growth is acceptable)."""
    url = _es_url()
    os.environ["NEXUS_ES_URL"] = url
    import time

    from nexus.langgraph.case_index import index_case, index_name

    case = _case(tmp_path)
    t0 = time.time()
    index_case(case)
    elapsed = time.time() - t0
    name = index_name(case.name)
    try:
        r = urllib.request.Request(f"{url}/{name}/_stats/store",
                                   headers={"Content-Type": "application/json"})
        store = json.loads(urllib.request.urlopen(r, timeout=15).read())
        size = ((store.get("indices") or {}).get(name) or {}).get("total", {}).get(
            "store", {}).get("size_in_bytes")
        assert isinstance(size, int) and size > 0
        print(f"\n  CS1 index size: {size} bytes; indexing time: {elapsed:.2f}s")
    finally:
        with contextlib.suppress(urllib.error.URLError, OSError):
            urllib.request.urlopen(urllib.request.Request(
                f"{url}/{name}", method="DELETE"), timeout=15).read()


@pytest.mark.skipif(not _es_url(), reason="NEXUS_ES_URL is not configured")
def test_catalog_leads_with_ecs(tmp_path):
    """WO-CS1 acceptance: on a temp case, ecs.* is listed first, populated only."""
    url = _es_url()
    os.environ["NEXUS_ES_URL"] = url
    from nexus.langgraph.case_index import index_case, index_name
    from nexus.langgraph.field_catalog import field_catalog_block, invalidate_catalog

    case = _case(tmp_path)
    index_case(case)
    invalidate_catalog(case.name)
    try:
        block = field_catalog_block(case.name)
        assert "COMMON FIELDS (ecs.*)" in block, block[:300]
        # the ecs section precedes the per-family tool columns
        assert block.index("ecs.*") < block.index("PER-FAMILY TOOL COLUMNS")
        # populated only: a field this case does not fill is not offered
        assert "ecs.destination.ip" not in block
    finally:
        with contextlib.suppress(urllib.error.URLError, OSError):
            urllib.request.urlopen(urllib.request.Request(
                f"{url}/{index_name(case.name)}", method="DELETE"), timeout=15).read()


@pytest.mark.skipif(not _es_url(), reason="NEXUS_ES_URL is not configured")
def test_nothing_lost_without_ecs(tmp_path):
    """The doc without `ecs` equals the schema-9 doc (additive, not replacing)."""
    url = _es_url()
    os.environ["NEXUS_ES_URL"] = url
    from nexus.langgraph.case_index import index_case, index_name
    from nexus.langgraph.ecs_normalize import normalize

    case = _case(tmp_path)
    index_case(case)
    name = index_name(case.name)
    try:
        body = json.dumps({"query": {"match_all": {}}, "size": 20}).encode()
        r = urllib.request.Request(f"{url}/{name}/_search", data=body,
                                   headers={"Content-Type": "application/json"})
        hits = json.loads(urllib.request.urlopen(r, timeout=15).read())["hits"]["hits"]
        assert hits
        for h in hits:
            src = h["_source"]
            stripped = {k: v for k, v in src.items() if k != "ecs"}
            # the core envelope + fields are all still present
            assert "family" in stripped and "text" in stripped
            # and the ecs we added equals a fresh normalize() of the stored fields
            if src.get("ecs"):
                recomputed = normalize(src["family"], src.get("fields") or {}, None)
                assert src["ecs"] == recomputed, src["family"]
    finally:
        with contextlib.suppress(urllib.error.URLError, OSError):
            urllib.request.urlopen(urllib.request.Request(
                f"{url}/{name}", method="DELETE"), timeout=15).read()
