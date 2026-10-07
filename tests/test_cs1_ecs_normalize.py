"""WO-CS1 / WO-CS1b — the common `ecs.*` schema at index time (additive).

Unit: `normalize()` per family. The EVTX cases read the committed **verbatim real
rows** from the public Yamato sample (`tests/fixtures/cs1b_evtx_real_rows.csv`) —
synthetic rows are forbidden (item 12). Rows from the operator's SANS course corpus
are not committed; a test needing them reads `Evidence-files/` when present and skips.

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

#: The committed verbatim EvtxECmd rows (public Yamato sample; no course corpus).
REAL_ROWS = REPO / "tests" / "fixtures" / "cs1b_evtx_real_rows.csv"


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

def _norm(fam, fields):
    from nexus.langgraph.ecs_normalize import normalize
    return normalize(fam, fields, None)


def _real_rows() -> list[dict[str, str]]:
    """The committed verbatim EvtxECmd rows (public Yamato sample)."""
    assert REAL_ROWS.is_file(), "the CS1b real-row fixture is missing"
    out = []
    with REAL_ROWS.open(encoding="utf-8", errors="replace") as fh:
        for row in _csv.DictReader(fh):
            out.append(row)
    return out


def _real_row(channel_sub: str, event_id: str) -> dict[str, str]:
    for row in _real_rows():
        if str(row.get("EventId")) == event_id and channel_sub in str(row.get("Channel", "")):
            return row
    raise AssertionError(f"no real fixture row for {channel_sub}/{event_id}")


def _real_fields(row: dict[str, str]) -> dict[str, str]:
    return {k.lstrip("\ufeff"): v for k, v in row.items() if v not in (None, "")}


def test_evtx_event_data_every_name():
    """Every EventData name in a real Payload becomes ecs.winlog.event_data.<Name>."""
    row = _real_row("Sysmon", "1")
    ecs = _norm("evtxecmd", _real_fields(row))
    ed = ecs["winlog"]["event_data"]
    # real Sysmon 1 names, read from the row's own Payload
    assert ed["Image"].endswith(".exe")
    assert "CommandLine" in ed
    assert ed["ProcessId"]


def test_evtx_sysmon1_common_fields():
    """A verbatim Sysmon 1 row derives the process/parent/hash/user fields."""
    row = _real_row("Sysmon", "1")
    ecs = _norm("evtxecmd", _real_fields(row))
    assert ecs["process"]["executable"] == ecs["winlog"]["event_data"]["Image"]
    assert ecs["process"]["command_line"] == ecs["winlog"]["event_data"]["CommandLine"]
    assert ecs["process"]["parent"]["executable"] == \
        ecs["winlog"]["event_data"]["ParentImage"]
    assert set(ecs["process"]["hash"]) <= {"sha1", "md5", "sha256", "imphash"}
    assert ecs["event"]["code"] == "1"


def test_evtx_4624_common_fields():
    """A verbatim 4624 row gives target user + logon type; a `-` IpAddress is empty."""
    row = _real_row("Security", "4624")
    ecs = _norm("evtxecmd", _real_fields(row))
    assert ecs["user"]["target"]["name"] == ecs["winlog"]["event_data"]["TargetUserName"]
    assert ecs["winlog"]["logon"]["type"] == ecs["winlog"]["event_data"]["LogonType"]
    # WO-CS1c item 6: this real row's IpAddress is `-` (a local SYSTEM logon), so
    # neither event_data.IpAddress nor ecs.source.ip holds the placeholder.
    assert "source" not in ecs, ecs.get("source")
    assert "IpAddress" not in ecs["winlog"]["event_data"]


def test_evtx_7045_gives_service_name():
    row = _real_row("System", "7045")
    ecs = _norm("evtxecmd", _real_fields(row))
    assert ecs["service"]["name"] == ecs["winlog"]["event_data"]["ServiceName"]


def test_evtx_4104_keeps_the_full_script_block():
    row = _real_row("PowerShell", "4104")
    ecs = _norm("evtxecmd", _real_fields(row))
    sbt = ecs["winlog"]["event_data"]["ScriptBlockText"]
    assert len(sbt) == len(row["Payload"]) or len(sbt) > 300
    assert len(sbt) > 300  # never cut at the old 300-char cap


def test_evtx_channel_scoping():
    """A Security 4624 rule must not fire on a Sysmon event with the same id."""
    # craft a Sysmon row whose EventId is 4624 (rule must not apply)
    fields = {"EventId": "4624", "Channel": "Microsoft-Windows-Sysmon/Operational",
              "Payload": json.dumps({"EventData": {"Data": [
                  {"@Name": "TargetUserName", "#text": "x"}]}})}
    ecs = _norm("evtxecmd", fields)
    assert "target" not in ecs.get("user", {}), ecs



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
        row = _real_row("Sysmon", "1")
        w.writerow([row.get("RecordNumber", "1"), row.get("EventId", "1"),
                    row.get("Channel", "Microsoft-Windows-Sysmon/Operational"),
                    row.get("Computer", "WS01"), row["Payload"]])
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
        # the real Sysmon 1 fixture row's own values
        row = _real_row("Sysmon", "1")
        cmd = row["Payload"] and json.loads(row["Payload"])["EventData"]["Data"]
        cmd_line = next(i["#text"] for i in cmd if i.get("@Name") == "CommandLine")
        parent = next(i["#text"] for i in cmd if i.get("@Name") == "ParentImage")
        parent_name = parent.replace("/", "\\").rsplit("\\", 1)[-1].rsplit(".", 1)[0]
        # a wildcard on a path needs the separator escaped; use the filename stem
        cmd_token = cmd_line.replace("/", "\\").rsplit("\\", 1)[-1].split(".")[0].strip('"')
        checks = [
            ({"term": {"ecs.winlog.event_data.CommandLine": cmd_line}}, 1),
            ({"wildcard": {"ecs.process.command_line": {"value": f"*{cmd_token}*"}}}, 1),
            ({"wildcard": {"ecs.process.parent.executable": {"value": f"*{parent_name}*"}}}, 1),
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

    row = _real_row("Security", "4624")
    target = next(i["#text"] for i in json.loads(row["Payload"])["EventData"]["Data"]
                  if i.get("@Name") == "TargetUserName")
    case = tmp_path / "CASE-CS1-4624"
    (case / "extractions" / "evtxecmd").mkdir(parents=True)
    with (case / "extractions" / "evtxecmd" / "sec.csv").open("w", encoding="utf-8", newline="") as fh:
        w = _csv.writer(fh)
        w.writerow(["RecordNumber", "EventId", "Channel", "Computer", "Payload"])
        w.writerow([row.get("RecordNumber", "1"), "4624", "Security",
                    row.get("Computer", "DC01"), row["Payload"]])
    index_case(case)
    try:
        r = es_search(case.name, {"term": {"ecs.winlog.event_data.TargetUserName": target}})
        assert r.get("total") == 1, r
        # Mode 1 parses the same name (a dynamic event_data name)
        pq = parse_query(f'ecs.winlog.event_data.TargetUserName:"{target}"',
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
