"""D474, D496, D497: a Chainsaw or Zircolite row is read back as its event (2026-10-30).

The rows are T12's (public, CC0; OD-T7), verbatim: Chainsaw 2.16.5's hunt CSV from the lane's T12-OPT run, and four
lines of Zircolite 4.5.0's own NDJSON template export of the same logs. Their event data used to be added after the
step that types an event, so a Zircolite 4688 row had no process and no user, its rule columns and the event's System
fields read as event data, and Chainsaw's YAML cell was read line by line (doubled quotes kept). Zircolite's CSV
export, which the lane read, prefixed `'` to an absent `-` (D496). A 4624's source workstation was the host (D497).
"""
from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from nexus.langgraph import tool_events
from nexus.langgraph.case_index import _record_fields
from nexus.langgraph.ecs_normalize import normalize

FIXTURES = Path(__file__).parent / "fixtures"
CHAINSAW = list(csv.DictReader((FIXTURES / "d474_chainsaw_t12_sigma.csv").open(encoding="utf-8", newline="")))
ZIRCOLITE = [line for line in (FIXTURES / "d474_zircolite_t12.ndjson").read_text(encoding="utf-8").splitlines()
             if line.strip()]
REPO = Path(__file__).resolve().parents[1]


def _chainsaw(event_id: str) -> dict:
    return normalize("chainsaw", next(r for r in CHAINSAW if r["Event ID"] == event_id))


def _zircolite(event_id: int) -> dict:
    # The indexer's own reading of a JSON line, as the lane's index passes it on.
    line = next(line for line in ZIRCOLITE if json.loads(line)["EventID"] == event_id)
    return normalize("zircolite", _record_fields(line))


def test_a_zircolite_4688_line_is_typed_as_its_event():
    ecs = _zircolite(4688)
    assert (ecs["winlog"]["channel"], ecs["event"]["code"], ecs["host"]["name"]) == (
        "Security", "4688", "fs01.offsec.lan")
    assert ecs["process"]["executable"] == "C:\\Windows\\System32\\cmd.exe"
    assert ecs["process"]["command_line"] == "cmd.exe /C whoami > C:\\Windows\\Temp\\bouWFQYO.tmp 2>&1"
    assert ecs["user"]["name"] == "OFFSEC\\FS01$"
    data = ecs["winlog"]["event_data"]
    own = {"title", "id", "description", "rule_level", "row_id", "OriginalLogfile", "Channel", "EventID", "Computer",
           "Provider_Name", "SystemTime", "EventRecordID", "Keywords"}
    assert not own & set(data), "the rule's and the tool's columns and the System fields are not event data"
    # Raw columns preserve the event's `-`; the shared ECS policy omits absent values (it must not type `'-`).
    raw = next(_record_fields(line) for line in ZIRCOLITE if json.loads(line)["EventID"] == 4688)
    assert raw["TargetUserName"] == "-"
    assert "TargetUserName" not in data


def test_zircolite_keeps_a_multi_line_value_as_written():
    access = _zircolite(5145)["winlog"]["event_data"]["AccessList"]
    assert access.startswith("%%4416\r\n\t\t\t\t%%4423"), "the CSV export turned these newlines into spaces"


def test_a_chainsaw_row_takes_its_channel_from_the_pinned_manifests_and_reads_its_yaml_cell():
    ecs = _chainsaw("4697")
    assert (ecs["winlog"]["channel"], ecs["event"]["code"], ecs["user"]["name"]) == (
        "Security", "4697", "OFFSEC\\admmig")
    service = ecs["winlog"]["event_data"]["ServiceFileName"]
    assert "$b='powershell.exe'" in service and "''powershell.exe''" not in service


def test_a_chainsaw_sysmon_row_is_typed_by_sysmons_own_channel():
    ecs = _chainsaw("1")
    assert ecs["winlog"]["channel"] == "Microsoft-Windows-Sysmon/Operational"
    assert ecs["process"]["executable"] == "C:\\TOOLS\\PsExec64.exe"
    assert ecs["process"]["hash"]["sha256"] == "ad6b98c01ee849874e4b4502c3d7853196f6044240d3271e4ab3fc6e3c08e9a4"


def test_both_tools_read_one_event_alike():
    for event_id in ("4697", "4624"):
        a, b = _chainsaw(event_id), _zircolite(int(event_id))
        for path in (("winlog", "channel"), ("winlog", "record_id"), ("event", "code"), ("host", "name"),
                     ("user",), ("source",)):
            left, right = a, b
            for key in path:
                left, right = (left or {}).get(key), (right or {}).get(key)
            assert left == right, (event_id, path, left, right)


def test_a_4624s_source_workstation_is_its_source_not_its_host():
    ecs = _chainsaw("4624")
    assert ecs["host"]["name"] == "fs03vuln.offsec.lan"
    assert (ecs["source"]["domain"], ecs["source"]["ip"]) == ("0Konuy9q8HtkWeKS", "10.23.123.11")


def test_a_hayabusa_logon_keeps_the_logging_host_when_the_source_workstation_differs():
    """D497: this verbatim T12 record used to replace Computer with WorkstationName in ecs.host.name."""
    with (FIXTURES / "d497_hayabusa_t12.csv").open(encoding="utf-8", newline="") as stream:
        row = next(csv.DictReader(stream))
    ecs = normalize("hayabusa", row)
    assert ecs["host"]["name"] == row["Computer"] == "fs03vuln.offsec.lan"
    assert ecs["source"]["domain"] == "0Konuy9q8HtkWeKS"


@pytest.mark.parametrize("compressed", [False, True])
def test_the_index_walk_reads_detection_exports_as_whole_events(tmp_path, monkeypatch, compressed):
    """The lane's two export formats pass through the real walker, field reader and normalizer."""
    import gzip

    from nexus.langgraph import pipeline_runs
    from nexus.langgraph.case_index import iter_index_doc_batches

    case = tmp_path / "CASE-DETECTION-EVENTS"
    extractions = case / "runs" / "RUN-1" / "extractions"
    monkeypatch.setattr(pipeline_runs, "resolve_tools_extractions", lambda case_dir, run_id="": extractions)
    for family, source, name in (
        ("chainsaw", "d474_chainsaw_t12_sigma.csv", "sigma.csv"),
        ("zircolite", "d474_zircolite_t12.ndjson", "zircolite.ndjson"),
    ):
        folder = extractions / family
        folder.mkdir(parents=True)
        raw = (FIXTURES / source).read_bytes()
        if compressed and family == "zircolite":
            raw, name = gzip.compress(raw), name + ".gz"
        (folder / name).write_bytes(raw)

    assert pipeline_runs._extractions_have_data(extractions / "zircolite")
    docs = [doc for batch in iter_index_doc_batches(case) for doc in batch]
    assert len(docs) == len(CHAINSAW) + len(ZIRCOLITE)
    assert all(doc["ecs"]["winlog"]["channel"] for doc in docs)
    assert all(doc["event_id"] == doc["ecs"]["event"]["code"] for doc in docs)
    process = next(doc for doc in docs if doc["family"] == "zircolite" and doc["event_id"] == "4688")
    assert process["ecs"]["process"]["executable"] == "C:\\Windows\\System32\\cmd.exe"
    assert process["fields"]["TargetUserName"] == "-"
    share = next(doc for doc in docs if doc["family"] == "zircolite" and doc["event_id"] == "5145")
    assert share["fields"]["AccessList"] == share["ecs"]["winlog"]["event_data"]["AccessList"]
    assert "\r\n" in share["fields"]["AccessList"]


INSTALLED = REPO / "tools" / "windows" / "extra"


@pytest.mark.skipif(not (INSTALLED / "zircolite").is_dir() or not (INSTALLED / "chainsaw").is_dir(),
                    reason="Chainsaw and Zircolite are not installed on this host")
def test_the_column_table_is_what_the_installed_tools_say():
    """The lane runs the installed copies; the table was generated from the tags. They are the same files."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "import_tool_event_columns", REPO / "devtools" / "knowledge" / "import_tool_event_columns.py")
    importer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(importer)
    table = tool_events._table()
    for tool, (_version, _repo, _tag, wanted) in importer.SOURCES.items():
        recorded = {s["file"]: s["sha256"] for s in table[tool]["sources"]}
        for path, installed in wanted.values():
            if installed is not None:
                assert importer.lf_sha256(installed.read_bytes()) == recorded[path], path
    files = {key: installed.read_bytes() for key, (_p, installed) in importer.SOURCES["chainsaw"][3].items()}
    assert importer.chainsaw_body(files)["columns"] == table["chainsaw"]["columns"]
    zirc = importer.SOURCES["zircolite"][3]
    assert importer.zircolite_system(zirc["config"][1].read_bytes()) == table["zircolite"]["system"]
    assert importer.zircolite_rule(zirc["template"][1].read_bytes()) == table["zircolite"]["rule"]
