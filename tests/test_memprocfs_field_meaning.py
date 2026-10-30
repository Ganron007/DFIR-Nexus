"""D470: MemProcFS's own tables are read by what each column means in that table (TA-5).

T22 (CASE-4387EB47, one memory image, 1,737,335 rows) is read from MemProcFS's forensic CSVs, and the ECS map had no
entry for them. Its 42,931 event-log rows from memory carried no `ecs.winlog.channel`, `ecs.event.code` or
`ecs.host.name`, so every stored Windows-event query (460 filters on `ecs.winlog.channel`) and the host identity
missed them; its 140 connections had no typed address; and the envelope `user` took `tasks.csv`'s `User`, a scheduled
task's principal id (`Author` 33 rows, `Users` 24), for an account. One column name can mean two things in two of
MemProcFS's tables, so its columns are mapped per table, by the tool's own file name.
"""
from __future__ import annotations

import csv
import io
import json
from pathlib import Path

import pytest

from nexus.langgraph.case_index import _host_user_event
from nexus.langgraph.ecs_normalize import load_ecs_map, normalize

T22 = json.loads((Path(__file__).parent / "fixtures" / "memprocfs_t22_rows.json").read_text(encoding="utf-8"))
ROWS = T22["rows"]


def _flat(node: dict, prefix: str = "") -> dict[str, str]:
    out: dict[str, str] = {}
    for key, value in node.items():
        path = f"{prefix}.{key}" if prefix else key
        if isinstance(value, dict):
            out.update(_flat(value, path))
        else:
            out[path] = value
    return out


def test_a_memory_connection_has_its_addresses_and_its_process():
    outlook = _flat(normalize("memprocfs", ROWS["net.csv"][1], table="net.csv"))
    assert outlook["source.ip"] == "172.16.6.101" and outlook["source.port"] == "62036"
    assert outlook["destination.ip"] == "172.16.4.10" and outlook["destination.port"] == "8080"
    assert outlook["process.pid"] == "904" and outlook["process.name"] == "OUTLOOK.EXE"


def test_memprocfs_no_address_marker_is_no_address():
    """D474: MemProcFS 5.19 writes `***` for an endpoint with no valid address (vmm/vmmnet.c:1158-1166) into net.csv's
    SrcAddr and DstAddr (vmm/modules/m_sys_net.c:151-165). T22's index held it as an address 141 times."""
    rows = [r for r in ROWS["net.csv"] if "***" in (r.get("SrcAddr"), r.get("DstAddr"))]
    assert rows, "T22's rows hold the marker"
    for row in rows:
        ecs = _flat(normalize("memprocfs", row, table="net.csv"))
        assert "***" not in (ecs.get("source.ip"), ecs.get("destination.ip"))


def test_an_event_read_from_memory_has_its_channel_code_provider_record_and_host():
    service = next(r for r in ROWS["eventlog.csv"] if r["EventID"] == "4697")
    ecs = _flat(normalize("memprocfs", service, table="eventlog.csv"))
    assert ecs["winlog.channel"] == "Security" and ecs["event.code"] == "4697"
    assert ecs["event.provider"] == "Microsoft-Windows-Security-Auditing" and ecs["winlog.record_id"] == "448042"
    assert ecs["host.name"] == "base-rd-01.shieldbase.lan"
    assert _host_user_event(service, "memprocfs", table="eventlog.csv")[0] == "base-rd-01.shieldbase.lan"


def test_a_scheduled_tasks_principal_id_is_no_account():
    for row in ROWS["tasks.csv"]:
        ecs = normalize("memprocfs", row, table="tasks.csv")
        assert "user" not in ecs, row["User"]
        assert _host_user_event(row, "memprocfs", table="tasks.csv", ecs=ecs)[1] == "", row["User"]


@pytest.mark.parametrize(("table", "accounts"), [
    ("process.csv", ["tdungan", "SYSTEM"]),
    ("services.csv", ["SYSTEM", "NT AUTHORITY\\LocalService"]),
    ("yara.csv", ["SYSTEM"]),
])
def test_a_process_service_or_yara_row_names_the_account_it_runs_as(table, accounts):
    for row, account in zip(ROWS[table], accounts, strict=True):
        ecs = normalize("memprocfs", row, table=table)
        assert ecs["user"]["name"] == account
        assert _host_user_event(row, "memprocfs", table=table, ecs=ecs)[1] == account


def test_a_table_the_map_does_not_list_maps_nothing_and_names_no_one():
    row = dict(ROWS["process.csv"][0])
    assert normalize("memprocfs", row, table="handles.csv") == {}
    assert _host_user_event(row, "memprocfs", table="handles.csv")[:2] == ("", "")


def test_every_mapped_column_is_a_column_of_its_table():
    """The names are MemProcFS 5.19's own headers (T22), never typed from memory."""
    emap = load_ecs_map()
    for section in ("family_columns", "event_host_user"):
        for table, entry in emap[section]["memprocfs"]["__tables__"].items():
            columns = set(entry) if section == "family_columns" else {c for cs in entry.values() for c in cs}
            assert columns <= set(T22["headers"][table]), (section, table, columns - set(T22["headers"][table]))


def test_the_index_builder_reads_each_table_by_its_own_entry(tmp_path, monkeypatch):
    """The real path: the lane's layout, the builder's walk, sanitiser and normaliser."""
    from nexus.langgraph import pipeline_runs
    from nexus.langgraph.case_index import iter_index_doc_batches

    case_dir = tmp_path / "CASE-D470-0001"
    extractions = case_dir / "runs" / "RUN-1" / "extractions"
    monkeypatch.setattr(pipeline_runs, "resolve_tools_extractions", lambda case_dir, run_id="": extractions)
    forensic = extractions / "memprocfs" / "mem.raw" / "forensic" / "csv"
    forensic.mkdir(parents=True)
    for table in ("net.csv", "tasks.csv", "eventlog.csv", "process.csv"):
        buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=T22["headers"][table], lineterminator="\n")
        writer.writeheader()
        writer.writerows(ROWS[table])
        (forensic / table).write_text(buffer.getvalue(), encoding="utf-8")

    docs = [doc for batch in iter_index_doc_batches(case_dir) for doc in batch]
    by_table: dict[str, list[dict]] = {}
    for doc in docs:
        by_table.setdefault(doc["file"].rsplit("/", 1)[-1], []).append(doc)
    assert {d["family"] for d in docs} == {"memprocfs"}
    # D474: the third row's `***` is MemProcFS's "no valid address" (vmmnet.c:1158-1166), not an address.
    assert [d["ecs"].get("destination", {}).get("ip") for d in by_table["net.csv"]] == [
        "172.16.4.5", "172.16.4.10", None]
    assert all("user" not in d for d in by_table["tasks.csv"])
    events = {d["ecs"]["event"]["code"]: d for d in by_table["eventlog.csv"]}
    assert events["4697"]["user"] == "shieldbase\\cbarton-a" and events["4697"]["host"] == "base-rd-01.shieldbase.lan"
    assert all(d["ecs"]["winlog"]["channel"] for d in by_table["eventlog.csv"])
    assert [d["user"] for d in by_table["process.csv"]] == ["tdungan", "system"]
