"""D117 (2026-10-13): Zeek, Suricata and flow outputs are read as records, mapped and classified on real outputs.

The fixtures in tests/fixtures/d117 are Zeek 9.0.0, Suricata 8.0.7 and tshark outputs for Zeek's public sample captures
(README there). The reader, the ECS map, the row builder and the category rules run on them as the index build does.
"""
from __future__ import annotations

from pathlib import Path

from nexus.langgraph.case_index import (
    _index_header,
    _open_text_auto,
    _zeek_header,
    iter_indexable_rows,
)
from nexus.langgraph.ecs_normalize import normalize
from nexus.langgraph.event_categories import OTHER
from nexus.langgraph.evidence_rows import evidence_rows_for_hits
from nexus.langgraph.path_sanitize import machine_roots, sanitize_field_map
from nexus.langgraph.subject import derive_subject, ecs_leaves

FIX = Path(__file__).resolve().parent / "fixtures" / "d117"


def _records(path: Path) -> list[tuple[int, dict[str, str]]]:
    """(starting line, fields) for each record of a fixture, read by the indexer's own reader."""
    header = _index_header(path)
    with _open_text_auto(path) as fh:
        return [(n, fields) for n, _raw, fields in iter_indexable_rows(path, fh, header, file_label=path.name)]


def _on_real_path(tmp_path: Path, family: str, rel: str, line: int, fields: dict[str, str]):
    """The row and subject one record gets: map its fields, make the hit, build the evidence row, derive the subject."""
    ecs = normalize(family, sanitize_field_map(fields, tmp_path, roots=machine_roots(tmp_path), family=family), None)
    hit = {"family": family, "file": rel, "line": line, "fields": fields, "ecs": ecs_leaves(ecs)}
    row = evidence_rows_for_hits([hit])[0]
    return row, derive_subject([row])


def test_zeek_conn_log_names_its_columns_and_stores_no_unset_cell():
    path = FIX / "zeek/http-bro-org/conn.log"
    assert "id.resp_h" in _zeek_header(path)
    records = _records(path)
    assert len(records) == 13  # the data lines; the `#` header block is not a record
    assert all("id.resp_h" in fields and "uid" in fields for _n, fields in records)
    assert all(value not in ("-", "(empty)") for _n, fields in records for value in fields.values())


def test_a_zeek_connection_is_a_network_connection_to_its_responder(tmp_path: Path):
    rel = "network/http-bro-org/zeek/conn.log"
    line, fields = _records(FIX / "zeek/http-bro-org/conn.log")[0]
    row, subject = _on_real_path(tmp_path, "zeek", rel, line, fields)
    assert subject["category"] == "network_connection"
    assert subject["entity"] == {"type": "address", "value": fields["id.resp_h"]}
    assert row["destination_ip"] == fields["id.resp_h"]


def test_zeek_dns_is_not_classified_yet(tmp_path: Path):
    # A DNS row's subject would be the resolver, not the name asked for: no category until that is decided (D117).
    rel = "network/dns53/zeek/dns.log"
    line, fields = _records(FIX / "zeek/dns53/dns.log")[0]
    _row, subject = _on_real_path(tmp_path, "zeek", rel, line, fields)
    assert subject["category"] == OTHER


def test_a_suricata_alert_carries_its_signature_and_destination(tmp_path: Path):
    rel = "network/conn-size/suricata/eve.json"
    alerts = [(n, f) for n, f in _records(FIX / "suricata/conn-size/eve.json") if f.get("event_type") == "alert"]
    assert alerts, "the fixture holds alert events"
    line, fields = alerts[0]
    assert fields["alert.signature"]  # nested keys are flattened into dotted fields, not lost
    row, subject = _on_real_path(tmp_path, "suricata", rel, line, fields)
    assert row["destination_ip"] == fields["dest_ip"]
    assert subject["category"] == "network_connection"
    assert subject["entity"] == {"type": "address", "value": fields["dest_ip"]}


def test_a_suricata_dns_query_list_stays_in_the_text(tmp_path: Path):
    # Suricata 8.0.7 writes DNS queries as a list. Lists are not flattened, so the name is in the text, not a field.
    dns = [(n, f) for n, f in _records(FIX / "suricata/dns53/eve.json") if f.get("event_type") == "dns"]
    assert dns
    _line, fields = dns[0]
    assert not any(key.startswith("dns.queries") for key in fields)


def test_a_flow_is_a_network_connection_to_its_destination(tmp_path: Path):
    rel = "ingest/network/conn-size-flows.csv"
    line, fields = _records(FIX / "network/conn-size/capture-flows.csv")[0]
    row, subject = _on_real_path(tmp_path, "network", rel, line, fields)
    assert row["destination_ip"] == fields["dst_ip"]
    assert subject["category"] == "network_connection"
    assert subject["entity"] == {"type": "address", "value": fields["dst_ip"]}


def test_a_flow_without_its_destination_is_not_classified(tmp_path: Path):
    # The same real flow with its destination removed: nothing names where it went, so it is not a connection
    # classified about the host (the requires check, D117).
    rel = "ingest/network/conn-size-flows.csv"
    line, fields = _records(FIX / "network/conn-size/capture-flows.csv")[0]
    no_destination = {key: value for key, value in fields.items() if key != "dst_ip"}
    _row, subject = _on_real_path(tmp_path, "network", rel, line, no_destination)
    assert subject["category"] == OTHER
    assert subject["entity"].get("type") != "host"
