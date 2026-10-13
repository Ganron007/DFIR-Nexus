"""D119 (2026-10-13): Volatility's JSON lines in a `.txt` file are records with fields, and netscan rows are network connections.

These tests read the case's own run, which is evidence and is never committed. They skip in a clean checkout.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from nexus.langgraph.case_index import (
    _index_header,
    _json_lines_text,
    _open_text_auto,
    iter_indexable_rows,
)
from nexus.langgraph.ecs_normalize import normalize
from nexus.langgraph.event_categories import OTHER, present, row_category
from nexus.langgraph.evidence_rows import evidence_rows_for_hits
from nexus.langgraph.path_sanitize import machine_roots, sanitize_field_map
from nexus.langgraph.subject import ecs_leaves

NETSCAN = (
    Path(__file__).resolve().parents[1] / "cases" / "CASE-C5B04D31" / "runs"
    / "RUN-20261011T110426201672Z-tools-5618aeb2" / "extractions" / "vol" / "vol-windows-0df078ab-22a6d17f.txt"
)
REL = "vol/vol-windows-0df078ab-22a6d17f.txt"

pytestmark = pytest.mark.skipif(not NETSCAN.is_file(), reason="the case run is not present in this checkout")


def test_the_file_is_read_as_json_lines_not_as_text():
    assert _json_lines_text(NETSCAN)


def test_every_netscan_row_is_a_record_with_its_fields(tmp_path: Path):
    header = _index_header(NETSCAN)
    with _open_text_auto(NETSCAN) as fh:
        records = list(iter_indexable_rows(NETSCAN, fh, header, file_label=NETSCAN.name))
    assert len(records) == 168
    assert all("ForeignAddr" in fields and "LocalAddr" in fields for _n, _raw, fields in records)


def test_a_connection_is_classified_by_its_foreign_address_and_a_listener_is_not(tmp_path: Path):
    header = _index_header(NETSCAN)
    with _open_text_auto(NETSCAN) as fh:
        records = list(iter_indexable_rows(NETSCAN, fh, header, file_label=NETSCAN.name))
    classified = 0
    for line, _raw, fields in records:
        # The real path: map the fields, make the hit, build the evidence row, and classify the row.
        ecs = normalize("vol", sanitize_field_map(fields, tmp_path, roots=machine_roots(tmp_path), family="vol"), None)
        hit = {"family": "vol", "file": REL, "line": line, "fields": fields, "ecs": ecs_leaves(ecs)}
        category = row_category(evidence_rows_for_hits([hit])[0])
        if present(fields["ForeignAddr"]):
            classified += 1
            assert category == "network_connection"
        else:
            # A listening socket names 0.0.0.0 or :: as its foreign end: no destination, so no connection.
            assert category == OTHER
    assert classified == sum(1 for _l, _r, f in records if present(f["ForeignAddr"]))
