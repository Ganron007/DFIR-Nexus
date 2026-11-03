"""Precision contracts on date primitives and unchanged published real rows."""
import csv
import shutil
from pathlib import Path

import pytest

from nexus.langgraph.case_index import _mapping_body, ast_to_es, iter_index_docs
from nexus.langgraph.query_dsl import parse_query, row_matches
from nexus.langgraph.timestamps import parse_time_value


def _parts(value):
    value = value.replace("+00:00", "Z")
    assert value.endswith("Z")
    head, dot, fraction = value[:-1].partition(".")
    return head, fraction.ljust(9, "0") if dot else "000000000"


@pytest.mark.parametrize("raw, microseconds, precision", [
    ("2020-11-14T04:49:43.634Z", 634000, "ms"),
    ("2020-11-14T04:49:43.634567Z", 634567, "us"),
    ("2020-11-14T04:49:43.6345678Z", 634567, "ns"),
    ("1755000000.123456", 123456, "us"),
    ("1755000000.123456789", 123456, "ns"),
    ("1755000000123", 123000, "ms"),
])
def test_time_value_keeps_fraction_and_declares_its_actual_unit(raw, microseconds, precision):
    got = parse_time_value(raw)
    assert got is not None
    assert got["dt"].microsecond == microseconds
    assert got["precision"] == precision


def test_primary_index_time_keeps_the_published_windows_source_fraction(tmp_path):
    source = Path(__file__).parent / "fixtures/cs1b_evtx_real_rows.csv"
    case = tmp_path / "CASE-PRECISION"
    target = case / "extractions/evtxecmd/real.csv"
    target.parent.mkdir(parents=True)
    shutil.copyfile(source, target)
    with source.open(encoding="utf-8-sig", newline="") as stream:
        original = next(csv.DictReader(stream))["TimeCreated"]
    document = next(doc for doc in iter_index_docs(case) if doc["family"] == "evtxecmd")
    assert _parts(document["ts"]) == _parts(original.replace(" ", "T") + "Z")
    assert document["ts_precision"] == "ns"
    assert document["ts_tz_assumed"] is True
    from nexus.langgraph.evidence_rows import hit_time_of
    from nexus.langgraph.timeline_merge import hits_to_events

    assert _parts(hits_to_events([document])[0]["timestamp"]) == _parts(document["ts"])
    assert _parts(hit_time_of({"text": original})) == _parts(document["ts"])


def test_primary_mapping_can_represent_the_declared_source_precision():
    assert _mapping_body()["mappings"]["properties"]["ts"]["type"] == "date_nanos"


def test_admitted_fractional_bounds_survive_compilation_and_description():
    lo, hi = "2020-11-14T04:49:43.634567800Z", "2020-11-14T04:49:43.634567900Z"
    query = parse_query(f"ts:>={lo} ts:<={hi}")
    filters = ast_to_es(query, search_fields=True)["bool"]["filter"]
    bounds = next(item["range"]["ts"] for item in filters if "range" in item and "ts" in item["range"])
    assert _parts(bounds["gte"]) == _parts(lo)
    assert _parts(bounds["lte"]) == _parts(hi)
    described = parse_query(query.describe())
    repeated = ast_to_es(described, search_fields=True)["bool"]["filter"]
    assert repeated == filters


@pytest.mark.parametrize("row_time, expected", [
    ("2020-11-14T04:49:43.634567850Z", True),
    ("2020-11-14T04:49:43.634567950Z", False),
    ("2020-11-14T04:49:43.614567850Z", False),
])
def test_csv_time_filter_compares_the_same_exact_instants(row_time, expected):
    query = parse_query("ts:>=2020-11-14T04:49:43.634567800Z ts:<=2020-11-14T04:49:43.634567900Z")
    matched, _ = row_matches(query, line_lower="", row_ts=row_time)
    assert matched is expected


@pytest.mark.parametrize("raw, expected", [
    ("2020-11-14T04:49:43.634567890Z", "2020-11-14T04:49:43.63456789Z"),
    ("2020-11-14T10:19:43.634567890+05:30", "2020-11-14T04:49:43.63456789Z"),
    ("11/14/2020 4:49:43.634567890 AM +00:00", "2020-11-14T04:49:43.63456789Z"),
    ("1755000000.123456789", "2025-08-12T12:00:00.123456789Z"),
    ("1755000000123.456789", "2025-08-12T12:00:00.123456789Z"),
    ("133005678900000001", "2022-06-24T18:11:30.0000001Z"),
])
def test_canonical_instant_roundtrips_without_float_or_datetime_loss(raw, expected):
    got = parse_time_value(raw)
    assert got["iso"] == expected
    repeated = parse_time_value(got["iso"])
    assert repeated["epoch_ns"] == got["epoch_ns"]


def test_date_filter_includes_the_final_nanosecond_and_excludes_next_midnight():
    query = parse_query("ts:2020-11-14")
    assert row_matches(query, line_lower="", row_ts="2020-11-14T23:59:59.999999999Z")[0]
    assert not row_matches(query, line_lower="", row_ts="2020-11-15T00:00:00Z")[0]
    assert ast_to_es(query, search_fields=True)["bool"]["filter"] == [
        {"range": {"ts": {"gte": "2020-11-14T00:00:00Z", "lte": "2020-11-14T23:59:59.999999999Z"}}},
    ]


@pytest.mark.parametrize("op", [">", "<"])
def test_strict_time_bound_excludes_the_same_instant(op):
    instant = "2020-11-14T04:49:43.634567890Z"
    query = parse_query(f"ts:{op}{instant}")
    assert not row_matches(query, line_lower="", row_ts=instant)[0]
    neighbor = "2020-11-14T04:49:43.634567891Z" if op == ">" else "2020-11-14T04:49:43.634567889Z"
    assert row_matches(query, line_lower="", row_ts=neighbor)[0]


def test_native_nanos_sort_uses_lossless_string_cursor_and_accepts_it_again():
    from nexus.langgraph.es_native import _prepare_request_sort

    sort, _ = _prepare_request_sort([{"ts": "desc"}, "_doc"], {"ts": "date_nanos"})
    assert sort[0] == {"ts": {"order": "desc", "format": "strict_date_optional_time_nanos"}}
    cursor = ["2020-11-14T04:49:43.634567890Z", 1]
    repeated, _ = _prepare_request_sort(sort, {"ts": "date_nanos"}, cursor)
    assert repeated == sort


def test_date_sort_format_cannot_be_admitted_for_a_keyword_field():
    from nexus.langgraph.es_native import ESQueryError, _prepare_request_sort

    with pytest.raises(ESQueryError, match="sort format requires a date or date_nanos field"):
        _prepare_request_sort([{"host": {"order": "asc", "format": "strict_date_optional_time_nanos"}}],
                              {"host": "keyword"})


def test_explicit_date_sort_format_remains_supported():
    from nexus.langgraph.es_native import _prepare_request_sort

    sort = [{"ts": {"order": "asc", "format": "strict_date_optional_time_nanos"}}]
    assert _prepare_request_sort(sort, {"ts": "date"})[0] == sort


def test_csv_epoch_column_uses_the_same_time_authority_as_indexing():
    query = parse_query("ts:2025-08-12T12:00:00.123456789Z")
    assert row_matches(query, line_lower="1755000000.123456789", row_fields={"ts": "1755000000.123456789"})[0]
    assert not row_matches(query, line_lower="1755000000.123456788", row_fields={"ts": "1755000000.123456788"})[0]


def test_typed_date_comparison_keeps_submicrosecond_difference():
    from nexus.langgraph.query_dsl import _filter_matches

    spec = {"type": "date_nanos", "name": "clock", "op": "gt", "value": "2020-11-14T04:49:43.634567890Z"}
    assert _filter_matches(spec, {"clock": "2020-11-14T04:49:43.634567891Z"})
    assert not _filter_matches(spec, {"clock": spec["value"]})


def test_briefing_compares_instants_instead_of_variable_width_iso_strings(tmp_path, monkeypatch):
    from nexus.langgraph import case_index
    from nexus.langgraph.briefing import _index_census

    clocks = ["2020-11-14T04:49:43Z", "2020-11-14T04:49:43.1Z", "2020-11-14T04:49:43.100000001Z"]
    monkeypatch.setattr(case_index, "es_aggregate", lambda *a, **k: {"top": [
        {"value": str(i), "count": 1, "first_seen": clock, "last_seen": clock}
        for i, clock in enumerate(clocks)
    ]})
    assert _index_census(tmp_path)["time_range"] == {"start": clocks[0], "end": clocks[-1]}


@pytest.mark.parametrize("raw", ["2020-11-14T04:49:43.634567890Z", "2020-11-14T10:19:43.634567890+05:30"])
def test_shared_importer_fields_carry_exact_source_time_beside_compatibility_datetime(raw):
    from nexus.ingest.base import Importer

    fields = Importer.resolve_timestamp_fields(raw)
    assert fields["timestamp_ns"] == 1605329383634567890
    assert fields["timestamp"].microsecond == 634567
    assert fields["ts_synthesized"] is False


def test_exact_clock_contract_refuses_rounded_or_noninteger_companions():
    from datetime import UTC, datetime

    from nexus.langgraph.timestamps import timestamp_epoch_ns, timestamp_iso

    view = datetime(2020, 11, 14, 4, 49, 43, 634567, tzinfo=UTC)
    exact = 1605329383634567890
    assert timestamp_epoch_ns(view, exact) == exact
    assert timestamp_iso(view, exact) == "2020-11-14T04:49:43.634567890Z"
    assert timestamp_iso(view) == view.isoformat()
    with pytest.raises(ValueError, match="disagrees"):
        timestamp_iso(view, exact + 1000)
    with pytest.raises(ValueError, match="integer nanoseconds"):
        timestamp_epoch_ns(view, True)


def test_exact_zero_fraction_remains_explicit_across_canonical_serialization():
    from datetime import UTC, datetime

    from nexus.langgraph.timestamps import source_timestamp_ns, timestamp_iso

    view = datetime(2020, 11, 14, 4, 49, 43, tzinfo=UTC)
    raw = "2020-11-14T04:49:43.000000000Z"
    assert timestamp_iso(view, source_timestamp_ns(raw, view)) == raw


def test_timeline_window_does_not_floor_a_source_clock_onto_its_upper_bound():
    from datetime import UTC, datetime

    from nexus.langgraph.timeline_merge import _in_window

    start = datetime(2020, 11, 14, 4, 49, 43, tzinfo=UTC)
    end = start.replace(microsecond=634567)
    assert _in_window("2020-11-14T04:49:43.634567000Z", start, end)
    assert not _in_window("2020-11-14T04:49:43.634567001Z", start, end)


@pytest.mark.parametrize("left, right", [
    ("2021-04-21T14:56:41.78Z", "2021-04-21T14:56:41.786Z"),
    ("2021-04-21T14:56:41Z", "2021-04-21T14:56:41.001Z"),
    ("2021-04-21T20:26:41.000000001+05:30", "2021-04-21T14:56:41.000000002Z"),
])
def test_rule_clock_order_uses_complete_instants_with_variable_width_fractions(left, right):
    from nexus.langgraph.timestamps import time_before

    assert time_before(left, right)
    assert not time_before(right, left)
    assert not time_before(left, left)
